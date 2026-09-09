"""Driver: run the Go witnesses through Lich's real WSL bridge + outcome
classifier, unmodified except for the harmless `go-runtime` addition to
`outcome.py::_EXPECTED` (see tooling/lich/outcome_go_runtime.patch).

This intentionally bypasses `sandbox.py`'s flag-file/witness_synth layer
(that needs an M1 review-flags.jsonl input and a new synthesizer for
malformed-fixture-tree witnesses -- explicitly out of scope per
tooling/LICH_WITNESS_PLAN.md: "new code, not reuse"). It drives the same
load-bearing pieces sandbox.py would call for each witness:
    bridge.wsl.run_in_wsl   -- the real cap-enforcing WSL child
    outcome.classify        -- the real six-way status classifier
and appends run-log-shaped JSONL records, matching sandbox.py's schema,
to reports/lich/run-log.jsonl.

Usage: python tooling/lich/run_witnesses.py
"""
from __future__ import annotations

import datetime as _dt
import json
import sys
import time
from pathlib import Path

_LICH_SCRIPTS = Path.home() / ".lava-workbench" / "lich" / "plugins" / "lich-sandbox" / "scripts"
sys.path.insert(0, str(_LICH_SCRIPTS))

from bridge.wsl import run_in_wsl  # noqa: E402
import outcome as _outcome  # noqa: E402

_REPO = Path(__file__).resolve().parents[2]
_WITNESS_FILE = str(Path(__file__).resolve().parent / "witness_go.py")
_OUT = _REPO / "reports" / "lich" / "run-log.jsonl"

_SENSOR_BIN_WSL = "/mnt/c/lava-sensor-exercise/sensor/bin/lab"
_LAB_DIR_WSL = "/mnt/c/lava-sensor-exercise/sensor/internal/lab"

WITNESSES = [
    {
        "id": "W1a-hang",
        "flag_class": "go-runtime",
        "description": "internal/probe exec runner: TIMEOUT kills whole process group (L09/L40)",
        "witness": {
            "args": [f"{_SENSOR_BIN_WSL}/probe.test",
                      ["-test.run=TestExecTimeoutKillsTheWholeProcessGroup", "-test.v"]],
            "kwargs": {},
        },
        "timeout_s": 10,
        "expect": "Go test forks a fixture child internally; RLIMIT_NPROC=0 "
                  "(unmodified -- relaxation was blocked, see report) is expected "
                  "to make that internal fork fail closed under Lich.",
    },
    {
        "id": "W1b-flood",
        "flag_class": "go-runtime",
        "description": "internal/probe exec runner: output cap + kill on overflow",
        "witness": {
            "args": [f"{_SENSOR_BIN_WSL}/probe.test",
                      ["-test.run=TestExecOutputCapAndKillOnOverflow", "-test.v"]],
            "kwargs": {},
        },
        "timeout_s": 10,
        "expect": "Same NPROC constraint as W1a (the flood fixture is also a forked child).",
    },
    {
        "id": "W2-malformed-fixtures",
        "flag_class": "go-runtime",
        "description": "internal/lab fault-injection subset against malformed/hostile "
                        "fixture data (size lies, symlink edge cases, contradictory SSH "
                        "oracle output, empty evidence) -- no internal subprocess forking, "
                        "so it needs no NPROC headroom.",
        "witness": {
            "args": [f"{_SENSOR_BIN_WSL}/lab.test",
                      ["-test.run=TestFaultInjection_(SizeLyingRead_CapRespected|"
                       "SymlinkIntoUserWritableTreeNotFollowed|"
                       "SysfsInRootSymlinksAreFollowed|"
                       "SSHOracleFaultsNeverProduceAFalseVerdict|"
                       "ContradictoryObservationsAreContested|"
                       "EmptyEvidenceStillProducesAWellShapedObject|"
                       "UnderClaim_UdevFallbackEstablishesModel)",
                       "-test.v"]],
            "kwargs": {"chdir": _LAB_DIR_WSL},
        },
        "timeout_s": 10,
        "expect": "exit 0, no panic, no hang -- clean under Lich's real, unmodified caps.",
    },
    {
        "id": "W3-panic-isolation",
        "flag_class": "go-runtime",
        "description": "internal/scan engine: a panicking check yields one unknown "
                        "finding, the rest unaffected",
        "witness": {
            "args": [f"{_SENSOR_BIN_WSL}/scan.test",
                      ["-test.run=TestPanicIsolation", "-test.v"]],
            "kwargs": {},
        },
        "timeout_s": 10,
        "expect": "exit 0 -- the Go test itself asserts panic isolation; no forking needed.",
    },
]


def _iso_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def run_one(w: dict) -> dict:
    start = time.monotonic()
    result = run_in_wsl(
        script_path=_WITNESS_FILE,
        entrypoint="witness_exec_replace",
        witness_json=json.dumps(w["witness"]),
        timeout_s=w["timeout_s"],
    )
    duration_ms = int((time.monotonic() - start) * 1000)
    status, error_class = _outcome.classify(
        flag_class=w["flag_class"],
        exit_code=result["exit_code"],
        stderr=result["stderr"],
        signal_name=result["signal"],
    )
    record = {
        "ts": _iso_now(),
        "witness_id": w["id"],
        "description": w["description"],
        "expect": w["expect"],
        "flag_ref": {"file": _WITNESS_FILE, "function": "witness_exec_replace",
                     "flag_class": w["flag_class"]},
        "witness": w["witness"],
        "status": status,
        "exit_code": result["exit_code"],
        "signal": result["signal"],
        "error_class": error_class,
        "stdout_head": result["stdout"][:2000],
        "stderr_head": result["stderr"][:2000],
        "duration_ms": duration_ms,
        "backend": "wsl",
    }
    return record


def main() -> int:
    _OUT.parent.mkdir(parents=True, exist_ok=True)
    with _OUT.open("a", encoding="utf-8") as fh:
        for w in WITNESSES:
            print(f"--- running {w['id']} ---")
            rec = run_one(w)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            print(json.dumps({k: rec[k] for k in
                               ("witness_id", "status", "exit_code", "signal",
                                "error_class", "duration_ms")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
