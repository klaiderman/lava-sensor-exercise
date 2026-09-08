#!/usr/bin/env python3
"""Tiny Custom Investigator (TCI).

Safe, bounded, unprivileged, read-only reconnaissance of a remote Linux host
over SSH, driven by a registry of symbolic ProbeIDs (tooling/tci/probes.json).
The planner never generates shell; it only selects ProbeIDs. A trusted
executor maps each ProbeID to exactly one allowlisted read-only command with
its own timeout and output cap. See README.md for the full contract.
"""
import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time

import check_registry

# --------------------------------------------------------------------------
# Evidence classification
# --------------------------------------------------------------------------
STATUSES = (
    "OK", "TIMEOUT", "EACCES", "ENOENT", "UTILITY_MISSING", "UNSUPPORTED",
    "EXECUTION_ERROR", "SESSION_LOST", "NOT_ATTEMPTED",
)

_RE_EACCES = re.compile(r'Permission denied|Operation not permitted|EACCES|EPERM')
_RE_UNSUPPORTED = re.compile(
    r'Operation not supported|Not supported|Function not implemented|'
    r'Inappropriate ioctl|ENOTSUP|EOPNOTSUPP|ENOSYS')
_RE_ENOENT = re.compile(
    r'No such file or directory|cannot access .*: No such file|not found')
_RE_CMD_NOT_FOUND = re.compile(r'command not found', re.I)


def classify_status(rc, stdout):
    """Return (status, classified_from) per the fixed precedence order:
    TIMEOUT -> UTILITY_MISSING -> EACCES -> UNSUPPORTED -> ENOENT ->
    EXECUTION_ERROR -> OK.
    """
    s = stdout or ""
    if rc in (124, 137):
        return "TIMEOUT", f"rc={rc}"
    if rc == 127 or _RE_CMD_NOT_FOUND.search(s):
        return "UTILITY_MISSING", ("rc=127" if rc == 127 else "command not found")
    if rc != 0:
        m = _RE_EACCES.search(s)
        if m:
            return "EACCES", m.group(0)
    m = _RE_UNSUPPORTED.search(s)
    if m:
        return "UNSUPPORTED", m.group(0)
    if rc != 0:
        m = _RE_ENOENT.search(s)
        if m:
            return "ENOENT", m.group(0)
    if rc != 0:
        return "EXECUTION_ERROR", f"rc={rc}"
    return "OK", "rc=0"


def make_evidence(pid, rc, stdout, cap_bytes=None, truncated=None,
                   duration_hint=None, status_override=None,
                   classified_from_override=None):
    if status_override is not None:
        status, classified_from = status_override, classified_from_override
    else:
        status, classified_from = classify_status(rc, stdout)
    if truncated is None:
        truncated = bool(cap_bytes) and len(stdout.encode("utf-8", "ignore")) >= cap_bytes
    return {
        "id": pid, "status": status, "rc": rc, "stdout": stdout,
        "truncated": truncated, "duration_hint": duration_hint,
        "classified_from": classified_from,
    }


# --------------------------------------------------------------------------
# Fact extraction (OK-only)
# --------------------------------------------------------------------------
class FactStore:
    """Per-run fact state. No module globals -- one instance per planner run."""

    def __init__(self):
        self.established = {}      # name -> value
        self.origin = {}           # name -> probe id that established it
        self.contested = {}        # name -> [{"probe":..., "value":...}, ...]
        self.unresolved = {}       # name -> [{"probe":..., "status":...}, ...]

    def set_fact(self, name, value, probe_id):
        if name in self.contested:
            self.contested[name].append({"probe": probe_id, "value": value})
            return
        if name in self.established:
            if self.established[name] != value:
                self.contested[name] = [
                    {"probe": self.origin[name], "value": self.established[name]},
                    {"probe": probe_id, "value": value},
                ]
                del self.established[name]
                del self.origin[name]
            return
        self.established[name] = value
        self.origin[name] = probe_id
        self.unresolved.pop(name, None)

    def mark_unresolved(self, name, probe_id, status):
        if name in self.established or name in self.contested:
            return
        self.unresolved.setdefault(name, []).append(
            {"probe": probe_id, "status": status})

    def satisfies(self, requires):
        for req in requires:
            fact = req.get("fact")
            if "eq" in req:
                if self.established.get(fact, object()) != req["eq"]:
                    return False
            elif req.get("exists"):
                if fact not in self.established:
                    return False
        return True

    def missing_for(self, requires):
        missing = []
        for req in requires:
            fact = req.get("fact")
            if "eq" in req:
                if self.established.get(fact, object()) != req["eq"]:
                    missing.append(fact)
            elif req.get("exists"):
                if fact not in self.established:
                    missing.append(fact)
        return missing


def apply_facts(probe, evidence, facts):
    """Apply probe['facts'] rules to `facts` (a FactStore) given `evidence`."""
    rules = probe.get("facts") or []
    if not rules:
        return
    if evidence["status"] != "OK":
        for rule in rules:
            facts.mark_unresolved(rule["name"], probe["id"], evidence["status"])
        return
    stdout = evidence["stdout"] or ""
    for rule in rules:
        name = rule["name"]
        if "value_from_group" in rule:
            m = re.search(rule["regex"], stdout, re.MULTILINE)
            if m:
                facts.set_fact(name, m.group(rule["value_from_group"]), probe["id"])
        elif "value_if_match" in rule:
            matched = re.search(rule["regex"], stdout, re.MULTILINE) is not None
            value = rule["value_if_match"] if matched else rule["value_if_nomatch"]
            facts.set_fact(name, value, probe["id"])
        elif rule.get("nonempty"):
            facts.set_fact(name, bool(stdout.strip()), probe["id"])
        elif rule.get("value") is True:
            if re.search(rule["regex"], stdout, re.MULTILINE):
                facts.set_fact(name, True, probe["id"])


# --------------------------------------------------------------------------
# Remote script protocol
# --------------------------------------------------------------------------
def escape_single_quotes(s):
    return s.replace("'", "'\\''")


def build_remote_script(probes):
    lines = ["export LC_ALL=C; export TERM=dumb;"]
    for p in probes:
        pid = p["id"]
        cmd_escaped = escape_single_quotes(p["cmd"])
        lines.append(f"printf '\\n__TCI_BEGIN %s\\n' '{pid}'")
        lines.append(
            f"( timeout -k 1 {p['timeout_s']} bash -c '{cmd_escaped}' "
            f"</dev/null 2>&1 | head -c {p['cap_bytes']}; "
            f"printf '\\n__TCI_RC %s\\n' \"${{PIPESTATUS[0]}}\" )")
        lines.append(f"printf '__TCI_END %s\\n' '{pid}'")
    return "\n".join(lines) + "\n"


_BLOCK_RE = re.compile(
    r'__TCI_BEGIN (?P<id>\S+)\n(?P<body>.*?)__TCI_RC (?P<rc>-?\d+)\n'
    r'__TCI_END (?P=id)\n?', re.S)
_BEGIN_RE = re.compile(r'__TCI_BEGIN (\S+)\n')


def parse_stream(output, expected_ids, caps=None):
    """Parse the remote script's stdout into {id: Evidence}.

    Probes with a matched BEGIN...RC...END block get a normally classified
    Evidence. A probe with a BEGIN but no matching END is SESSION_LOST
    (stream got cut off mid-probe). A probe never begun at all is
    NOT_ATTEMPTED (it was never reached / the session died before it).
    """
    caps = caps or {}
    evidence = {}
    for m in _BLOCK_RE.finditer(output):
        pid = m.group("id")
        body = m.group("body")
        if body.endswith("\n"):
            body = body[:-1]
        rc = int(m.group("rc"))
        evidence[pid] = make_evidence(pid, rc, body, cap_bytes=caps.get(pid))

    completed = set(evidence.keys())
    for pid, pos in ((m.group(1), m.start()) for m in _BEGIN_RE.finditer(output)):
        if pid in completed:
            continue
        body = output[pos:]
        evidence[pid] = make_evidence(
            pid, None, body, truncated=True,
            status_override="SESSION_LOST", classified_from_override="incomplete_stream")
        completed.add(pid)

    for pid in expected_ids:
        if pid not in evidence:
            evidence[pid] = make_evidence(
                pid, None, "", truncated=False,
                status_override="NOT_ATTEMPTED", classified_from_override="no_begin_marker")
    return evidence


# --------------------------------------------------------------------------
# .env raw parser
# --------------------------------------------------------------------------
def parse_env_file(path):
    """RAW line parser: split on first '=', strip CR, strip one layer of
    surrounding quotes. Never lets bash interpret backslashes."""
    result = {}
    with open(path, "r", encoding="utf-8", newline="") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if not line or line.lstrip().startswith("#"):
                continue
            if "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            result[key] = val
    return result


def to_unix_path(path):
    """Convert a Windows-style key path to a unix path via cygpath -u, if it
    looks like one; otherwise return unchanged."""
    if not path or not re.match(r'^[A-Za-z]:[\\/]', path):
        return path
    try:
        out = subprocess.run(["cygpath", "-u", path], capture_output=True,
                              text=True, timeout=5)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return path


def _run_script_bytes(cmd, script, timeout_s, log, timeout_msg):
    """Run `cmd` feeding `script` on stdin using raw bytes I/O.

    Deliberately avoids subprocess's text=True mode: on Windows, text-mode
    stdin is newline-translated ('\\n' -> '\\r\\n'), which corrupts the bash
    script (bash chokes on the stray '\\r'). Encoding/decoding ourselves
    keeps every line ending exactly '\\n' end to end.
    """
    try:
        proc = subprocess.run(cmd, input=script.encode("utf-8"),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout_s)
        out, err = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        out = e.stdout if isinstance(e.stdout, (bytes, bytearray)) else b""
        err = e.stderr if isinstance(e.stderr, (bytes, bytearray)) else b""
        log(timeout_msg)
    return (out or b"").decode("utf-8", "replace") + (err or b"").decode("utf-8", "replace")


# --------------------------------------------------------------------------
# Executors
# --------------------------------------------------------------------------
class FakeExecutor:
    """Test executor: `handler(probes) -> {id: Evidence}`."""

    def __init__(self, handler):
        self.handler = handler

    def run_batch(self, probes):
        return self.handler(probes)


class LocalExecutor:
    """Runs the remote script through a local shell (WSL or plain bash) --
    used to validate the wire protocol without touching the real host."""

    def __init__(self, shell_cmd=None, log=None):
        self.shell_cmd = shell_cmd or ["wsl", "-e", "bash", "-s"]
        self.log = log or (lambda msg: None)

    def run_batch(self, probes):
        script = build_remote_script(probes)
        caps = {p["id"]: p["cap_bytes"] for p in probes}
        total_timeout = min(600, sum(p["timeout_s"] for p in probes) + 60)
        self.log(f"executing batch of {len(probes)} probes (local shell)")
        output = _run_script_bytes(self.shell_cmd, script, total_timeout, self.log,
                                    "local batch subprocess timed out")
        return parse_stream(output, [p["id"] for p in probes], caps)


class SshExecutor:
    """Runs the remote script over ssh in a single session. Never logs
    host/user/key values -- only placeholders."""

    def __init__(self, env_file, log=None):
        self.env = parse_env_file(env_file)
        self.log = log or (lambda msg: None)

    def _ssh_command(self):
        host = self.env.get("TARGET_HOST", "")
        user = self.env.get("TARGET_USER", "")
        key = to_unix_path(self.env.get("SSH_KEY_PATH", ""))
        home = os.environ.get("HOME", os.path.expanduser("~"))
        known_hosts = f"{home}/.ssh/known_hosts.lava"
        cmd = [
            "ssh", "-i", key,
            "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=15",
            "-o", "ServerAliveInterval=10",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={known_hosts}",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            f"{user}@{host}", "bash", "-s",
        ]
        return cmd

    def run_batch(self, probes):
        script = build_remote_script(probes)
        caps = {p["id"]: p["cap_bytes"] for p in probes}
        total_timeout = min(600, sum(p["timeout_s"] for p in probes) + 60)
        self.log(
            f"executing batch of {len(probes)} probes over ssh "
            f"<USER>@<HOST> with key <KEY>")
        output = _run_script_bytes(self._ssh_command(), script, total_timeout,
                                    self.log, "ssh batch subprocess timed out")
        return parse_stream(output, [p["id"] for p in probes], caps)


# --------------------------------------------------------------------------
# Planner
# --------------------------------------------------------------------------
class Planner:
    def __init__(self, probes, executor, out_dir=None, max_probes=400,
                 max_rounds=6, log=None):
        self.probes_by_id = {p["id"]: p for p in probes}
        self.executor = executor
        self.out_dir = out_dir
        self.max_probes = max_probes
        self.max_rounds = max_rounds
        self.log = log or (lambda msg: None)
        self.facts = FactStore()
        self.evidence = {}
        self.ran = set()
        self.not_attempted_budget = set()

        self.fact_producers = {}
        for p in probes:
            for rule in (p.get("facts") or []):
                self.fact_producers.setdefault(rule["name"], []).append(p["id"])

    def _eligible(self):
        return sorted(
            (p for pid, p in self.probes_by_id.items()
             if pid not in self.ran and self.facts.satisfies(p["requires"])),
            key=lambda p: (-p["priority"], p["id"]))

    def run(self):
        round_no = 0
        while round_no < self.max_rounds:
            eligible = self._eligible()
            if not eligible:
                break
            remaining_budget = self.max_probes - len(self.ran)
            if remaining_budget <= 0:
                for p in eligible:
                    self.not_attempted_budget.add(p["id"])
                self.log(f"round {round_no}: budget exhausted, "
                         f"{len(eligible)} eligible probe(s) not attempted")
                break
            batch = eligible[:remaining_budget]
            cut = eligible[remaining_budget:]
            for p in cut:
                self.not_attempted_budget.add(p["id"])
            self.log(f"round {round_no}: running batch of {len(batch)} probe(s)"
                     + (f", {len(cut)} cut by budget" if cut else ""))
            t0 = time.time()
            batch_evidence = self.executor.run_batch(batch)
            dt = time.time() - t0
            for p in sorted(batch, key=lambda p: p["id"]):
                ev = batch_evidence.get(p["id"]) or make_evidence(
                    p["id"], None, "", status_override="SESSION_LOST",
                    classified_from_override="missing_from_executor_result")
                ev["duration_hint"] = ev.get("duration_hint") or round(dt, 3)
                self.evidence[p["id"]] = ev
                self.ran.add(p["id"])
                apply_facts(p, ev, self.facts)
                self.log(f"  {p['id']}: {ev['status']}")
                self._write_probe_file(round_no, p["id"], ev)
            round_no += 1
            if cut:
                break

        not_eligible = {}
        for pid, p in self.probes_by_id.items():
            if pid in self.ran or pid in self.not_attempted_budget:
                continue
            not_eligible[pid] = self.facts.missing_for(p["requires"])

        return self._report(not_eligible)

    def _write_probe_file(self, round_no, pid, evidence):
        if not self.out_dir:
            return
        probes_dir = os.path.join(self.out_dir, "probes")
        os.makedirs(probes_dir, exist_ok=True)
        path = os.path.join(probes_dir, f"{round_no}_{pid}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    def _report(self, not_eligible):
        alternatives_remaining = {}
        for fact in self.facts.unresolved:
            producers = self.fact_producers.get(fact, [])
            alternatives_remaining[fact] = [
                pid for pid in producers if pid not in self.ran]
        return {
            "established_facts": dict(self.facts.established),
            "contested": dict(self.facts.contested),
            "unresolved": {k: v for k, v in self.facts.unresolved.items()},
            "alternatives_remaining": alternatives_remaining,
            "not_attempted_budget": sorted(self.not_attempted_budget),
            "not_eligible": not_eligible,
        }


# --------------------------------------------------------------------------
# Snapshot sanitizer
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_IPV6_RE = re.compile(r'\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b')
_MAC_RE = re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')
_SERIAL_RE = re.compile(r'(?i)(serial\S*[=: ]+)(\S+)')


def sanitize_stdout(stdout, sensitivity):
    if sensitivity == "identity":
        s = _MAC_RE.sub("<mac>", stdout)
        s = _IPV4_RE.sub("<ip>", s)
        s = _IPV6_RE.sub("<ip>", s)
        s = _SERIAL_RE.sub(lambda m: m.group(1) + "<serial>", s)
        return s
    if sensitivity == "maybe_secret_adjacent":
        lines = stdout.splitlines()
        return "\n".join(lines[:40])
    return stdout


def build_snapshot(registry, report, evidence_by_id, generated_at=None):
    probes_by_id = {p["id"]: p for p in registry["probes"]}
    statuses_summary = {}
    sanitized_evidence = {}
    for pid, ev in evidence_by_id.items():
        statuses_summary[ev["status"]] = statuses_summary.get(ev["status"], 0) + 1
        sensitivity = probes_by_id.get(pid, {}).get("sensitivity", "low")
        sanitized_evidence[pid] = {
            "status": ev["status"],
            "rc": ev["rc"],
            "truncated": ev["truncated"],
            "stdout": sanitize_stdout(ev["stdout"] or "", sensitivity),
        }
    return {
        "generated_at": generated_at or datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tool": "tci",
        "registry_version": registry.get("version"),
        "probe_count": len(registry.get("probes", [])),
        "statuses_summary": statuses_summary,
        "established_facts": report["established_facts"],
        "contested": report["contested"],
        "unresolved": report["unresolved"],
        "not_attempted_budget": report["not_attempted_budget"],
        "not_eligible": report["not_eligible"],
        "evidence": sanitized_evidence,
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def make_logger(out_dir):
    if not out_dir:
        return lambda msg: None
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "run.log")

    def log(msg):
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    return log


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    ap = argparse.ArgumentParser(prog="tci.py")
    ap.add_argument("--registry", required=True)
    ap.add_argument("--env-file")
    ap.add_argument("--executor", choices=["ssh", "wsl", "local"], default="wsl")
    ap.add_argument("--local-shell", action="store_true")
    ap.add_argument("--out-dir")
    ap.add_argument("--snapshot")
    ap.add_argument("--max-probes", type=int, default=400)
    ap.add_argument("--max-rounds", type=int, default=6)
    ap.add_argument("--only-group")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    registry = check_registry.load_registry(args.registry)
    ok, errors = check_registry.validate_registry(registry)
    if not ok:
        print(f"REGISTRY INVALID: {len(errors)} error(s)", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    probes = registry["probes"]
    if args.only_group:
        groups = set(args.only_group.split(","))
        probes = [p for p in probes if p.get("group") in groups]

    if args.dry_run:
        facts = FactStore()
        first_round = sorted(
            (p for p in probes if facts.satisfies(p["requires"])),
            key=lambda p: (-p["priority"], p["id"]))
        print(f"registry OK: {len(probes)} probe(s) selected")
        print(f"first round: {len(first_round)} probe(s)")
        for p in first_round:
            print(f"  {p['id']}  [{p['group']}]  {p['cmd']}")
        return 0

    log = make_logger(args.out_dir)
    log(f"tci run starting: executor={args.executor} probes={len(probes)}")

    if args.executor == "ssh":
        if not args.env_file:
            print("--env-file is required for --executor ssh", file=sys.stderr)
            return 2
        executor = SshExecutor(args.env_file, log=log)
    elif args.executor == "wsl":
        executor = LocalExecutor(["wsl", "-e", "bash", "-s"], log=log)
    else:
        executor = LocalExecutor(["bash", "-s"], log=log)

    planner = Planner(probes, executor, out_dir=args.out_dir,
                       max_probes=args.max_probes, max_rounds=args.max_rounds,
                       log=log)
    report = planner.run()

    if args.out_dir:
        with open(os.path.join(args.out_dir, "facts.json"), "w", encoding="utf-8") as f:
            json.dump(report["established_facts"], f, indent=2)
        with open(os.path.join(args.out_dir, "report.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

    if args.snapshot:
        snapshot = build_snapshot(registry, report, planner.evidence)
        os.makedirs(os.path.dirname(args.snapshot) or ".", exist_ok=True)
        with open(args.snapshot, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)

    log("tci run complete")
    print(f"ran {len(planner.ran)} probe(s); "
          f"established {len(report['established_facts'])} fact(s); "
          f"contested {len(report['contested'])}; "
          f"unresolved {len(report['unresolved'])}; "
          f"not_attempted_budget {len(report['not_attempted_budget'])}; "
          f"not_eligible {len(report['not_eligible'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
