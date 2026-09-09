# Lava Sensor Exercise

A read-only Linux posture sensor. It runs as an ordinary user, describes the machine it is on, and writes one JSON file of findings — where every finding carries the observations it was derived from, and says `unknown` rather than guess when those observations were not enough.

## What it does

`sensor scan --out findings.json` produces two things: a `machine` block describing the host (identity, owner, hardware, OS, storage — every field with a `*_source` naming the path or command it came from), and one finding per registered check.

Each finding is `pass`, `fail` or `unknown`.

`unknown` is a real answer, not a failure to answer. It means the sensor attempted the observation and can say exactly why it did not resolve. Every `unknown` carries a `reason` from a closed vocabulary — `EACCES`, `EPERM`, `ENOENT`, `TIMEOUT`, `UTILITY_MISSING`, `BUDGET_EXHAUSTED`, `CONTESTED`, `NO_EVIDENCE` and a few more — plus the evidence behind it. The distinctions that vocabulary protects are the point of the tool:

- **denied is not absent** — `EACCES` on a directory never becomes "nothing is in there"
- **a missing utility is not a missing capability** — `ipmitool` not being installed says nothing about whether a BMC exists
- **a timeout is not a negative** — a probe that did not finish is not a control that is off

## Highlights

- **Evidence entails the verdict.** Every finding carries a generated `completeness` object: how many observations were made, how many were load-bearing, which of those failed, and whether an absence is provable from them. The engine derives it; checks do not write it themselves.
- **Honest uncertainty is enforced, not encouraged.** Observations are load-bearing by default; exempting one requires recording why, and the reason ships in the evidence. A check that claims an enumeration completed while a load-bearing observation failed is downgraded to `unknown` and marked `entailment_violation`, and the test suite fails the build on any such claim. The same rule can be pointed at a `findings.json` after the fact, so an artifact can be audited without re-running anything.
- **Bounded everywhere.** One read primitive and one subprocess runner. Reads are capped by policy, never by the file's own reported size — `st_size` lies under `/proc` and `/sys`. Every subprocess gets its own process group, a deadline, a `WaitDelay` and capped output, and is killed as a group if it overruns. Walks carry depth, entry, time and mount-boundary limits, and report which one they hit.
- **Failure isolation.** One finding per registered check, always. A check that panics, times out, or never runs because the scan deadline expired still emits a schema-valid finding. Silent omission is the failure mode the engine exists to prevent.
- **Unprivileged and read-only.** The only file written is `--out`.
- **No third-party code in the binary.** The shipped executable imports the standard library only.

## Checks

26 checks across five categories.

| Category | What it inspects |
|---|---|
| `REMOTE_ACCESS` | How the machine can be logged into and what that permits: sshd root-login and authentication policy resolved over the full `Include` chain, whether the configuration on disk is the one the running daemon actually loaded, non-loopback listeners taken from the kernel socket tables, who can log in and who can escalate, and host packet-filter state. |
| `SECRETS_ON_DISK` | Credential material and who can reach it: private key material, application credential files judged against the permission rule their own software documents, the OS's own secret stores, and cloud-init/Ignition provisioning payloads. Metadata only — a candidate's first 64 bytes are read to classify it and discarded; no secret value ever enters the output. |
| `BMC_INBAND_ACCESS` | Whether the host can reach its own baseboard management controller from inside the OS: firmware declaration, whether the controller answers, who may open the device node, latent host interfaces, and client tooling inventory. No IPMI command is ever issued and the device node is never opened. |
| `STORAGE_POSTURE` | Data-at-rest and hand-back hygiene on rented hardware: block-level encryption, redundancy of the root filesystem, attached-but-unaccounted block devices, and whether drive health telemetry is observable at all. |
| `BOOT_CHAIN` | Whether the boot path can be trusted: Secure Boot state, UEFI platform Setup Mode, kernel lockdown, taint from unsigned or out-of-tree modules, TPM presence, boot artifact readability, and running-versus-installed kernel drift. |

`STORAGE_POSTURE` and `BOOT_CHAIN` are the two categories the sensor adds; the other three are required by the exercise.

## Build and run

From a clean clone. The target host needs no Go toolchain — the binary is a static `linux/amd64` executable.

```
git clone https://github.com/klaiderman/lava-sensor-exercise
cd lava-sensor-exercise/sensor
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sensor ./cmd/sensor
./bin/sensor scan --out findings.json
```

Run it as an ordinary user. No `sudo`, and no arguments beyond those — the only other flag is `--version`. There is deliberately no `--timeout`, no `--root` and no `--skip`: a bound an operator can raise from the command line is not a bound.

Tests: `go test ./...` from the `sensor` directory. Linux-only tests skip on other platforms.

Exit codes: `0` the scan completed and the file was written; `1` the file was written but failed the sensor's own structural self-check, with the failing JSON pointers on stderr; `2` the file could not be written, or the invocation was invalid. A finding's verdict never becomes an exit code — a run in which every check fails still exits `0`, because the sensor did its job.

## Output

`findings.json` has a `machine` block, a `findings` array sorted by `(category, check_id)`, and a run-level `scan` block (`duration_ms`, `deadline_ms`, `checks_run`, `budget_cut`, `euid`, `degradations`, `self_check`). Run-level facts live in `scan` and never inside a finding, so a reader can tell "this check failed" from "this run was cut short".

A finding, abbreviated:

```json
{
  "category": "SECRETS_ON_DISK",
  "check_id": "PRIVATE_KEY_MATERIAL_EXPOSURE",
  "status": "unknown",
  "severity": "high",
  "title": "Readability of private key material on disk",
  "reason": "EACCES",
  "evidence": {
    "detail": "the search could not cover everything it was pointed at: 1 directory/ies under /etc/ssl could not be read (/etc/ssl/private); exposed key material there can neither be confirmed nor excluded",
    "observations": [
      {
        "source": "/etc/ssl",
        "observation_type": "dir_walk",
        "status": "OK",
        "entries_scanned": 247,
        "unreadable_dirs": ["/etc/ssl/private"],
        "budget_exhausted": "none",
        "load_bearing": true,
        "duration_ms": 3
      }
    ],
    "completeness": {
      "load_bearing_total": 15,
      "load_bearing_ok": 14,
      "not_ok": ["/etc/ssl (EACCES)"],
      "absence_provable": false,
      "statement": "14 of 15 load-bearing observations succeeded; not observed: /etc/ssl (EACCES) — an absence is not provable from this"
    }
  },
  "collected_at": "2026-01-01T00:00:00Z",
  "impact": "high",
  "duration_ms": 41
}
```

The walk found nothing, and says so as a boundary rather than as an absence.

## Design

**Fixed check registry.** `checks.All()` returns an explicit, ordered Go slice of check values. There is no plugin system, no registry DSL and no `init()`-time self-registration — the roster is greppable, and a duplicate `check_id` fails validation at startup rather than silently dropping a finding.

**Typed observations.** Every fact the sensor learns flows through one package as an `Observation`: the path opened or the argv run, the value, a coarse status, and the symbolic errno separately. The errno is kept alongside the status precisely so that `EPERM` (a capability gate) never collapses into `EACCES` (a mode bit), and so that `UTILITY_MISSING` stays its own class. Two primitives produce them all — one bounded read path and one bounded subprocess runner — so boundedness, read-only behaviour and errno fidelity are enforced in one place rather than restated in 26.

**Centralized finalization.** A check returns a verdict and the observations behind it; the engine does the rest. In one function it downgrades any `pass`/`fail` resting on a failed or truncated load-bearing observation to `unknown`, applies the severity rule, generates the `completeness` object, and renders the evidence. A check cannot accidentally pass on an observation it forgot to inspect, and it cannot invent its own evidence shape.

**Shared observations, isolated verdicts.** The handful of observations more than one check needs — the sshd configuration as `sshd` itself resolves it, the mount table, the group database — are read once per scan and shared. Where one check's answer genuinely conditions another's, that is explicit: the sshd checks all carry the same `daemon_state` block, and if the configuration chain is newer than the daemon's start time they report `unknown`/`CONTESTED` rather than a policy verdict, because what is on disk is then not what the listening daemon is enforcing.

**Severity.** Each check declares its `impact`. Reported severity is that impact for `fail` and `unknown`, and `info` for `pass`. An unverifiable control is an assurance gap of the same weight as a failing one; down-weighting `unknown` would make a permission-starved run look healthier than a privileged one.

## Safety

Properties the implementation actually holds, at the sensor process:

- **Read-only.** Exactly one write in the non-test code, to the `--out` path.
- **No network.** No networking package is imported by the shipped binary.
- **No escalation.** `sudo`, `su`, `doas`, `pkexec` and setuid appear nowhere. The effective uid of the run is recorded in the artifact.
- **Bounded subprocesses.** Each runs in its own process group with a deadline, a `WaitDelay`, capped stdout/stderr, `/dev/null` on stdin and a fixed minimal environment. No shell, ever, so a recorded exit status is always the child's own. On overrun the whole group is killed.
- **Binaries are resolved from a fixed set of system directories**, not from the inherited `PATH`, so a writable directory early in a user's `PATH` cannot supply the binary whose output becomes evidence.
- **The sensor process opens only regular files.** The file descriptor is `fstat`ed after opening — not a prior `lstat` — so device nodes, FIFOs, sockets and directories are refused in one test, and `O_NONBLOCK` means a FIFO with no writer cannot block the open. `/sys` and `/proc` are read through `os.Root`, so a symlink escaping those trees is refused by the kernel with no TOCTOU window.
- **Bounded enumeration.** Walks never follow symlinks, never cross a mount boundary, prune synthetic trees, and cap depth, entry count and wall time — and a walk that hit any of those limits reports which, so absence is only ever claimed from an enumeration that completed.

## Testing

237 test functions, most of them semantic rather than parsing tests: denied is not absent, zero observations is not a proven absence, a truncated tool output is not a healthy result, a missing utility does not turn another check unknown. Failure isolation is proved with a real panicking check inside the full roster and a real sleeping grandchild whose descendants are verified gone after a group kill.

A roster-wide entailment gate runs every check against adversarial fixture trees and fails the build if any verdict's prose out-claims its observations; a negative test proves the gate can actually fail.

Three container profiles exercise the binary end to end: a host-shaped Ubuntu userspace, a generic minimal image, and a deliberately hostile one — an unmapped uid with no home or `/etc/passwd` entry, key directories at mode `0000`, and most utilities removed. The generated findings are asserted mechanically, not eyeballed. The container profiles cannot reproduce firmware, DMI, NVMe controllers or a BMC, and do not pretend to; those cases are covered by fixtures, and the sensor was validated by running it unprivileged on real bare metal.

## Notes and limitations

- **Protection judgements read mode bits and group membership, not POSIX ACLs.** When a check concludes that a directory an unprivileged account cannot traverse shields what is behind it, an ACL granting another user traverse on that directory would make the conclusion wrong. ACLs *are* decoded for candidate files; the gap is on ancestors.
- **Drive health is gathered by invoking `smartctl` / `nvme`**, which open the block device themselves. Unprivileged they are denied and the check reports `unknown` with the errno — but the "opens only regular files" property above is a property of the sensor process, not of its children.
- **`sshd -G` reports the effective configuration as `sshd` would load it from disk now** — not the state of the listening process. It is labelled that way in the evidence, and a separate check compares the configuration chain's modification times against the daemon's start time to say whether the two can be assumed to agree. Where they cannot, the SSH checks report `unknown` rather than a policy verdict.
- **The out-of-band read of BMC identity attributes cannot be cancelled** once issued — it drives a live bus transaction. It runs under a short deadline and is abandoned on overrun rather than waited on, so the scan always finishes; the cost is one goroutine that may outlive the check.
- **Checks run sequentially** under a whole-scan deadline. On a healthy host the full roster completes in well under a second, but a host slow enough to exhaust the deadline will report the later checks as `BUDGET_EXHAUSTED` rather than reordering to save them.

## Context

Built for Lava's Sensor Exercise.
