# sensor

A read-only, bounded, unprivileged Linux posture sensor. It describes the
machine it runs on and reports one finding per registered check into a single
JSON file.

## Build

One command, from this directory. The target host needs no Go toolchain: the
binary is a static `linux/amd64` executable.

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sensor ./cmd/sensor
```

The source also builds with a plain `go build ./...` on any Go 1.26 toolchain.

## Run

One command, as an ordinary user. No `sudo`, no arguments beyond these.

```
./sensor scan --out findings.json
```

The only other flag is `--version`. There is deliberately no `--timeout`, no
`--root` and no `--skip`: the whole-scan deadline is a 60-second constant, and a
bound an operator can raise from the command line is not a bound.

**Expected runtime:** well under a second on the current roster; the scan is
bounded at 60 seconds by default and every check, subprocess and file read has
its own smaller bound inside that.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The scan completed and the output file was written. |
| 1 | The output file was written, but it failed the sensor's structural self-check. The failing JSON pointers are printed to stderr. |
| 2 | The output file could not be written, or the invocation was invalid. |

A finding's verdict never becomes an exit code: a run in which every check
fails still exits 0, because the sensor did its job. Everything the sensor says
about itself goes to stderr; the output file contains only the report.

## Evidence entails the verdict

Every finding carries a generated `completeness` object: how many observations
were made, how many were load-bearing, which of those did not succeed, and
whether an absence is provable from them. Checks do not write that sentence
themselves — the engine derives it from the observations.

Observations are load-bearing by default: a check that wants one exempted has to
record why, and the reason ships in the evidence as
`not_load_bearing_because`. A check that claims an enumeration finished while a
load-bearing observation failed — or that reaches a verdict with no successful
observation at all — is downgraded to `unknown` and marked with
`entailment_violation`, and the test suite fails the build on any such claim.
The same rule can be pointed at an artifact after the fact, so a findings.json
from a container or from a real host can be audited without re-running anything.

## What is in the output

Two parts, plus one extra block.

- `machine` — part one: what this machine is. Every field carries a sibling
  `*_source` naming the exact path or command it came from, so the report
  documents its own provenance.
- `findings` — one finding per registered check, always, sorted by
  `(category, check_id)`. There are 26 checks across five categories:
  `REMOTE_ACCESS`, `SECRETS_ON_DISK`, `BMC_INBAND_ACCESS` and the two the
  sensor adds, `STORAGE_POSTURE` and `BOOT_CHAIN`.
- `scan` — an extra run-level block: `started_at`, `duration_ms`,
  `deadline_ms`, `checks_run`, `budget_cut`, `budget_cut_count`, `euid`,
  `degradations` and `self_check`. Run-level facts live here and never inside
  the findings array, so a reader can tell "this check failed" from "this run
  was cut short". `degradations` names any capability the sensor lost at
  startup (an `os.Root` that would not open, for instance) rather than letting
  it show up as a silent scattering of unknowns.

## What the sensor does not do

It never writes anything except the `--out` file. It never opens a network
socket, never runs `sudo`, `su` or `doas`, never spawns a shell, and never
opens a device node, FIFO or socket for reading. Every subprocess runs in its
own process group with a deadline, a `WaitDelay` and capped output, and is
killed as a group if it overruns. Every file read is capped by policy — never by
the file's own reported size, which lies under `/proc` and `/sys`.

## What `unknown` means

`unknown` is a real answer, not a failure to answer. It means the sensor
attempted the observation and can say exactly why it did not resolve, and every
`unknown` carries a `reason` from a closed vocabulary plus the evidence behind
it:

| reason | meaning |
|---|---|
| `EACCES` | The object exists; this uid may not read it. **Denied is not absent.** |
| `EPERM` | A kernel capability gate refused the operation — a different problem from a mode bit. |
| `ENOENT` | The path does not exist, proven by a successful listing of its parent. |
| `EINVAL` | The object is not the kind of thing the question needs — a symlink where a directory was wanted, an attribute the filesystem does not support. Every errno of that shape (`ENOTDIR`, `ENOTREG`, `ENOTSUP`, `ELOOP`, `EISDIR`, `ENXIO`, `ENODATA`) maps here through `scan.NormalizeReason`, so no internal token reaches an artifact. |
| `TIMEOUT` | The probe was attempted and did not finish inside its budget. Never a failure of the control. |
| `UTILITY_MISSING` | A helper binary is not installed. **Never** "the capability is absent". |
| `BUDGET_EXHAUSTED` | A walk, read or scan hit its cap before completing, so absence is not provable. |
| `PARSE_ERROR` | Output was obtained but did not match the expected shape. |
| `EXECUTION_ERROR` | A tool ran and failed for its own reasons. |
| `CONTESTED` | Two observations disagree. Both are recorded; neither is silently preferred. |
| `TIMESTAMP_RESOLUTION` | Two events were observed with a timestamp too coarse to order them. Nothing disagrees; the instrument does not resolve the question. |
| `NO_EVIDENCE` | The check reached a verdict with no successful observation behind it. A conclusion with nothing under it is not a conclusion. |
| `NOT_ATTEMPTED` | The observation was reachable and the sensor declined to make it, by design — it never opens a device node, and it never walks a directory on network storage or behind a symlink it cannot trust. Not a denial, and not an absence. |
| `POLICY` | The control was observed and is not in the state the check asks about. This is the reason on a `fail`. |
| `INTERNAL_ERROR` | The check itself panicked, or produced a reason outside this table. Either is a defect in the sensor rather than a fact about the host, and it says so instead of inventing a plausible errno. |

The vocabulary is closed in code (`scan.ReasonVocabulary`) and enforced at one
point in `finalize`, and `TestEveryFindingReasonIsInTheClosedVocabulary` runs the
whole roster over a tree built to provoke the awkward cases.

An `unknown` is reported at the check's declared impact, not downgraded: an
unverifiable control is an assurance gap of the same weight as a failing one.
A `pass` is always reported at severity `info`.

Undeterminable values in the `machine` block follow the same discipline: strings
are the literal `"unknown"`, integers are `0` **together with** an entry in
`machine.unknowns` giving the reason and the sources tried, and every field
carries a sibling `*_source`. No field is ever an empty string or a guess.

## Tests

```
go vet ./... && go test ./... -count=1
```

Linux-specific behaviour (process-group kills, `O_NOFOLLOW`, `os.Root` over
`/sys` and `/proc`, permission fixtures) is skipped on non-Linux hosts. To
exercise it from a Windows workstation, cross-compile the test binaries and run
them under WSL from their package directory:

```
GOOS=linux GOARCH=amd64 go test -c -o bin/probe.test ./internal/probe
wsl -e bash -lc "cd internal/probe && ../../bin/probe.test -test.v"
```

The full suite is 220 test cases: 19 in `internal/probe`, 32 in
`internal/scan`, 92 in `internal/checks` and 10 in `cmd/sensor`.

Fixture profiles live under `internal/checks/testdata/` (A: host-shaped bare
metal, B: generic minimal VM, C: restricted container). They are materialised
into a temporary directory before each test because symlinks and permission
bits — the two things that make a sysfs fixture honest — cannot be committed
portably. There is no `--root` flag and no environment variable that selects a
filesystem root: the fixture seam is an unexported constructor, and a test
enforces that production code never reaches it.
