# ARCHITECTURE_NOTES — R5 Go implementation architecture

Every load-bearing sentence cites a fact ID from `facts.jsonl`. Recommendations are verdicts, each with the condition that would reverse it.

## 1. Module layout

**Recommendation.** Keep the proposed shape, with three changes: fold `schema` into `output`, drop a separate `evidence` package (the evidence types belong to the `check` contract package, not to a package of their own), and split `machine` per domain.

```
sensor/
  go.mod                       module lavasensor  (go 1.26)
  cmd/sensor/main.go           ~120 LOC: flag parsing, wiring, exit codes. No logic.
  internal/
    check/                     Check, Category, Severity, Status, Finding, Observation, Registry, Register()
    checks/
      remote_access.go         one file per category; each file's init() calls check.Register(...)
      secrets_on_disk.go
      bmc_inband.go
      boot_integrity.go        the custom category
    runner/                    per-check deadline + recover() + scan deadline + deterministic ordering
    sysread/                   bounded file reads, mode gating, os.Root handles, bounded WalkDir, xattr/ACL
    procexec/                  bounded subprocess runner (interface + real impl)
    machine/                   Describe(); machine/{dmi,cpu,mem,block,osrelease}.go
    output/                    document types, deterministic encoder, go:embed finding.schema.json + validation
```

`cmd/` + `internal/` is the official Go guidance; the `golang-standards/project-layout` scaffolding (`pkg/`, `api/`, `configs/`) is explicitly not a Go-team standard and is aimed at much larger repos (R5-F10). Per-domain packages under `machine/` follow ghw's proven organisation (R5-F4). Nine packages for 2-4k LOC is near the upper bound of useful; anything finer costs more import wiring than it buys.

**Registration.** A fixed registry built at process start, mirroring node_exporter's `factories map[string]func(...)` + per-file `init()` (R5-F1) and osquery-go's `NewPlugin(name, columns, generateFunc)` metadata-as-data model (R5-F8). Keep the metadata (`ID`, `Category`, `Title`, `Impact`) as Go struct literals next to the check body; do not externalise them to YAML the way kube-bench does — at this size a YAML DSL adds a parser, a second schema and a new failure mode for no benefit (R5-F9).

One deviation from node_exporter, deliberate: prefer an explicit `checks.All()` returning an ordered slice over `init()` side effects. `init()` registration makes the set of live checks invisible at the call site, and D3 requires that every registered check emits exactly one finding — a reviewer must be able to read the roster in one place. Both are acceptable; explicit is better here.

**Isolation.** node_exporter is the closest prior art and it is *not* sufficient: its `execute()` only logs a returned error, with no `recover()` and no per-collector deadline (R5-F2). Per-check panic recovery and per-check context deadlines are our own addition. Its `ErrNoData` sentinel is worth copying as the ancestor of our UNKNOWN (R5-F3).

**Concurrency.** Run checks sequentially by default. Determinism (D8) and a small check count make concurrency unnecessary, and sequential execution makes the scan-deadline accounting trivially auditable. If wall time becomes a problem, add a bounded worker pool with a fixed size and sort the findings before writing — never an unbounded fan-out (R5-F2).

*Reversal condition:* if the check count exceeds roughly 30, or one check legitimately needs multi-second I/O, revisit the bounded pool.

## 2. Runner design (bounded execution)

Three nested budgets: whole-scan deadline → per-check context → per-subprocess `WaitDelay`.

The load-bearing fact: `exec.CommandContext` installs a default `Cancel` of `cmd.Process.Kill()`, and `os.Process.Kill` kills only that process, not its children — so setting `Setpgid` alone buys nothing (R5-F11). The runner must set `cmd.Cancel` itself to `syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)`.

`WaitDelay` is separately mandatory. LOCAL_REPRO: a command whose grandchild inherited stdout blocked `cmd.Output()` for 30.01s against a 3s context; with `WaitDelay=200ms` it returned in 0.21s with `exec.ErrWaitDelay`, output still captured (R5-F13). This behaviour exists specifically for golang/go#23019, cited by URL inside `os/exec` source (R5-F17).

Neither substitutes for the other. LOCAL_REPRO: `WaitDelay` alone bounded our wait but left the `sleep` grandchild running on the machine; `Setpgid` + negative-PID kill left zero survivors (R5-F14). Leaving stray processes on a customer's production host is a read-only violation, so both are required.

Output is capped by assigning a limiting `io.Writer` to `cmd.Stdout`/`cmd.Stderr` before `Start`, never by hand-rolling `StdoutPipe` — os/exec documents that calling `Wait` before pipe reads complete is incorrect, and `cmd.Output()` is uncapped (R5-F16). All of this uses stdlib `syscall` only (R5-F15).

Error mapping, in order: `exec.ErrWaitDelay` or `ctx.Err() != nil` → `TIMEOUT`; `exec.ErrNotFound` → `UTILITY_MISSING`; `*exec.ExitError` → `EXEC_ERROR` with the exit code as evidence; success → `OK`. Note that `CommandContext` surfaces `signal: killed` rather than the context error, so the runner must consult `ctx.Err()` explicitly (R5-F11).

**Panic isolation.** Each check runs inside a function whose `defer recover()` converts a panic into an `unknown` finding carrying the recovered value and, optionally, a truncated stack as evidence. A panic in check N must not prevent check N+1, and must not prevent the document from being written (D3, R5-F2).

**Scan deadline.** A parent context with the whole-scan budget; each check gets `min(perCheckBudget, remaining)`. When the parent expires, every not-yet-run check still emits a finding — status `unknown`, reason "scan deadline exhausted before this check ran". Silently omitting them is the failure mode D3 calls a critical failure.

## 3. Safe file reading

**Primitive.** `open(O_RDONLY|O_NONBLOCK)` → `Fstat` on the returned fd → reject non-regular → `io.ReadAll(io.LimitReader(f, cap+1))` → truncated if `len > cap` (R5-F20). Gating on the *open fd* rather than a pre-open `Lstat` closes the TOCTOU window; `O_NONBLOCK` matters because LOCAL_REPRO showed a plain `os.Open` on a FIFO blocking indefinitely while the `O_NONBLOCK` open returned at once (R5-F24).

**Never trust `Stat().Size()`.** inode(7) and kernel `sysfs.rst` document that pseudofiles misreport size, and LOCAL_REPRO measured `/proc/meminfo`, `/proc/cpuinfo`, `/proc/self/status` at st_size 0 while `/sys/devices/system/cpu/online` reported 4096 (R5-F18). `os.ReadFile` handles this correctly — its source comments name `/proc` explicitly — but it grows without bound, which is why it is not the sensor's primitive (R5-F19).

**Symlink policy, corrected by evidence.** A blanket `O_NOFOLLOW` or "reject symlinks" rule would return zero block devices: LOCAL_REPRO found 28 of 28 entries in `/sys/block` are relative symlinks (R5-F21). The policy is therefore path-scoped, and the right mechanism is `os.Root`: `os.OpenRoot("/sys").ReadFile("block/loop0/size")` followed the relative `../devices/...` symlink and succeeded, while `Open("../etc/passwd")` failed with "path escapes from parent" (R5-F22). `os.Root` also works on `/proc` including the magic `self` symlink (R5-F23) — this resolves the one open question the source survey could not settle. In user-writable trees (`/home`, `/tmp`, `/var/tmp`) the secrets walk does not follow symlinks at all, which `filepath.WalkDir` gives for free (R5-F29).

`os.DirFS` is *not* an alternative: its own doc says it is not a chroot-style mechanism and directs callers to `Root.FS` (R5-F45).

**xdev.** Capture the walk root's `syscall.Stat_t.Dev` and skip entries whose `Dev` differs. LOCAL_REPRO showed distinct `Dev` per mount (`/`=2096, `/proc`=61, `/sys`=24, `/dev`=6, `/run`=63, `/tmp`=71) (R5-F25). Caveat to state in evidence: `Dev` is a mount-view identity, not a physical device identity (bind mounts, btrfs subvolumes).

**Bounded walks.** `filepath.WalkDir` (not `Walk`), with depth cap, entry-count cap, deadline check, xdev check and a prune list, returning `fs.SkipDir` on prune and `fs.SkipAll` on exhaustion (R5-F29). When a budget is hit, that fact goes into the finding's evidence — absence must never be inferred from a truncated walk.

**ACLs.** `getfacl` is absent on the target, so the only path is `syscall.Getxattr(path, "system.posix_acl_access", buf)` — present in stdlib on linux and exercised in LOCAL_REPRO (R5-F26) — plus a hand-written decoder for the kernel's fixed wire format (4-byte LE header with version 0x0002, then 8-byte `{tag,perm,id}` entries). No maintained Go library decodes it: `pkg/xattr` returns raw bytes only and `joshlf/go-acl` has not been touched since 2020 (R5-F27). About 50 lines. `ENODATA` means "no ACL", distinct from `EACCES` and `EOPNOTSUPP`.

**x/sys verdict (CONTESTED, resolved).** The widespread claim that stdlib `syscall` is deprecated overstates the source: `src/syscall/syscall.go` carries a NOTE preferring `golang.org/x/sys`, but no symbol carries a godoc `Deprecated:` tag, and every symbol needed here — `Setpgid`, `Kill`, `SIGKILL`, `Stat_t.Dev`, `Getxattr`, `Listxattr`, `Statfs`/`Statfs_t.Flags` — exists in stdlib on linux/amd64 and was exercised in LOCAL_REPRO (R5-F28). Verdict: no `x/sys`. *Reversal condition:* needing `statx`, `openat2` flags or netlink, at which point `x/sys` becomes the one justified system dependency.

## 4. Evidence model

```go
type Status string   // "pass" | "fail" | "unknown"
type ObsStatus string // OK | EACCES | ENOENT | UNSUPPORTED | TIMEOUT | UTILITY_MISSING | EXEC_ERROR | TRUNCATED | BUDGET_EXHAUSTED

type Observation struct {
    Source    string    `json:"source"`              // "/sys/class/dmi/id/product_name" or "ipmitool mc info"
    Kind      string    `json:"kind"`                // "file" | "dir" | "command" | "syscall"
    Status    ObsStatus `json:"status"`
    Value     string    `json:"value,omitempty"`     // capped, never secret content
    Errno     string    `json:"errno,omitempty"`     // "EACCES"
    ExitCode  *int      `json:"exit_code,omitempty"`
    Truncated bool      `json:"truncated,omitempty"`
    Bytes     int64     `json:"bytes,omitempty"`
    Elapsed   int64     `json:"elapsed_ms,omitempty"`
}
```

A check accumulates `[]Observation` and then decides. The decision rule that keeps D3 honest: a check may return `pass`/`fail` only if the observations it depends on are `OK`; if any *load-bearing* observation is not `OK`, the result is `unknown` with a reason naming that observation. `ENOENT` from a *successful listing* is the one case where absence is provable and `pass`/`fail` remains legitimate. ghw does the weaker version of this — an explicit `"unknown"` sentinel instead of `""` on unreadable DMI (R5-F6) — and we extend it by carrying the errno.

Severity follows D6: reported `severity` = the check's declared impact when status is `fail` or `unknown`; `info` for observational checks. The engine applies this, not each check by hand.

**Determinism.** `encoding/json` sorts map keys and emits struct fields in declaration order, both confirmed by LOCAL_REPRO (R5-F30). Encode with `json.NewEncoder` + `SetEscapeHTML(false)` + `SetIndent("", "  ")` so config text in evidence stays readable; `Encode` appends a trailing newline, which matters when hashing the artifact (R5-F31). Format `collected_at` explicitly as `t.UTC().Format(time.RFC3339)` — marshalling a `time.Time` yields RFC3339Nano with trailing zeros trimmed, so the field width varies between runs (R5-F32). Use `int64` for every byte count, size, mode, uid and exit code; float formatting follows an ES6 shortest-round-trip rule that can render exponents (R5-F57). Sort findings by `(category, check_id)` before writing.

**Do not adopt `encoding/json/v2`.** It is still behind `GOEXPERIMENT=jsonv2` in Go 1.26 and, decisively, its migration notes state that maps marshal in *non-deterministic* order in v2 unless `Deterministic` is set — it would silently break D8 for exactly the evidence maps this document is made of (R5-F56).

## 5. Schema validation

**Library: `github.com/santhosh-tekuri/jsonschema/v6`.** Chosen on measured conformance, not README claims: the Bowtie run of 2026-09-08 (raw report-history data, pass rates recomputed) puts v6.0.2 at 1301/1301 on draft 2020-12, 1261/1261 on 2019-09 and 929/929 on draft-07, while `xeipuuv/gojsonschema` manages 874/929 on draft-07 with 20 hard errors and is not registered for the modern dialects at all (R5-F52). Only those two Go implementations have Bowtie harnesses; `kaptinlin` and `qri-io` draft claims are self-reported (R5-F53). Dependency footprint decides the rest: santhosh v6 pulls only `golang.org/x/text`, versus kaptinlin's YAML + i18n + uuid tree and a `go 1.27` directive, and qri-io/xeipuuv are stale with open correctness bugs (R5-F54).

This is the sensor's **one** third-party dependency. Everything else is stdlib.

**Timing: validate at runtime, before writing.** `go:embed` Lava's `finding.schema.json`, compile once at startup, marshal the document, validate, and only then write `--out`. On failure: write nothing to `--out`, print the failing instance pointers to stderr, exit 1. Test-time-only validation protects fixtures the grader may never run; the standing risk is "we cannot run it = no credit", which is a property of the delivered artifact (R5-F58). Keep the same validation in a golden test so failures surface in development first.

*Reversal condition:* if the real schema needs draft-03/04-only handling, or trips a santhosh open issue on `$dynamicRef`, fall back to `kaptinlin` after running the official test suite against it ourselves. Build-time codegen (`omissis/go-jsonschema`) is disqualified as the validation strategy because it fixes the schema at compile time, though it remains a legitimate *addition* once the real file arrives (R5-F55).

**Blocked on input:** `finding.schema.json` is not in the repository (R5-F51, filed as R5-OR1). The strategy above is decidable without it; the document's field shapes are not.

## 6. Machine description

| Field | Source | Unknown policy |
|---|---|---|
| `host_id` | `/etc/machine-id` (0444 on the target); DMI `product_uuid` is 0400 root-only → EACCES | Emit `host_id_source`. If machine-id is unreadable, fall back to a hash of stable hardware identifiers and say so; never random, never time-derived. |
| `hostname` | `/proc/sys/kernel/hostname` (avoids `os.Hostname`'s syscall path being conflated with DNS) | ENOENT/EACCES → explicit unknown + errno |
| `vendor`, `model` | `/sys/class/dmi/id/{sys_vendor,product_name}`, `board_*` as fallback | Per-field: unreadable → explicit unknown + the path and errno, following ghw's sentinel discipline but with evidence (R5-F6) |
| `cpu.model` | `/proc/cpuinfo` `model name` | unknown + reason |
| `cpu.cores` | `/sys/devices/system/cpu/cpu*/topology/{physical_package_id,core_id}` distinct-pair count; `/proc/cpuinfo` `physical id`+`core id` as fallback; logical count from `/sys/devices/system/cpu/online` | Always emit `cores_basis` naming which method produced the number (B3b) |
| `memory_bytes` | `/proc/meminfo` `MemTotal` kB × 1024, as int64 | unknown + reason |
| `os.name/version` | `/etc/os-release` (`NAME`, `VERSION_ID`), shell-quote aware parse | per-key unknown |
| `os.kernel` | `/proc/sys/kernel/osrelease` | unknown + reason |
| `storage[]` | `/sys/block/*` (all symlinks — R5-F21), size = `size` × 512, model from `device/model` then `device/nvme*/model`, transport/rotational/wwn as extras | Device still listed with `model: unknown` + the path tried and its errno |

Read everything through `os.Root("/sys")` / `os.Root("/proc")` handles opened once (R5-F22, R5-F23). Exclude `loop`/`ram`/`zram` from `storage[]` unless nothing else exists, and say so. No field is ever `""` (B6).

One CGO consequence worth stating in evidence: with `CGO_ENABLED=0`, `os/user` parses `/etc/passwd` directly rather than going through NSS (R5-F34). Harmless on this host (nsswitch is files-only) but any user/group finding must describe its source as "/etc/passwd as parsed in-process", which on an LDAP/SSSD host would be materially incomplete.

## 7. CLI and packaging

**Interface.** `flag.NewFlagSet` plus a switch on `os.Args[1]`; `flag.ExitOnError` already exits 2 on a bad flag (R5-F37). Cobra is rejected: four extra modules including a YAML parser for one subcommand (R5-F39).

```
sensor scan --out findings.json [--timeout 60s]
sensor --version
```

`--out` semantics: write to a temp file in the same directory then `os.Rename` (atomic, no half-written artifact); refuse to write outside the given path; never write anything else anywhere. Logging goes to stderr only, so stdout stays free and `--out -` could later mean stdout. `--timeout` sets the whole-scan deadline with a documented default (60s) and a hard maximum; there is no flag that disables timeouts, no `--root`, no `--as-root`.

**Exit codes:** `0` = scan completed and findings.json written, whatever the pass/fail/unknown mix; `1` = could not complete or could not write; `2` = usage error. Never make exit status depend on finding severity — that is the trivy wart (R5-F38).

**`--version`** from `runtime/debug.ReadBuildInfo()` (`vcs.revision`, `vcs.modified`), with a `-ldflags -X` semantic version (R5-F35).

**Build (this is the deployment reality, not a preference — `go` is UTILITY_MISSING on the target):**

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags="-s -w" -o dist/sensor ./cmd/sensor
```

Proven end to end on this workstation: Go 1.26.2 on Windows produced "ELF 64-bit LSB executable, x86-64, statically linked", `ldd` reported "not a dynamic executable", and the binaries ran as uid 1000 under Linux (R5-F33). `-trimpath` also stops `C:\lava-sensor-exercise\...` paths being shipped to a customer (R5-F35).

*Host-build fallback,* if a toolchain ever appears there: the same command without the env prefix, from the unpacked source. Documented, not relied on.

**The one command Lava runs.** Since A2 is graded on a clean unpack, the safest formulation is a two-token instruction with the chmod folded in:

```
tar xzf lava-sensor.tar.gz && cd lava-sensor && ./run.sh
```

where `run.sh` is three lines: `chmod +x ./sensor`, `./sensor scan --out findings.json`, `echo` the output path. Windows filesystems carry no exec bit, so the tar header mode must be set explicitly to 0755 *and* the chmod kept as a belt-and-braces step (R5-F36) — a non-executable binary is the cheapest possible way to fail "if we cannot run it, we cannot give you credit for it".

**Tarball layout.**

```
lava-sensor/
  run.sh                     the one command
  sensor                     prebuilt static linux/amd64 (mode 0755)
  findings.json              from the real run on the Lava host
  NOTES.md                   one page
  README.md                  run command, rebuild command, what it does/does not do
  src/                       full Go module: go.mod, go.sum, cmd/, internal/, testdata/
  session/                   exported Claude session
```

## 8. Testability

Summarised here; details in `TEST_STRATEGY.md`. Two seams, both unexported and test-only:

1. **Filesystem root** — each machine/check package holds an unexported `fs.FS` (or `*os.Root`) field defaulting to the real root, settable only from same-package `_test.go`. Production has no `--root` flag and reads no root-related environment variable. This is a deliberate rejection of ghw's `GHW_CHROOT`/`WithChroot` (R5-F5) and gopsutil's `HOST_PROC`/`HOST_SYS` (R5-F7): an ambient env override means anything that can set an environment variable can rewrite every finding.
2. **Command runner** — a one-method interface satisfied in production by the bounded `procexec` implementation and in tests by a fixture-driven fake. This also avoids most `PATH` manipulation, which forces tests to be non-parallel (R5-F49).

Plus a `now func() time.Time` injected into the runner for byte-stable golden files; `testing/synctest` is the wrong tool for this (R5-F48).

Avoid: package-level mutable state, `init()` side effects beyond registration, and any production flag that weakens a safety property.
