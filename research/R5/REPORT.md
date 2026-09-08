# R5 — Go implementation architecture: report

Answers to the ten questions. Each is a verdict with cited fact IDs and the disconfirming condition that would reverse it. Detail lives in `ARCHITECTURE_NOTES.md`, `IMPL_BVB.md`, `PATTERNS.md`, `TEST_STRATEGY.md`; evidence in `facts.jsonl` (58 facts) and `sources.jsonl` (58 sources); method and reproductions in `PROVENANCE.md`.

**Headline:** the architecture is right; the risk is not in the layout but in three runtime details that documentation alone would have let us get wrong — the default `Cancel` kills only the process leader (R5-F11), `WaitDelay` bounds our wait but leaves orphans on the customer's host (R5-F14), and every `/sys/block` entry is a symlink so a "reject symlinks" safety rule would enumerate zero disks (R5-F21). All three were established by reproduction, not by reading.

---

## 1. Module layout — keep it, with three amendments

**Verdict.** `cmd/sensor` + `internal/{check,checks,runner,sysread,procexec,machine,output}`. Fold `schema` into `output` (validation is a property of writing the document), drop a standalone `evidence` package (the evidence types are part of the `check` contract), and split `machine` per domain (`dmi.go`, `cpu.go`, `mem.go`, `block.go`, `osrelease.go`) following ghw's per-domain organisation (R5-F4). Nine packages for 2-4k LOC is the upper bound of useful.

`cmd/` + `internal/` is official Go guidance; `golang-standards/project-layout`'s own README states it is not a Go-team standard (R5-F10).

**Registration.** A fixed registry built at process start — node_exporter's `factories` map plus per-file `init()` (R5-F1), osquery-go's `NewPlugin(name, columns, generateFunc)` metadata-as-data (R5-F8), kube-bench's separation of check metadata from the runner (R5-F9, but keep the metadata in Go, not YAML). One deviation: prefer an explicit `checks.All()` roster over `init()` side effects, because D3 requires a reviewer to see the complete check set in one place.

**Isolation is where the prior art fails us.** node_exporter's `execute()` only logs a returned error — no `recover()`, no per-collector deadline, unbounded goroutine fan-out (R5-F2). Per-check panic recovery and per-check deadlines are our addition. Its `ErrNoData` sentinel is worth copying as the ancestor of UNKNOWN (R5-F3). Run checks sequentially for determinism.

*Reverses if:* the check count passes ~30 or a check needs multi-second I/O, then a bounded worker pool with findings sorted before write.

## 2. Bounded execution — three nested budgets, two independent kill mechanisms

**Verdict.** Whole-scan deadline, then per-check `context`, then per-subprocess `WaitDelay`, with `Setpgid: true` **and** a custom `cmd.Cancel` doing `syscall.Kill(-pid, SIGKILL)`. Pattern in `PATTERNS.md` section 1.

`exec.CommandContext`'s default `Cancel` is `cmd.Process.Kill()`, and `os.Process.Kill` documents that it kills only that process — so `Setpgid` alone buys nothing (R5-F11). `WaitDelay` is separately mandatory: LOCAL_REPRO measured a grandchild-held pipe blocking `cmd.Output()` for **30.01s against a 3s context**, dropping to **0.21s** with `WaitDelay=200ms` while still capturing the output (R5-F13); the mechanism exists for golang/go#23019, cited by URL inside `os/exec` source (R5-F17).

The non-obvious part, and the reason both are required: **`WaitDelay` alone left the `sleep` grandchild running on the machine** after we returned; `Setpgid` plus negative-PID kill left zero survivors (R5-F14). Leaving stray processes on a customer's production host is a read-only violation even though our own scan completed cleanly. No source states this; it came from reproduction.

Cap output with a limiting `io.Writer` on `cmd.Stdout`/`cmd.Stderr` before `Start`, never `StdoutPipe` (documented as incorrect to `Wait` before reads complete) and never `cmd.Output()` (uncapped) (R5-F16). All stdlib (R5-F15). Map `ErrWaitDelay`/`ctx.Err()` to TIMEOUT, `ErrNotFound` to UTILITY_MISSING, `*exec.ExitError` to EXEC_ERROR with the exit code; consult `ctx.Err()` explicitly because `CommandContext` surfaces `signal: killed` (R5-F11). Panic isolation via `defer recover()` per check, with the `Finding` initialised *before* the defer so a panic still yields a complete finding.

*Reverses if:* a future Go makes `CommandContext` group-kill by default — the custom `Cancel` becomes redundant but harmless, so keep it.

## 3. Safe file reading — `os.Root` plus a bounded, mode-gated primitive

**Verdict.** `open(O_RDONLY|O_NONBLOCK)`, then `Fstat` on the open fd, reject non-regular, then `io.ReadAll(io.LimitReader(f, cap+1))` with truncation flagged (R5-F20). Gate on the open fd, not a pre-open `Lstat`, to close the TOCTOU window; `O_NONBLOCK` because LOCAL_REPRO showed a plain open on a FIFO blocking indefinitely while `O_NONBLOCK` returned instantly (R5-F24).

Never size a buffer from `Stat`: inode(7) and kernel `sysfs.rst` document the lie, and LOCAL_REPRO measured `/proc/*` at st_size 0 and a sysfs attribute at 4096 (R5-F18). `os.ReadFile` handles this correctly — its source comments name `/proc` — but is unbounded, which is why it is not the primitive (R5-F19).

**Symlink policy, corrected by evidence.** A blanket `O_NOFOLLOW`/reject-symlinks rule would return **zero block devices**: 28 of 28 `/sys/block` entries are relative symlinks (R5-F21). Use `os.Root` instead: LOCAL_REPRO confirmed it follows in-root relative symlinks (`block/loop0/size` via `../devices/...`) and refuses `../etc/passwd` with "path escapes from parent" (R5-F22), and that it works on `/proc` including the magic `self` symlink (R5-F23 — this closed the one question the documentation survey could not answer). `os.DirFS` is not an alternative; its own doc says it is not a chroot-style mechanism (R5-F45). In user-writable trees the secrets walk does not follow symlinks at all, which `WalkDir` gives for free (R5-F29).

**xdev** by comparing `syscall.Stat_t.Dev` against the walk root's — distinct per mount in LOCAL_REPRO (R5-F25); state in evidence that `Dev` is a mount-view identity, not a physical device. **Bounded walks** with `WalkDir` plus depth/entry/deadline/xdev caps and a prune list, `SkipDir` to prune and `SkipAll` on exhaustion, recording exhaustion in evidence (R5-F29).

**ACLs vs `getfacl`:** `getfacl` is absent on the target, so shelling out fails on the machine that matters. `syscall.Getxattr` is stdlib and works (R5-F26); the wire format is fixed kernel uapi (4-byte LE header v2, 8-byte entries) and no maintained Go library decodes it (R5-F27). About 50 lines, BUILD.

**`golang.org/x/sys`: not justified** for this deliverable. CONTESTED and resolved — the "deprecated" claim is a package NOTE, not a `Deprecated:` tag, and every needed symbol (`Setpgid`, `Kill`, `SIGKILL`, `Stat_t.Dev`, `Getxattr`, `Listxattr`, `Statfs`/`Statfs_t.Flags`) exists in stdlib on linux/amd64 and was exercised (R5-F28).

*Reverses if:* we need `statx`, `openat2` flags or netlink, then add x/sys as the one system dependency. Or if `os.OpenRoot` fails on the target kernel, degrade to plain bounded reads with explicit `Lstat` gating and accept the TOCTOU window (R5-OR4).

## 4. Evidence model — typed `Observation`, one decision rule

**Verdict.** `Observation{Source, Kind, Status, Value, Errno, ExitCode, Truncated, Bytes, Elapsed}` with `Status` in {OK, EACCES, ENOENT, UNSUPPORTED, TIMEOUT, UTILITY_MISSING, EXEC_ERROR, TRUNCATED, BUDGET_EXHAUSTED}. A check accumulates observations, then applies one rule: **`pass`/`fail` only if every load-bearing observation is `OK`; otherwise `unknown` naming the observation that failed.** The single exception is `ENOENT` from a *successful listing*, the only case where absence is provable. ghw does the weak version of this (an `"unknown"` sentinel instead of `""` on unreadable DMI, R5-F6); we carry the errno as well.

Severity per D6, applied by the engine: declared impact when `fail`/`unknown`, `info` for observational checks.

**Determinism.** `encoding/json` sorts map keys and preserves struct declaration order, both reproduced (R5-F30). Encode via `json.Encoder` with `SetEscapeHTML(false)` and `SetIndent("", "  ")`; account for the trailing newline (R5-F31). `collected_at` is a pre-formatted `t.UTC().Format(time.RFC3339)` string — marshalling a `time.Time` gives RFC3339Nano with trailing zeros trimmed, so the field width varies between runs (R5-F32). `int64` everywhere; float formatting follows an ES6 shortest-round-trip rule that can emit exponents (R5-F57). Sort findings by `(category, check_id)`.

**Do not use `encoding/json/v2`:** still `GOEXPERIMENT`-gated in Go 1.26 and marshals maps in *non-deterministic* order unless `Deterministic` is set — it would silently break D8 for exactly the evidence maps this document is made of (R5-F56).

## 5. Schema validation — `santhosh-tekuri/jsonschema/v6`, validate at runtime before writing

**Verdict.** REUSE `github.com/santhosh-tekuri/jsonschema/v6`, chosen on measured conformance rather than README claims. The Bowtie run of 2026-09-08 (raw report-history data, pass rates recomputed rather than read off a badge): **v6.0.2 scores 1301/1301 on draft 2020-12, 1261/1261 on 2019-09, 929/929 on draft-07**, while `xeipuuv/gojsonschema` manages 874/929 on draft-07 with 20 hard errors and is not registered for the modern dialects at all (R5-F52). Only those two Go implementations have harnesses; kaptinlin's and qri-io's 2020-12 claims are self-reported (R5-F53). Footprint decides the rest: one production dependency (`golang.org/x/text`), released 2026-08-06, versus kaptinlin's YAML+i18n+uuid tree and a `go 1.27` directive; qri-io stale since 2024-12 with `$ref` bugs; xeipuuv untouched since 2020 (R5-F54).

**Timing: runtime, embedded, before the write.** `go:embed` the schema, compile once, marshal, validate, and only then write `--out`; on failure write nothing, print the failing instance pointers to stderr, exit 1. Test-time-only validation protects fixtures the grader may never run, while "we cannot run it = no credit" is a property of the delivered artifact (R5-F58). Keep the same validation in a golden test so it fails in development first.

Build-time codegen (`omissis/go-jsonschema`) is disqualified *as the strategy* — it fixes the schema at compile time and cannot validate the produced document — but is a legitimate addition once the real file arrives (R5-F55).

**`finding.schema.json` is not in the repository** (R5-F51). Filed as R5-OR1, non-blocking: the library choice is robust to the dialect answer; only the field shapes are deferred.

*Reverses if:* the real schema needs draft-03/04, or trips a santhosh `$dynamicRef` issue, then fall back to kaptinlin **after** running the official test suite ourselves.

## 6. Machine description — per-field sources, per-field unknown

Full table in `ARCHITECTURE_NOTES.md` section 6. Key points: `host_id` from `/etc/machine-id` (0444 on the target) with `host_id_source` recorded, since DMI `product_uuid` is 0400 root-only; `cpu.cores` from `/sys/devices/system/cpu/cpu*/topology` distinct `(physical_package_id, core_id)` pairs with `cores_basis` always stated (B3b); `memory_bytes` from `MemTotal` times 1024 as `int64`; storage from `/sys/block/*` (all symlinks — R5-F21) with `size` times 512 and model from `device/model` then the NVMe path. Everything read through `os.Root("/sys")` / `os.Root("/proc")` handles opened once (R5-F22, R5-F23).

**Unknown policy:** no field is ever `""`. An unreadable source yields an explicit unknown carrying the path tried and the errno — ghw's sentinel discipline (R5-F6) plus evidence. A device whose model is unreadable is still listed, with `model: unknown` and the errno. One provenance caveat to state in output: with `CGO_ENABLED=0`, `os/user` parses `/etc/passwd` in-process rather than going through NSS (R5-F34) — harmless on this files-only host, materially incomplete on an LDAP host.

## 7. CLI and packaging — stdlib `flag`, static cross-build, one command

**Verdict.** `flag.NewFlagSet` plus a switch on `os.Args[1]` (R5-F37). Cobra rejected: four modules including a YAML parser for one subcommand (R5-F39).

`sensor scan --out findings.json [--timeout 60s]` and `sensor --version`. `--out` writes to a temp file in the same directory then `os.Rename` (atomic, no half-written artifact). Logging to stderr only. **No** `--root`, `--as-root`, or `--no-timeout`. **Exit codes:** 0 = scan completed and file written whatever the pass/fail/unknown mix; 1 = could not complete or could not write; 2 = usage error. Never key exit status to finding severity — that is trivy's documented wart (R5-F38). `--version` from `runtime/debug.ReadBuildInfo` (R5-F35).

**Build from Windows** — this is the deployment reality, since `go` is UTILITY_MISSING on the target:

```powershell
$env:GOOS='linux'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
go build -trimpath -ldflags="-s -w" -o dist/sensor ./cmd/sensor
```

Proven end to end this session: four binaries built this way ran under Linux as uid 1000; `file` reported "statically linked" and `ldd` "not a dynamic executable" (R5-F33). `-trimpath` also stops `C:\lava-sensor-exercise\...` paths shipping to a customer (R5-F35). Host-build fallback if a toolchain ever appears: the same command without the env prefix, documented but not relied on.

**The one command:** `tar xzf lava-sensor.tar.gz && cd lava-sensor && ./run.sh`, where `run.sh` does `chmod +x ./sensor` then `./sensor scan --out findings.json`. Windows has no exec bit, so the tar header mode must be set to 0755 explicitly **and** the chmod kept (R5-F36) — a non-executable binary is the cheapest possible way to fail A2. **Tarball:** `run.sh`, `sensor`, `findings.json`, `NOTES.md`, `README.md`, `src/` (full module), `session/`.

## 8. Testability — two unexported seams, zero production weakening

**Verdict.** (1) An unexported `fs.FS`/`*os.Root` field per reading package, settable only from same-package `_test.go`; (2) a one-method command-runner interface with a fixture-driven fake; (3) an injected `now func() time.Time`. Details and the fault-injection matrix in `TEST_STRATEGY.md`.

This is a deliberate rejection of the two production overrides found in the prior art — ghw's `WithChroot`/`GHW_CHROOT` (R5-F5) and gopsutil's `HOST_PROC`/`HOST_SYS` (R5-F7). In a security sensor an ambient env override means anything that can set an environment variable rewrites every finding while the tool reports success. `os.Root` is additionally a production safety win, not just a seam (R5-F22). Fixtures live in `testdata/`, which the go tool excludes from builds (R5-F46); `fstest.MapFS` symlink support must be proven by a test rather than assumed, because sysfs is 100% symlinks (R5-F44, R5-F21). Golden files use the `-update` idiom (R5-F47) and are byte-stable because of R5-F30/F31/F32. `testing/synctest` is the wrong tool for clock injection (R5-F48); `t.Setenv` forces PATH-shim tests to be non-parallel (R5-F49). Avoid: global mutable state, `init()` side effects beyond registration, any flag that widens the read root or disables a timeout.

## 9. Implementation build-vs-buy

Full table with evidence in `IMPL_BVB.md`.

| Subsystem | Verdict |
|---|---|
| procfs/sysfs parsing | **BUILD** (STEAL_PATTERN field naming from prometheus/procfs) — we need the bounded reader anyway (R5-F19, F20) |
| DMI | **BUILD**, patterned on ghw's 8-line `linuxdmi.Item` (R5-F6); importing ghw brings `GHW_CHROOT` (R5-F5) |
| Block-device enumeration | **BUILD**, patterned on ghw `pkg/block`; `os.Root("/sys")` handles the all-symlinks problem (R5-F21, F22) |
| JSON-schema validation | **REUSE santhosh-tekuri/jsonschema/v6** — measured 100% on three dialects, one dep (R5-F52, F54) |
| POSIX ACLs | **BUILD** about 50 LOC over `syscall.Getxattr`; no maintained decoder exists (R5-F26, F27). Shelling to `getfacl`: **REJECT**, absent on target |
| sshd_config parsing | **BUILD**, narrow. x/crypto/ssh has no file parser (R5-F40); kevinburke/ssh_config is a *client* parser with unsupported `Match` (R5-F41); no maintained server parser found (R5-F42). Grep-based parsing: **REJECT** — first-value-wins, `Include` lexical order and `Match` scoping each break it, and the target's config opens with an `Include` (R5-F43) |
| Bounded exec | **BUILD** on stdlib; the correctness is in the combination, which no library encodes (R5-F11, F12, F14) |
| CLI framework | **REJECT** (R5-F39) |
| `golang.org/x/sys` | **REJECT** for this deliverable (R5-F28) |
| gopsutil / ghw as libraries | **REJECT** — ambient production root overrides (R5-F5, F7) |
| Deterministic JSON | **BUILD** on `encoding/json` v1; **avoid v2** (R5-F30, F56) |
| Golden-file harness | **REJECT** — about 10 lines of stdlib (R5-F47) |

**Net: one third-party dependency in the shipped binary.**

## 10. Bottom line

**The smallest architecture we would be comfortable shipping onto a real customer host** is a single static `CGO_ENABLED=0 linux/amd64` binary, roughly 2.5k LOC, one dependency (`santhosh-tekuri/jsonschema/v6`), containing: an explicit ordered registry of about 14 checks across four categories; a sequential runner enforcing a whole-scan deadline, a per-check deadline and a per-check `recover()`, which emits exactly one finding per registered check even when the check never ran; one bounded read primitive (`O_NONBLOCK` open, mode gate on the fd, cap+1 truncation detection) used for every file; `os.Root` handles for `/sys` and `/proc`; one bounded exec primitive (`Setpgid` plus custom group-kill `Cancel` plus `WaitDelay` plus capped writer) used for every subprocess; a typed `Observation` type that carries errno, exit code, timeout and truncation into the evidence; and a deterministic writer that validates against the embedded schema before writing atomically. Two unexported test seams, no production flag that weakens anything.

That is smaller than the brief permits, and the smallness is the point: every element above exists because removing it would let a specific failure mode through, and each was demonstrated rather than assumed.

**What would make us abandon the Fixed Registry default.** Nothing found in this research does. The default survives because the three arguments usually made for a rule engine or runtime planner all fail here: the check set is small and known at build time (R5-F1, R5-F8), externalising check definitions to a DSL adds a parser and a schema for no benefit at this size (R5-F9), and determinism is a stated output requirement (D8) that a planner would directly undermine. The strongest disconfirming evidence would be a requirement we do not have — Lava asking for checks to be added or reconfigured *without rebuilding the binary*, for example a customer-supplied policy file. If that requirement appeared, the honest answer is still not a runtime LLM or a rule engine, but kube-bench's shape: declarative check definitions in a data file with a fixed Go runner (R5-F9). Absent that requirement, adding it would be unreviewable complexity that weakens the safety story.

**Weakest claims in this report**, stated plainly: R5-F14 (orphan survival) rests on a single LOCAL_REPRO on WSL2 kernel 6.18, not on the target's 6.8/7.0 — the design is unchanged either way, but the "required, not belt-and-braces" framing depends on it; R5-F42 (no maintained Go sshd_config parser) is a negative claim from a non-exhaustive survey; R5-F50 (the ACL decode loop) was never exercised against real ACL bytes because `setfacl` is absent locally; R5-F36 (tar exec bit) is LIKELY and must be verified by extracting the real tarball on Linux before submission. Every LOCAL_REPRO ran on a VM with no DMI and no NVMe, so hardware-shaped facts carry the host-confirmation requests R5-OR2 through R5-OR5.

**Nothing in the 10 questions was left unanswered**, and no artifact was truncated.
