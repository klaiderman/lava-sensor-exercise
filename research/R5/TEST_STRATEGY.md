# TEST_STRATEGY — seams, fixtures, fault injection, golden files

Guiding constraint: a seam exists to make a check testable, and must not make the production binary less safe. Every seam below is stated with its production-safety impact.

## 1. Seams

### 1.1 Filesystem root (`fs.FS` / `*os.Root`) — test-only

Each reading package holds an **unexported** field:

```go
type reader struct { sys fs.FS; proc fs.FS }        // production: sysRoot.FS(), procRoot.FS()
func newReader() *reader { /* os.OpenRoot("/sys"), os.OpenRoot("/proc") */ }
// reader_test.go, same package:
func newTestReader(sys, proc fs.FS) *reader { return &reader{sys: sys, proc: proc} }
```

*Production-safety impact: none, and it removes one.* There is no `--root` flag and no root-related environment variable. This is a deliberate rejection of two named anti-patterns found in the prior art: ghw's `option.WithChroot` + `GHW_CHROOT` (R5-F5) and gopsutil's `HOST_PROC`/`HOST_SYS`/`HOST_ETC` (R5-F7). In a security sensor an ambient root override means anything that can set an environment variable — an inherited environment, a compromised cron wrapper — can rewrite every finding while the tool reports success. The constructor is the only place the real root is chosen, and it is not parameterised from the command line.

Note that `os.Root` is *also* a production safety win, not just a seam: it performs openat per component and refuses paths escaping the root, including via symlinks (R5-F22), which a userspace Lstat-then-open check cannot do without a TOCTOU window.

### 1.2 Command runner interface — test-only implementation

```go
type Runner interface { Run(ctx context.Context, name string, args ...string) Observation }
```

Production: the bounded implementation from `PATTERNS.md` §1 (Setpgid + custom Cancel + WaitDelay + capped writer, R5-F11/F12/F14/F16). Tests: a fake keyed on `name+args` returning fixture stdout, an exit code, or a synthetic `TIMEOUT`/`UTILITY_MISSING` observation.

*Production-safety impact: none.* The interface is satisfied by exactly one production type, constructed in `main`. There is no flag or env var that swaps it. It also reduces reliance on `PATH` manipulation in tests, which matters because `t.Setenv` forbids `t.Parallel` (R5-F49).

### 1.3 Clock

`now func() time.Time` on the runner struct; production passes `time.Now`, tests pass a constant. *Production-safety impact: none* — timestamps are output data, not control flow, and no timeout is derived from it (deadlines come from `context`, which uses the monotonic clock). `testing/synctest` is the wrong tool: it virtualises time for goroutines blocked inside a bubble, not for stamping deterministic output, and its Go 1.24 experimental API was removed in 1.26 (R5-F48).

### 1.4 What is deliberately not a seam

No `--root`, no `--as-root`, no `--no-timeout`, no `--unsafe`, no `--skip-check`. Any flag that disables a timeout or widens the read root is a production safety hole regardless of how convenient it is in tests. Also avoided: package-level mutable state and `init()` side effects beyond check registration (which is why `checks.All()` is preferred over `init()` self-registration despite node_exporter's precedent, R5-F1).

## 2. Fixtures

`testdata/` next to each package — the go tool ignores directories named `testdata` when matching packages, so fixtures never reach the shipped binary (R5-F46).

```
internal/machine/testdata/
  lava-host/sys/...            trimmed copy of the target's sysfs shape (DMI ids, block/nvme0n1/*)
  lava-host/proc/...           meminfo, cpuinfo, sys/kernel/osrelease
  minimal-vm/                  no DMI, no NVMe, one virtio disk  -> exercises unknown paths
  eacces/                      files chmod 0000 -> exercises EACCES-is-not-absent
internal/checks/testdata/
  sshd/{simple,include,match}/ sshd_config trees for first-value-wins, Include, Match (R5-F43)
  golden/findings.json         whole-document golden
```

Two fixture-tree mechanisms, chosen per test:

* **`fstest.MapFS`** for flat attribute reads. Symlink entries are supported in current Go but this must be proven by one dedicated unit test rather than assumed, because 28/28 `/sys/block` entries are symlinks and a MapFS that models them poorly would silently pass tests the real code would fail (R5-F44, R5-F21).
* **A real tree built in `t.TempDir()`** with `os.Symlink` and `os.Chmod` for anything involving symlink traversal, permissions or `os.Root`. This is the honest fixture for sysfs; `os.DirFS` over it is acceptable *only* because the tree is trusted test data — it is not a security boundary (R5-F45).

## 3. Fault injection

Each row below must produce `unknown` with a reason, never `pass`, never `fail`, and never a missing finding (D3).

| Fault | Injection | Expected |
|---|---|---|
| EACCES on a file | `os.Chmod(path, 0o000)` inside `t.TempDir()`; skip the test if running as root (uid 0 bypasses the mode bits) | `unknown`, reason names the path, evidence carries `EACCES` |
| EACCES on a directory during a walk | `os.Chmod(dir, 0o000)` mid-tree | walk continues, subtree recorded as an observation boundary, not as "no secrets found" |
| Missing utility | fake `Runner` returns `UTILITY_MISSING`; or `t.Setenv("PATH", emptyDir)` (non-parallel, R5-F49) | `unknown`, reason "utility not present", never "capability absent" |
| Subprocess timeout | shim script `#!/bin/sh\nsleep 30` in a temp dir, real bounded runner, 200ms budget | returns in well under a second with `TIMEOUT`; assert no surviving child (R5-F14) |
| Grandchild holds stdout | shim `sleep 30 & echo hi; exit 0` | returns at `WaitDelay`, `exec.ErrWaitDelay`, partial output preserved (R5-F13) |
| Output flood | shim emitting 10 MB | capped at the limit, `Truncated: true` in evidence, memory flat (R5-F20) |
| Size-0 pseudofile | read a real `/proc/meminfo` in an integration test | parsed correctly despite `st_size == 0` (R5-F18, R5-F19) |
| Device node / FIFO in a scanned path | `syscall.Mkfifo` in `t.TempDir()`, plus a path pointing at `/dev/zero` | rejected by the mode gate; the test must fail if it ever blocks (bound it with a timer — LOCAL_REPRO measured a plain open blocking indefinitely, R5-F24) |
| Malformed input | truncated `os-release`, `cpuinfo` with no `model name`, `sys/block/x/size` containing `"abc"` | `unknown` with a parse reason; never a zero value passed off as measured |
| Panic in a check | a test-only check that panics, registered in a test registry | that finding is `unknown` with the panic in evidence; all other findings present (R5-F2) |
| Scan deadline exhausted | 1ms whole-scan budget | every registered check still emits a finding with reason "scan deadline exhausted" |
| Symlink escape attempt | fixture symlink pointing outside the root | `os.Root` refuses with "path escapes from parent" (R5-F22) |

## 4. Golden-file tests

Whole-document golden: run the full registry against the `lava-host` fixture tree with the fake runner and a fixed clock, encode with the production writer, compare bytes.

Byte comparison is only meaningful because output is deterministic by construction: `encoding/json` sorts map keys and preserves struct declaration order (R5-F30), the encoder disables HTML escaping and appends exactly one trailing newline (R5-F31), `collected_at` is a pre-formatted RFC3339 string rather than a marshalled `time.Time` whose width varies (R5-F32), findings are sorted by `(category, check_id)`, and all numerics are `int64` (R5-F57). This is also why the build must not enable `GOEXPERIMENT=jsonv2`, under which maps marshal in non-deterministic order (R5-F56).

The `-update` flag idiom (`var update = flag.Bool("update", false, ...)`) is a de facto convention, not a stdlib feature (R5-F47). Adopt it, but require the golden diff to be reviewed in the commit: a reflexive `go test -update` is how a regression gets blessed.

## 5. Schema-conformance tests

`go:embed` Lava's `finding.schema.json` once and use it in three places: the runtime pre-write validation (R5-F58), the golden test, and a property-style test that runs every check against every fixture tree and validates each produced document. `santhosh-tekuri/jsonschema/v6` is the validator, selected on measured Bowtie conformance rather than README claims (R5-F52).

Additional invariant tests that need no schema:
* every registered check appears exactly once in the output (D3);
* `check_id` values are unique and UPPER_SNAKE_CASE;
* `reason` is non-empty whenever status is `fail` or `unknown` (D1);
* no `machine` field is the empty string (B6);
* a secret-shaped-value scan over the whole document (key material headers, long base64 runs, anything from `/etc/shadow`) finds nothing (C5a);
* two runs over the same fixture differ only in the timestamp fields (D8).

## 6. What is not tested here

Anything requiring root, anything requiring the real Lava host, and the ACL decoder's entry-parsing loop against live ACL bytes — `setfacl` is absent from the local WSL image, so that path was only exercised to its `ENODATA` branch (R5-F50). The decoder is therefore tested against a hand-built byte fixture (`02 00 00 00` header plus synthetic entries), and the production check reports `unknown` with the raw byte length as evidence if the version field is not 2.
