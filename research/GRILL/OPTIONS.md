# OPTIONS — four candidate architectures for the sensor

Track GRILL (`architecture-challenger`). These are candidates to be attacked, not proposals.
`sensor/` is empty at the time of writing (`ls sensor/` → no files), so all four options start from zero LOC.

Shared, non-negotiable substrate (identical in all four; not a differentiator, so it is stated once):
the bounded runner (Setpgid + group-kill `Cancel` + `WaitDelay` + capped writers + exactly one `Wait`; F21, F22, F23, L09-L12), the one read primitive (`O_RDONLY|O_NONBLOCK|O_CLOEXEC` → `Fstat(fd)` → `IsRegular` → `LimitReader(cap+1)`; F14, F15, F16, L05, L13), `os.Root` for `/sys` and `/proc` with degradation (F19, L15), the out-of-band deadline for device-adjacent reads (F44, L40), deterministic `encoding/json` v1 output (F72, L47), zero third-party runtime dependencies with `santhosh-tekuri/jsonschema/v6` as a test-only import (F69, F70, C-06, D-05), and static `linux/amd64` cross-build because `go` is UTILITY_MISSING on the target (F73, L50; `services.build_tools`, `services.utility_inventory`).

Where the four differ is exactly three models: **registry/evidence**, **bounded-exec ownership**, **unknown-handling**. Pairwise divergence is asserted at the end of this file.

Pre-task defaults, per option: see the "Defaults" line in each section (Fixed Registry / stdlib-first / static binary / test-only seams).

---

## Option 1 — Fixed Registry, flat

**Shape.** One `internal/checks` package holding ~14-18 check functions. `checks.All()` returns an ordered slice of `check.Check{ID, Category, Title, Impact, Fn}` (explicit roster over `init()` side effects, per R5 ARCHITECTURE_NOTES §1 and F68). The engine iterates the slice, gives each check a context with `min(perCheck, remaining)`, recovers panics, and appends exactly one finding per element. Each check function does its own I/O through the shared primitives, accumulates `[]Observation`, and decides its own `pass|fail|unknown`. There is no phase structure, no capability layer, no data description of a check.

**Module layout.**
```
cmd/sensor/main.go
internal/check/     Check, Finding, Observation, Status, ObsStatus, Registry
internal/checks/    remote_access.go secrets_on_disk.go bmc_inband.go storage_posture.go boot_chain.go
internal/runner/    per-check deadline, recover(), scan deadline, ordering
internal/sysread/   bounded reads, os.Root handles, WalkDir budgets, Getxattr/ACL
internal/procexec/  bounded subprocess runner (interface + real impl)
internal/machine/   Describe(); dmi.go cpu.go mem.go block.go osrelease.go
internal/output/    document types, deterministic encoder, stdlib invariant check
```

**Check-registry / evidence model.** Registry = ordered `[]Check` literal. Evidence = each check's own `[]Observation` (the R5 §4 struct: Source, Kind, ObsStatus, Value, Errno, ExitCode, Truncated, Bytes, Elapsed), serialised into the finding's `evidence` object. Observations are private to the check that made them; two checks that need `/proc/net/tcp` read it twice.

**Bounded-exec model.** Every check calls `procexec.Run(ctx, ...)` / `sysread.ReadFile(...)` itself. Boundedness is *enforced by the primitives* (there is no other way to open a file or start a process, L09/L13), but *invoked* by the check. The engine owns only the per-check deadline and the scan deadline.

**Unknown-handling model.** By convention plus one helper: a check calls `obs.Require(o1, o2)` and returns `unknown` if any load-bearing observation is not `OK`. Nothing forces a check author to use the helper; a check that writes `return Fail(...)` after an EACCES observation compiles and passes review only if a human notices. Un-run checks (scan deadline) are synthesised as `unknown` centrally by the engine (D3, L34).

**Machine-description strategy.** `machine.Describe()` reads the ranked chains directly (F33, D-02): DMI 0444 attrs, `/etc/machine-id` keyed-hash, `/proc/meminfo`, `/sys/block/*` × 512 (F55, L28). Host-vs-generic is per-read: ENOENT on the parent (`/sys/class/dmi/id` absent, as on WSL2 — F7) → not-applicable; EACCES → denied (F3, `identity.dmi_ls`). No capability object exists; the branch is `if err != nil` at each site.

**Testing model.** Unexported `fs.FS`/`*os.Root` seam per package + runner interface + injected `now` (L51, F75; TEST_STRATEGY §1). Per-check table tests over `testdata/` trees; one whole-document golden; fault injection by fixture (chmod 0000 tree, FIFO at a config path, hanging fake runner).

**Dependencies.** Runtime: none. Test-only: `santhosh-tekuri/jsonschema/v6` v6.0.3 (F69).

**LOC estimate.** ~1,300-1,700 (engine+primitives ~500, checks ~700, machine ~300, output ~150), excluding tests.

**Lava host vs generic host.** On the Lava host every check reaches its deep path: `sshd -G` runs and returns 85 directives (`network.sshd_g_effective`, F24), BMC sysfs identity is read (`bmc.bmc_sysfs_attrs`, F43), efivars gives Secure Boot + Setup Mode bytes (`kernel.secureboot`, F48), `/sys/block/nvme1n1` with no partitions is enumerated (`storage.lsblk_fs`, F57). On a machine with no NVMe/IPMI/systemd, each check independently hits ENOENT-on-parent and emits `unknown`/not-applicable with its own wording — the reason strings are not centrally normalised.

**Defaults.** Upholds all four (Fixed Registry: yes; stdlib-first: yes; static binary: yes; test-only seams: yes).

---

## Option 2 — Fixed Registry, capability-gated tree

**Shape.** Same fixed roster as Option 1, but each `Check` additionally declares `Requires []Capability` (e.g. `CapSysfsDMI`, `CapEfivars`, `CapIpmiSysfs`, `CapSystemd`, `CapSshdBinary`, `CapProcNetTCP`). A deterministic **capability probe phase** runs first — a fixed, ordered list of cheap existence/permission observations (`/run/systemd/system` for sd_booted, F53; `/sys/class/dmi/id` parent stat, F7; `/sys/firmware/efi/efivars` presence, F48; `/sys/devices/platform/ipmi_bmc.*`, F43; `sshd` on PATH) — producing a `CapabilitySet` where each capability carries the observation that established or refused it. The engine then runs each check; a check whose capabilities are unmet is **not skipped** — the engine emits its finding as `unknown` with the gate's own observation as evidence (L38, D3).

**Module layout.** Option 1's layout plus `internal/capability/` (probe list, `Set`, `Explain(cap) Observation`), and `internal/checks/` files grouped per category with capability declarations in the struct literal.

**Check-registry / evidence model.** Registry = ordered `[]Check` with `Requires`. Evidence = per-check `[]Observation` **plus** the capability observations the engine injects for any unmet gate. The capability set is the one piece of shared state; individual observations are still per-check.

**Bounded-exec model.** Same primitives, but the capability phase has its own small budget and its results *pre-empt* work: a check requiring `CapSshdBinary` never starts a subprocess when `sshd` is not on PATH, so the exec budget is spent only where it can produce an answer. Budget accounting is two-tier (capability phase + check phase) against the same scan deadline.

**Unknown-handling model.** Two centrally-enforced classes: (a) unmet gate → engine-authored `unknown` with a normalised reason vocabulary (`UNSUPPORTED`, `UTILITY_MISSING`, `EACCES`, `ENOENT-parent`; L07, L35); (b) un-run-at-deadline → engine-authored `unknown/BUDGET`. Only the third class — "gate met but the read still failed" — is left to the check, and that is the case where the check has a real observation to cite anyway. This is strictly more central than Option 1.

**Machine-description strategy.** The capability set *is* the machine-description strategy: `Describe()` consumes the same set, so "does this box have DMI at all" is answered once, with provenance, and both the machine block and the checks cite the same observation. Gating is on observed paths/capabilities, never on distro ID/hostname/vendor (L37) — required, because the Lava host is Ubuntu 24.04 on Supermicro (`identity.os_release`, `identity.dmi`) and a WSL2 Ubuntu has `ID=ubuntu` with no DMI at all (F7).

**Testing model.** Option 1's seams plus a `CapabilitySet` that is directly constructible in tests: a table test can assert "capability X absent ⇒ finding is `unknown` with reason Y" for all N checks in one loop — the D3 invariant becomes a single test rather than N hand-written ones (L34, L36).

**Dependencies.** Identical to Option 1.

**LOC estimate.** ~1,500-1,900 (adds ~150-250 for the capability package and declarations, removes some duplicated per-check existence probing).

**Lava host vs generic host.** Lava host: nearly all capabilities are met (DMI 0444 attrs, efivars, ipmi_bmc sysfs, systemd, sshd, `/proc/net/tcp`), so the gate layer is almost a no-op and every check runs its deep path — genericity costs the Lava result nothing. Generic host with no NVMe/IPMI/systemd: the gate layer produces one honest observation per missing subsystem and N normalised `unknown`s citing it, instead of N independently-worded failures.

**Defaults.** Upholds all four. The capability phase is *not* a planner: the probe list and the check roster are both fixed at compile time; nothing is chosen at runtime except which reason a check reports.

---

## Option 3 — Data-driven check table

**Shape.** Checks are rows in an embedded JSON/YAML table (`go:embed checks.json`): `{id, category, title, impact, source: {kind: file|dir|command|xattr, path|argv}, parser: <named>, predicate: <named op + operand>, unknown_when: [...]}`. A ~300-line interpreter walks the table, executes each row through the shared primitives, applies the named parser and predicate, and emits the finding. Adding a check that fits the table is a data edit; anything that does not fit needs a new named parser/predicate in Go (an "escape hatch" row kind `native` that points at a Go function).

**Module layout.** Option 1's layout with `internal/checks/` replaced by `internal/table/` (`checks.json`, `interpreter.go`, `parsers.go`, `predicates.go`, `native.go`) and a `tabletest` validator that checks the table against its own JSON Schema at test time.

**Check-registry / evidence model.** Registry = the embedded table (data). Evidence is **generated by the interpreter**, not written by check authors: every row automatically yields `{source, kind, status, value|errno, exit_code, bytes, elapsed_ms}` because the interpreter is the only thing performing I/O. This is the option's real strength — evidence quality is uniform by construction and cannot be a restatement of the title (D2).

**Bounded-exec model.** Fully central: the interpreter is the single call site for `procexec.Run` and `sysread.ReadFile`. No check code exists that could bypass a timeout or a cap, because check code does not exist. Budgets are attributes of the row.

**Unknown-handling model.** Also fully central and declarative: the interpreter maps the outcome class of the row's source (`OK|EACCES|ENOENT|UNSUPPORTED|TIMEOUT|UTILITY_MISSING|TRUNCATED|BUDGET|EXEC_ERROR`, L07) onto `pass|fail|unknown` through one table, so `TIMEOUT ≠ false` and `EACCES ≠ absent` are enforced in exactly one function.

**Machine-description strategy.** `machine.Describe()` cannot be expressed as predicate rows (it is a ranked chain with provenance, D-02), so it stays hand-written Go — the table covers findings only. Host-vs-generic is a per-row `unknown_when` list plus the parent-ENOENT rule in the interpreter.

**Testing model.** Two layers: unit tests for each named parser/predicate, and a fixture-driven run of the whole table against `testdata/` trees. Attractive property: a table row is trivially fuzzable and the row set is machine-checkable for D3 (`len(findings) == len(rows)`).

**Dependencies.** Runtime: none (JSON table parsed by `encoding/json`; YAML would add a dependency and is therefore rejected — F74's reasoning applied to `yaml/v3`). Test-only: santhosh v6, plus a second schema for the table itself.

**LOC estimate.** ~1,700-2,300 Go + ~400 lines of table, of which the interpreter/parsers/predicates are ~600-800 — most of it written *before* the first finding exists.

**Lava host vs generic host.** The rows that fit are the flat sysfs reads this host is rich in: taint bits (`kernel.module_taint`, F49), lockdown/LSM (`kernel.lsm`, F50), sysctls (`users.kernel_hardening`, F13), efivars bytes (`kernel.secureboot`, F48), device-node modes (`bmc.ipmi_dev_perms`, F42). The rows that do not fit are precisely the checks that carry this exercise's engineering content: the `sshd -G`-vs-walker reconciliation with CONTESTED output (F24, F27, D-03), the ACL decode (F41, L52), the storage/redundancy derivation (F60), and the taint-attribution join across `/sys/module/*/taint` (F49). Those become `native` rows, i.e. Option 1 with a JSON indirection in front of it.

**Defaults.** Fixed Registry: **upheld in spirit, weakened in form** — the roster is still fixed at compile time (embedded), so it is deterministic and reviewable, but the check *semantics* now live in a DSL that must itself be reviewed and versioned. Stdlib-first: upheld (JSON only). Static binary: upheld. Test-only seams: upheld.

---

## Option 4 — Collector/evaluator split

**Shape.** Two phases. **Collect:** a fixed list of collectors performs all I/O, each writing typed observations into an in-memory `EvidenceStore` keyed by a stable source key (`file:/proc/net/tcp`, `cmd:sshd -G`, `xattr:/dev/ipmi0#system.posix_acl_access`). **Evaluate:** a fixed list of evaluators, each a *pure function* `func(*Store) Finding` with no I/O capability at all (they receive a read-only store interface; there is no `os` import in the package). One observation can feed many findings; two observations of the same question can coexist in the store and be reported as CONTESTED.

**Module layout.**
```
internal/collect/    collector list, EvidenceStore, source keys, phase budget
internal/evaluate/   pure evaluators per category; no os/exec imports (enforced by a go-list test)
internal/check/      shared types
internal/runner/     phase orchestration, deadlines, recover()
internal/sysread/ internal/procexec/ internal/machine/ internal/output/  (as Option 1)
```

**Check-registry / evidence model.** Two registries: collectors (what to observe) and evaluators (what to conclude). Each evaluator declares `Needs []SourceKey`. Evidence in the finding is the *subset of the store* the evaluator declared — assembled by the engine, so an evaluator cannot cite an observation it did not depend on, and cannot omit one it did.

**Bounded-exec model.** Boundedness is confined to phase 1. The whole exec/read budget is spent in `collect`, where it can be accounted globally (e.g. "12 of 40 exec-seconds used"); `evaluate` is provably unbounded-safe because it does no I/O — it cannot hang, cannot hit EACCES, cannot leak a process. The scan deadline cuts collection, never evaluation, so the document is always produced.

**Unknown-handling model.** The strongest of the four and centrally enforced: an evaluator returns `pass|fail` only if every `Needs` key resolves to `ObsStatus == OK`; the engine checks this *after* the evaluator returns and downgrades a `pass|fail` whose dependencies were not OK to `unknown` with the offending key. A budget cut mid-scan needs no special case — missing keys are just not-OK. Two disagreeing observations for one question are first-class: `Store.Get(key)` returns a slice, and the engine marks the finding CONTESTED when an evaluator's dependencies disagree (C-03, D-03).

**Machine-description strategy.** `Describe()` becomes an evaluator over the same store, so the machine block and the findings are guaranteed to be consistent (today's Option 1 risk: `machine.storage[]` says nvme1n1 exists while a storage check says unknown). Capability detection is implicit — a capability *is* a source key whose observation is ENOENT/EACCES.

**Testing model.** The best of the four: a recorded store (JSON) from the real Lava host replays every evaluator with zero I/O, so evaluator tests are pure, fast, parallel and need no fixture trees at all. Collector tests still need `testdata/`. A recorded store from the real host is also a regression corpus for later checks — including checks written *after* host access ends.

**Dependencies.** Identical to Option 1.

**LOC estimate.** ~1,700-2,100 (store + keys + dependency plumbing ~300-400 over Option 1; individual evaluators are shorter than Option 1's checks).

**Lava host vs generic host.** Lava host: one collection pass yields `/proc/net/tcp`, `systemctl show ssh.socket`, `sshd -G`, the sshd file chain, DMI, efivars, taint, ipmi_bmc attrs, udev DB, `/sys/block/*`; the sshd oracle and the walker land in the store side by side and either agree (one finding, high confidence) or disagree (CONTESTED, both cited). Generic host: the same collector list runs, most keys resolve to ENOENT-on-parent, and every evaluator emits `unknown` naming the exact missing key — no per-check wording drift.

**Defaults.** Fixed Registry: upheld (two fixed registries instead of one). Stdlib-first: upheld. Static binary: upheld. Test-only seams: upheld, and *reduced in importance* — the store is a natural seam, so fewer packages need an `fs.FS` field.

---

## Pairwise divergence check (required by the prompt)

| Pair | registry/evidence | bounded-exec | unknown-handling | Verdict |
|---|---|---|---|---|
| 1 vs 2 | same shape, +capability declarations and engine-injected gate evidence | differs: two-tier budget, gate pre-empts exec | differs materially: two of three unknown classes move from convention to engine | genuinely different |
| 1 vs 3 | differs: Go literals vs embedded data, author-written vs generated evidence | differs: check-invoked vs interpreter-owned | differs: convention vs one outcome-class table | genuinely different |
| 1 vs 4 | differs: per-check private observations vs shared store with declared Needs | differs: distributed vs confined to phase 1 | differs: convention vs post-hoc engine downgrade on dependency status | genuinely different |
| 2 vs 4 | differs: capability set (booleans + provenance) vs full observation store | differs: pre-emption vs phase confinement | differs: gate-driven vs dependency-driven | genuinely different |
| 3 vs 4 | both centralise evidence generation, but 3 generates per row and 4 shares across evaluators | 3 = interpreter, 4 = phase | 3 = outcome-class table, 4 = dependency status | genuinely different |
| 2 vs 3 | differs on all three | — | — | genuinely different |

No two options collapse.
