# ATTACKS — twelve categories, twelve host situations, per option

Severity labels: `fatal` (would make the deliverable violate a contract requirement or a CLAUDE.md invariant), `serious` (real defect, mitigable by discipline or extra time), `cosmetic`.
Citations: fact ids from `research/FACTS.jsonl`, law ids from `research/DESIGN_LAWS.md`, probe ids from `state/HOST_SNAPSHOT.evidence.json`, decision ids from `research/DECISIONS.md` (LD-1…LD-9 are the lead's final decisions; the architecture shape LD-9 is what this document feeds).

Structure per option: (a) the twelve attack categories, each a labelled attack with a citation; (b) the twelve concrete host situations, which describe the option's mechanism — any weakness surfaced there is carried by, and labelled in, the matching category row above (e.g. Option 3 situation 12 is category 2's `fatal`); (c) the severity-vs-status rule; (d) the time estimate; (e) the single reversing fact.

Timing baseline for every estimate below: `sensor/` is empty (no Go file exists yet), the target has no Go toolchain so every iteration is cross-compile + upload (F73, `services.utility_inventory`), and the derived schema is in hand (F101, `task/derived/finding.schema.json`). "First schema-valid real-host run" = one findings.json produced by the binary on the Lava host that validates against the derived schema — not a complete check set.

---

# Option 1 — Fixed Registry, flat

## Attack categories

| # | Category | Attack | Severity |
|---|---|---|---|
| 1 | Task fit | Meets every structural requirement (one finding per registered check, D3/L34; categories as file-level groupings, C1/C2). Nothing in the brief asks for more structure. No attack lands here beyond "it is the boring answer". | `cosmetic` |
| 2 | Correctness | The correctness that matters here is not logic, it is *discipline*: L34 ("an unset verdict never defaults to PASS"), L07 (closed reason vocabulary), L39 ("missing utility ≠ missing capability") are all upheld only by each check author remembering them. Five independent shipped tools got exactly this wrong (F63 ghw EACCES→"unknown", F65 osquery `disk_encryption` zero rows non-root, F65 Wazuh `sshd -T`, F46 ipmitool errno clobber). A flat registry has the same structure those tools have. | `serious` |
| 3 | Evidence quality | Evidence is hand-assembled per check, so quality varies with author attention; D2 demands "the path you read, the value you found, the command you ran, the errno you got back". Mitigable by making `Observation` the only way to record anything (R5 §4). | `serious` |
| 4 | Safety | Strong: boundedness lives in the two primitives (L09-L13), which are the only way to open a file or start a process. A check *can* still call `os.ReadFile` directly — needs a grep test (L49-style, as `go-list-deps-zero-third-party`). | `cosmetic` |
| 5 | Host fit | Excellent. Every deep path this host offers (`network.sshd_g_effective` 85 directives, `bmc.bmc_sysfs_attrs`, `kernel.secureboot`, `kernel.module_taint`, `storage.lsblk_fs`) is a straight-line function. Nothing about the Lava host wants indirection. | `cosmetic` |
| 6 | Generic-machine behaviour | Weakest area. With no capability layer, "no systemd / no DMI / no NVMe" is discovered N times by N checks, each wording its own reason. L35 requires the reason vocabulary to stay a closed set of five classes; N independent authors drift. | `serious` |
| 7 | Portability | Fine: gating is per-read `errno`, which is inherently capability-based (L37). No distro/hostname branching is even convenient here. | `cosmetic` |
| 8 | Complexity | Lowest of the four. A YAGNI reviewer scores this best; `research/PRIOR_ART.md` already rejects a declarative rule engine as over-engineering at 3-6 checks per category (F68). | `cosmetic` |
| 9 | Time-to-build | Best of the four; see estimate below. | `cosmetic` |
| 10 | Build-vs-buy | Matches the reconciled matrix exactly (own read primitives, own runner, own walker, `sshd -G` reused, santhosh test-only — PRIOR_ART §1, C-05/C-06, LD-6). | `cosmetic` |
| 11 | Failure modes | The realistic failure is a *silent under-claim*: a check that reports `fail` (or `pass`) on an observation it never actually got. L36 requires an under-claim fixture per check; with 14-18 hand-written checks that is 14-18 hand-written fixtures nobody will finish under time pressure. | `serious` |
| 12 | Testability | Adequate but repetitive: the D3 invariant ("registered ⇒ emitted, never pass by default") must be asserted per check rather than once over a table. `registry-count-invariant` (L34 fixture) catches omission but not wrong-status-under-EACCES. | `serious` |

## Twelve host situations

| # | Situation | Mechanism in Option 1 |
|---|---|---|
| 1 | `EACCES` on `/etc/sudoers.d` | The sudo-policy check stats `/etc/sudoers.d` (0750 root:root, `users.sudoers_ls`), gets EACCES on readdir, and must itself apply L10 (EACCES on a *directory* = absence unprovable) → `unknown`, reason `EACCES`, evidence = path+mode+errno. Correct only by author discipline; group membership (`users.sudo_group`) is still reported as fact (L22). |
| 2 | `sshd -T` failing unprivileged | Never invoked (L18, F26, PRIOR_ART REJECT). The check runs `/usr/sbin/sshd -G` through the bounded runner (F24, `network.sshd_g_effective`) and captures the real rc (L41 — never through a pipeline). |
| 3 | Socket-activated `sshd` | The listener check reads `/proc/net/tcp{,6}` and `systemctl show ssh.socket` (L20, F30, `network.ssh_socket_cat`, `network.ss_listen`); sshd_config never decides the listen address. Owner of :22 stays UNKNOWN (F31, `/proc/<pid>/fd` of uid 0 unreadable). |
| 4 | `/dev/ipmi0` root-only + no `ipmitool` | Per LD-3 the device is never opened. The check stats it (0600 root:root, `bmc.ipmi_dev_ls`/`bmc.ipmi_dev_perms`, F42), reads BMC identity from `/sys/devices/platform/ipmi_bmc.0/*` (0444, F43, `bmc.bmc_sysfs_attrs`) under an out-of-band deadline (L40, F44), and reports `ipmitool` absence as inventory (`bmc.ipmitool_which`, F39/L39 — missing utility ≠ missing capability). Four separable findings per L26. |
| 5 | `nvme smart-log` returning `EACCES` | The health check reports `unknown` with reason CAP_SYS_ADMIN and cites `storage.nvme_smart_rc` / `storage.nvme_smart_try` (F59) while still reporting identity from world-readable sysfs (F56, L30). The UNKNOWN *is* the finding. |
| 6 | Unused `nvme1n1` | Enumerated from `/sys/block` (all symlinks — F18/R5-OR4 — so `os.Root` traversal, L15); no partitions, no udev fs signature, no holders (`storage.lsblk_fs`, F57). Wording must be "no filesystem signature known to udev", not "no filesystem" (C-37). The sensor never reads the device (D-08). |
| 7 | Secure Boot off + Setup Mode + tainted `bnxt_en` | Three separate checks per L46: efivars 5-byte read skipping the 4-byte attribute prefix (F48, `kernel.secureboot`), Setup Mode as its own check, taint bit table decoded as data with attribution via `/sys/module/bnxt_en/taint` (F49, `kernel.module_taint`). Taint E does not imply enforcement (L46). |
| 8 | No NVMe, no IPMI, no systemd | Each check independently hits ENOENT-on-parent; sd_booted via `/run/systemd/system` (F53, L38). Answers are correct but the reasons are N independently authored strings. | 
| 9 | Hanging subprocess | `procexec`: Setpgid + `Cancel` = `Kill(-pid, SIGKILL)` + `WaitDelay` (F21/F22/F23, L09-L12) → `unknown`/TIMEOUT, zero surviving descendants. Not option-specific. |
| 10 | 200 MB sysfs read | Read primitive caps at policy cap+1 and sets `truncated` (F14/F15, L05); `st_size` is never trusted. Truncated ⇒ never PASS. |
| 11 | A check that panics | Engine `recover()` per check → `unknown` carrying the recovered value; check N+1 runs; document still written (L34, R5 §2 — node_exporter does *not* do this, F68). |
| 12 | Budget cut mid-scan + two disagreeing observations | Budget: engine synthesises `unknown`/BUDGET for un-run checks (L14, F17 — the deadline never waits on a stuck goroutine). Disagreement (`sshd -G` vs the Include walker, C-03/LD-5): the *same check* holds both observations, so it can emit CONTESTED — but only that one check can; there is no general mechanism, and a disagreement spanning two checks is invisible. |

**Severity-vs-status rule.** LD-2: `severity` = declared `impact` when `fail` or `unknown`, `info` when `pass`, always `info` for observational checks. **Centrally enforceable: yes** — the engine sets `severity` after the check returns; the check only declares `Impact` in its struct literal. This is the one central guarantee Option 1 gets for free.

**Time to first schema-valid real-host run: ~55-70 min (estimate).** Assumes `go build` cross-compiles cleanly on this toolchain (verified once already — F73, four repro binaries ran under WSL as uid 1000) and that scp/rsync upload works per the SSH plan (unverified in this session). What could double it: the schema-validation loop — the derived schema requires `check_id` to match `^[A-Z][A-Z0-9_]*$`, `status`/`severity` enums, and `reason` required when status is `fail|unknown` (conditional `required`), so the first run typically fails validation two or three times before the shape is right; and `format: date-time` needs format assertion enabled in the validator (R5-OR1 answer).

**Single reversing fact.** If check authorship is delegated across parallel agents (or the check count exceeds ~20), the "discipline holds because one author remembers L07/L34/L39" premise fails — F63/F65 document five shipped tools that failed exactly this way. That would make Option 1 the wrong choice.

---

# Option 2 — Fixed Registry, capability-gated tree

## Attack categories

| # | Category | Attack | Severity |
|---|---|---|---|
| 1 | Task fit | Directly serves F1 of the contract ("how gracefully your sensor handles unanswerable checks while maintaining a clean, generic architecture") and L38 ("capability gate before probe"). Best structural fit of the four. | `cosmetic` |
| 2 | Correctness | Real risk: the gate becomes a *second* source of truth that can be wrong. `kernel.apparmor_profiles` is the proof — mode 0444 yet `cat` returns Permission denied (F94/F50, C-08). A capability inferred from mode bits would say "readable" and the check would then report `fail`/`pass` on nothing. L42 exists precisely because mode bits are not authorisation. Gates must be established by *attempting the read*, not by stat. | `serious` |
| 3 | Evidence quality | Better than Option 1 for the gated case (engine injects the gate observation), unchanged for the ungated case. | `cosmetic` |
| 4 | Safety | Same primitives; the capability phase adds one more budget to account for, and a capability probe that itself hangs (BMC sysfs, F44) must run under L40's out-of-band deadline like any other device-adjacent read. Easy to forget. | `serious` |
| 5 | Host fit | On this host almost every gate is met, so the layer is near-inert (`identity.dmi_ls`, `kernel.secureboot`, `bmc.bmc_sysfs_attrs`, `network.sshd_g_effective` all succeed). It buys nothing *here* — its value is entirely on the generic machine. That is the YAGNI attack, and it is a fair one. | `serious` |
| 6 | Generic-machine behaviour | Strongest of the four for the *stated* requirement: one probe establishes "no systemd" (F53) and N checks cite the same observation with normalised reasons (L35). | `cosmetic` |
| 7 | Portability | Best. L37 (never gate on distro ID / hostname / vendor) is enforced structurally: capabilities are observations, so there is no place to put a distro string. | `cosmetic` |
| 8 | Complexity | One extra package and a `Requires` field per check. A YAGNI reviewer will ask whether ~200 LOC of gating earns its keep when the host meets almost every gate; the honest answer is that it earns it on the *generic* requirement, which is graded (contract F1). | `serious` |
| 9 | Time-to-build | ~15-25 min over Option 1, inside the 90-minute bar but with less margin. | `serious` |
| 10 | Build-vs-buy | No dependency implications; the capability set is our own ~150 LOC. Matches PRIOR_ART. | `cosmetic` |
| 11 | Failure modes | The dangerous one: a capability probe that is *wrong in the permissive direction* silently converts a should-be-unknown into a pass/fail across many checks at once — a single point of failure that Option 1 does not have. Bounded by making gates read-attempts (see #2). | `serious` |
| 12 | Testability | Best of the registry family: "capability absent ⇒ every dependent check emits `unknown` with the gate's reason" is one table-driven test over the whole roster, satisfying L34/L36 in one place. | `cosmetic` |

## Twelve host situations

| # | Situation | Mechanism in Option 2 |
|---|---|---|
| 1 | `EACCES` on `/etc/sudoers.d` | Capability `CapSudoersDir` is established by an actual readdir attempt (not a stat, per #2 above); it resolves EACCES (`users.sudoers_ls`), and the engine emits the sudo-policy finding as `unknown` with that observation. The group-membership finding is ungated and still reports fact (L22, `users.sudo_group`). |
| 2 | `sshd -T` failing unprivileged | Same as Option 1 (never run). `CapSshdBinary` gates the `-G` exec; if absent → walker fallback path instead of `unknown` (LD-5) — a capability can select a *fallback*, not only a gate. |
| 3 | Socket-activated `sshd` | `CapSystemd` (via `/run/systemd/system`, F53) selects `systemctl show ssh.socket`; without it the listener check falls back to `/proc/net/tcp` alone and says so (L20, `network.ssh_socket_cat`). |
| 4 | `/dev/ipmi0` root-only + no `ipmitool` | Three capabilities: `CapIpmiSysfs` (met, `bmc.bmc_sysfs_attrs`), `CapIpmiDevOpenable` (refused: 0600 root:root, `bmc.ipmi_dev_perms`), `CapIpmitool` (absent, `bmc.ipmitool_which`). Per LD-3 the second is *evidence only* and never leads to an open. The four L26 findings each cite the capability that decided them. |
| 5 | `nvme smart-log` EACCES | `CapNvmeAdmin` refused (F59, `storage.nvme_smart_rc`); engine emits `unknown` with the CAP_SYS_ADMIN reason; identity findings ungated (F56). |
| 6 | Unused `nvme1n1` | `CapSysBlock` met; per-device attributes read; `CapUdevDB` met (`/run/udev/data` readable, C-37/F57) so the "no filesystem signature known to udev" wording is available; the negative is scoped, not absolute. |
| 7 | Secure Boot off + Setup Mode + taint | `CapEfivars` met (`kernel.secureboot`, F48). Important trap: `CapEfivars` *absent* must map to not-applicable, not "Secure Boot disabled" (L46) — the gate reason carries that distinction, which is exactly what the gate layer is for. Taint is ungated (`/proc/sys/kernel/tainted` is world-readable, F49). |
| 8 | No NVMe, no IPMI, no systemd | The best case for this option: three gate observations produce N normalised `unknown`s, all citing the same evidence. This is the situation the option exists for. |
| 9 | Hanging subprocess | As Option 1 (shared runner). Additional requirement: the capability phase's own execs (`sshd` presence) go through the same runner. |
| 10 | 200 MB sysfs read | As Option 1 (shared primitive). |
| 11 | A check that panics | As Option 1. Extra exposure: a panic in the *capability phase* would poison many checks — the phase needs its own `recover()` per probe, and a panicked probe must resolve to "capability unknown ⇒ dependent checks unknown", never "capability met". |
| 12 | Budget cut + disagreement | Budget: two-tier accounting; if the capability phase eats the budget, every check emits `unknown`/BUDGET (L14) — a *worse* failure mode than Option 1, where at least the checks that ran early produced answers. Disagreement: same limitation as Option 1 — contested evidence is handled inside the one check that holds both observations (LD-5). |

**Severity-vs-status rule.** LD-2, applied by the engine exactly as in Option 1. **Centrally enforceable: yes**, and slightly better — the gate-authored `unknown`s are engine-constructed end to end, so their severity cannot diverge.

**Time to first schema-valid real-host run: ~70-90 min (estimate).** Sits on the ~90-minute bar; explicitly penalised for that in the scorecard. Assumes the capability list stays at ~8-10 probes. What could double it: the capability set needing more edge cases than expected — C-08 (`kernel.apparmor_profiles`: 0444 yet EACCES) says gates cannot be stat-based, so each gate is a real read attempt with its own error taxonomy, and the number of gates tends to grow one per check until it becomes a second registry.

**Single reversing fact.** If, on the Lava host, essentially every gate is met (which the snapshot already suggests: `identity.dmi_ls`, `kernel.secureboot`, `kernel.lsm`, `bmc.bmc_sysfs_attrs`, `network.sshd_g_effective`, `services.time_sync` all succeed) **and** the graders never run the binary on a second machine, the gate layer is pure cost on the artifact being graded — CLAUDE.md's "genericity must not weaken the Lava-host result" becomes "genericity spent time that the Lava-host result needed". That would make Option 2 the wrong choice.

---

# Option 3 — Data-driven check table

## Attack categories

| # | Category | Attack | Severity |
|---|---|---|---|
| 1 | Task fit | The brief's graded content is judgment about unanswerable checks (contract F1) and evidence that a reader can act on (D2). A DSL is a *delivery mechanism*, not judgment; the checks that carry the judgment are the ones it cannot express. | `serious` |
| 2 | Correctness | The load-bearing checks on this host are derivations, not predicates: `sshd -G` output reconciled against an Include-aware walker with first-obtained-value-wins and CONTESTED on disagreement (F24, F27, LD-5); POSIX ACL decode from raw xattr bytes (F41, L52); taint attribution joining `/proc/sys/kernel/tainted` with `/sys/module/*/taint` (F49); redundancy derived from `/proc/mdstat` + `/dev/mapper` + holders (F58, F60); efivars 5-byte read skipping a 4-byte attribute prefix (F48). Each becomes a `native` escape-hatch row. When the interesting half of the roster is native rows, the table is an indirection over Option 1. | `fatal` |
| 3 | Evidence quality | Genuinely the best: the interpreter is the sole I/O site, so `{source, status, errno, exit_code, bytes, elapsed_ms}` is emitted uniformly and cannot be a restatement of the title (D2). This is the option's one clear win. | `cosmetic` |
| 4 | Safety | Also strong: one call site for exec and read means a timeout or cap cannot be bypassed (L09-L13). Counter-risk: a `native` row re-opens the bypass, and now there are two enforcement regimes to review instead of one. | `serious` |
| 5 | Host fit | Half-fit. The flat sysfs rows (sysctls F13 `users.kernel_hardening`, lockdown/LSM F50 `kernel.lsm`, device modes F42 `bmc.ipmi_dev_perms`, taint bits F49) fit beautifully. The four host-defining checks (sshd effective policy, BMC identity under an out-of-band deadline per L40, storage posture, ACLs) do not. | `serious` |
| 6 | Generic-machine behaviour | Good: `unknown_when` is declarative and the parent-ENOENT vs EACCES vs UTILITY_MISSING taxonomy (GENERIC_FALLBACK_PLAN §0) is applied once by the interpreter. | `cosmetic` |
| 7 | Portability | Good, same reason. | `cosmetic` |
| 8 | Complexity | The heaviest. `research/PRIOR_ART.md` §1 already carries an explicit verdict: "Declarative rule engine (Wazuh/kube-bench style YAML) — **REJECT — over-engineering** … at 3-6 checks per category a DSL adds a parser and a failure mode for nothing" (F68), and R5 ARCHITECTURE_NOTES §1 repeats it for kube-bench (R5-F9). Choosing Option 3 means overruling a reconciled KB verdict. | `fatal` |
| 9 | Time-to-build | Worst: ~600-800 LOC of interpreter/parsers/predicates must exist before the first finding does. See estimate. | `fatal` |
| 10 | Build-vs-buy | Builds a rule engine — the single thing PRIOR_ART names as the over-engineering trap (F68). Also would tempt a YAML dependency, which F74's reasoning (four modules for one subcommand) rejects by analogy. | `serious` |
| 11 | Failure modes | New failure class the other three do not have: a malformed or drifted table row. `unknown` because the *table* is wrong is not a posture finding, it is a bug wearing a finding's clothes — and D3 makes silently mis-stating a check a critical failure. | `serious` |
| 12 | Testability | Mixed: parsers/predicates are highly testable in isolation and `len(findings) == len(rows)` gives D3 for free; but the native rows need Option 1's tests anyway, so the test surface is the union, not the intersection. | `serious` |

## Twelve host situations

| # | Situation | Mechanism in Option 3 |
|---|---|---|
| 1 | `EACCES` on `/etc/sudoers.d` | Row `{source: dir /etc/sudoers.d}`; interpreter's outcome table maps EACCES-on-directory → `unknown` (L10). Handled cleanly and centrally — a genuine strength. |
| 2 | `sshd -T` failing unprivileged | Not expressible as a row: the required behaviour is "`-G` primary, walker fallback, disagreement ⇒ CONTESTED" (LD-5, F24, F26). Becomes a `native` row. |
| 3 | Socket-activated `sshd` | Partially expressible: rows for `/proc/net/tcp` and `systemctl show ssh.socket` (`network.ss_listen`, `network.ssh_socket_cat`), but correlating them into one listener verdict (L20) is a join, not a predicate → native or a bespoke parser. |
| 4 | `/dev/ipmi0` root-only + no `ipmitool` | Mode/owner rows work (`bmc.ipmi_dev_perms`, F42) and the `ipmitool`-absent row is clean inventory (`bmc.ipmitool_which`, L39). But the BMC sysfs identity read needs the out-of-band goroutine deadline of L40 (F44) — a per-row `timeout` attribute is not the same thing as an abandonable goroutine, so this row needs interpreter support written specially for it. |
| 5 | `nvme smart-log` EACCES | Per LD-3/D-08 no command is run; the row is "read `/sys/class/nvme/nvme0/*` identity" + a declared unknown-by-construction finding for SMART citing `storage.nvme_smart_rc` (F59). Expressible, if the table can express "this UNKNOWN is the finding". |
| 6 | Unused `nvme1n1` | Enumeration is a loop over `/sys/block/*` with symlink traversal (F18, L15) — the table needs a "for each device" row kind, i.e. iteration in the DSL. That is the point at which a DSL becomes a language. |
| 7 | Secure Boot off + Setup Mode + taint | Rows fit well if the parser library includes `efivar_bool_at_offset_4` (F48) and `bit_table` (F49) — both are named parsers, which is the DSL working as intended. Taint *attribution* to `bnxt_en` (`kernel.module_taint`) is a join → native. |
| 8 | No NVMe, no IPMI, no systemd | Best case: every row's `unknown_when` fires and the interpreter emits normalised `unknown`s. |
| 9 | Hanging subprocess | Central by construction — the interpreter is the only exec site (L09-L12). |
| 10 | 200 MB sysfs read | Central by construction (L05); per-row cap attribute. |
| 11 | A check that panics | A row cannot panic (no user code), but a *parser* can, and a native row certainly can → `recover()` still required around row execution. Net: same protection, slightly smaller blast radius. |
| 12 | Budget cut + disagreement | Budget: interpreter emits `unknown`/BUDGET for unexecuted rows — clean. Disagreement: **the table has no representation for two sources answering one question.** `sshd -G` vs walker (C-03, LD-5) and any future cross-check must live in native code. This is the structural gap. |

**Severity-vs-status rule.** LD-2 applied by the interpreter from each row's `impact` field. **Centrally enforceable: yes** — arguably the most airtight of the four, since even the `impact` value is data. This does not offset attacks #2/#8/#9.

**Time to first schema-valid real-host run: ~120-160 min (estimate) — over the ~90-minute bar, explicitly penalised.** The interpreter, the named parser/predicate library, the table's own schema and its validation must all exist before finding #1. Nothing here is speculative: it is the same work as Option 1's checks plus a language to describe them.

**Single reversing fact.** F68 + PRIOR_ART §1's standing REJECT of a declarative rule engine at this check count, combined with contract C9 ("a handful of checks done thoughtfully beats twenty done thinly") — the table's only real payoff is cheap check multiplication, and the brief explicitly does not reward that. If that reading of C9 is right, Option 3 is the wrong choice; and I judge it to be right.

---

# Option 4 — Collector/evaluator split

## Attack categories

| # | Category | Attack | Severity |
|---|---|---|---|
| 1 | Task fit | Very strong. The one requirement no other option handles structurally is the contradiction case: LD-5 mandates "disagreement → CONTESTED evidence" between `sshd -G` and the walker, and CLAUDE.md states "contradiction ≠ first observation wins: record both, report contested". Only Option 4 makes that a property of the architecture rather than of one check. | `cosmetic` |
| 2 | Correctness | The strongest correctness guarantee of the four: evaluators have no I/O, so the engine can verify *after the fact* that every `pass`/`fail` rests on observations whose `ObsStatus == OK` and downgrade otherwise (R5 §4's decision rule, mechanised). That converts L34/L07/L39 from convention into a checked invariant. | `cosmetic` |
| 3 | Evidence quality | Best-in-class and *provably complete*: the finding's evidence is assembled by the engine from the evaluator's declared `Needs`, so it cannot omit a load-bearing observation or include a decorative one (D2). | `cosmetic` |
| 4 | Safety | Best: all exec and file I/O is confined to one phase with one global budget; the evaluate phase is structurally incapable of hanging, leaking a process, or touching the host (E1, E2, E6). An import-graph test (`no os/exec in internal/evaluate`) makes it enforceable, in the spirit of L49's `go-list-deps` fixture. | `cosmetic` |
| 5 | Host fit | Good, with one real cost: collection must be *speculative* — the collector list is fixed, so on this host it will collect observations that no evaluator ends up needing (wasted budget), and any evaluator needing something not collected returns `unknown` even though the data was one read away. That coupling bug is invisible until run time unless a test asserts `Needs ⊆ collected keys`. | `serious` |
| 6 | Generic-machine behaviour | Very good: a missing capability is just a source key resolving to ENOENT/EACCES, and every evaluator citing it says the same thing. Equivalent to Option 2's benefit without a separate gate concept. | `cosmetic` |
| 7 | Portability | Good, same reason; gating is on keys, never on distro (L37). | `cosmetic` |
| 8 | Complexity | Highest conceptual load of the three non-DSL options: two registries, a key namespace, a dependency declaration per evaluator. A YAGNI reviewer will call the store a database-shaped thing for ~15 checks, and E5 lists "database" as an explicit out-of-scope trap. The defence is that it is a map, not a store — but the naming invites the criticism. | `serious` |
| 9 | Time-to-build | ~90-110 min: the plumbing (keys, store, Needs, downgrade rule, `Needs ⊆ collected` test) is front-loaded before finding #1, like Option 3 but ~3× smaller. On/over the bar. | `serious` |
| 10 | Build-vs-buy | No dependency implications; consistent with LD-6 and PRIOR_ART. The store is ~150 LOC of stdlib maps. | `cosmetic` |
| 11 | Failure modes | Two specific ones: (a) key drift — an evaluator declares `file:/proc/net/tcp6` while the collector wrote `file:/proc/net/tcp`, producing a spurious `unknown` that *looks* like an honest one, which is exactly the class of dishonesty D3 calls critical; (b) memory — the store holds every observation for the whole run, so a capped-but-large read (L05 caps, F14) is retained rather than consumed and discarded. Both are bounded by tests and caps, not by structure. | `serious` |
| 12 | Testability | Best of the four by a wide margin: a recorded store from the real Lava host replays every evaluator with zero I/O, giving pure, fast, parallel tests and a regression corpus that survives the end of host access — which matters because host access is the scarce resource in this exercise (`state/SSH_PLAN.md`, lead-only). |  `cosmetic` |

## Twelve host situations

| # | Situation | Mechanism in Option 4 |
|---|---|---|
| 1 | `EACCES` on `/etc/sudoers.d` | Collector writes `dir:/etc/sudoers.d → {EACCES, mode 0750 root:root}` (`users.sudoers_ls`). Every evaluator that declared that key is downgraded to `unknown` by the engine; the group-membership evaluator, which declared only `file:/etc/group`, still emits its fact (L22, L43, `users.sudo_group`). |
| 2 | `sshd -T` failing unprivileged | Never collected (L18, F26). `cmd:sshd -G` is a collected key with its real rc (F24, `network.sshd_g_effective`, L41); `file:/etc/ssh/sshd_config` + drop-ins are separate keys (`network.sshd_config_d`). |
| 3 | Socket-activated `sshd` | Keys `file:/proc/net/tcp`, `file:/proc/net/tcp6`, `cmd:systemctl show ssh.socket` (`network.ss_listen`, `network.ssh_socket_cat`, F30, L20). One listener evaluator consumes all three; a second evaluator (config-staleness, `network.sshd_dropin_mtime_vs_boot`, F34) reuses them at zero extra I/O — the "one observation, many checks" payoff, concretely. |
| 4 | `/dev/ipmi0` root-only + no `ipmitool` | Keys: `stat:/dev/ipmi0` (0600 root:root, F42), `dir:/sys/devices/platform/ipmi_bmc.0` attributes (F43, L40 out-of-band deadline inside the collector), `which:ipmitool` (absent), `file:/proc/devices` (`ipmidev`), `dir:/sys/firmware/dmi/entries` listing (F4, L02 — names only, attributes 0400). Four L26 evaluators read from those same keys. Per LD-3 no command is ever issued. |
| 5 | `nvme smart-log` EACCES | No command per LD-3/D-08; the SMART evaluator declares `cap:nvme_admin` whose collected observation is the refusal (F59, `storage.nvme_smart_rc`), so the `unknown` cites the actual proof. Identity evaluator uses world-readable sysfs keys (F56). |
| 6 | Unused `nvme1n1` | Collector enumerates `/sys/block/*` via `os.Root` (F18/F19) and the udev DB (`/run/udev/data`, F57, C-37); one evaluator reports the device in `machine.storage[]` (size × 512, F55/L28) and another reports "attached, no partition table, no udev fs signature, no holders" — both from the same observations, guaranteed consistent. |
| 7 | Secure Boot off + Setup Mode + taint | Keys `file:/sys/firmware/efi/efivars/SecureBoot-*`, `…/SetupMode-*` (F48, `kernel.secureboot`), `file:/proc/sys/kernel/tainted`, `file:/sys/module/bnxt_en/taint` (F49, `kernel.module_taint`), `file:/sys/kernel/security/lockdown` (F50, `kernel.lsm`). Three-plus evaluators per L46; the taint→module join is trivial because both observations are in the store. |
| 8 | No NVMe, no IPMI, no systemd | Collectors run, keys resolve ENOENT-on-parent, every dependent evaluator emits `unknown` naming the missing key. Same outcome as Option 2 with no separate capability concept. Cost: collectors still *attempt* everything, so the wasted-attempt budget is larger than Option 2's pre-empted one (attack #5). |
| 9 | Hanging subprocess | Same runner (L09-L12), and it can only be hit in phase 1, so a hang can never delay document production (L14, F17). |
| 10 | 200 MB sysfs read | Same primitive (L05); additionally, the capped value is *retained* in the store, so the store needs its own aggregate cap (attack #11b). |
| 11 | A check that panics | An evaluator panic is recovered → `unknown` for that finding only; because evaluators are pure, a panic cannot leave a process, fd or partial write behind. A collector panic is recovered per collector and leaves its keys unresolved, which the dependency rule already handles as `unknown`. Strictly better isolation than the other three. |
| 12 | Budget cut + disagreement | Budget: collection stops at the deadline; every evaluator still runs (no I/O, microseconds) and those with unresolved keys emit `unknown`/BUDGET. **The document is always complete** — the strongest D3 answer of the four. Disagreement: `Store.Get(key)` returns a slice, so `cmd:sshd -G` and `walk:/etc/ssh/sshd_config` can both answer "PasswordAuthentication" and the evaluator emits CONTESTED with both cited (C-03, C-04, LD-5) — architectural, not per-check. |

**Severity-vs-status rule.** LD-2 applied by the engine. **Centrally enforceable: yes, and uniquely coupled to status** — because the engine can *change* a status (downgrade to `unknown` on a not-OK dependency), it must recompute severity after the downgrade; in the other three options the status is final when the check returns. That is a one-line ordering requirement, and getting it wrong yields a `pass`-severity `unknown`, which is a schema-valid lie. Worth naming in the implementation prompt.

**Time to first schema-valid real-host run: ~85-110 min (estimate).** Assumes the key namespace is settled up front (a mid-build key rename is the expensive mistake). What could double it: the `Needs ⊆ collected keys` coupling — every added evaluator is a chance to reference a key no collector produces, and each such miss looks like a legitimate `unknown` in the output rather than a build error, so it costs a debugging pass on the host rather than a compile error locally.

**Single reversing fact.** If the delivered check count stays at the contract's recommended depth — C9, "a handful of checks done thoughtfully beats twenty done thinly", i.e. ~3-6 per category over 5 categories — then the "one observation feeds many checks" payoff is small (on this host the concrete overlaps are: `/proc/net/tcp` shared by 2-3 remote-access findings, DMI shared by machine+identity, `/sys/block` shared by machine+storage-posture — roughly three sharings), and the plumbing does not pay for itself before the deadline. That would make Option 4 the wrong choice.
