# PONYTAIL_PASS1 — YAGNI attack on the four architecture candidates

Reviewer: `ponytail-reviewer` (Ponytail ruleset, clone `356918eb`, intensity **full**). Read-only pass; nothing outside `reports/` written.
Inputs: `research/GRILL/{OPTIONS,ATTACKS,SCORECARD,OPEN_QUESTIONS}.md`, `research/{DECISIONS,DESIGN_LAWS,PRIOR_ART}.md`, `task/derived/TASK_CONTRACT.md`.
Binding context: LD-1..LD-8; one Opus author in one pass (LD-8); 18-24 checks in 5 categories; ~70-90 min to first schema-valid host run.

## (a) Ponytail rules applied

| Rule (heading / clause) | How it shaped this review |
|---|---|
| **The ladder — rung 1 "Does this need to exist at all?"** | Applied to the capability phase (Opt 2) and the EvidenceStore (Opt 4). Both exist to serve one deliverable each; both deliverables are reachable one rung higher. |
| **The ladder — rung 2 "Already in this codebase?"** | The read/exec primitives already classify errno. A capability gate re-performs the check's own first read. Reuse the classification, don't cache it in a second phase. |
| **The ladder — rung 3/6 "Stdlib does it / can it be one line?"** | `sync.OnceValue` for the one genuinely shared gate (sd_booted); `exec.LookPath` at the call site instead of a `CapSshdBinary` registry entry. |
| **Rules — "no interface with one implementation, no factory for one product, no config for a value that never changes"** | Kills `procexec` interface+impl, the two-registry split, and any `--timeout`/`--config` flag. Budgets are constants. |
| **Rules — "Fewest files possible"** | 8-9 internal packages for ~1.4k LOC is package-per-noun. Collapse to 3. |
| **Rules — "Deletion over addition"** | Every finding below is a deletion except two (~45 LOC added, both mechanising a graded invariant). |
| **"Lazy code without its check is unfinished" (ONE runnable check)** | Turns L36's 18-24 hand-written under-claim fixtures into one table test over the roster plus ~8 real parser fixtures. |
| **"When NOT to be lazy" — never simplify away input validation at trust boundaries, error handling that prevents data loss, security measures** | The whole (d) section. The host is a trust boundary; UNKNOWN semantics are the "error handling", boundedness is the "security measure". |
| **"Never lazy about understanding the problem"** | Read all four options, both plan layers and the laws before cutting; three cuts I first wanted (see (d)) were withdrawn after tracing L40/F44 and D3. |
| **Output — "every paragraph defending a simplification is complexity smuggled back in as prose"** | Estimate scrutiny: Opt 2's defence of its gate layer is longer than the gate layer's payload. |

## (b) Findings, ranked by complexity saved vs risk

**1. The capability phase (Opt 2) is a cache in front of the read the check already makes.** ~200-250 LOC, one extra budget, one extra roster.
→ *Accidental because*: ATTACKS #2 already concedes gates cannot be stat-based (`kernel.apparmor_profiles` 0444 yet EACCES, F94/C-08), so every gate must be a real read attempt — i.e. the check's own first observation, performed earlier and stored. Its one non-duplicative deliverable is a **normalised reason vocabulary** across N checks. On the graded artifact the layer is near-inert (ATTACKS #5: every gate met). It also invents ATTACKS #11 (a permissive gate flips many checks at once) and ATTACKS #12 (capability phase eats the budget so *everything* is unknown) — two failure modes Option 1 does not have.
→ *Simpler*: one exported type and one function shared by both primitives — `func classify(err error) (ObsStatus, Reason)` over the closed L07 set, plus a `parentENOENT(path) bool` helper for the not-applicable case. ~15-25 LOC buys identical reason normalisation with no phase, no `Requires`, no two-tier accounting. The one gate that is genuinely shared and expensive-if-repeated (sd_booted, `/run/systemd/system`, F53) is `sync.OnceValue[Observation]` — one line. Pre-emption for `sshd` is `exec.LookPath` at the call site returning UTILITY_MISSING directly (L39).
→ *Must not touch*: **capability detection + generic fallbacks stay** — they move from a pre-phase to per-read errno classification, which C-08 proves is *strictly more accurate*. L37 (never gate on distro/hostname) stays structural: no distro string exists anywhere. L35's five classes become a Go type instead of a convention.
→ *Ponytail rule*: ladder rung 1 + rung 2; "no unrequested abstractions".

**2. The EvidenceStore + source-key namespace (Opt 4) is a database-shaped thing for three actual sharings.** ~300-400 LOC of plumbing plus a `Needs` subset-of-collected test plus an unspecified aggregate memory cap (OPEN_QUESTIONS §3 has no fact bounding it; §7.4 asks the lead to invent one).
→ *Accidental because*: the option's own reversing fact counts the real overlaps — `/proc/net/tcp` (2-3 findings), DMI (machine+identity), `/sys/block` (machine+storage). Three. It converts compile-time-checkable struct field access into runtime string keys, and ATTACKS #11a names the consequence: key drift produces *a spurious unknown that looks honest*, the exact dishonesty class D3 calls critical — and it surfaces only on the host, where every debug round trip is a cross-compile plus upload (F73, no Go on target, upload path unverified per OPEN_QUESTIONS §3).
→ *Simpler*: build the three shared observations once before the loop into a plain struct passed to every check — `func All(ctx context.Context, env *Env) []Finding`. ~10 LOC, compile-time-checked, no namespace, no coupling test, no memory policy. The replay-without-host property Opt 4 is loved for comes free: `findings.json` from the real run *is* the regression corpus (its evidence already contains every observation, D2) — a golden-file test, zero machinery.
→ *Must not touch*: CONTESTED for LD-5 stays — it lives in the one check holding both `sshd -G` and the walker, which is where the disagreement actually is. Per-check isolation and the always-complete document stay (see #3).
→ *Ponytail rule*: ladder rung 1; "no unrequested abstractions"; E5's "database" trap quoted back.

**3. KEEP and build: the ~30-LOC load-bearing-observation downgrade.** The single addition worth its lines.
→ Mark each `Observation` load-bearing; after a check returns, the engine downgrades any `pass|fail` whose load-bearing observations are not `OK`, citing the offending one. This mechanises L34/L39/D3 without a store or a phase, and it makes findings #1 and #2 safe to take: *an unmet gate is just a not-OK load-bearing observation*.
→ *Ponytail pairing*: "lazy code without its check is unfinished" — it earns exactly **one** table test (for each check: inject not-OK, assert `status==unknown` and `reason` set), which replaces the 18-24 hand-written under-claim fixtures L36 asks for and ATTACKS #11 says nobody will finish.
→ *Ordering caveat, one line*: severity is derived **after** the downgrade, inside the same `finalize(f)` the engine already needs for LD-2. A `pass`-severity `unknown` is a schema-valid lie (ATTACKS Opt-4 severity note). Checks declare `Impact` only; they never set `severity`.

**4. Eight internal packages for ~1,400 LOC.** `check`, `checks`, `runner`, `sysread`, `procexec`, `machine`, `output` (plus `capability`).
→ *Accidental because*: package-per-noun. Each package pays a per-package unexported test seam (L51), a constructor and an import-cycle negotiation. `sysread` and `procexec` are one concept ("bounded observation carrying an errno"); `check` (types) + `runner` (engine) + `output` (document + encoder) are one concept ("build and emit the document"); `internal/machine` is five files for ~10 reads into one struct.
→ *Simpler*: `cmd/sensor/main.go`, `internal/probe/` (read + exec + Observation + classify), `internal/scan/` (types, registry, runner, machine, encode), `internal/checks/`. Three internal packages, ~3 seams instead of 8. `Describe()` is one file.
→ *Must not touch*: L09's "no other package builds an exec.Cmd" gets *easier* — one package owns both primitives, one grep test covers it. Caps and timeouts unmoved.
→ *Ponytail rule*: "Fewest files possible"; "Boring over clever".

**5. `internal/procexec/` "(interface + real impl)" and the "hanging fake runner" fixture.** Opt 1 layout, verbatim.
→ *Accidental because*: an interface with one production implementation, and the fake tests the mock. The thing under test is Setpgid + group-kill + `WaitDelay` + capped writers (F21-F23, L09-L12) — a fake runner exercises **none** of it, and OR-OPEN-3 needs the real behaviour proved on kernel 6.8 anyway.
→ *Simpler*: a package-private `var run = realRun` func value for the two places a test needs determinism; test boundedness against a **real** child that forks a grandchild holding stdout, and assert zero surviving descendants. ~40 LOC deleted, and the same test discharges OR-OPEN-3 on the first host run.
→ *Must not touch*: timeouts, group-kill, output caps, exactly-one-`Wait` — all strengthened, because the test now actually executes them.
→ *Ponytail rule*: "no interface with one implementation"; "lazy code without its check" (the check must exercise the real logic).

**6. Two read paths for the `os.Root` degradation (L15/F19).** "os.Root for /sys and /proc, degrade to plain bounded reads + lstat gating if OpenRoot fails."
→ *Accidental because*: written as a fallback *branch* it is a second reviewable code path for a scenario OR-OPEN-3 settles on the first run.
→ *Simpler*: one read function taking an optional `*os.Root` (nil means resolve the path directly). The fd gate (O_RDONLY|O_NONBLOCK|O_CLOEXEC, `Fstat(fd)`, `IsRegular`, `LimitReader(cap+1)`) is identical either way and is what actually closes TOCTOU (C-23); `os.Root` only adds escape refusal. ~40 LOC, one path, one test with root=nil.
→ *Must not touch*: the fd gate and the caps are unconditional in both modes; an `OpenRoot` failure is recorded as an observation, never silent.
→ *Ponytail rule*: ladder rung 6; "shortest working diff".

**7. Hand-written `evidence` objects.** SCORECARD steal #3 is filed as "0 LOC, discipline" — make it a type instead of a discipline.
→ *Simpler*: `evidence` is produced by exactly one function from `[]Observation`; no check ever constructs a map. ~150 LOC of per-check evidence assembly never written, and D2 ("not a restatement of the title") becomes structurally impossible to violate.
→ *Must not touch*: all nine Observation fields stay (see (d)).
→ *Ponytail rule*: "Deletion over addition"; rung 2 (reuse the one shape that already exists).

**8. Pre-emptive flag and log guard.** A1 specifies exactly `sensor scan --out findings.json`.
→ No `--timeout`, `--config`, `--category`, `--format`, `--verbose`; no logger, no levels. Budgets are `const`. Nobody will set them: the grader runs one command from a clean unpack (A2). stderr carries exactly one thing — the write-failure message before exit 1 (AM-8). **The evidence is the log.**
→ *Ponytail rule*: "no config for a value that never changes"; "no scaffolding for later".

**9. Roster size is the schedule risk, not the architecture.** 5 categories x 3-6 checks = up to 24; C9 says "a handful of checks done thoughtfully beats twenty done thinly".
→ Ship **3 per category (15 checks)**, deepest-evidence first, and add the 4th-6th only with time left. LD-1 (two custom categories) is binding and untouched; the per-category *count* is not. This buys the margin every option's estimate lacks and is the cheapest schedule insurance available.
→ *Ponytail rule*: ladder rung 1 applied to the work item, not the code.

**10. Estimates that hide complexity.** Opt 2's p50 (70-90 min) **equals the entire budget** (70-90 min) — the estimate is the deadline, before the schema-validation loop ATTACKS itself names as the usual doubler (conditional `required: reason`, the `check_id` pattern, `format: date-time` assertion) and before an upload path no fact verifies. ATTACKS also concedes gates "tend to grow one per check until it becomes a second registry" — an unbounded term inside a fixed estimate. Opt 4's cost is worse than its number: its characteristic bug is observable **only on the host**, spending the scarcest resource in the exercise.

## (c) Re-ranking by **essential** complexity only

Essential = ~15-24 honest checks, one machine block, bounded/isolated/read-only execution, a schema-valid document. Everything else is a bet on a future.

| Rank | Option | One line |
|---|---|---|
| **1** | **Option 1 + steal #1 ("Option 1.5")** | The checks, two primitives, one loop, and ~45 LOC that mechanise the one graded invariant — nothing exists that a finding does not need. |
| 2 | Option 2 | Pays ~250 LOC and two new failure modes for a reason vocabulary that a type plus one `classify()` delivers. |
| 3 | Option 4 | Best design on paper; ~400 LOC of key/store/coupling plumbing for three real sharings, and its failure mode debits host time. |
| 4 | Option 3 | Builds the rule engine PRIOR_ART §1 already rejected (F68); the interesting half of the roster escapes into `native` rows. Agreed fatal. |

**Build this: Option 1 + the ~30-LOC load-bearing downgrade + the ~15-LOC shared `classify()` + the 3-field `Env`.** About +55 LOC over the cheapest option, about −450 against Option 2 and −600 against Option 4, and it reaches a schema-valid host run soonest — the only unrecoverable deadline here (A3). Note that Option 2's own escape hatch is *"ship Option 1's roster first, add the gate layer second"*: I am recommending the lead make the fallback the plan and spend the recovered ~25 minutes on check depth (C9) and a second host round trip. If time remains after the first valid `findings.json`, steal the gate layer then — it is purely additive and nothing in 1.5 blocks it.

## (d) What I deliberately did **not** recommend cutting

- **Per-subprocess timeout, Setpgid + group-kill `Cancel`, `WaitDelay`, capped writers, exactly one `Wait` (F21-F23, L09-L12).** E2. Group-kill is the entire difference between "bounded" and "bounded unless the child forks".
- **The out-of-band goroutine deadline for BMC and device-adjacent reads (L40, F44).** Looks like a duplicate of the per-check ctx timeout; it is not — a blocking KCS read is uncancellable, `ctx` cannot interrupt it, and timer-plus-abandon is the only mechanism that exists. Cutting it would violate "nothing hangs forever on a device that does not answer".
- **Per-check `recover()` and the engine-synthesised `unknown`/BUDGET for un-run checks.** E3 plus D3. Isolation is not gold-plating at 15+ checks.
- **All nine `Observation` fields** (Source, Kind, ObsStatus, Value, Errno, ExitCode, Truncated, Bytes, Elapsed). Reads as gold-plating; each is load-bearing: Errno makes EACCES != absent, ExitCode makes EXECUTION_ERROR != false, Truncated+Bytes make "truncated implies never PASS" (L05) legible, Elapsed makes TIMEOUT != false auditable.
- **The closed reason vocabulary (L07/L35) and UNKNOWN-with-reason for every unanswerable check (D3).** The laziest possible output is to omit what you could not check; the brief calls that "a critical failure".
- **`sshd -G` primary + Include-aware walker fallback + CONTESTED (L18/LD-5).** A real, evidenced fallback rather than speculative generality — and the walker is also the only provenance source.
- **The ACL byte decoder (~50 LOC), the efivars 4-byte-prefix skip, the taint bit table, the mountinfo `" - "` split.** Fiddly, and they are the exercise's actual content, not accidental complexity.
- **Header-only secret classification, never a value and never a hash (L23).** A security measure — Ponytail's own "When NOT to be lazy" forbids touching it.
- **Test-time schema validation, the release gate, and "write the file anyway, exit 1" (LD-6/D-05).** Kept. One caution, not a cut: keep the runtime self-check at ~20 lines of invariants over the built document, and make invalid states unrepresentable (typed status/severity constants, an `Unknown(reason, obs...)` constructor). If it starts to resemble a schema interpreter, that is a second hand-written schema and CLAUDE.md forbids it.
- **`os.Root`.** Stdlib containment at zero dependency cost; hand-rolling it would be the opposite of lazy.

### Where Ponytail's ruleset would have cut something the invariants forbid
Applied naively, the ladder ("does this need to exist at all / can it be one line") argues for: (i) deleting the L40 goroutine deadline as a duplicate timeout — forbidden, F44 shows `ctx` cannot cancel a blocking read; (ii) deleting per-check `recover()` because a well-written check does not panic — forbidden by E3, and node_exporter's lack of it is cited as prior art *against* (F68); (iii) trimming Observation to `{source, value}` as gold-plated evidence — forbidden by D2/L05; (iv) the laziest output of all, omitting unanswerable checks instead of emitting `unknown` — forbidden by D3, and it is precisely what the brief grades (F1). One further Ponytail-suggested cut I decline on evidence rather than invariant grounds: deleting the second custom category (BOOT_CHAIN), since C3 requires only one — LD-1 is binding and Setup Mode (F49) is the most severe fact on this host, so dropping it would under-report.
