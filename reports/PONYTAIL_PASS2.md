# PONYTAIL_PASS2 — implementation review (ponytail-reviewer, level: full)

Ruleset: $HOME/.lava-workbench/ponytail/skills/ponytail/SKILL.md @ 356918e.
Read-only pass. No file under `sensor/` was modified.

Gate: from `sensor/`, `GOOS=linux go vet ./...` clean; `GOOS=linux go build ./...` clean
(Go 1.26.2). 13,357 LOC of Go across 40 files, 5,290 of them tests.

## (a) Ponytail rules applied, and what each contributed

| Rule (by its heading/name) | What it did here |
|---|---|
| **Rules — "no interface with one implementation"** | Found `probe.Files`: 11 methods, 1 impl, 0 fakes (F1). Spared `probe.Runner`, which has 2 real fakes. |
| **The ladder #2 — "Already in this codebase?" / "re-implementing what is a few files over is the most common slop"** | Found `internal/lab/support_test.go` is a copy of `internal/checks/fixture_test.go` (F2), and 3 copies of one regexp (F5). |
| **Rules — "no config for a value that never changes"** | Found `--timeout`, which LD-9 and PONYTAIL_PASS1 both excluded (F3). |
| **Rules — "no boilerplate, no scaffolding for later"** | Found `sysdep_other.go`: unreachable on the target, and it silently zeroes O_NOFOLLOW (F4). |
| **Rules — "Deletion over addition"** | Found `probe.Which`, `Observation.Failed`, `KindConfigRes`, `KindDeviceProbe`, `ReasonENODEV` (F5). |
| **When NOT to be lazy — "never simplify away input validation at trust boundaries, error handling, security measures"** | Blocked the cuts listed in (d): SelfCheck, ReadOOB, limitWriter, the status+errno split, the finalize downgrade. |
| **"Lazy code without its check is unfinished"** | Every cut below names the test that must still pass; none removes a check. |
| **"Never lazy about understanding the problem. Read fully, then be lazy."** | Traced `Reader.open` -> `Classify` -> `finalize.firstUnclean` -> `renderObservation` end to end first; that is why F1 is a signature change and not a behaviour change. |

Ponytail's contribution vs generic review: F1/F3/F4 are Ponytail-specific (a generic review
reads them as clean layering, operator flexibility, portability). F2 and F5 a generic review
would also find. Ponytail's restraint clauses did the most work — see (d).

## (b) Findings, ranked by complexity saved vs risk

**F1 — `probe.Files`: an 11-method interface with exactly one implementation that no test uses.**
- what: `internal/probe/read.go:61`, plus 13 `f probe.Files` parameters in `internal/checks/`.
- why accidental: `*probe.Reader` is the only implementer in the module. The doc comment
  promises "tests may substitute a fake" and no such fake exists — tests use the real Reader
  over a fixture tree via `NewRootedReader`. The interface is actively in the way: it omits
  `ModTime`, so `internal/checks/remote_access.go:311` casts back out of it
  (`if r, ok := f.(*probe.Reader)`) and carries an unreachable `return time.Time{}, false`.
  An interface you must cast out of is not an abstraction, it is a detour.
- simpler: `Env.Files *probe.Reader`; delete the interface; the 13 parameters become
  `*probe.Reader`; `statModTime` collapses to `env.Files.ModTime(p)`. ~20 LOC and one
  indirection gone. Mechanical, zero behaviour change.
- invariant it must not touch: none. All reads still go through the one bounded primitive —
  more strictly, since no other type can ever be substituted for it.
- Ponytail rule: **Rules — no interface with one implementation**.

**F2 — `internal/lab/support_test.go` is a near-verbatim copy of `internal/checks/fixture_test.go`.**
- what: ~130 duplicated LOC (fixture materialiser, restorePermissions, lines/fixtureLines,
  decodePath, skipIfRoot, requireLinux, fakeRunner, fixedClock, newTestEnv/newLabEnv),
  identical down to the t.Logf strings.
- why accidental: the header calls it a "deliberate, independent reimplementation ... so that a
  bug in the author's materialiser cannot mask a bug here". A byte-similar copy buys no
  independence — the same bug is in both copies. It is duplication wearing independence as a
  costume.
- simpler: one `internal/fixture` package (non-test, under internal/, so it never ships in the
  binary) exporting `Build(t, srcRoot, name) string` and `NewFakeRunner()`; both suites import
  it. The lab-only helpers (execError, timeout, sshdGOutput, chmodPath, runFullScan) stay in
  lab. ~130 LOC deleted; 31 lab tests and 60 checks tests unchanged.
- invariant it must not touch: the author-not-reviewer gate. Preserved — that gate is about who
  writes the assertions, and all of lab's assertions stay in lab. A shared file-copier cannot
  hide a verdict bug: if it mis-builds a tree, both suites fail loudly because fixtures do not
  build.
- Ponytail rule: **The ladder #2 — Already in this codebase?**

**F3 — the `--timeout` flag (`cmd/sensor/main.go:49,84`).**
- why accidental: LD-9 freezes the flag set at "--out (required) and --version only", and
  PONYTAIL_PASS1 named --timeout explicitly as the thing not to add. It shipped anyway and is
  NOT among the 13 documented deviations, so it is an undocumented 14th. Nothing sets it: no
  script, no Docker profile, no run command; its only callers are the two tests that exist to
  test it. It also widens a safety bound on request — `--timeout 24h` is accepted.
- simpler: delete the flag, its validation, its two usage strings and its two test cases; keep
  `scan.DefaultScanDeadline` as the constant the deadline already comes from. ~12 LOC.
- invariant it must not touch: the whole-scan deadline. Untouched and strictly stronger — the
  bound becomes non-widenable. `DefaultScanDeadline = 60s` still flows to
  `context.WithDeadline`, and `scan.deadline_ms` still appears in the artifact.
- Ponytail rule: **Rules — no config for a value that never changes**.

**F4 — `sysdep_other.go` plus `fifo_other_test.go`: 58 LOC of !unix scaffolding.**
- why accidental: its own comment says "nothing here is reachable on the target". It exists so
  `go vet` runs on a Windows workstation, but `GOOS=linux go vet ./...` does that and is what
  the release path uses (verified clean above). Worse than dead: every function in it returns a
  falsehood — `openNoFollow = 0` silently deletes the O_NOFOLLOW / TOCTOU guard from
  `Reader.open`, `ownerOf` returns ok=false, `getxattr` returns ENOTSUP. A build that compiles
  into a weaker sensor is a trap, not portability.
- simpler: delete both files; `sysdep_unix.go` already carries `//go:build unix`. Document
  `GOOS=linux go vet ./... && GOOS=linux go build ./...` as the workstation command. 58 LOC and
  one silently-weakened build configuration gone.
- invariant it must not touch: the read-only and bounded guarantees. Strengthened — after the
  cut there is no build of the sensor in which O_NOFOLLOW is absent.
- Ponytail rule: **Rules — no boilerplate, no scaffolding "for later"**.

**F5 — dead declarations and one triplicated regexp.**
- what: `probe.Which` (0 call sites), `Observation.Failed()` (0), `KindConfigRes` and
  `KindDeviceProbe` (declared, never assigned to any Observation.Kind), `scan.ReasonENODEV`
  (declared, never used — `Observation.Reason()` already emits ENODEV from Errno, so the
  constant carries nothing). Separately `^[A-Z][A-Z0-9_]*$` is compiled three times in package
  scan: checkIDPattern and categoryPattern (engine.go:20-21) and upperSnake (output.go:35).
- simpler: delete the five declarations; keep one upperSnake and use it in all three places.
  ~14 LOC and 2 compiled regexps.
- invariant it must not touch: the closed reason vocabulary. EACCES/EPERM/ENOENT/EINVAL/
  TIMEOUT/UTILITY_MISSING/BUDGET_EXHAUSTED/PARSE_ERROR/EXECUTION_ERROR/CONTESTED/POLICY/
  INTERNAL_ERROR all stay; only the one unused alias goes and no output string changes.
- Ponytail rule: **Rules — Deletion over addition**.

**F6 (cosmetic) — the subcommand pre-scan loop, `cmd/sensor/main.go:56-65`.**
- 10 lines so flags may precede `scan`, for a binary documented to be invoked exactly one way.
  Simpler: `if len(args) > 0 && args[0] == "scan" { args = args[1:] }` plus the existing check.
  ~7 LOC. Touches nothing. Ponytail rule: **The ladder #6 — Can it be one line?**

Total: ~240 LOC (~1.8% of the module), no invariant weakened, two strengthened (F3, F4).
The roster is not where the fat is: 26 checks of real host-observation logic is essential
complexity. I found NO plugin registry, no capability pre-phase, no config system, no evidence
store, no wrapper-around-wrapper and no layer that exists to be a layer. LD-9's flat shape held.

## (c) N/A for pass 2 (option ranking was pass 1). Removal order: F5 -> F4 -> F3 -> F6 -> F2 -> F1.

## (d) What I deliberately did NOT recommend cutting

- **`scan.SelfCheck` (~145 LOC hand-rolling what finding.schema.json already says).** The single
  biggest thing Ponytail's ladder points at — rung 5, "already-installed dependency solves it":
  santhosh-tekuri/jsonschema/v6 is already in the module and does this in one call. **The
  project's invariants forbid the cut.** LD-6/D-05 requires zero third-party RUNTIME deps AND
  schema validation of the output; both can only hold via a stdlib mirror. This is the one place
  Ponytail's ruleset would have cut something the invariants forbid, and the invariant is right:
  a customer-facing binary carrying schema machinery is the worse trade. I did verify the mirror
  is honest: it enforces the status/severity enums, the reason-required rule, RFC3339, check_id
  uniqueness and the AM-5 zero-integer rule; the v6 validator covers the rest at the gate.
- **`probe.ReadOOB` and its abandoned goroutine (45 LOC).** Looks like exactly the concurrency
  Ponytail deletes. It is the only thing between a KCS retry storm and a hung scan; a context
  cannot cancel an issued sysfs bus read. Per-read timeouts are a hard limit. Keep.
- **`probe.Runner` interface.** One production impl, but two genuine fakes drive the `sshd -G`
  oracle and the timeout / exec-error classes. The rule is "one implementation", not "one
  production implementation". Keep.
- **`limitWriter` + Setpgid + group kill + WaitDelay + the outTrunc kill (~90 LOC).** Output caps
  and process-group teardown are hard limits. Keep.
- **The 8-value ObsStatus plus the separate symbolic Errno.** Reads like two ways to say one
  thing; it is how EPERM stays distinct from EACCES (L03) and how "EACCES is not absent"
  survives into the finding. Keep.
- **`finalize.firstUnclean` and the downgrade (~30 LOC).** 30 lines carrying "TIMEOUT is not
  false", "a truncated value never supports a pass" and the LD-2 severity rule for all 26
  checks. The highest invariant-per-line in the module. Keep, and do not inline it into checks.
- **`Meta.DirsPruned` / `UnreadableDirs` / `CrossedMounts` / `BudgetExhausted`.** One walk caller
  and they look like gold-plated evidence. They are the proof a listing COMPLETED, which is the
  only thing that makes a proven absence provable (L25). Keep.
- **The 26 per-check budget values in the roster.** Config, but config somebody did set, and it
  is the per-check timeout invariant. Keep. Cosmetic only: 6 distinct values express 3 design
  tiers; naming them budgetCheap/Medium/Expensive is a wash on LOC.
- **`internal/lab` as a package.** Only its duplicated support file is a finding; the 31
  independent-lab tests are the author-not-reviewer gate. Keep the package.
- **One weak spot flagged rather than cut:** fakeRunner's unstubbed default is UTILITY_MISSING,
  so a few "missing utility is not missing capability" tests partly assert the fake's default.
  Docker profile C (PATH=/nonexistent, real binary, 26 checks, exit 0) is the independent
  confirmation, so the coverage is real. Do not delete either; do not let the fake become the
  only witness.
