# SCORECARD — ranked comparison (recommendation, not a decision)

The lead decides (LD-9 is the open slot this feeds). Scores are relative to each other, not absolute.
Legend: **++** strong · **+** adequate · **~** mixed · **−** weak · **−−** disqualifying-ish.

## Matrix

| Attack category | 1. Flat registry | 2. Capability-gated | 3. Data-driven table | 4. Collector/evaluator |
|---|---|---|---|---|
| Task fit (contract F1, D3) | + | ++ | ~ | ++ |
| Correctness (L07/L34/L39 upheld how?) | ~ (convention) | + (gate central, rest convention) | − (derivations don't fit) | ++ (engine-checked) |
| Evidence quality (D2) | ~ | + | ++ (generated) | ++ (declared + assembled) |
| Safety (E1/E2/E6) | + | + | ++ (one I/O site) | ++ (I/O confined to phase 1) |
| Host fit (Lava host) | ++ | + (gates near-inert here) | ~ (half the roster is native rows) | + (speculative collection) |
| Generic-machine behaviour | − | ++ | + | ++ |
| Portability (L37) | + | ++ | + | + |
| Complexity / YAGNI | ++ | + | −− | ~ |
| Time to build | ++ | + | −− | ~ |
| Build-vs-buy (PRIOR_ART) | ++ | ++ | − (builds the rejected rule engine, F68) | ++ |
| Failure modes | ~ | ~ (gate = single point of failure) | − (table drift is a bug in finding's clothing) | ~ (key drift, store memory) |
| Testability (L34/L36) | ~ | ++ (one table test for D3) | + | ++ (recorded store replays without host) |
| **`fatal` attacks** | 0 | 0 | 3 (correctness, complexity, time) | 0 |
| **`serious` attacks** | 5 | 6 | 6 | 4 |
| **Time to first schema-valid real-host run (est.)** | ~55-70 min | ~70-90 min | ~120-160 min (**over the ~90 min bar**) | ~85-110 min (**on/over the bar**) |
| **Severity rule (LD-2) centrally enforceable?** | yes | yes | yes | yes, with an ordering caveat (recompute severity after a dependency downgrade) |

All time figures are estimates. They assume the verified cross-compile path (`GOOS=linux GOARCH=amd64 CGO_ENABLED=0`, F73) and an upload path that has not been exercised in this session; the schema-validation loop (conditional `required: reason` when `status` is `fail|unknown`, `check_id` pattern `^[A-Z][A-Z0-9_]*$`, `format: date-time` needing format assertion — R5-OR1) is the most common reason a first estimate doubles.

## Ranked recommendation

**#1 — Option 2, Fixed Registry with a capability-gated tree.** Ranked #1 by this analysis because it moves two of the three `unknown` classes from author convention into the engine (which is the graded content, contract F1) at ~150-250 LOC over the cheapest option, keeps the frozen Fixed-Registry default intact, and fits in the time box with some margin. It is also the only option that degrades gracefully under time pressure: ship Option 1's roster first, add the gate layer second, and the intermediate state is a working sensor.

**#2 — Option 4, collector/evaluator split.** Ranked #2 because it is the technically strongest design — engine-verified `pass|fail` dependencies, an always-complete document under a budget cut, first-class CONTESTED evidence for LD-5, and a recorded-store test harness that outlives host access — but it front-loads plumbing at the exact moment the schedule is tightest, and its payoff (one observation feeding many checks) is modest at the contract's recommended check depth (C9).

**#3 — Option 1, flat registry.** Ranked #3 because it is the fastest and the YAGNI-cleanest, but it upholds L07/L34/L39 by convention only, and `research/CONTRADICTIONS.md`'s cross-cutting observation records five shipped tools (ghw, osquery ×2, ipmitool, Wazuh — F63, F65, F46) failing exactly that way with exactly that structure. It stays a serious contender precisely because two cheap steals close most of the gap (see below).

**#4 — Option 3, data-driven check table.** Ranked #4 and, on this analysis, not viable: three `fatal` attacks. The checks that carry the exercise's engineering content are derivations, not predicates (`sshd -G` vs walker with CONTESTED, ACL byte decode, taint attribution, redundancy derivation), so they escape into native rows; `research/PRIOR_ART.md` §1 already carries a standing REJECT of a declarative rule engine at this check count (F68); and it is the only option that cannot reach a real-host run inside the time box.

## Cheap steals the lead should consider regardless of which option wins

1. **From Option 4 into Options 1/2 (~30 LOC):** mark each `Observation` load-bearing, and have the engine downgrade any returned `pass|fail` whose load-bearing observations are not `ObsStatus == OK`. This mechanises L34/L39 without a store or a two-phase split, and is the single highest-value line-per-line change available.
2. **From Option 4 into Option 2 (~20 LOC):** let `Store.Get`-style multiplicity exist for the one place LD-5 requires it (`sshd -G` vs the Include walker) rather than inventing a general store.
3. **From Option 3 into all (~0 LOC, discipline):** the evidence object shape is generated from the observation, never hand-written per check (D2).
4. **From Option 2 into Option 1 (~150 LOC):** the gate layer itself — which is what promotes Option 1 to Option 2. Gates must be established by an actual read attempt, never by mode bits (`kernel.apparmor_profiles`: 0444 yet EACCES, F94/C-08, L42).

## The single fact that would flip the ranking

**LD-8 — that one agent (`claude-opus-5`) writes the whole sensor in one pass.** The #1/#3 ranking rests on "convention holds because a single author holds all of L07/L34/L39 in one context", and the #1/#2 ranking rests on "the mechanised invariant is not worth its plumbing for one author". If check authorship is split across parallel agents, or the roster grows past ~20 checks, that premise fails — F63/F65 document five shipped tools that failed exactly this way — and **Option 4 moves to #1, with Option 2 second and Option 1 last.**
