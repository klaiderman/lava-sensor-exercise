# Gauss Convergence Learnings — R4

Sessions: 1 (manual-refine-dominant) | Last updated: 2026-09-09

## Session Trajectory

- prompt.v1.md (craft): Clarity 7.0, Completeness 7.0, Efficiency 8.0, Model Fit 9.0, Failure Resilience 10.0 → overall 8.3, sigma 1.21 (floor 0.75) FAIL.
- prompt.v2.md (manual refine — added `<examples>`, `<task_roadmap>`, `<success_criteria>`, split 11 of 12 long authored sentences, added a markdown subheading): overall 9.4, sigma 0.71 PASS. `convergence.py` confirmed DEPLOY at iteration 1 with **zero** auto-fixes needed (8/8 assertions on first check) — the manual refine pass had already closed the gap the auto-fixer exists to close.
- Harden pass (12-attack red-team, `audit.json`): 3 patches applied (system-prompt non-disclosure, encoded/obfuscated/hypothetical-framing closure, read-only-probe constraint). Clarity dipped to 8.1 (one new patch sentence exceeded 40 words), sigma rose to 0.84 FAIL.
- Re-score attempt via `convergence.py --verbose`: reached DEPLOY (9.4/0.71) in 3 iterations, but its `fix_clarity` function rewrote semicolon-joined long sentences by inserting periods — and it does not distinguish "prose I may edit" from a block the task explicitly requires to be embedded **verbatim** (`<host_summary>`). It silently altered the verbatim host-context block. Caught by a post-hoc diff against `prompt.v1.md`'s `<host_summary>` block, not by the tool itself.
- **Failed hypothesis, logged per the no-regression contract:** "let `convergence.py`'s automated Clarity fixer run on a prompt containing a mandated-verbatim block" — REJECTED. `convergence.py` has no concept of a protected span; it will rewrite anything matching its long-sentence heuristic, including quoted/verbatim source material. Do not run the automated fixer (only `self-eval.py` for read-only scoring) on any prompt with an embedded verbatim requirement. Reverted to `prompt.v2.md`'s `<host_summary>` and reapplied the 3 harden patches by hand.
- Manual fix: split the one new >40-word patch sentence into two. Re-scored via `self-eval.py` only (not `convergence.py`): overall 9.4, sigma 0.71 PASS, 8/8 SAT assertions confirmed by direct regex replay, `<host_summary>` byte-identical to `prompt.v1.md`. Added a third `<example>` (OBSERVATION_REQUEST + single-probe contradiction-hunting) to reach the registry's 3-5 few-shot recommendation for Claude 5.x — no regression (still 9.4/0.71).

## Recommendation for future R-track prompts with a verbatim evidence block

Do not run `convergence.py` (the auto-fixer) directly on the final artifact once a verbatim block is embedded. Use `self-eval.py` (read-only) for scoring, and apply any clarity/efficiency fixes by hand, restricting edits to spans outside the verbatim tag. If `convergence.py` must run (e.g., on `prompt.v1.md`), diff the verbatim block afterward before trusting the output.
