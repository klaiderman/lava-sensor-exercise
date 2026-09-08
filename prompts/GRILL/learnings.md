# Gauss Convergence Learnings — GRILL

## Session 1 — post-refine baseline (prompt.v2.md)
`convergence.py` reached DEPLOY at iteration 1 (9.5/10, sigma 0.605) with zero auto-fixes applied. The manual refine pass (splitting 5 over-40-word sentences, adding a fallback-trigger phrase, adding "think thoroughly") had already closed every gap the auto-fixer targets.

## Session 2 — post-harden regression, and a failed hypothesis
After applying 4 hardening patches (see `audit.json`) directly to `prompt.md`, `convergence.py` regressed to sigma 0.81 (FAIL, floor 0.75) because the hand-authored patch text introduced 2 new sentences over 40 words. Ran `convergence.py --verbose` with its own `fix_clarity` auto-fixer active (3 iterations, hypothesis "fix Clarity" each time) — it could not resolve the regression and plateaued at 9.3/10 with sigma still 0.81.

**Failed hypothesis, logged per the no-regression contract:** "the auto-fixer's `fix_clarity` heuristic is sufficient to repair a Clarity regression caused by newly hand-added long sentences." Outcome: FALSE. The auto-fixer applied changes on iterations 1-2 but each was reverted (no improvement over baseline), then plateaued on iteration 3. Confirmed via diff that `prompt.md` was unchanged after the run (the auto-revert-on-regression logic worked correctly — no corruption, just no fix).

**Resolution:** manually re-identified the 2 new long sentences (via the same clarity-diagnostic script used in Session 1) and split each into two shorter imperative-friendly sentences by hand. Re-ran `convergence.py`: DEPLOY restored at iteration 1, 9.5/10, sigma 0.605.

**Recommendation for future tracks:** when hardening patches are applied by hand after a prompt has already converged, immediately re-run the same long-sentence diagnostic used during refine — don't assume the auto-fixer will absorb hand-authored prose the way it absorbs its own generated text. This is the GRILL-specific analogue of R4's harden-stage lesson (auto-fixer behavior after manual edits needs a manual verification pass, not blind trust).

## Session 3 — contract-check gap closure
Adding the final-message instruction to `<output_format>` (to close the one CONTRACT_CHECK.md mapping gap) cost 0.10 overall (9.54 -> 9.44) and moved sigma from 0.605 to 0.689 — both still comfortably inside the DEPLOY bar (floor 0.75). No auto-fix needed; this was accepted as the honest cost of contract completeness over a marginal heuristic-score gain.

## Prompt profile (from `convergence.py`'s own fingerprint)
Words: ~2783 | Sections: 25+ | XML: yes | Markdown: yes | Examples: yes | Domain: architecture-challenge / reasoning-over-KB.
