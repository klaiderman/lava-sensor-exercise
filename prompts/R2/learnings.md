# Learnings — R2 (r2-lava-context)

## Iteration 1 (manual): baseline v1 -> v2
- Hypothesis: failure_resilience (5.0/10) was low because only 2/4 of `self-eval.py`'s pattern buckets matched (`edge case|...|otherwise`, `validate|...|confirm`); missing `if...(error|fail|cannot|unable|unclear|missing|invalid|empty)` and `fallback|default to|if unsure|if you cannot|if not provided|when in doubt`.
- Fix: added an explicit "Fallback rules" block to `<edge_cases>` using exactly that phrasing ("default to", "if you cannot", "if unsure"), and shortened several long sentences elsewhere for clarity.
- Outcome: failure_resilience 5.0 -> 10.0 (4/4 patterns). clarity 6.76 -> 6.81 (marginal). **Kept.**

## Iteration 2 (manual): constraint-bullet imperative rewrite
- Hypothesis: clarity's imperative-sentence-density bonus was low because several `<constraints>` bullets opened with nouns/negations ("Same-domain crawl only...", "No login-walled scraping.") instead of the verb list `self-eval.py` scans for.
- Fix: reworded 8 constraint bullets to open with an imperative verb from the scanned list (Limit, Avoid, Never, Treat, Use, Verify, Classify) without changing their meaning.
- Outcome: clarity 6.81 -> 6.91. Cosmetic improvement to real prompt quality too (more scannable). **Kept.**

## Iteration 3 (automated, REJECTED): convergence.py `--max 30` on a throwaway copy
- Hypothesis: let the Convergence Engine's automated "fix Clarity" hypothesis run to close the gap mechanically.
- Result: reached clarity 8/10, overall 9.2/10, 8/8 SAT, but did so by inserting `. ` sentence breaks at fixed word-count intervals **inside the verbatim `<host_context>` block**, e.g. splitting `` `systemd-detect-virt` = none (real hardware; DMI, BMC, TPM present) `` into two "sentences" mid-parenthetical (`...real hardware.` / `DMI, BMC, TPM present).`), and elsewhere starting new "sentences" with a lowercase word (`you never create, edit...`) because the splitter doesn't recapitalize.
- **Why rejected:** the intent file requires the host context be embedded verbatim; this is a hard constraint, not a style choice. A heuristic score gain that corrupts required-verbatim evidence and produces ungrammatical fragments is a regression on real quality even though the linter score went up. Per CLAUDE.md capability-fidelity module ("never silently substitute") and rule 4 ("never inflate"), the auto-converged file was discarded; the manual v2 (iterations 1-2 above) was kept as the working baseline instead.
- Logged per the no-regression contract: this hypothesis (mechanical sentence-splitting as a clarity fix) is unsafe on any prompt with an embedded verbatim/quoted block and should not be re-tried on this prompt family without first excluding such blocks from the splitter's scan range.

## Final state
- Heuristic scores (prompt.md): Clarity 7.0, Completeness 10.0, Efficiency 8.0, Model Fit 10.0, Failure Resilience 10.0. Overall 9.0/10. Sigma 1.18 (dynamic floor 0.75, CLAUDE.md's stated fixed floor 0.45). 8/8 SAT assertions pass.
- **Verdict: HOLD**, on sigma alone. The dispersion is structural for this prompt class: two hard, non-negotiable requirements (verbatim host context; full 14-item execution contract) put a ceiling on how "clean" Clarity can score under a regex/imperative-density heuristic, while Completeness/Model-Fit/Resilience saturate near 10 because the contract and registry rules are fully satisfied. Chasing sigma further would require either shrinking mandatory verbatim/contract content (not permitted) or deliberately degrading a high-scoring axis to reduce spread (reward-hacking the linter, explicitly against the honest-numbers contract). Neither was done. A 4th manual iteration was judged not to have a legitimate, non-cosmetic lever left within the 4-iteration budget and was not attempted.
