# LIFECYCLE_LOG.md — GRILL (`architecture-challenger`, target `claude-opus-5`)

## Stage 1 — Read the briefing (procedure step 1)

Read, in order: `wixie/CLAUDE.md` (Lifecycle table, DEPLOY bar, behavioral contracts, scoring-provenance caveat), `wixie/shared/models-registry.json`'s `claude-opus-5` entry (family Claude 5.x, format xml, reasoning adaptive-thinking, few_shot 3-5 `<example>` tags, key_constraint on the drop-in-Opus-4.8-pricing/longer-output/self-verification tendency and the separate rate-limit bucket), `wixie/shared/references/model-profiles.md` §1 "Claude 4.x" (closest profile — **Claude 5.x has a registry entry but no dedicated profile section in this file; gap noted per instruction, same gap R1-R5 already logged**), then all six plugin SKILL.md files (prompt-crafter, prompt-refiner, convergence-engine, prompt-tester, prompt-harden, prompt-translate) plus their reviewer/optimizer/executor/red-team/adapter agent files. Confirmed real CLI invocation via `--help`/header/no-arg reads on `convergence.py`, `output-eval.py`, `output-test.py`, `self-eval.py`, `token-count.py`.

Also read `prompts/raw/EXECUTION_CONTRACT.md` to confirm what it contains, per the task's instruction that GRILL is a reasoning-over-KB prompt and must NOT embed it — confirmed the 14 items are research-methodology-specific (deep-research phases, Trafilatura/Crawl4AI/Crawlee, PROVENANCE.md, OBSERVATION_REQUEST) and genuinely do not apply to a worker that only reads existing KB files and reasons over them.

Read prior R1/R2/R4 folders in `prompts/` as structural precedent (metadata.json shape, CONTRACT_CHECK.md shape, LIFECYCLE_LOG.md shape) — confirmed still current via direct file read (precedent-freshness discipline), not assumed from memory.

**E0 deep-research note (per task instruction):** not run for this prompt-engineering pass — the task explicitly said it isn't needed; GRILL's subject matter (this project's own architecture options) is exactly what the worker reasons over from the KB, not something the prompt-engineer needs to pre-research.

## Stage 2 — Direction Lock (procedure step 2)

Taken from `prompts/raw/GRILL.intent.md`'s "Direction Lock" section verbatim (intent, target model, audience, output format, constraints, the four option families, attack requirements, deliverables) — not re-asked. Host context handled per the lead's explicit instruction: a short pointer to `state/HOST_SNAPSHOT.json` and its `evidence`-array citation format, not the verbatim host summary (avoiding the σ-dispersion problem the lead flagged from R2/R3).

## Stage 3 — Craft (procedure step 3)

Wrote `prompt.v1.md`: Claude 5.x XML sections (`<role>`, `<context>`, `<mandatory_files>`, `<task>` with the 4 option families, `<task_roadmap>`, `<attack_requirements>` with the 12 host situations, `<method>`, `<constraints>`, `<output_format>`, `<success_criteria>`, `<edge_cases>`, `<examples>`). Peeked at `state/HOST_SNAPSHOT.json`'s real structure (not its content, just its shape) to confirm the `evidence` array's `category.probe_name` citation format before writing the citation instruction.

`self-eval.py` baseline: Clarity 7.6, Completeness 10.0, Efficiency 8.5, Model Fit 9.5, Failure Resilience 7.5 -> overall 8.62, sigma 1.00 (floor 0.75) FAIL.

## Stage 4 — Refine (procedure step 4)

Diagnosed via direct script-internals recomputation (not guessing): 5 sentences over 40 words (capping the Clarity long-sentence penalty at its -1.5 max), one missing Failure-Resilience trigger pattern (`fallback`/`default to`/`if unsure`/`when in doubt` — 3 of 4 patterns matched, this one didn't), and Model Fit missing the "think thoroughly" bonus (registry-mandated phrasing was absent from v1).

Applied to `prompt.v2.md`: split all 5 long sentences into shorter ones without changing their instructions; added "when in doubt, default to..." and "...or you are unsure whether..." language in the uncited-claim edge case (closing the Failure-Resilience gap); added "Think thoroughly about whether a citation actually supports the claim" to `<method>` (closing the Model Fit gap).

Result: Clarity 7.6->9.2, Completeness 10.0 (unchanged), Efficiency 8.5 (unchanged), Model Fit 9.5->10.0, Failure Resilience 7.5->10.0 -> overall 9.54, sigma 0.605 (floor 0.75) **PASS**.

## Stage 5 — Converge (procedure step 5)

```
python convergence.py prompt.v2.md --verbose
```
`Iteration 1: 9.5/10 -> DEPLOY (8/8 assertions, sigma 0.61 <= 0.75)`. Zero auto-fixes applied — Stage 4's manual refine had already closed every gap the auto-fixer targets. No failed hypotheses to log from this run (see `learnings.md` Session 1).

**Scoring provenance note:** `self-eval.py`'s `dynamic_sigma_floor()` applies 0.75 (not the flat 0.45 in `wixie/CLAUDE.md`'s table) for prompts over 2000 words. Per `CLAUDE.md`'s own override rule, this is applied and disclosed in `metadata.json.scores.sigma_floor_note` — same disclosed override already used for R1-R5. Under the strict flat-0.45 reading this prompt is HOLD on sigma alone; not hidden.

## Stage 6 — Structural test (procedure step 6)

Copied `prompt.v2.md` to `prompt.md` (canonical name for the remaining stages and for `output-test.py`, which expects `prompt.*` in the folder). Wrote `tests.json` (5 cases: 2 typical, 3 edge-case covering missing-KB-file, instruction-injection-in-a-KB-file, and uncited-claim-handling — the task's own named priorities). Ran the test-runner's Layer-1 role-play protocol by hand (Pass 1 parse -> Pass 2 generate without peeking at assertions -> Pass 3 check): 5/5 pass, saved to `test-results.json`. `tier_risk: true` flagged honestly (target is Opus-class `claude-opus-5`, simulation ran at this agent's Sonnet tier). Layer-2 measured corpus explicitly not run (no GRILL-specific domain corpus exists; same honest gap as R1-R5).

## Stage 7 — Output test (procedure step 7)

```
python output-test.py prompts/GRILL --dry-run
```
Phase 1 preflight only: prompt quality 9.5/10 DEPLOY, token budget OK.

Wrote a stub `metadata.json` (`target_model: claude-opus-5`, `config.max_tokens: 4000`) so `output-test.py`'s real-call phase would target the correct model and the task-mandated 4000-token cap (the lead's instruction: previous 1500-token calls on R1-R5 returned 0 visible words because adaptive thinking consumed the budget). `ANTHROPIC_API_KEY` was present in the environment (value never printed). Ran the bounded real call:
```
python output-test.py prompts/GRILL --max 1 --no-fix
```
Result: `Posted to claude-opus-5... 73 words (235 tokens, $0.075)`. Unlike R1-R5's 0-word result at 1500 tokens, 4000 tokens was enough for a visible, partial completion (`output-reference.md`): the model announced it would `ls`/read `CLAUDE.md` and inventory the KB files — exactly `<task_roadmap>` step 1. This is a genuine structural-compliance signal, if necessarily partial (a raw single-turn `messages.create()` call has no real tool loop, so it cannot actually execute the Bash commands it proposed or produce the four `research/GRILL/` files).

`output-test.py`'s own Phase 3 scorer returned FAIL/2.0 (structural 1/10, prior_art 1/10, assertions 0/5, schema 0/1). Diagnosed this as a category mismatch, not a prompt defect: that scorer's heuristics expect a direct single-turn completion to already contain deliverable content, which is structurally impossible for an agentic file-writing prompt without real tool execution. Recorded honestly in `metadata.json.output_test` rather than either hidden or misreported as a prompt failure.

## Stage 8 — Harden (procedure step 8)

Ran the full 12-attack red-team by hand against `prompt.md`, risk level HIGH (autonomous Read/Write/Edit/Glob/Grep/Bash worker ingesting untrusted KB files, feeding a lead decision). Cross-referenced against both the generic attack taxonomy and the task's 6 named hardening priorities. 8/12 generic attacks already RESISTANT; of the 6 named priorities, 4 were already resistant and 2 (cosmetic-variant options, time-estimate optimism) plus 1 generic attack (context manipulation via a KB file claiming pre-approved scope exceptions) were found genuinely vulnerable. Full detail in `audit.json`.

Applied 4 patches to `prompt.md`: (1) KB false-authority/pre-approval claims explicitly rejected, (2) a draft `research/DECISIONS.md` cannot soften the required full attack pass, (3) a cross-option cosmetic-collapse self-check, (4) a time-estimate anti-optimism "name what could double it" rule.

**Regression caught and fixed (not silently absorbed):** re-ran `convergence.py --verbose` to re-score post-patch. The hand-authored patch text introduced 2 new sentences over 40 words, dropping Clarity and pushing sigma to 0.81 (> 0.75 floor) — HOLD. The auto-fixer's own `fix_clarity` hypothesis ran 3 iterations and plateaued without resolving it (see `learnings.md` Session 2 for the logged failed hypothesis). Manually re-ran the same long-sentence diagnostic used in Stage 4, found the 2 new offending sentences, and split each by hand. Re-scored: DEPLOY restored, 9.5/10, sigma 0.605.

## Stage 9 — Target-model adaptation (procedure step 9)

Source and target are both `claude-opus-5` (crafted directly for the target from Stage 3 onward, per the task's explicit model instruction) — no cross-family XML->Markdown/minimal conversion needed. Adaptation confirmed `claude-opus-5`-specific nuances already present: "think thoroughly" phrasing (never "step by step") verified via case-insensitive search; 3 worked `<example>`-equivalent illustrations present (the intent's own attack/scorecard format examples, meeting the registry's 3-5 few-shot guidance); the `<constraints>` conciseness/scope-discipline sentence explicitly counters the registry's noted "longer output + self-verification" tendency; no forced tool-use assumptions. `score-delta.json` written per the adapter's honest-numbers contract.

## Stage 10 — Contract check (procedure step 10)

Wrote `CONTRACT_CHECK.md` mapping every `GRILL.intent.md` Direction Lock item, all 4 option families, every attack-requirement bullet (the 12 host situations, the severity-vs-status rule, the ~90-minute time estimate, the single reversing fact), and all 4 file deliverables to exact `prompt.md` line ranges — instead of the 14-item `EXECUTION_CONTRACT.md`, per the task's explicit instruction that GRILL does not use that contract.

One item was initially not mapped to a line range: the intent's exact final chat-turn message shape (ranked options, top fatal attack per option, the reversing fact) is a session-end behavior, not a `research/GRILL/` file. Rather than disclose-and-leave-open, closed the gap: added an explicit instruction to `<output_format>` telling the worker what to say in its final turn. Re-scored (`convergence.py`): still DEPLOY, 9.4/10, sigma 0.69 (floor 0.75). Re-checked: **100% mapped, 0 open gaps.**

## Stage 11 — Metadata + this log (procedure step 11)

`metadata.json` and this file written last, after every other artifact existed, so both reflect final state.

## Artifacts in `prompts/GRILL/`

`prompt.v1.md`, `prompt.v2.md`, `prompt.md` (final), `tests.json`, `test-results.json`, `output-test-results.json`, `output-reference.md`, `audit.json`, `score-delta.json`, `learnings.md`, `learnings.json` (auto-generated by `convergence.py`), `CONTRACT_CHECK.md`, `metadata.json`, `LIFECYCLE_LOG.md` (this file).
