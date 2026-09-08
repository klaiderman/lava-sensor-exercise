# LIFECYCLE_LOG.md — R4 (`r4-host-investigation`, target `claude-opus-5`)

## Stage 1 — Read the briefing (procedure step 1)

Read in order: `wixie/CLAUDE.md` (Lifecycle table, DEPLOY bar, behavioral contracts), `wixie/shared/models-registry.json` (`claude-opus-5` entry: family Claude 5.x, format xml, reasoning adaptive-thinking, few_shot 3-5 `<example>` tags, key_constraint on longer-output/self-verification tendency), `wixie/shared/references/model-profiles.md` §1 "Claude 4.x" (closest profile; Claude 5.x has a registry entry but no dedicated profile section in this file — **gap noted per instruction**), then all six plugin SKILL.md files plus their reviewer/optimizer/executor/red-team/adapter agent files (prompt-crafter, prompt-refiner, convergence-engine, prompt-tester, prompt-harden, prompt-translate). Confirmed CLI usage via `--help`/header reads on `convergence.py`, `output-eval.py`, `output-test.py`, `self-eval.py`, `token-count.py`.

Verified paths exist before citing them (precedent-freshness discipline): `deep-research` plugin at commit `a0d67e9` (matches the contract), `wixie` at `cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9` (matches the agent brief), all 8 named Vis conduct modules, the venv python, and both `state/HOST_SNAPSHOT*.json` files.

**E0 deep-research note (per task instruction):** Wixie's own `/deep-research` stage (auto-firing inside `/create`) was NOT run for this prompt-engineering pass — the task explicitly said it isn't needed here, since the subject matter (this host, this kernel, this vendor stack) is exactly what the *worker* prompt sends its own worker off to research; the prompt-engineer's job is to specify that research contract, not pre-conduct it.

## Stage 2 — Direction Lock (procedure step 2)

Direction Lock: taken from the intent file's "Direction Lock" section verbatim (intent, target model, audience, output format, constraints) — not re-asked. Host context section copied byte-for-byte into `<host_summary>`.

## Stage 3 — Craft (procedure step 3)

Wrote `prompt.v1.md`: Claude 5.x XML sections (`<role>`, `<context>` with `<host_summary>` + `<mandatory_files>`, `<task>` with the 6 question groups + contradiction-hunting, `<method>` with deep-research/Vis/extraction/source-standards/observation-request subsections, `<constraints>`, `<output_format>`, `<edge_cases>`). Embedded all 14 `EXECUTION_CONTRACT.md` items in substance. `self-eval.py` baseline: Clarity 7.0, Completeness 7.0, Efficiency 8.0, Model Fit 9.0, Failure Resilience 10.0 → overall 8.3, sigma 1.21 (floor 0.75) FAIL.

## Stage 4 — Refine (procedure step 4)

Diagnosed via `self-eval.py` internals (component-by-component recomputation, not guessing): Completeness capped by a missing "task:/you will/instructions:" style phrase (regex quirk, not a real gap) and no `<example>` block; Clarity capped by 12 sentences over 40 words and a low imperative-sentence ratio; Model Fit missing the few-shot bonus.

Applied to `prompt.v2.md`:
- Added `<task_roadmap>` (7-step ordering) and `<success_criteria>` (7 checkable done-conditions) — the prompt-anatomy "task roadmap" and "success criteria" mandatory components.
- Added `<examples>` with 2 worked examples (NVMe evidence-table row + facts.jsonl line; indirect-injection-in-a-vendor-PDF response) — the "expected output" mandatory component and the registry's few-shot guidance.
- Split 11 of the 12 over-40-word sentences that were *my own authored prose* into shorter imperative sentences (the 12th is inside the mandated-verbatim `<host_summary>` block and was left untouched).
- Added one markdown subheading (`### Questions to answer`) for structural variety.

Result: Clarity 7.0→8.6(disp. 9), Completeness 7.0→10.0, Efficiency unchanged 8.0, Model Fit 9.0→10.0, Failure Resilience unchanged 10.0 → overall 9.4, sigma 0.71 (floor 0.75) **PASS**.

## Stage 5 — Converge (procedure step 5)

```
python convergence.py prompt.v2.md --verbose
```
Output: `Iteration 1: 9.4/10 → DEPLOY (8/8 assertions, sigma 0.71 <= 0.75)`. Zero fixes applied — the manual refine pass in Stage 4 had already closed every gap the auto-fixer targets. No failed hypotheses to log for this run.

**Scoring provenance note:** `self-eval.py`'s `dynamic_sigma_floor()` applies 0.75 (not the flat 0.45 in `wixie/CLAUDE.md`'s DEPLOY-bar table) for prompts over 2000 words, with an inline rationale that 0.45 is unreachable for structured XML prompts at this length. Per `CLAUDE.md`'s own rule ("when a module conflicts with a plugin-local instruction, the plugin wins — but log the override"), this override is applied and logged in `metadata.json.scores.sigma_floor_note`. Under the strict flat-0.45 reading, this prompt would be HOLD on sigma alone (0.71 > 0.45); this is disclosed, not hidden.

## Stage 6 — Structural test (procedure step 6)

Wrote `tests.json` (5 cases: 2 typical, 3 edge-case covering EACCES-vs-absent, hostname-hardcode refusal, and indirect-injection-in-vendor-doc — the three named hardening priorities). Ran the test-runner's Layer-1 role-play protocol by hand (Pass 1 parse → Pass 2 generate without peeking at assertions → Pass 3 check): 5/5 pass, saved to `test-results.json`. `tier_risk: true` flagged honestly — target is Opus-class (`claude-opus-5`), simulation ran at Sonnet tier (this agent), so pass/fail is a proxy signal per `executor.md`'s own rule, not proof of `claude-opus-5`'s actual behavior.

## Stage 7 — Output test (procedure step 7)

```
python output-test.py prompts/R4 --dry-run
```
Phase 1 preflight only: prompt quality 9.4/10 DEPLOY, token budget OK, schema generated, forecast flagged "[!!] Estimated output (15,950 tokens) EXCEEDS budget (1,500) by 963%" — an honest, useful early warning that a single 1500-token completion cannot hold this task's real output shape.

`ANTHROPIC_API_KEY` was present in the environment (value never printed, per instruction). Ran the bounded real call:
```
python output-test.py prompts/R4 --max 1 --no-fix
```
Result: `Posted to claude-opus-5... 0 words (1,500 tokens, $0.221)`. The model ID resolved and billed successfully (MODEL_MAP in `output-test.py` has no entry for `claude-opus-5`, so it passed the literal string straight to the API — and the API accepted it and charged for it, confirming `claude-opus-5` is a live, reachable model on this account). No visible completion text came back: all 1500 output tokens were consumed, plausibly by adaptive-thinking under the registry's noted "tends to longer output + self-verification" behavior colliding with a cap this task instructed be ≤1500. This makes the "response opens in the mandated structure" check **inconclusive**, not failed — recorded honestly in `metadata.json.output_test` rather than glossed over. Full detail in `output-test-results.json`.

## Stage 8 — Harden (procedure step 8)

Ran the full 12-attack red-team by hand against `prompt.v2.md`, risk level HIGH (autonomous Read/Write/Bash/Web* worker whose emitted probe commands may be run unreviewed by a human lead). 8/12 already RESISTANT, most strongly on the track's named priority (indirect injection — has a dedicated worked example). 4 hardening opportunities found: system-prompt data-extraction, encoding/obfuscation bypass, output-manipulation into an unsafe recommended probe, and hypothetical/fictional-framing refusal bypass. Full detail in `audit.json`.

Applied 3 patches (folding the encoding/obfuscation and hypothetical-framing fixes into one clause, per the honest low-relevance note on language-switching in `audit.json`) to `prompt.md`.

**Incident, caught and reverted:** re-ran `convergence.py --verbose` to re-score post-patch. It reached DEPLOY (9.4/0.71) in 3 iterations, but its `fix_clarity` function rewrote long semicolon-joined sentences by inserting line breaks — with no awareness that `<host_summary>` is a **mandated-verbatim** block. A post-hoc diff against `prompt.v1.md`'s `<host_summary>` caught the corruption (confirmed `DIFFERENT`). Reverted `prompt.md` to `prompt.v2.md` + the 3 harden patches applied by hand, re-verified `<host_summary>` byte-identical to `prompt.v1.md` (confirmed `IDENTICAL`), and re-ran `self-eval.py` (read-only scoring, not the auto-fixer) to confirm DEPLOY: 9.4/10, sigma 0.71 PASS, 8/8 SAT assertions replayed directly via regex and confirmed. This failed hypothesis — "the automated convergence fixer is safe to run on a prompt containing a verbatim-mandated block" — is logged in `learnings.md` with the recommendation for future R-track runs.

## Stage 9 — Target-model adaptation (procedure step 9)

Source and target are both `claude-opus-5` (crafted directly for the target from Stage 3 onward, per the intent file's explicit model promotion) — no cross-family XML→Markdown/minimal conversion was needed. Adaptation instead applied `claude-opus-5`-specific nuances from the registry: confirmed "think thoroughly" phrasing (never "step by step"); confirmed the existing `<constraints>` scope-discipline sentence already counters the registry's noted "longer output + self-verification" tendency; added a 3rd worked `<example>` (single-probe contradiction-hunting + `OBSERVATION_REQUEST`) to reach the registry's 3-5-example few-shot recommendation. Re-scored non-regressive: 9.4→9.4, sigma 0.71→0.71. `score-delta.json` written per the adapter's honest-numbers contract, including the v1→final delta (8.3→9.4, sigma 1.21→0.71) for full-pipeline visibility.

## Stage 10 — Contract check (procedure step 10)

`CONTRACT_CHECK.md`: all 14 `EXECUTION_CONTRACT.md` items mapped to exact line ranges in `prompt.md`. Result: **14/14 PASS**, no fix required at this pass.

## Stage 11 — Metadata + this log (procedure step 11)

`metadata.json` and this file written last, after all other artifacts existed, so both reflect final state rather than an intermediate one.

## Artifacts in `prompts/R4/`

`prompt.v1.md`, `prompt.v2.md`, `prompt.md` (final), `tests.json`, `test-results.json`, `output-test-results.json`, `audit.json`, `score-delta.json`, `learnings.md`, `CONTRACT_CHECK.md`, `metadata.json`, `LIFECYCLE_LOG.md` (this file).
