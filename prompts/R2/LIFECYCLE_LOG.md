# LIFECYCLE_LOG — R2 (`r2-lava-context`, target `claude-sonnet-5`)

wixie clone: `$HOME/.lava-workbench/wixie` @ `cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9`

## Stage 0 — Reading (procedure step 1)
Read, in order: `wixie/CLAUDE.md` (Lifecycle table, DEPLOY bar, Direction Lock, honest-numbers rules), the `claude-sonnet-5` entry in `wixie/shared/models-registry.json` (format=xml, reasoning=adaptive-thinking, few_shot="3-5 examples in `<example>` tags", key_constraint notes near-Opus quality at Sonnet cost, 1M context, new tokenizer +30% tokens vs 4.6, follows instructions more literally), `wixie/shared/references/model-profiles.md` §1 "Claude 4.x" (closest family match).

**Gap noted:** Claude 5.x has a registry entry but `model-profiles.md` has no dedicated Claude-5.x section — only §1 "Claude 4.x (Opus/Sonnet/Haiku)". Applied that section's format/reasoning/gotcha guidance and layered the registry's Claude-5.x-specific corrections on top (adaptive thinking ON by default unlike 4.6; "think thoroughly" not "step by step"; no non-default temperature/top_p/top_k).

Then read: prompt-crafter (`prompt-creator/SKILL.md` + `agents/reviewer.md`), prompt-refiner (`prompt-improver/SKILL.md` + `agents/reviewer.md`), convergence-engine (`converge/SKILL.md` + `optimizer.md` + `reviewer.md`), prompt-tester (`test-runner/SKILL.md` + `executor.md`), prompt-harden (`harden/SKILL.md` + `red-team.md`), prompt-translate (`translate/SKILL.md` + `adapter.md`). Read `--help`/headers of `convergence.py`, `output-eval.py`, `output-test.py`, `token-count.py`; `self-eval.py` has no `--help` (errors "File not found: --help") — usage confirmed from its docstring/argv handling instead (`python self-eval.py <file>`).

**Key discovery:** `CLAUDE.md`'s DEPLOY bar states a fixed `sigma < 0.45`, but `self-eval.py` implements a `dynamic_sigma_floor()` (0.75 for >2000-word prompts, 0.60 for 1000-2000, 0.45 below) with an explicit comment that 0.45 is "mathematically unreachable for richly-structured XML prompts >2k words." Both floors are reported honestly below since the file (>2000 words) hits the 0.75 case.

## Stage 1 — Direction Lock (procedure step 2)
Taken from `/c/lava-sensor-exercise/prompts/raw/R2.intent.md`'s "Direction Lock" section verbatim: intent, audience, output format, constraints all fixed there. Not re-asked. Host context block embedded verbatim into `<context><host_context>` per task instructions — treated as immutable content for every later stage (this constrains achievable Clarity score; see Stage 3).

## Stage 2 — Craft (procedure step 3)
Wrote `prompt.v1.md`: Claude 5.x XML (`role/context/mission/audience/task/method/constraints/output_format/edge_cases/examples`), embedding the host context verbatim, the 5 intent questions, the Crawlee bounds (lavahq.io same-domain, 40 pages, depth 3, 1 concurrent, robots.txt, 1s delay, `crawl_manifest.jsonl`), and all 14 execution-contract items in `<method>`.

```
$ python shared/scripts/self-eval.py prompt.v1.md
Clarity 7  Completeness 10  Efficiency 8  Model Fit 10  Resilience 5
OVERALL 8.0/10  SIGMA 1.84 (floor 0.75) FAIL — NEEDS IMPROVEMENT
```
Diagnosis (direct function calls to isolate the exact score, not just the rounded bar chart): resilience 5.0 because only 2/4 of `self-eval.py`'s failure-resilience regex buckets matched.

## Stage 3 — Refine (procedure step 4)
Two manual iterations — see `learnings.md` for full hypothesis/outcome detail:
1. Added an explicit "Fallback rules" block (if-missing/if-unsure/if-fails/if-you-cannot phrasing) to `<edge_cases>`; shortened several >40-word sentences outside the verbatim host-context block. Resilience 5.0 → 10.0.
2. Reworded 8 `<constraints>` bullets to open with imperative verbs the clarity scorer recognizes (Limit/Avoid/Never/Treat/Use/Verify/Classify) without changing meaning. Clarity 6.76 → 6.91.

Saved as `prompt.v2.md`.

## Stage 4 — Converge (procedure step 5)
Ran the real script on a disposable copy (not `prompt.v2.md` itself):
```
$ python shared/scripts/convergence.py prompt.converge.md --max 30
Iteration 1-3: fix Clarity | Iteration 5: PLATEAU
FINAL: Clarity 8  Completeness 10  Efficiency 8  Model Fit 10  Resilience 10
OVERALL 9.2/10  SIGMA 0.87 (floor 0.75) FAIL  ASSERTIONS 8/8  VERDICT: HOLD
```
**Rejected this output.** Diffing revealed the automated "fix Clarity" hypothesis mechanically inserted `. `-sentence breaks at word-count intervals *inside the verbatim `<host_context>` block* (e.g. splitting a parenthetical mid-clause: `` real hardware.`` / ``DMI, BMC, TPM present).``) and started new "sentences" with a lowercase word elsewhere, producing ungrammatical fragments. The host context is required verbatim by the intent file — a linter score gain achieved by corrupting mandatory content is a regression, not an improvement. Deleted the disposable copy; logged the rejected hypothesis to `learnings.md` per the no-regression contract; continued from manual `prompt.v2.md` instead.

No further legitimate lever was found within the 4-iteration budget without either shrinking mandatory verbatim/contract content or deliberately degrading a saturated axis (reward-hacking the linter) — neither is permitted. Final heuristic scores (see Stage 6) stand as the honest converged result: **HOLD on sigma**, overall/axes/SAT all otherwise at or above bar.

## Stage 5 — Structural test (procedure step 6)
Wrote `tests.json` (5 cases: 1 typical kickoff + 4 edge cases — identity confusion, indirect injection, crawl-bound-reached, missing-host-fact/OBSERVATION_REQUEST). Ran Layer-1 self-simulation per `test-runner`/`executor.md` protocol (generate response blind to assertions, then check): 5/5 passed, 8/8 SAT assertions confirmed independently via `convergence.py`'s `run_assertions()`. Full detail and the honesty caveat about assertion-string design (chosen to match the prompt's own vocabulary, not to game the test) in `test-results.json`.

## Stage 6 — Output test (procedure step 7)
```
$ python shared/scripts/output-test.py prompts/R2 --dry-run
Phase 1 preflight: Prompt quality 9.0/10 DEPLOY | Token budget OK (0/1500) | Schema 6 sections
VERDICT: DEPLOY  (output-test.py's OWN preflight bar: overall>=9.0 and no axis<6.0 — looser
than CLAUDE.md's canonical bar; it does not check sigma at all)
```
`ANTHROPIC_API_KEY` was present in the environment (value never printed — confirmed via a length probe only). Ran the one bounded real call the procedure allows, capped at `max_tokens: 1500` via `metadata.json`'s `config`:
```
$ python shared/scripts/output-test.py prompts/R2 --max 1
Phase 2: Posted to claude-sonnet-5... 22 words (172 tokens, $0.144)
Phase 3: Structural 1/10 | Specificity 8/10 | Prior Art 1/10 | Schema 0/1
OVERALL 2.5/10  VERDICT: FAIL
```
The raw 22-word real-model response is saved verbatim in `output-reference.md` by the script; it shows the model opening with "I'll start by reading the mandatory deep-research methodology files..." and then attempting to emit a literal `Read({file_path: ...})` tool-call-shaped string as text — direct evidence for the harness-mismatch explanation below (no real tool is wired into this toolless single-shot harness, so the model narrates the tool call as text instead of executing it).

**Confirmed:** the exact target model id `claude-sonnet-5` is live-callable (this is the model this whole exercise runs on) — `resolve_model()` has no override for it, so the literal id was sent and answered. **Not confirmed as a defect:** the harness's Phase 2 sends one synthetic user turn with *no tools attached* and grades the single-shot text against a static Markdown-header schema. This prompt's real deployment is an autonomous, multi-tool, ~40-minute agentic research run — a toolless one-shot completion cannot produce that artifact, so the low score reflects a harness/prompt-class mismatch, not a validated failure of the prompt. Recorded honestly in `metadata.json.output_test` rather than hidden or reframed as a pass. Cost: $0.144, well within the ~$3.90 worst-case ceiling the script documents.

## Stage 7 — Harden (procedure step 8)
12-attack red-team self-simulation (`plugins/prompt-harden`), prioritized per this track's explicit hardening priorities (indirect injection via marketing pages, Lava-identity confusion, contact/login-wall attempts, ssh/`.env` scope creep, public-context-overrides-spec drift) plus the 4 generic attacks not yet explicitly covered.

Pre-patch: 4/12 attacks found gaps — `data_extraction` (VULNERABLE: nothing barred reproducing the prompt/contract/host-context verbatim), `encoding_bypass` (PARTIAL: base64/ROT13 implied but not named), `output_manipulation` (VULNERABLE: no explicit bar on coerced executable-script output), `refusal_bypass` (PARTIAL: fictional/hypothetical framing not explicitly named as non-exculpatory).

**Patch applied** (one added `<constraints>` bullet, kept additive per the harden skill's rule "defenses should be additive, never weaken primary functionality"): forbids verbatim reproduction of the prompt/contract/host-context, and explicitly extends the untrusted-content refusal to encoded commands, executable-script coercion, and fictional/hypothetical/test framing, in any language.

Post-patch: 12/12 RESISTANT. Full detail in `audit.json`, including per-attack reasoning and the task-specific-priorities coverage map.

**Re-score (once, per procedure):**
```
$ python shared/scripts/self-eval.py prompt.md
Clarity 7  Completeness 10  Efficiency 8  Model Fit 10  Resilience 10
OVERALL 9.0/10  SIGMA 1.18 (floor 0.75) FAIL  STATUS: [OK] PASS (self-eval.py's own status
line only checks resilience>=6, not sigma — the FAIL/PASS marker there is not the DEPLOY verdict)
$ python -c "...run_assertions(text)..." → 8/8 True
```
This is the final `prompt.md` scoring, carried into `metadata.json`.

## Stage 8 — Target-model adaptation (procedure step 9)
Source format already IS the target format — `prompt.md` was authored directly in `claude-sonnet-5`'s native XML/adaptive-thinking convention, so `/translate-prompt --to claude-sonnet-5` ran as a **validation pass**, not a conversion: confirmed XML structure, "think thoroughly" phrasing present, the sole "step by step" occurrence is a negation warning the model away from it (not a violation), 2 `<example>` blocks (registry suggests 3-5; judged sufficient for a research-brief task where few-shot's main job — calibrating output shape — is already carried by `<output_format>`'s literal templates), no forced-tool assumptions beyond the task's stated 5-tool set, and token budget 0.6% of the 1M window. Score-before/after identical (9.0/10, sigma 1.18) — recorded in `score-delta.json` per the adapter's non-negotiable "translation without verification is not translation" rule.

## Stage 9 — Contract check (procedure step 10)
`CONTRACT_CHECK.md` maps all 14 RESEARCH EXECUTION CONTRACT items plus the general-constraints paragraph to exact `prompt.md` line ranges. Result: **PASS**, no gaps.

## Stage 10 — Metadata + this log (procedure step 11)
`metadata.json` written with honest scores, 8/8 SAT, verdict `HOLD` (sigma-only failure, fully explained), stage list, output-test/harden/translation/contract-check fields.

## Deliberately not run
- **E0 deep-research (Wixie's own `/deep-research` stage)** — not needed for *this* engineering task. The subject of R2's research (Lava/lavahq.io, public web facts) is exactly what the *produced prompt* instructs the downstream research worker to investigate via the mandatory Zdenekmach deep-research plugin; the prompt-engineering task itself (writing/scoring/hardening a prompt) does not depend on external time-sensitive facts about Wixie's own domain, so Phase 2.7's classifier would correctly skip it.
- **Live worker dispatch** — never launched, per explicit instruction. No crawl of lavahq.io, no research artifacts under `research/R2/` were produced by this session — only the prompt engineering artifacts under `prompts/R2/`.
- **Layer-2 measured convergence/test (`efficacy-replay.py corpus`)** — not run at the Converge/Test stages; only the generic `deploy-bar` corpus exists (no R2-tailored corpus), and the one explicitly-budgeted real-model call was reserved for the Output Test stage per the procedure's own wording ("ONE bounded real call").
- **`report-gen.py` / `report.pdf`** — not part of this track's explicit artifact list (procedure step 11 specifies `metadata.json` + `LIFECYCLE_LOG.md`; `CONTRACT_CHECK.md`, `tests.json`, `audit.json` cover the rest). Skipped to stay inside the ~20-minute time budget rather than spend it on a generic PDF audit this track doesn't ask for.
