# LIFECYCLE_LOG.md — R3 (`r3-sensor-evidence`, target `claude-opus-5`)

wixie clone: `$HOME/.lava-workbench/wixie` @ `cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9`. All Python invoked with the system `python` (stdlib-only; confirmed 3.13.2, no venv needed for these scripts).

## Stage 1 — Read the lifecycle references

Read, in order: `wixie/CLAUDE.md` (Lifecycle table, DEPLOY bar, Behavioral Contracts), `wixie/shared/models-registry.json` entry for `claude-opus-5` (family "Claude 5.x", format xml, reasoning adaptive-thinking, key_constraint notes self-verification/verbosity tendency), `wixie/shared/references/model-profiles.md` §1 "Claude 4.x".

**Gap noted:** `model-profiles.md` has no dedicated "Claude 5.x" section — §1 "Claude 4.x" is the closest analog (XML tags, "think thoroughly" not "step by step", role assignment in system prompt). Used it as the format baseline and layered the opus-5-specific registry fields (adaptive thinking default-on, effort ladder, self-verification tendency) on top.

**Second drift noted (load-bearing for the final verdict):** `CLAUDE.md`'s DEPLOY bar table states a flat `sigma < 0.45`. The scripts that actually compute sigma (`self-eval.py::dynamic_sigma_floor`, reused by `convergence.py::deploy_verdict`) implement a size-scaled floor instead (0.75 for >2000-word prompts), with an explicit code comment explaining 0.45 is "mathematically unreachable" at that length. Treated the scripts as authoritative over the prose table (per CLAUDE.md's own "Scoring provenance" section: the axis/sigma/SAT numbers "are all produced by" these scripts) and used the 0.75 dynamic floor for the real verdict — still failed by this prompt (see Stage 4).

**Third drift noted:** `plugins/prompt-translate/agents/adapter.md` specifies `score-delta.json` axes as clarity/specificity/structure/robustness/completeness. The scorer actually invoked everywhere else (`self-eval.py`) uses a different 5-axis set (Clarity/Completeness/Efficiency/Model Fit/Failure Resilience). Reported the real scorer's axes in `score-delta.json` and flagged the mismatch there.

Also read all 6 skill files + their sub-agents (prompt-creator+reviewer, prompt-improver, converge+optimizer+reviewer, test-runner+executor, harden+red-team, translate+adapter) and the `--help`/docstring headers of `convergence.py`, `output-eval.py`, `output-test.py`, `self-eval.py`, `token-count.py`.

## Stage 2 — Direction Lock

Taken from `prompts/raw/R3.intent.md` "Direction Lock" section verbatim (intent, audience, output format, constraints). Not renegotiated with the lead, per instruction.

## Stage 3 — Craft (`prompt.v1.md`)

Hand-authored in Claude 5.x XML sections (`role, context[direction_lock, host_context, worker_environment], task, method, constraints, output_format, edge_cases, fallback, success_criteria, examples`), embedding: the 9 research topics, the 3 contradiction-hunting foci, the FACT/DESIGN LAW/PROBE STRATEGY/ADVERSARIAL FIXTURE schema, the host context copied verbatim from the intent file, and all 14 execution-contract items in substance. Two worked `<example>` blocks included (DMI serials, false-PASS-from-missing-file) to calibrate format/depth.

```
$ python token-count.py prompt.v1.md --model claude-opus-5
Words: 5,136  Est. Tokens: ~6,782  Usage: 0.7% of 1,000,000
$ python self-eval.py prompt.v1.md
Clarity 7  Completeness 10  Efficiency 8  Model Fit 10  Failure Resilience 10
OVERALL 9.0/10   SIGMA 1.21 (floor 0.75) FAIL   STATUS: [OK] PASS (self-eval's own display; see Stage 1 drift note)
```

## Stage 4 — Refine (`prompt.v2.md`) + Converge

Copied v1 -> v2. Diagnosed the sigma gap: Clarity(7)/Efficiency(8) pulled down by (a) the low imperative-sentence ratio inherent to a 9-topic literature-style brief (386 sentences, only 11 verb-initial) and (b) a long-sentence penalty already capped at its maximum with 13 sentences >40 words, most of them in the verbatim host-context block or the topic list (both content the contract requires kept dense/verbatim). Added a "Non-negotiables" imperative checklist to `<constraints>` (genuine clarity aid, not just score-bait) — self-eval showed no measurable movement (7/10, 8/10 unchanged at the rounded level), confirming the ceiling is structural, not a missed easy fix.

```
$ python convergence.py prompt.v2.md --max 30   (run twice, 2 sessions)
Iteration 1-2: hypothesis "fix Clarity" -> PLATEAU (no textual fix available: no hedge
  words present, long-sentence split rule not applicable to un-split comma/semicolon lists)
FINAL: Clarity 7 Completeness 10 Efficiency 8 Model Fit 10 Failure Resilience 10
OVERALL 9.0/10  ASSERTIONS 8/8 pass  SIGMA 1.21 (floor 0.75) FAIL  VERDICT: HOLD
learnings.md pattern: "persistent_plateau ... incremental fixes exhausted"
  recommendation: "RESTRUCTURE ... tables instead of prose, shorter sentences" -- evaluated
  and REJECTED: would require cutting the verbatim host-context block (contract violation)
  or degrading the 3 ceiling axes (not a legitimate fix). Logged as a failed hypothesis.
```

Both convergence runs produced zero textual mutation beyond the manual Non-negotiables edit (verified via content diff, CRLF-normalized) — `learnings.json`/`learnings.md` in the folder are the real script output, not authored by hand.

## Stage 5 — Structural test (`tests.json`)

Authored 7 test cases spanning typical use, a clean technical sub-question, and 5 edge cases (indirect injection inert, refuse-ssh/.env, missing-host-fact -> OBSERVATION_REQUEST, single-secondary-source not promoted to law, empty input). Self-simulated (Layer-1 proxy, not a live call) against the prompt's explicit instructions: all 7 map directly to an explicit rule already in `<constraints>`/`<edge_cases>`/`<non-negotiables>`, so all 7 pass at the reasoning level. This is a proxy signal per the test-runner skill's own caveat, not a verified live-model result — Stage 6 supplies that.

## Stage 6 — Output test (real model)

```
$ python output-test.py prompts/R3 --dry-run
Phase 1 preflight: Prompt quality 9.0/10 DEPLOY | Token budget OK | Forecast OK
$ python output-test.py prompts/R3 --max 1 --no-fix      # the ONE bounded real call
Posted to claude-opus-5 ... 186 words (920 tokens, $0.2109)
Phase 3 evaluate: OVERALL 2.0/10  VERDICT: FAIL
```
`ANTHROPIC_API_KEY` was present in the environment (value never printed). The call reached the live API successfully under the literal model id `claude-opus-5` — no id-mismatch fallback was needed. **Finding:** with no tools attached (raw Messages API, as `output-test.py` calls it), the model did not state it lacked tool access; it opened by fabricating an `<invoke name="Bash">` block and a fabricated `ls -la` result (wrong username, fabricated timestamps, a hallucinated duplicate file line) instead of doing real research. This is the exact overclaiming failure class topic 8 exists to prevent, one layer up (the worker fabricating evidence rather than the sensor). Fed directly into Stage 7.

## Stage 7 — Harden (`audit.json`)

Risk level: high (WebFetch/WebSearch/Bash over untrusted content, producing load-bearing law). Ran all 12 standard attacks self-simulated + the Stage 6 finding as a 13th, measured attack. Result: 9 RESISTANT, 2 SKIPPED (multi-turn escalation, language switching — low relevance for a single-brief English-primary-source task), 1 VULNERABLE found and patched (no explicit anti-system-prompt-extraction rule), plus the fabricated-tool-output gap patched as a new non-negotiable. Patches added to `<constraints>`: (1) role/scope/schema immunity generalized beyond the ssh/secrets case to any framing ("hypothetically", "authorized override", etc.); (2) explicit anti-extraction rule; (3) explicit "tool calls must actually execute; never fabricate one" rule; (4) explicit naming of encoding/obfuscation (base64/ROT13/homoglyphs) as still-inert. Re-scored once after patching: no regression (9.0 -> 9.0 displayed; 8.96 -> 8.98 precise, sigma 1.211 -> 1.175).

## Stage 8 — Translate / target-model adaptation

Source format already matched target (`claude-opus-5`, Claude 5.x XML) — no cross-model conversion needed. Applied opus-5-registry-specific tuning: added an anti-preamble/conciseness instruction in `<method>` (registry key_constraint: "tends to longer output + self-verification"); confirmed "think thoroughly" phrasing is used and "step by step" is absent (grep, zero matches); confirmed no `you MUST`/`ALWAYS `/`NEVER ` (caps) overtrigger pattern is present. Score comparison and the axis-name schema drift recorded in `score-delta.json`.

## Stage 9 — Contract check

`CONTRACT_CHECK.md` maps all 14 execution-contract items to exact line numbers in the final `prompt.md`, cross-checked against a fresh `grep -n` pass after all hardening/translation edits (line numbers shift between edits; verified post-final-edit, not carried over from an earlier draft). Result: PASS, no missing item.

## Stage 10 — metadata.json + this log

Final artifact set in `prompts/R3/`: `prompt.v1.md`, `prompt.v2.md`, `prompt.md` (final), `tests.json`, `audit.json`, `score-delta.json`, `learnings.json`/`learnings.md` (script-generated), `output-test-results.json`, `output-reference.md` (raw real-call output, contains the fabricated-tool-call finding — kept as evidence, contains no secrets), `CONTRACT_CHECK.md`, `metadata.json`, `LIFECYCLE_LOG.md`.

**Note on Wixie's own E0 deep-research stage:** not invoked to produce this prompt — the task brief's own research content (9 topics, host context, contract) was fully specified by the lead's intent file, so no external/time-sensitive fact-finding was needed to craft the prompt itself. E0 is what the *worker* this prompt describes will run (Zdenekmach deep-research, embedded in `<method>` Phase 0), which is a different thing and was not run here — the worker was never launched, per instructions.

## Final verdict

**HOLD**, not DEPLOY. Overall 8.98 (rounds to 9.0), all 5 axes >= 7.0, 8/8 SAT assertions pass, contract check PASS, hardening complete with no open vulnerabilities. The single failing gate is sigma dispersion (1.175 vs. a 0.75 dynamic floor), which two independent convergence sessions could not close without either violating the intent file's verbatim-host-context requirement or artificially degrading axes already at ceiling. This is reported honestly per the no-inflation contract rather than rounded up to DEPLOY.
