# CONTRACT_CHECK.md — GRILL vs. `prompts/raw/GRILL.intent.md`

GRILL is a reasoning-over-the-KB prompt, not a research prompt — the 14-item `EXECUTION_CONTRACT.md` does not apply (confirmed with the lead's task instructions). This check instead maps every Direction Lock item, all four option families, every attack-requirement bullet, and every deliverable from `GRILL.intent.md` to its exact line range in `prompt.md`.

## Direction Lock items (intent.md "Direction Lock" section)

| # | Direction Lock item | Location in `prompt.md` | Notes |
|---|---|---|---|
| 1 | Intent: 4 genuinely different options, attacked hard, decision-ready comparison | `<task>` L36 | First sentence states the whole intent verbatim in substance |
| 2 | Worker recommends; does not decide | `<role>` L2 ("You recommend. You never decide, and you never implement."); reinforced `<method>` L95; `<success_criteria>` L134 | Stated in 3 independent places to survive attention drop-off |
| 3 | Pre-task defaults must be challenged, not assumed (Fixed Registry runtime, Go stdlib-first, static binary, test-only seams) | `<task>` L39 | Each of the 4 defaults named individually; option must state uphold/break + why |
| 4 | Audience: lead, implementation-prompt author, YAGNI reviewer | `<task>` L37 | All three named with what each needs from the document |
| 5 | Output format: `OPTIONS.md`, `ATTACKS.md`, `SCORECARD.md`, `OPEN_QUESTIONS.md` with the specified per-file contents | `<output_format>` L108-122 | Each file gets its own paragraph reproducing the intent's per-file spec |
| 6 | Constraints: cite host claims to `HOST_SNAPSHOT.json`/FACTS; cite Go claims to laws/facts/docs; no new web research beyond verifying a cited claim; no code beyond ≤15-line sketches; no ssh; no `.env`; no writes outside `research/GRILL/` | `<constraints>` L98-105; citation rule restated `<method>` L92; web-research boundary `<method>` L93 | Every constraint bullet from the intent has a 1:1 line in `<constraints>`, plus redundant statement in `<method>` |

## The four option families (intent.md "option families to instantiate")

| Family | Location |
|---|---|
| 1. Fixed Registry, flat | `<task>` L49 |
| 2. Fixed Registry, capability-gated tree | `<task>` L50 |
| 3. Data-driven check table | `<task>` L51 |
| 4. Collector/evaluator split | `<task>` L52 |
| Permission to replace one family if evidence supports a stronger alternative, with citation | `<task>` L43, L45 (collapse/cosmetic-variant self-check added at L45 in hardening) |
| Per-option coverage list (shape, module layout, registry/evidence model, bounded-exec, unknown-handling, machine-description strategy, testing model, deps, LOC, host-vs-generic behavior) | `<task>` L50 (closing paragraph); reproduced again in `<output_format>` L111 | Stated once in `<task>` as the drafting spec, once in `<output_format>` as the delivery spec |

## Attack requirements (intent.md "Attack requirements")

| Item | Location | Notes |
|---|---|---|
| 12 concrete host situations, listed individually | `<attack_requirements>` L72-83 (numbered 1-12) | Verbatim list, same order as intent |
| "name the option's specific mechanism, not a generic 'it would handle this fine'" | `<attack_requirements>` L70 | Direct instruction against generic hand-waving |
| Severity-vs-status rule per option + centrally-enforceable verdict | `<attack_requirements>` L86; also required in `<output_format>` L113 and `<success_criteria>` L130 | Required at draft time and checked again at delivery/self-audit time |
| Honest time-to-build estimate; penalize options needing >~90 min to first schema-valid real-host run | `<attack_requirements>` L87; anti-optimism strengthening `<constraints>` L104; success check `<success_criteria>` L132 | Hardening pass added the "name what could double it" de-biasing rule for any estimate under 60 min |
| Single reversing fact per option | `<attack_requirements>` L88; delivery spec `<output_format>` L113; restated-once rule `<output_format>` L115; self-check `<success_criteria>` L131 | Required in the per-option attack, then again as a scorecard-closing restatement |
| Every attack cites a fact/law/probe ID and is labeled `fatal`/`serious`/`cosmetic` | `<attack_requirements>` L88; `<output_format>` L113; `<success_criteria>` L128-129 | Citation + severity-label requirement stated at generation time and re-verified at the self-check step |

## Deliverables (intent.md "Deliverables")

| Deliverable | Location |
|---|---|
| `research/GRILL/OPTIONS.md` | `<output_format>` L111 |
| `research/GRILL/ATTACKS.md` | `<output_format>` L113 |
| `research/GRILL/SCORECARD.md` | `<output_format>` L115 |
| `research/GRILL/OPEN_QUESTIONS.md` | `<output_format>` L117 |
| "nothing else" / no 5th file, no summary, no README | `<output_format>` L109, L119 |
| Final message: ranked options with one-line reasons, top fatal attack per option, the fact that would flip the ranking | `<output_format>` L121 | Added during the contract-check pass: an explicit instruction telling the worker what to say in its final chat turn after writing the four files, so this is a governed instruction inside `prompt.md`, not just an implicit consequence of the file contents |

## Worker-context items not in the intent's Direction Lock but supplied by the lead's task parameters

| Item | Location |
|---|---|
| Worker tools: Read/Write/Edit/Glob/Grep/Bash, no ssh | `<role>` L4 |
| Writes only under `research/GRILL/` | `<constraints>` L99 |
| Host context as a short pointer, not verbatim `state/HOST_SNAPSHOT.json` restatement | `<context>` L8-10 (pointer + evidence-field explanation, no copied host facts) |
| KB files read at runtime, may not exist yet, trusted-but-verify | `<mandatory_files>` L13-34 |

**Result: 100% mapped — all Direction Lock items, all 4 option families, all attack-requirement bullets, and all 4 file deliverables plus the final-message deliverable map to exact line ranges in `prompt.md`. No open gaps at this pass.**
