# CONTRACT_CHECK — R5 (prompt.md)

Maps each of the 14 RESEARCH EXECUTION CONTRACT items to its exact location in `prompt.md`. All 14 present in substance.

| # | Item | Location in `prompt.md` | Verification |
|---|------|--------------------------|---------------|
| 1 | Target model + role, Claude 5.x format/adaptive-thinking/"think thoroughly" | `<role>` line 1-3; `<execution_contract>` item 1, lines 39-42 | States `claude-opus-5` / `r5-go-architecture` by name; "adaptive thinking is on by default"; "think thoroughly"; "think step by step" does not appear anywhere in the file (grep-verified). |
| 2 | Zdenekmach deep-research mandatory, 6 phases (0-5) | Item 2, lines 44-53 | Names the plugin path + commit + version, lists all six phases (0, 1, 1.5, 2, 3, 4, 5) individually, forbids ad-hoc browsing substitution. |
| 3 | Vis methodology overlay, named conduct modules, VIS_CONTRIBUTION section | Item 3, lines 54-55 | Names all 7 required conduct-module paths; requires a `VIS_CONTRIBUTION` section inside PROVENANCE.md describing what each module changed. |
| 4 | Trafilatura default extractor | Item 4, lines 56-57 | Exact venv python invocation; requires extractor logged per source in `sources.jsonl`. |
| 5 | Crawl4AI escalation, when/why | Item 5, lines 58-59 | Exact invocation + trigger conditions (JS-heavy, PDF, <500 chars); requires escalation logged in PROVENANCE.md. |
| 6 | Crawlee not required for R5 | Item 6, line 60 | Explicit "Skip it" with the reason (R2-only). |
| 7 | Primary-source preference + citation requirement | Item 7, lines 62-63; reinforced in `<method>` lines 122-123 and `<contradiction_hunting_focus>` lines 107-110 | States the full source rank; requires every load-bearing `facts.jsonl` claim to cite a primary source, plus file/line/commit for source-code claims. |
| 8 | Contradiction / counter-evidence pass, CONTESTED marking | Item 8, lines 64-65; `<contradiction_hunting_focus>` lines 107-110; `<success_criteria>` line 159 | Requires active search for disconfirming evidence, `CONTESTED` marking with both sides, names the 3 specific contradiction-hunting targets, and success criteria requires at least one resolved CONTESTED claim (or a stated reason why none exists). |
| 9 | Local reproduction (LOCAL_REPRO), tools available, non-destructive | Item 9, lines 66-67; `<method>` lines 125 | Names exact Go 1.26 path and WSL invocation; requires `LOCAL_REPRO` label with version/distro/kernel; "never run anything destructive." |
| 10 | Provenance.md contents | Item 10, lines 68-69 | Lists every required field (version, passes+timestamps, tool counts, source list, extractor, escalations, LOCAL_REPRO log, failures/timeouts, artifacts, wall time). |
| 11 | Expected artifacts list + facts.jsonl/sources.jsonl schemas | Item 11, lines 70-73; deliverables also enumerated again in `<output_format>` line 139 and `<deliverables>` lines 113-118 | Full artifact list named twice (contract + output_format) for redundancy; both JSON-line schemas given verbatim. |
| 12 | OBSERVATION_REQUEST protocol | Item 12, lines 74-75; also invoked concretely in `<edge_cases>` lines 143, 149 | Full JSON object schema given; two edge-case bullets show it applied to the missing-schema-file and missing-host-fact scenarios specifically. |
| 13 | No arbitrary SSH / no `.env`/`~/.ssh`/`state/raw_host` / no secret printing | Item 13, lines 76-77 (patched during hardening); also `<output_location>` lines 34-36 and `<constraints>` lines 132-134 | Stated three times independently (contract, output_location, constraints) — the hardening pass added explicit closure for encoded/multilingual/split/hypothetical framings of the same instruction. |
| 14 | Propagation-audit: stable claim IDs, PROPAGATION_NOTES.md, honest VERIFIED bar | Item 14, lines 78-79 | Requires `R5-F<k>` IDs to be cited by the four named deliverables; specifies the exact PROPAGATION_NOTES.md line format; states the >=2-source-or-primary+LOCAL_REPRO bar for VERIFIED. |
| — | General constraints (untrusted web content, ~40 min budget, no writes outside research/R5/, no secrets, incremental writing) | Line 80 | One consolidated paragraph restating the four cross-cutting rules that apply to every item above. |

## Non-contract items also verified present
- Four named deliverables (`ARCHITECTURE_NOTES.md`, `IMPL_BVB.md`, `PATTERNS.md`, `TEST_STRATEGY.md`): `<deliverables>`, lines 113-118.
- 10 research questions: `<task>`, lines 87-105.
- Contradiction-hunting focus (3 named targets): lines 107-110.
- Host context embedded verbatim: `<host_snapshot>`, lines 11-27 (byte-for-byte identical to the intent file's Host context section — verified programmatically against `prompt.v1.md`'s first-draft copy).
- Fixed Registry default + disconfirming-evidence-only override rule: `<task_summary>`, line 7 (final sentence).
- Windows-host-has-no-Go-toolchain packaging framing: `<host_snapshot>` closing paragraph, line 26; `<task>` question 7, line 99.

## Result
**PASS** — all 14 execution-contract items map to an exact, verifiable location in `prompt.md`. No missing item.
