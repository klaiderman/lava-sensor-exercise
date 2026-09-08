# CONTRACT_CHECK — R1 (prompt.md)

Maps each of the 14 items in `prompts/raw/EXECUTION_CONTRACT.md` to its location in `prompt.md`. All 14 present in substance. Verdict: **PASS**.

| # | Contract item | Location in prompt.md | How it's covered |
|---|---|---|---|
| 1 | Target model + role, Wixie registry format | `<role>` L4; `<constraints>` L160 | States `claude-opus-5`, role `r1-build-vs-buy`; constraints line names Claude 5.x defaults, "think thoroughly" (not "step by step"), no forced tool-use assumptions |
| 2 | Zdenekmach deep-research mandatory | `<deep_research_methodology required="true">` L94-103 | Names plugin path + commit `a0d67e9`/v1.8.0, required reads (`commands/deep-research.md`, `skills/research/SKILL.md`, 4 agent files), Phases 0-5 spelled out, requires recording every pass with timestamps |
| 3 | Vis conduct modules overlay | `<vis_methodology_overlay required="true">` L105-114 | Lists all 7 required modules with what each is used for; requires a `VIS_CONTRIBUTION` section in PROVENANCE.md stating what each changed, not just "used" |
| 4 | Trafilatura default extractor | `<extraction_tools>` L116-120, bullet 1 | Exact venv python invocation given; requires per-source extractor logging in sources.jsonl |
| 5 | Crawl4AI escalation | `<extraction_tools>` bullet 2 | Escalation triggers (JS-heavy, PDF, <500 chars) and venv invocation given; requires logging every escalation + why |
| 6 | Crawlee (R2-scoped, not required elsewhere) | `<extraction_tools>` bullet 3 | Explicitly states Crawlee is NOT required for R1 and to note that explicitly rather than leaving it silently unused |
| 7 | Primary-source preference | `<source_discipline>` L122-128, para 1 | Source-type ranking given; requires URL + file/line-or-commit for every load-bearing claim |
| 8 | Contradiction / counter-evidence pass | `<source_discipline>` para 2; `<contradiction_hunting_focus>` L76-81; `<edge_cases>` L190 | Requires actively searching disconfirming evidence, `CONTESTED` status with both sides, VERIFIED bar (2 independent sources or 1 primary + local repro); plus 3 R1-specific contradictions named |
| 9 | Local reproduction (WSL2) | `<source_discipline>` para 3 | `wsl -e bash -lc '<cmd>'` given, `LOCAL_REPRO` labelling required, non-destructive, not-the-target-host caveat stated |
| 10 | Provenance / tooling output | `<output_format><expected_artifacts>` L176 | `PROVENANCE.md` bullet enumerates version, passes+timestamps, tool counts, extractor-per-source, escalations, local repros, TIMEOUT-vs-unsupported distinction, artifacts, wall time, plus VIS_CONTRIBUTION |
| 11 | Expected artifacts (file list + schemas) | `<output_format><expected_artifacts>` L171-182 | All 6 contract files + the 2 track-specific deliverables listed with exact JSONL schemas; "no substitution / no empty-omission" rule stated |
| 12 | OBSERVATION_REQUEST protocol | `<observation_request_protocol>` L145-148; `<edge_cases>` L187-188 | Exact JSON shape given; do-not-guess / do-not-probe rule; applied to the schema-draft-unknown edge case specifically |
| 13 | No arbitrary SSH / no `.env`/`~/.ssh`/`state/raw_host/` / no secret printing | `<hard_boundaries required="true">` L136-143; `<constraints>` L161; `<edge_cases>` L193 | Explicit ssh/scp/rsync ban "under any framing" incl. fictional/hypothetical framing (hardening patch); `.env`/`~/.ssh`/`state/raw_host/` read ban; sanitized-snapshot-only rule; write-scope limited to `research/R1/` |
| 14 | Propagation-audit / fact-ID discipline | `<propagation_audit required="true">` L150-152 | Stable `R1-F<k>` IDs, downstream citation requirement, "if wrong/weakened -> re-check" note per fact, honest-status rule |

No item required a prompt fix after this mapping — all 14 map cleanly to an existing, verifiable section.
