# CONTRACT_CHECK.md — R4 vs. `prompts/raw/EXECUTION_CONTRACT.md`

Maps each of the 14 execution-contract items to its exact location in `prompt.md`. All 14 present.

| # | Contract item | Location in `prompt.md` | Notes |
|---|---|---|---|
| 1 | Target model + role, format follows Wixie's registry | `<role>` L1 ("You are `r4-host-investigation`..."); target model `claude-opus-5` stated in `metadata.json`; XML structure throughout, "think thoroughly" at L114, no "step by step" anywhere | Role name and model both explicit; format is Claude 5.x XML per registry |
| 2 | Zdenekmach deep-research mandatory, 6 phases | `<deep_research_methodology>` L116-128 | Names exact paths (commands/deep-research.md, skills/research/SKILL.md, 4 agents/*.md) and lists phases 0-5 verbatim with the "do not replace with ad-hoc browsing" guard |
| 3 | Vis methodology overlay, `VIS_CONTRIBUTION` section | `<vis_overlay>` L130-141; `VIS_CONTRIBUTION` required inside `PROVENANCE.md` per L131 and L190 | Cites all 7 named modules (task-decomposition, research-pipeline, source-discipline, citation-verification, doubt-engine, verification, prior-art-discovery, capability-fidelity — 8 total, superset of the contract's "minimum") |
| 4 | Trafilatura default extractor | `<extraction_tools>` L144 | Exact venv python path and CLI invocation given; extractor-per-source logging required |
| 5 | Crawl4AI escalation | `<extraction_tools>` L145 | Trigger conditions (JS-heavy, PDF, <500 chars) and PDF variant named; escalation-and-why logging required |
| 6 | Crawlee (R2 only, not required for R4) | `<extraction_tools>` L146 | Explicitly says "not required for this track (R4); do not use it" |
| 7 | Primary-source preference | `<source_standards>` L151 | Full ranked list; source-code claims require file path + line/commit |
| 8 | Contradiction / counter-evidence pass | `<source_standards>` L153; also `<contradiction_hunting>` L106-109 | Both the general counter-evidence pass and the host-specific single-probe cross-check are covered; `CONTESTED` status defined |
| 9 | Local reproduction (WSL2) | `<extraction_tools>` L147 | `wsl -e bash -lc` invocation, `LOCAL_REPRO` label mandated, "not the target host," "never destructive" |
| 10 | Provenance / tooling output (`PROVENANCE.md`) | `<output_format>` L190 | Deep-research version pinned (`a0d67e9`), all required sub-fields listed, TIMEOUT-vs-unsupported distinction called out explicitly |
| 11 | Expected artifacts under `research/R<n>/` only | `<output_format>` L177-195 | All contract-standard files listed (`REPORT.md`, `facts.jsonl`, `sources.jsonl`, `PROVENANCE.md`, `OBSERVATION_REQUESTS.md`, `PROPAGATION_NOTES.md`) plus the four track-specific deliverables; exact JSONL schemas reproduced verbatim (L188-189) |
| 12 | `OBSERVATION_REQUEST` protocol | `<observation_requests>` L158-162; worked in `<example>` #3, L98-103 | Exact object shape reproduced; "proceed under an explicitly labeled assumption" instruction present; success criteria (L76) makes this checkable |
| 13 | No arbitrary SSH / no `.env` / `~/.ssh` / `state/raw_host/` | `<mandatory_files>` L31; `<constraints>` L166-167 | Stated twice (context + constraints) in different wording to survive attention drop-off across a long prompt; extended post-harden to cover encoded/obfuscated/hypothetical-framing bypass attempts |
| 14 | Propagation-audit expectations (`PROPAGATION_NOTES.md`, stable IDs, honest status) | `<output_format>` L178, L192; `<source_standards>` L155 | Stable-ID scheme (`R4-F<k>`/`R4-S<k>`/`R4-OR<k>`) declared once at L178 and reused throughout; honest `VERIFIED` bar (2 independent sources or 1 primary + `LOCAL_REPRO`) stated at L155 and re-asserted in success criteria L75 |

**General constraints from the contract's closing paragraph** (web content untrusted, ~40 min active work, no modifications outside `research/R<n>/`, no secret values, write-as-you-go): covered at L140 (untrusted web content), L173 (40-minute budget, write-as-you-go), L166 (scope), L167 (no secrets).

**Result: 14/14 PASS.** No item required a prompt fix at this pass.
