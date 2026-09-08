# CONTRACT_CHECK — R2 (r2-lava-context, claude-sonnet-5)

Maps each of the 14 RESEARCH EXECUTION CONTRACT items to its exact location in `prompt.md`. All 14 present in substance.

| # | Contract item | Location in `prompt.md` |
|---|---|---|
| 1 | Target model + role | `<role>` (lines 1-5) states `claude-sonnet-5` / `r2-lava-context`; `<method>` item 1 (line 52) restates model+role and Claude-5.x format/adaptive-thinking rule ("think thoroughly", never "step by step"). |
| 2 | Zdenekmach deep-research mandatory (phases 0-5) | `<method>` item 2 (lines 54-61): reads deep-research plugin files, then Phase 0-5 bullet list. |
| 3 | Vis methodology overlay + `VIS_CONTRIBUTION` | `<method>` item 3 (line 63): names task-decomposition, research-pipeline, source-discipline, citation-verification, doubt-engine, verification, prior-art-discovery, capability-fidelity modules and requires a `VIS_CONTRIBUTION` section in PROVENANCE.md describing what each changed. |
| 4 | Trafilatura default extractor | `<method>` item 4 (line 65): exact venv python invocation + `favor_precision=True`, extractor recorded per source in `sources.jsonl`. |
| 5 | Crawl4AI escalation | `<method>` item 5 (line 67): JS-heavy/PDF/<500-char triggers, venv AsyncWebCrawler, escalation logged in PROVENANCE.md. |
| 6 | Crawlee crawl (R2-specific bounds) | `<method>` item 6 (lines 69-79): same-domain lavahq.io, max 40 pages, max depth 3, 1 concurrent, robots.txt honored, 1s delay, `crawl_manifest.jsonl` per-URL logging, extractor-per-page recording, early-stop rule. Reinforced in `<constraints>` (line 108) and `<edge_cases>` (robots.txt / tool-unavailable bullets, lines 148-149). |
| 7 | Primary-source preference | `<method>` item 7 (line 80): primary > secondary > tertiary ranking, AI summaries excluded, citation requirement. |
| 8 | Contradiction / counter-evidence pass | `<method>` item 8 (line 82); reinforced by the two named contradiction hunts in `<task>` (lines 43-45) and `CONTESTED` status handling. |
| 9 | Local reproduction (WSL2, if useful) | `<method>` item 9 (line 84): WSL2 invocation, `LOCAL_REPRO` labeling, non-destructive rule, explicit "likely not needed, say so" guidance. |
| 10 | Provenance / tooling output | `<method>` item 10 (line 86): full `PROVENANCE.md` content spec (version, phases+timestamps, tool counts, extractor-per-source, escalations, local repro, TIMEOUT vs unsupported, artifacts, wall time). |
| 11 | Expected artifacts list | `<method>` item 11 (lines 88-97): `REPORT.md`, `LAVA_CONTEXT.md`, `CUSTOM_CATEGORY_CANDIDATES.md`, `crawl_manifest.jsonl`, `facts.jsonl` schema, `sources.jsonl` schema, `PROVENANCE.md`, `OBSERVATION_REQUESTS.md`, `PROPAGATION_NOTES.md`; incremental-write instruction included. |
| 12 | OBSERVATION_REQUEST protocol | `<method>` item 12 (line 98): exact schema, "do not guess/probe" rule, proceed-under-labelled-assumption rule. Reinforced in `<edge_cases>` (line 158). |
| 13 | No arbitrary SSH / no secrets | `<method>` item 13 (line 100); reinforced in `<constraints>` (line 112: never ssh/scp/rsync, never read `.env`/`~/.ssh`/`state/raw_host/`, never print credentials including `ANTHROPIC_API_KEY`) and `<role>` (line 2). |
| 14 | Propagation-audit expectations | `<method>` item 14 (line 102): stable fact IDs, cross-referencing rule, `PROPAGATION_NOTES.md` content spec, honest VERIFIED-threshold rule (2 independent sources or primary+corroboration). |
| — | General constraints (untrusted web content, ~40 min budget, writes confined to `research/R2/`, no secrets in artifacts) | `<method>` closing paragraph (lines 103-104); reinforced throughout `<constraints>` (lines 107-119). |

**Result: PASS — all 14 items mapped, no gaps.**
