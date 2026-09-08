# EXECUTION_STATE

## Current phase
Phase 12: R1–R5 research workers running in parallel (launched ~01:45Z on 2026-09-09; 40-min box each; budget 45 min). Expected artifacts: `research/R{1..5}/{REPORT.md, facts.jsonl, sources.jsonl, PROVENANCE.md, OBSERVATION_REQUESTS.md, PROPAGATION_NOTES.md}` + track deliverables. Clock started 2026-09-08T21:00:43Z; elapsed at last update ≈ 2h50m against a ≈1h40m target for this point. Overrun sources: workbench bootstrap depth, TCI build, two recon fixes, five full Wixie lifecycles (~25 min), a gate interruption/session fork. Recovery plan: synthesis + architecture tightly boxed (25 min), implementation via one vertical slice then expansion, protect testing/review/real-host validation.

## Completed
- Phases 1–5, 7, 9–11: contract (56 reqs), SSH plan + connection, workbench (12 tools), TCI recon (169 probes) → sanitized HOST_SNAPSHOT, CLAUDE.md v1, models chosen, five Wixie production prompts (R1/R4/R5 DEPLOY, R2/R3 HOLD-on-dispersion), all five approved by the user, R5 gate re-presented after the UI omission.
- User decisions (2026-09-09): schema derived from the brief (`task/derived/finding.schema.json` + SCHEMA_PROVENANCE.md; AM-1 settled); repo made PRIVATE and full engineering history pushed (checkpoints 1–2 on origin/main, attribution klaiderman verified); API-key value in one sub-agent transcript → redact + disclose at export.
- Tool use so far: Wixie (5 lifecycles), Pech (usage measurement), Lich (bridge fix; witness pending), TCI (recon). See state/TOOL_USAGE.md.

## Active agents
- r1-build-vs-buy (opus), r2-lava-context (sonnet), r3-sensor-evidence (opus), r4-host-investigation (opus), r5-go-architecture (opus) → research/R1..R5/

## Important artifacts
- task/derived/{TASK_OVERVIEW,TASK_CONTRACT,TASK_INDEX}.md, task_contract.json, finding.schema.json (DERIVED), SCHEMA_PROVENANCE.md
- state/{SSH_PLAN.md, HOST_SNAPSHOT.json, HOST_SNAPSHOT.evidence.json, HOST_SUMMARY.md, NOTES_INPUTS.md, TOOL_USAGE.md, USAGE_REPORT.md, usage.jsonl, time_events.jsonl}
- prompts/raw/* (intents, contract, launch notes); prompts/R1..R5/* (production prompts + Wixie artifacts)
- tooling/{tci/, loadenv.sh, build_snapshot.py, fill_intents.py, extract_schema.py, measure_usage.py, lich_wsl_bridge_fix.patch, LICH_WITNESS_PLAN.md}

## Frozen decisions
- Go; local orchestration + controlled SSH; TCI-only host observation; research agents get no SSH
- Cross-compile static linux/amd64 (host has no Go); upload via scp/rsync per Lava cheatsheet
- Validation source: task/derived/finding.schema.json (derived); disclose in NOTES
- Git: private repo, push checkpoints, no squash; public only after end-of-exercise release audit + explicit approval
- Export: redact the single API-key value, disclose in NOTES; include both session transcripts (573ece1e… and fork b64b46f1…)
- Bash tool rule: no apostrophes inside heredocs; prose/Python via Write tool

## Open questions
- Custom category choice (storage vs kernel/boot chain vs other) — decided after R2/R4 evidence + Grill-Me
- Severity-vs-status rule (AM-4/D6) — confirm at architecture freeze with R3 input
- Lich witness for a Go binary — adapter plan exists; decide at review phase

## Blockers
- None.

## Next 3 actions
1. Collect R1–R5 final reports → build research KB (INDEX, FACTS, SOURCES, DESIGN_LAWS, PRIOR_ART, CONTRADICTIONS) via a synthesis agent; Emu checkpoint; propagation audit
2. Grill-Me: four architecture options + challenger (Opus) + Ponytail pass → Fable decision → research/DECISIONS.md → CLAUDE.md freeze → checkpoint 3
3. Implementation prompt through Wixie → approval → vertical slice
