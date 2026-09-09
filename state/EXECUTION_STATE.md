# EXECUTION_STATE

## Current phase
Phase 14: Grill-Me done → Ponytail pass 1 running → lead architecture decision (LD-9) → CLAUDE.md freeze. In parallel: `check-registry-drafter` (Opus) producing `research/CHECK_REGISTRY.md` (the concrete check list the implementation prompt needs). Clock started 2026-09-08T21:00:43Z; elapsed ≈2h55m at 23:55Z. Remaining chain estimate: LD-9 + freeze 10 min → implementation prompt Wixie lifecycle 15–20 min (parallel with nothing else blocking) → approval → implementation 70–90 min (Opus author) → test lab 25 min → Staticcheck/Hydra/Fable review/Lich 25 min → real-host run 10 min → audit/export/transcript/NOTES/clean-room/tarball 30 min. We will exceed the 4 h guideline (≈5.5–6 h active); validation phases are protected, optional polish is what gives.

## Completed
- Phases 1–13: contract, SSH, workbench, TCI recon (193-probe registry, 3 rounds), CLAUDE.md, five Wixie prompts approved, five research tracks, Fable synthesis (100 facts / 52 laws / 38 contradictions / propagation audit), lead decisions LD-1..LD-8 (`research/DECISIONS.md`), contract + summary + snapshot propagation fixes, all research observation requests answered or explicitly OPEN (`research/OBSERVATION_ANSWERS.md`, D-09).
- Grill-Me (approved prompt, Opus): `research/GRILL/{OPTIONS,ATTACKS,SCORECARD,OPEN_QUESTIONS}.md` — ranking Opt2 capability-gated Fixed Registry > Opt4 collector/evaluator > Opt1 flat > Opt3 data-driven (fatal); cheap steals identified.
- Test substrate ready: WSL Ubuntu 26.04 + Docker (profile A image `lava-sensor-testlab:profileA` built; `tooling/testlab/run_in_docker.sh` for profiles A/B/C).
- Git: checkpoints 1–6 on origin/main (private), attribution klaiderman verified.

## Active agents
- ponytail-reviewer-pass1 (opus) → reports/PONYTAIL_PASS1.md
- check-registry-drafter (opus) → research/CHECK_REGISTRY.md

## Important artifacts
- research/{DECISIONS.md, DESIGN_LAWS.md, PRIOR_ART.md, FACTS.jsonl, SOURCES.jsonl, CONTRADICTIONS.md, PROPAGATION_AUDIT.md, INDEX.md, OBSERVATION_ANSWERS.md, GRILL/}
- task/derived/{TASK_CONTRACT.md, finding.schema.json (DERIVED), SCHEMA_PROVENANCE.md}
- state/{HOST_SNAPSHOT.json, HOST_SNAPSHOT.evidence.json, HOST_SUMMARY.md, NOTES_INPUTS.md, TOOL_USAGE.md, emu/}
- prompts/raw/IMPL.intent.md (skeleton with placeholders), prompts/GRILL/prompt.md (approved)
- tooling/{tci/, testlab/, extract_schema.py, emu_checkpoint.sh, measure_usage.py, build_snapshot.py}

## Frozen decisions
- LD-1..LD-8 (see research/DECISIONS.md): two custom categories STORAGE_POSTURE + BOOT_CHAIN; severity = impact for fail/unknown, info for pass; no IPMI commands ever; host_id keyed hash of machine-id; sshd -G primary + parser fallback; zero runtime deps (jsonschema/v6 test-only + release gate); bounded primitives; implementation author claude-opus-5
- Earlier: Go; local orchestration + controlled SSH; TCI-only host observation; cross-compiled static linux/amd64; derived schema is the validation source; private repo, no squash; export redaction + disclosure

## Open questions
- LD-9 architecture shape — decide after Ponytail pass 1 (leaning Option 2 + steal #1 load-bearing-observation downgrade + steal #3 generated evidence + limited multiplicity for sshd -G vs walker)

## Blockers
- None.

## Next 3 actions
1. Ponytail pass 1 result → LD-9 → DECISIONS.md final → CLAUDE.md architecture freeze → checkpoint 7
2. CHECK_REGISTRY.md → fill IMPL.intent.md placeholders → Wixie lifecycle (Sonnet engineer) → AskUserQuestion approval
3. Launch implementation-author (Opus): vertical slice → schema validation → full check set; in parallel prepare fixture profiles A/B/C from FIXTURE_MATRIX
