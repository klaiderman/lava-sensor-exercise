# EXECUTION_STATE

## Current phase
Phase 16: implementation — vertical slice (`implementation-author`, claude-opus-5, approved prompt `prompts/IMPL/prompt.md` after a user-requested hardening-only pass: 12/12 attacks, 4 minimal patches, HOLD 8.65/σ0.833 accepted). The author stops after the slice; the lead validates `sensor/bin/findings.wsl.json` against `task/derived/finding.schema.json`, then resumes the author for Tier 1 → Tier 2 → tests → README. Clock started 2026-09-08T21:00:43Z; elapsed ≈3h37m at 00:37Z. Remaining: slice ~25 min → expansion ~50 min → test lab (test-lab-author) ~25 min → prefilter + fresh-Fable review + Lich ~25 min → Ponytail pass 2 → real-host run ~10 min → audit/export/NOTES/clean-room/tarball ~30 min. Over the 4 h guideline (≈6 h active expected); validation phases protected.

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

## Packaging-time checklist additions (do not forget)
- Ask the user for the FINAL Claude Code Usage panel figure and refresh the authoritative row in state/USAGE_REPORT.md (mid-run snapshot $263.46 at 00:21Z); Pech / measure_usage.py stay secondary token evidence.
- Ship BOTH native session JSONL files (573ece1e… + fork b64b46f1…); NOTES must say mid-turn (/btw) messages live in attachment records, not user turns (state/BTW_INDEX.md).

## Next 3 actions
1. Ponytail pass 1 result → LD-9 → DECISIONS.md final → CLAUDE.md architecture freeze → checkpoint 7
2. CHECK_REGISTRY.md → fill IMPL.intent.md placeholders → Wixie lifecycle (Sonnet engineer) → AskUserQuestion approval
3. Launch implementation-author (Opus): vertical slice → schema validation → full check set; in parallel prepare fixture profiles A/B/C from FIXTURE_MATRIX
