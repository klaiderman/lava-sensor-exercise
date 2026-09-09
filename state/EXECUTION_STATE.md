# EXECUTION_STATE

## Current phase
Phase 19–20: review + fixes. Implementation complete (26 checks; 153 tests WSL) and test lab complete (reports/TEST_REPORT.md; 10/10 faults, 12/12 storage, schema/determinism PASS). First real-host run done (reports/real_host/findings.json: 26 checks, 88 ms, 10 pass / 11 fail / 5 unknown, exit 0, validator PASS). Fix batch 1 (5 defects: diskless-root unknown, smartctl JSON parse, SSH_POLICY_IN_FORCE timestamp resolution, provisioning payload-class rule, credential-file account scope) sent to the author. Running: fresh-Fable code-reviewer, Ponytail pass 2, Lich witness runner, transcript-HTML author. Clock started 2026-09-08T21:00:43Z; elapsed ≈5h05m at 02:05Z. Remaining: author + lab finish (~20 min) → Ponytail pass 2 (Opus) + Lich witness (Sonnet) + fresh-Fable code review in parallel (~25 min) → fixes → regression → re-verify → real-host run (tooling/host_run.sh) → final audits → export/redaction → transcript HTML → NOTES → clean-room → tarball (~45 min). Expected ≈6h active; validation phases protected.

## Completed
- Phases 1–16: contract, SSH, workbench, TCI recon (193 probes), CLAUDE.md, five Wixie prompts + research (R1–R5), Fable synthesis + propagation audit, decisions LD-1..LD-9 (architecture frozen: Option 1.5), CHECK_REGISTRY (25+1), IMPL prompt (Wixie + hardening-only pass) approved, vertical slice lead-validated (schema PASS), all 26 checks implemented (WSL uid 1000: 8 pass / 5 fail / 13 unknown; validator PASS 0 violations).
- Tooling ready: validate_findings.py (self-tested), host_run.sh (SSH_PLAN-exact), prefilter.sh (run), testlab Docker profile A image, emu_checkpoint.sh, extract_schema.py, measure_usage.py.
- Ledgers: agents.jsonl, time_events.jsonl, TOOL_USAGE.md (Wixie, Vis, deep-research, Trafilatura, Crawlee, Pech, Emu, Ponytail-1, Lich-fix, Staticcheck, Hydra logged; Lich witness + Ponytail-2 + Crawl4AI-in-research pending), USAGE_REPORT.md (authoritative $263.46 snapshot; final refresh due), BTW_INDEX.md.
- Git: checkpoints 1–10 on origin/main (private), attribution klaiderman verified.

## Active agents
- implementation-author (opus): per-check tests, Docker run, README, IMPLEMENTATION_NOTES → final report
- test-lab-author (sonnet): profiles A/B/C, fault injection, storage matrix, schema tests, real-binary runs → reports/TEST_REPORT.md

## Important artifacts
- sensor/ (Go module `lava-sensor-exercise/sensor`), reports/{PREFILTER.md, IMPLEMENTATION_NOTES.md, PONYTAIL_PASS1.md, testlab/}, research/{DECISIONS.md, CHECK_REGISTRY.md, DESIGN_LAWS.md, …}, task/derived/finding.schema.json (DERIVED), state/HOST_SNAPSHOT*.json, prompts/*/prompt.md

## Frozen decisions
- LD-1..LD-9 (research/DECISIONS.md); derived schema is the validation source; private repo, no squash, public only after release audit + approval; export: redact one API-key value + disclose; both session JSONL files ship; Claude Code Usage panel = authoritative cost, Pech secondary.

## Open questions
- None blocking. Release-audit items: hostname in fixtures/tests; sanitized snapshot files in the repo.

## Blockers
- None.

## Packaging-time checklist additions (do not forget)
- Ask the user for the FINAL Claude Code Usage panel figure and refresh the authoritative row in state/USAGE_REPORT.md (mid-run snapshot $263.46 at 00:21Z).
- Ship BOTH native session JSONL files (573ece1e… + fork b64b46f1…), redact the single API-key value in the exported copy, disclose in NOTES; NOTES must say mid-turn (/btw) messages live in attachment records (state/BTW_INDEX.md).
- Emu checkpoint before final implementation/review (formal #2); Pech/measure_usage re-run; TOOL_USAGE final audit incl. Crawl4AI evidence from research PROVENANCE files.

## Next 3 actions
1. Collect author + lab reports → Emu checkpoint #2 → launch Ponytail pass 2 (Opus), Lich witness runner (Sonnet), fresh-Fable code-reviewer in parallel
2. Triage findings → author fixes → regression (go test, validator, prefilter re-run) → independent re-verification of important defects
3. Real-host run via tooling/host_run.sh → compare with HOST_SUMMARY/CHECK_REGISTRY predictions → final audits (contract, safety, tool use) → export + redaction → transcript HTML → NOTES.md → clean-room gate → tarball
