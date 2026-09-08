# EXECUTION_STATE

## Current phase
Phase 10: Wixie full lifecycles for R1–R5 running in parallel (5 Sonnet prompt-engineers). Budget 20 min. Expected artifact: `prompts/R{1..5}/prompt.md` + metadata/tests/audit/contract-check. Next gate: show all five to the user + AskUserQuestion approvals (plus 3 open decisions). Clock started 2026-09-08T21:00:43Z; elapsed at last update ~85 min (target for this point ≈ 55 min; overrun came from workbench scan/bootstrap depth, TCI build, and two recon fixes — recover by keeping research strictly time-boxed at 40 min and running synthesis/architecture tightly).

## Completed
- Phases 1–3: clock, environment sanity, both originals read (PDF≡HTML), TASK_OVERVIEW, TASK_CONTRACT (56 reqs, 8 ambiguities, 6 pending-schema), TASK_INDEX, task_contract.json
- Phase 4: SSH_PLAN; first harmless connection; host key TOFU into ~/.ssh/known_hosts.lava
- Workbench: 12 tools scanned/installed/smoke-tested (tooling/bootstrap_*.md); TOOL_USAGE.md seeded (all NOT_YET_USED)
- Phase 5: Tiny Custom Investigator built (175-probe registry, validator, 33 tests); recon rounds 1–2 (169 probes, 9 facts, 0 unresolved); registry fixes (is_virtual rule, ipmi dev probe); HOST_SNAPSHOT.json + HOST_SNAPSHOT.evidence.json (sanitized) + HOST_SUMMARY.md
- Phase 7: root CLAUDE.md (v1 with host facts)
- Phase 9: models chosen — R1 Opus 5, R2 Sonnet 5, R3 Opus 5, R4 Opus 5 (promoted), R5 Opus 5; intents filled with host summary
- Git: checkpoint 1 committed locally (ea39434) as klaiderman; no pushes (repo is public — decision pending)

## Active agents
- wixie-prompt-engineer-R1..R5 (sonnet ×5) → prompts/R1..R5/
- usage-measurer (sonnet) → tooling/measure_usage.py, state/usage.jsonl, state/USAGE_REPORT.md
- lich-fixer (sonnet) → tooling/lich_wsl_bridge_fix.patch, tooling/LICH_WITNESS_PLAN.md

## Important artifacts
- task/derived/{TASK_OVERVIEW,TASK_CONTRACT,TASK_INDEX}.md, task_contract.json
- state/{SSH_PLAN.md, HOST_SNAPSHOT.json, HOST_SNAPSHOT.evidence.json, HOST_SUMMARY.md, NOTES_INPUTS.md, TOOL_USAGE.md, time_events.jsonl}
- tooling/tci/ (recon executor), tooling/loadenv.sh, tooling/build_snapshot.py, tooling/fill_intents.py
- prompts/raw/{EXECUTION_CONTRACT.md, R1..R5.intent.md}; .claude/agents/wixie-prompt-engineer.md

## Frozen decisions
- Language Go; local orchestration + controlled SSH; workbench at ~/.lava-workbench; recon via TCI only; research agents get no SSH
- Cross-compile static linux/amd64 binary locally (host has no Go); upload per Lava cheatsheet (scp/rsync)
- Bash tool rule: no apostrophes inside heredocs (harness wrapping breaks); prose/Python via Write tool

## Open questions (for the user at the approval gate)
1. finding.schema.json — not on this machine; need the real file (blocks schema validation + AM-1/AM-5/AM-7 settlement)
2. GitHub repo klaiderman/lava-sensor-exercise is PUBLIC — make private, or keep public and push sanitized material only, or never push?
3. A bootstrap sub-agent printed the ANTHROPIC_API_KEY value (from ~/.claude/settings.json) into its own transcript — export unchanged (+rotate) or redact that one value with disclosure in NOTES?

## Blockers
- Schema file (validation only). Nothing else blocking.

## Next 3 actions
1. Collect 5 production prompts → verify CONTRACT_CHECK + verdicts → present to user → AskUserQuestion approvals (+3 open decisions)
2. Launch R1–R5 research workers (Opus/Sonnet per plan) with approved prompts; 40-min box
3. Meanwhile: Emu checkpoint procedure ready; test-lab substrate decision (Docker vs WSL) from the substrate check
