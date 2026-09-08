# EXECUTION_STATE

## Current phase
Phase 13: synthesis + contradiction/propagation audit (Fable `research-synthesizer` running; budget 25 min). Then Grill-Me (approved prompt, Opus) → Ponytail pass 1 → lead architecture decision → `research/DECISIONS.md` → CLAUDE.md freeze → checkpoint. Clock started 2026-09-08T21:00:43Z; research phase ended ≈23:12Z (elapsed ≈2h12m vs ≈2h25m target for end-of-research — we are inside the envelope again after the timestamp correction).

## Completed
- Phases 1–12: contract, SSH, workbench, TCI recon (now 193 probes), CLAUDE.md v1, five Wixie prompts approved, five research tracks complete (R1 57 facts; R2 19; R3 66 + 39 laws + 51 fixtures; R4 60; R5 58), Grill-Me prompt Wixie-DEPLOY and approved.
- User decisions: derived schema (AM-1 settled), repo private + full history pushed (checkpoints 1–4 + fixes on origin/main, attribution verified), API-key redact-and-disclose at export.
- Lead-executed observation answers for R4/R5 in `research/OBSERVATION_ANSWERS.md` (R1/R3 answers being appended).
- Tool use so far: Wixie (6 lifecycles), Pech, Emu (formal post-research checkpoint), Lich (bridge fix), deep-research + Vis (R1–R5), Crawlee + Trafilatura (R2 and others), TCI.

## Active agents
- research-synthesizer (fable) → research/{FACTS.jsonl, SOURCES.jsonl, DESIGN_LAWS.md, PRIOR_ART.md, CONTRADICTIONS.md, DECISIONS.md (draft), INDEX.md, PROPAGATION_AUDIT.md}

## Important artifacts
- task/derived/{TASK_CONTRACT.md, finding.schema.json (DERIVED), SCHEMA_PROVENANCE.md}
- state/{HOST_SNAPSHOT.json, HOST_SNAPSHOT.evidence.json, HOST_SUMMARY.md, NOTES_INPUTS.md, TOOL_USAGE.md, USAGE_REPORT.md, emu/}
- research/R1..R5/*, research/OBSERVATION_ANSWERS.md; prompts/{R1..R5,GRILL}/prompt.md; prompts/raw/IMPL.intent.md (skeleton)
- tooling/{tci/, extract_schema.py, emu_checkpoint.sh, measure_usage.py, build_snapshot.py}

## Frozen decisions
- Go; local orchestration + controlled SSH; TCI-only host observation; research agents get no SSH
- Cross-compile static linux/amd64 (host has no Go); upload via scp/rsync per Lava cheatsheet
- Validation source: task/derived/finding.schema.json (derived; disclosed in NOTES)
- Git: private repo, push checkpoints, no squash; public only after release audit + explicit approval
- Export: redact the single API-key value + disclose; include both session transcripts
- Bash tool rule: no apostrophes inside heredocs; probe ids lowercase

## Open questions (decide at architecture freeze)
- Custom category: boot/firmware trust (R2/R4 favour; Lava benchmark example is Kernel Flags) vs storage data-at-rest posture (kickoff hint; R4: strong but narrow; unused nvme1n1 = decommissioning-hygiene angle) vs both
- x/sys (R1 REUSE) vs stdlib syscall only (R5); schema validation test-only (R1) vs runtime self-check (R5)
- sshd -G unprivileged (R1) — host answer pending in this turn
- Severity-vs-status rule (AM-4/D6)

## Blockers
- None.

## Next 3 actions
1. Append R1/R3 observation answers; collect synthesizer output; check propagation-audit survivals and fix lead artifacts
2. Launch architecture-challenger (Grill-Me, Opus) on the KB → Ponytail pass 1 → lead decision → DECISIONS.md final → CLAUDE.md freeze → checkpoint 5
3. Fill IMPL.intent.md placeholders → Wixie lifecycle → approval → vertical slice
