# Emu Checkpoint
> Saved at: 2026-09-08T23:14:01Z
> Session: 408b8879

## Branch
main

## Modified Files
agents.jsonl
research/R1/PROVENANCE.md
research/R1/REPORT.md
research/R3/REPORT.md
state/HOST_SNAPSHOT.evidence.json
state/HOST_SNAPSHOT.json
state/HOST_SNAPSHOT.raw.json
state/time_events.jsonl
tooling/tci/check_registry.py
tooling/tci/probes.json

## Staged Files
None

## Recent Commits
67de14c checkpoint 4: research R2/R4/R5 complete (R1/R3 in progress), TCI follow-up probes for R4/R5 observation requests, OBSERVATION_ANSWERS, snapshot mdadm.conf correction, Emu checkpoint smoke, agent definitions
4ef3b59 tooling: Emu checkpoint script (real PreCompact hook + manual checkpoint, mirrored to state/emu), research-synthesizer agent definition, Grill-Me intent; R2 research complete
d0d863d schema: drop invalid fragment $id from derived finding.schema.json; provenance note on format assertion; validated (metaschema + 8 behavioural checks)
a86407d checkpoint 3: derived finding.schema.json + provenance (AM-1 settled by user), contract/CLAUDE.md schema updates, gitignore research scratch, execution state
cc4013d checkpoint 2: Wixie production prompts R1-R5 (approved), TCI recon fixes, tool usage + Pech usage measurement, Lich bridge fix, worker launch notes
ea39434 checkpoint 1: task contract, SSH plan, host recon snapshot, initial CLAUDE.md, TCI tooling, R1-R5 intents

## Project Instructions
# Lava Sensor Exercise — project instructions

## What we are building
A read-only, bounded, unprivileged Linux posture sensor in Go (`sensor scan --out findings.json`) that describes the machine and reports per-check findings (`pass|fail|unknown`) validating against Lava's `finding.schema.json`. Host-first (Lava's real bare-metal server), generic by design (behaves correctly on other Linux machines by capability detection + fallbacks + explicit UNKNOWN). Deliverable is a tarball: source + one run command, real-host `findings.json`, one-page `NOTES.md`, the exported Claude session.

## Authoritative inputs (immutable)
- `task/original/Lava-Sensor-Exercise.html` (primary brief), `task/original/Lava-Sensor-Exercise.pdf` (same content)
- Schema: no separate `finding.schema.json` was supplied. By user decision (2026-09-09) the contract embedded in the brief was transcribed into `task/derived/finding.schema.json` (DERIVED artifact, draft 2020-12; provenance in `task/derived/SCHEMA_PROVENANCE.md`). That file is the single validation source for tests and the final output; never fork a second hand-written schema; regenerate it only via `python tooling/extract_schema.py`.

## Where things live
- Task understanding: `task/derived/TASK_OVERVIEW.md`, `task/derived/TASK_CONTRACT.md` (requirement IDs A1…F5, ambiguities AM-1…AM-8), `task/derived/task_contract.json`, `task/derived/TASK_INDEX.md`
- Host access + evidence: `state/SSH_PLAN.md`, `state/HOST_SNAPSHOT.json` (sanitized, agent-visible), `state/raw_host/` (raw probe output, gitignored, lead-only)
- Run state: `state/EXECUTION_STATE.md` (phase, agents, next actions), `state/NOTES_INPUTS.md` (assumptions/ambiguities/rejections as they happen), `state/time_events.jsonl`, `state/TOOL_USAGE.md`, `state/usage.jsonl`
- Research KB: `research/` (`INDEX.md`, `FACTS.jsonl`, `SOURCES.jsonl`, `DESIGN_LAWS.md`, `PRIOR_ART.md`, `CONTRADICTIONS.md`, `DECISIONS.md`, per-track `R1..R5/`)
- Prompts: `prompts/raw/*.intent.md` (lead intents), `prompts/R*/prompt.md` (Wixie production prompts + metadata)
- Sensor: `sensor/` (Go module; tests + `testdata/` fixtures live with the source)
- Reports: `reports/` (`TEST_REPORT.md`, `claude-transcript.html`); staging: `submission/`; agent tree: `agents.jsonl` (append-only)
- Tooling: `tooling/loadenv.sh` (safe `.env` loader — never `source .env` directly), `tooling/tci/` (Tiny Custom Investigator: probe registry + trusted SSH executor)
- Workbench (external tools) is OUTSIDE the repo at `$HOME/.lava-workbench/`; project-scoped agents in `.claude/agents/`

## Commands (current)
- Load target env without printing values: `. tooling/loadenv.sh` (exports `TARGET_HOST`, `TARGET_USER`, `SSH_KEY_PATH`, `SSH_KEY_PATH_UNIX`)
- Host recon (lead only, run from the repo root): `python tooling/tci/tci.py --registry tooling/tci/probes.json --env-file .env --executor ssh --out-dir state/raw_host --snapshot state/HOST_SNAPSHOT.raw.json` then `python tooling/build_snapshot.py`
- Validate probe registry: `python tooling/tci/check_registry.py tooling/tci/probes.json`
- Build/test/run sensor: (filled in at the vertical slice)
- Final run on the host: (filled in after implementation; exact documented command only)

## Core safety invariants (apply to recon AND the sensor)
- Read only. Never change the target: no writes outside the output file, no service/module/config changes, no network calls from the sensor.
- Bounded. Every subprocess has a timeout and an output cap; file reads are capped and only regular files are opened (never device nodes/FIFOs); bounded directory walks; whole-scan deadline.
- Isolated. One check failing (panic, timeout, malformed data) never affects the others.
- Unprivileged. Never `sudo`/`su`/`doas`; the target account is in group `sudo` — irrelevant, unused, reported as evidence only.
- No secret values in evidence, logs, transcripts or artifacts: metadata only (path, mode, owner, type, size). Never print `.env`, keys, tokens, `ANTHROPIC_API_KEY`.

## Evidence semantics (PASS / FAIL / UNKNOWN)
- Every registered check emits exactly one finding per run. Never silently skip a check. `unknown` requires a `reason` and evidence of why (errno, missing utility, timeout, budget).
- TIMEOUT ≠ false. EACCES ≠ absent. UNSUPPORTED ≠ false. EXECUTION_ERROR ≠ false. Missing utility ≠ missing capability (prefer sysfs/procfs; exec is a fallback). Absence is only provable from a successful listing.
- Contradiction ≠ first observation wins: record both, report contested.
- Under-claiming is also a bug: if a fallback can establish the answer, use it before saying unknown.
- Evidence is actionable: path read, value found, command run, exit code/errno, timeout — not a restatement of the title.

## Design rules
- Host-first but generic-by-design: gate on capabilities/evidence, never on hostname/vendor/customer; deep branches for what the Lava host actually has; generic fallbacks + UNKNOWN elsewhere. Genericity must not weaken the Lava-host result.
- Runtime default: Fixed Registry of checks — deterministic, explicit, reviewable, bounded. No runtime LLM, no planner, no external rule engine. (Architecture freeze pending; see `research/DECISIONS.md`.)
- Stdlib → native OS primitive → justified dependency → minimal custom code. No daemon, DB, scheduler, API, UI, CI, packaging beyond the tarball.
- Testing uses test-only seams (fs root / runner injection inside packages), not a production "override root" flag.

## Process gates
- Research agents never get SSH; they file `OBSERVATION_REQUEST`s. Only the lead's TCI executor observes the host.
- Load-bearing prompts (R1–R5, implementation, load-bearing architecture) go through the FULL Wixie lifecycle to PRODUCTION_GRADE and need explicit user approval (`AskUserQuestion`) before launch.

## User-Flagged Context
2026-09-08T22:52:03Z TEST RUN (pre-synthesis smoke of Emu machinery): R1-R5 research launched 01:45Z; derived schema settled by user; repo private + pushed; awaiting R1/R3/R4/R5 reports.
2026-09-08T22:53:56Z SMOKE 2: Emu PreCompact hook with POSIX paths; research R1/R3/R4/R5 still running, R2 done; schema derived and validated; repo private, checkpoints 1-3 pushed.
2026-09-08T22:54:27Z SMOKE 3 (POSIX paths): Emu PreCompact hook digest test; R2 done, R1/R3/R4/R5 running; GRILL prompt lifecycle running.