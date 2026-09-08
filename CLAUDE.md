# Lava Sensor Exercise — project instructions

## What we are building
A read-only, bounded, unprivileged Linux posture sensor in Go (`sensor scan --out findings.json`) that describes the machine and reports per-check findings (`pass|fail|unknown`) validating against Lava's `finding.schema.json`. Host-first (Lava's real bare-metal server), generic by design (behaves correctly on other Linux machines by capability detection + fallbacks + explicit UNKNOWN). Deliverable is a tarball: source + one run command, real-host `findings.json`, one-page `NOTES.md`, the exported Claude session.

## Authoritative inputs (immutable)
- `task/original/Lava-Sensor-Exercise.html` (primary brief), `task/original/Lava-Sensor-Exercise.pdf` (same content)
- `task/original/finding.schema.json` — the ONLY schema source of truth. NOT present yet (asked for). Never reconstruct it from the brief's example; never maintain a second hand-written schema.

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
- Host recon (lead only): `python tooling/tci/tci.py --registry tooling/tci/probes.json --env-file /c/lava-sensor-exercise/.env --executor ssh --out-dir state/raw_host --snapshot state/HOST_SNAPSHOT.raw.json`
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
- Author ≠ reviewer: the implementation author never reviews; final independent review is a fresh Fable context that did not write the code.
- Git: local commits only until the user decides the push policy (remote is public). Identity must be `klaiderman` / `63550727+klaiderman@users.noreply.github.com` (verify `git config --local user.email` before committing). Never commit `.env`, keys, tokens, raw host artifacts.
- Update this file only when a durable project truth changes (architecture freeze, command changes, a recurring mistake becomes a rule, a reviewer-found invariant).

## Host facts established so far (details in `state/HOST_SNAPSHOT.json`; compact text in `state/HOST_SUMMARY.md`)
- Latitude.sh bare-metal Supermicro AS-3015MR-H10TNR (H13SRE-F), AMD EPYC 4484PX 12c/24t, ~93 GiB RAM, no swap; Ubuntu 24.04.4, running kernel 6.8.0-139-generic with 7.0.0-31 installed (reboot pending).
- Login user uid 1000 `ubuntu`, groups `ubuntu sudo`; sudoers unreadable; key-only SSH (OpenSSH 9.6p1, socket-activated, PermitRootLogin prohibit-password, PasswordAuthentication no).
- Storage: 2x Micron 7450 PRO NVMe; nvme0n1 = EFI + ext4 root; nvme1n1 unused (no partitions/fs); no dm/LVM/LUKS/md/multipath/network storage; SMART needs root.
- BMC: KCS via ipmi_si (ACPI IPI0001), `/dev/ipmi0` root-only 0600, BMC sysfs attrs readable (IPMI 2.0, Supermicro), no ipmitool; BMC USB NIC (aspeed_vhub RNDIS) present but DOWN.
- Boot/kernel: Secure Boot disabled + Setup Mode, lockdown none, tainted OE (unsigned out-of-tree `bnxt_en`), TPM 2.0 root-only, AppArmor on, dmesg_restrict 1.
- Host has gcc/make/tar/curl/rsync but NO Go: we cross-compile a static linux/amd64 binary locally and upload it (`scp`/`rsync` per Lava cheatsheet).
