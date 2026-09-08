# TASK_OVERVIEW — Lava Sensor Exercise (high-level map)

Sources: `task/original/Lava-Sensor-Exercise.html`, `task/original/Lava-Sensor-Exercise.pdf` (8 pages, printed from the same HTML by HeadlessChrome; word-level diff shows identical content). The referenced `finding.schema.json` was NOT supplied locally as of exercise start (see Risks).

## What Lava is asking us to build
A command-line **posture sensor** run as an unprivileged user on a real bare-metal Linux server:

    sensor scan --out findings.json

It must (1) **describe the machine** and (2) **check its posture** in categories, writing JSON that validates against `finding.schema.json`.

- Part one, machine description (at least): stable host identifier + hostname; owner "as far as the machine itself can tell"; hardware vendor/model, CPU model + core count, memory; OS distribution/version/kernel; storage block devices with model + size. Unknown must be said explicitly, never an empty string or a guess.
- Part two, categories: `REMOTE_ACCESS`, `SECRETS_ON_DISK`, `BMC_INBAND_ACCESS`, plus **at least one category of our own**. Each category >= 2 relevant checks; every check is its own finding with its own status (`pass|fail|unknown`), severity (`critical|high|medium|low|info`), title, reason (required on fail/unknown), evidence, collected_at.

## What problem they are testing
1. **Judgment** — graceful handling of unanswerable checks inside a clean, generic architecture. Not edge-case coverage.
2. **How we work with Claude** — what we specified before generating, what we rejected, what we verified before believing.
3. **Safety on someone else's machine** — read-only, bounded in time and output, does not fall over on the unexpected.

Explicitly NOT tested: prior BMC/IPMI/firmware knowledge, Go fluency, volume of checks.

## What they care about (signals from the brief)
- "Claiming to have checked when you could not is a critical failure." Silent omission destroys trust. UNKNOWN is a first-class answer.
- Evidence that lets a reader believe without re-running: path read, value found, command run, errno returned.
- "What is actually in force on the running system" vs what one config file says (REMOTE_ACCESS).
- Secrets: what is there AND how well protected (who can read it).
- BMC in-band: KCS path via `ipmi_si`/`ipmi_devintf`, device node, `ipmitool`; whether it exists and who is permitted.
- Severity `info` is a real answer. A handful of thoughtful checks beats twenty thin ones.
- Custom category with clear engineering intent; an unanticipated but well-supported category impresses most. Kernel Flags is their benchmark example.
- Machine description "matters more than it looks" once there is more than one server -> stable identity.

## What success looks like
- Source + the one command that runs it; it runs on their server as their user.
- `findings.json` from a real run on the supplied server, valid against the real schema.
- `NOTES.md` <= 1 page: assumptions; ambiguities + how settled; custom category + why; what we'd do with another day; one thing Claude got wrong that we rejected, with reason.
- The Claude session, exported, unedited ("messy real one is far better received").
- One tarball by email. No repo/accounts.

## Major constraints
Required: read-only; every subprocess bounded (timeout + output cap; nothing hangs on a non-answering device); one failing check cannot take others down; unprivileged, no escalation; use Claude and send the session.
Out of scope (ungraded, time sinks): daemon/scheduler, database, UI, API server, packaging, CI.
Language: any; Go preferred -> we build in Go.
Product follow-up topics (outbound-only config/updates, customer identity, volume, isolation) are conversation material only — not implementation scope.

## Obvious risks / unknowns
- **Schema missing locally.** Brief says the shape is fixed by `finding.schema.json`. We must obtain the real file; we will not reconstruct it from the JSON example. Blocks final validation, not recon/research/design.
- **SSH key path** from `.env` did not resolve at first attempt (backslash handling in the loader); must be fixed before recon.
- Unprivileged visibility on a bare-metal host: `dmidecode` needs root; `/sys/class/dmi/id/{product_uuid,board_serial}` usually root-only while `sys_vendor`/`product_name` are world-readable; `/dev/ipmi0` perms; `sshd -T` needs root -> effective sshd config must be derived (Include, drop-ins, Match blocks, runtime sockets) and honestly bounded.
- Stable `host_id`: `/etc/machine-id` (usually readable) vs DMI UUID (root) -> explicit precedence + provenance.
- "Owner" is inherently ambiguous -> define what the machine can tell (motd/issue, login banner, cloud-init/provisioning metadata, domain, certs) and allow explicit unknown.
- Secrets checks must never emit secret values; unprivileged scanning cannot read other users' files — that itself is evidence, not failure.
- Storage/infrastructure was flagged as a priority by the interviewer context; the host's real storage stack is unknown until recon.
- Orchestration overhead vs 4-hour guideline; protect real-host validation, correctness review and contract audit.

## Initial attack plan
1. Fix access blockers (schema file, key path) while workbench bootstraps in parallel.
2. Detailed TASK_CONTRACT + SSH_PLAN -> connect -> ~15 min broad, safe host recon (storage priority) -> HOST_SNAPSHOT.
3. Root CLAUDE.md. Wixie-engineer R1-R5 prompts -> approval -> parallel research via deep-research + Vis.
4. Synthesis + propagation audit -> Grill-Me architecture (4 options) -> freeze (default: Fixed Registry runtime, no runtime LLM).
5. Implementation prompt -> approval -> Go vertical slice -> schema validation -> full sensor.
6. Host-shaped local lab + fault injection + genericity profiles -> TEST_REPORT.
7. Staticcheck -> Hydra -> fresh Fable review -> Lich witness -> fixes -> re-verify.
8. Exact artifact on the real host -> real findings.json -> schema validation -> audit -> NOTES.md -> export -> clean-room -> tarball.
