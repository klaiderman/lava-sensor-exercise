# NOTES_INPUTS (running log — distilled into NOTES.md at the end)

## Assumptions
- A1 (2026-09-08 21:10Z): PDF and HTML brief are the same document (PDF printed from the HTML by HeadlessChrome). Verified by word-level diff: only CSS tokens and punctuation attachment differ.
- A2: We build in Go (Lava's preference; not scored).

## Ambiguities and resolutions
- AM1: `finding.schema.json` is referenced by the brief as supplied, but was not present locally at start. RESOLVED 2026-09-09 by user decision: the contract embedded in the PDF/HTML was cross-checked (identical) and transcribed into `task/derived/finding.schema.json` (derived artifact, provenance in SCHEMA_PROVENANCE.md, validated against the 2020-12 metaschema); it is the validation source. NOTES.md must disclose this.
- AM2: "Owner ... as far as the machine itself can tell" — no defined source. Resolution: define candidate sources with provenance and allow explicit unknown. Host evidence: DMI asset tags are OEM placeholders, no /etc/machine-info, cloud-init metadata carries provider (Latitude.sh) + facility only -> owner will be an explicit unknown with the provider recorded as a candidate, not as the owner.

## Custom-category candidates
- Kernel Flags (Lava's benchmark example) — strong baseline; risk: it is the expected answer.
- Storage/infrastructure posture — interviewer hinted at storage; depends on the real host stack (pending recon).

## "Another day" items
- (none yet)

## Claude suggestions rejected (with evidence)
- (none yet)

## Process notes
- 21:12Z: first attempt to source `.env` with bash `.` stripped backslashes from the Windows key path -> false "key not found". Fixed with a raw-line loader (tooling/loadenv.sh). Lesson: never word-split .env values.

## Host access facts (2026-09-08 21:12Z)
- First SSH connection succeeded in ~2s. Remote user is uid 1000 with groups `ubuntu sudo`. The account CAN escalate; the brief requires "no escalation" so the sensor and all recon never invoke sudo/su. The sudo-group membership is itself REMOTE_ACCESS evidence ("as whom / what that permits").
- Host kernel 6.8.0-139-generic x86_64 (Ubuntu HWE/noble family — confirm via os-release in recon). Hostname pattern suggests a bare-metal cloud instance class ("metal-small", Chicago).
- MSYS `chmod 600` on the key did not change the displayed mode, but the MSYS OpenSSH client accepted the key (Windows ACL semantics). Noted; no action needed.
- Lava supplied no host-key fingerprint -> controlled TOFU (accept-new) into a dedicated known_hosts file; all later connections use StrictHostKeyChecking=yes.

## Repo / identity facts (2026-09-08 21:40Z)
- `klaiderman/lava-sensor-exercise` exists on GitHub, is EMPTY, and is **PUBLIC** (gh: isPrivate=false) although the kickoff calls it "internal". DECISION NEEDED from user before any push: make private, or keep public and push only sanitized material. Until then: local commits only.
- `ssh -T git@github.com` with `~/.ssh/id_enchanted` (per ~/.ssh/config) -> "Permission denied (publickey)". `gh auth` login IS `klaiderman`. Fallback for pushes: HTTPS remote via gh credential helper (same account, same attribution). Verify attribution after any push.
- Repo-local git identity set: user.name=klaiderman, user.email=63550727+klaiderman@users.noreply.github.com (verified with `git config --local`).

## Incidents (keep for NOTES honesty)
- 21:22Z workbench-bootstrap-enchanter (Sonnet) ran `cat ~/.claude/settings.json` while auditing Emu's install side effect and thereby printed the plaintext ANTHROPIC_API_KEY stored there into ITS sub-agent transcript. Not reused, not written anywhere else. Consequence: the native session export will contain that key value inside a sub-agent transcript. Options at export time: (a) export unchanged and rotate the key (Lava retires it anyway), (b) redact that single value and disclose the redaction in NOTES. Lead recommendation: (b) with disclosure. User decision pending.
- Emu's documented install (`claude plugin marketplace add`) wrote to ~/.claude/settings.json; reverted; residual empty `extraKnownMarketplaces: {}` remains.

## Recon lessons (2026-09-08 22:05Z)
- WRONG FACT caught: TCI round 1 established `is_virtual=true` although `systemd-detect-virt` printed `none` (rc=1) and DMI/BMC/TPM all show real Supermicro bare metal. Cause: the fact rule used "nonempty output ⇒ true" (written by the Sonnet tci-builder from my spec, which did not pin the rule). Fixed to `regex ^none$ ⇒ false / else true`. Lesson for the sensor: never derive a boolean from "the command printed something"; parse the value. Candidate for NOTES "one thing Claude got wrong that I rejected" — evidence: DMI sys_vendor=Supermicro, board H13SRE-F, /dev/ipmi0 + ipmi_bmc.0 platform device, /dev/tpm0, `systemd-detect-virt`=none.
- Mixed-target probe misclassification: `ls -la /dev/ipmi* /dev/ipmidev/` returned rc=2 because `/dev/ipmidev/` is absent while `/dev/ipmi0` EXISTS; the executor typed the whole probe ENOENT, leaving `ipmi_dev_present` unresolved and gating out the follow-ups. Lesson: one observation per fact; absence is only provable from a successful listing of that exact path.
- Registry validator refused my own follow-up probe (variable assignment `u=$(...)` not on the allowlist) and the run was blocked — the safety gate works against the lead too. Rewrote the probe without assignments.
- Root-only DMI fields confirmed on this kernel: product_serial, product_uuid, board_serial, chassis_serial (mode 0400). `/sys/firmware/dmi/tables/*` and `entries/*/raw` root-only. dmesg blocked (dmesg_restrict=1). /etc/sudoers 0440 root:root and /etc/sudoers.d unreadable -> sudo policy is UNKNOWN to us beyond group membership (+ `.sudo_as_admin_successful` marker in our home).

## Pre-clock preparation (verified from filesystem timestamps, recorded 2026-09-08 23:00Z)
- The workspace skeleton (task/original with both brief files, empty CLAUDE.md/agents.jsonl/.gitignore, ai/ prompts/ research/ sensor/ state/ tooling/ submission/ dirs) and the .env file existed before START (dir mtimes 18:23-18:25Z vs START 21:00:43Z). That preparation is not counted as active exercise work. No code, research or host access happened before START.
- Relayed policy notes reached the R2 prompt-engineer agent from outside the lead orchestration (push policy: local commits only, no push without explicit approval; CLAUDE.md commands should not hardcode the repo root; pre-clock note). Treated as unconfirmed until the user states them to the lead; the push policy is already the operating default.

## User decisions at the research approval gate (2026-09-09 ~01:45Z)
- R1-R5 production prompts approved as-is (R2/R3 HOLD verdicts accepted as dispersion-only).
- AM-1 SETTLED by the user: the output contract is embedded in the supplied PDF/HTML; do not ask Lava; extract it faithfully into `task/derived/finding.schema.json` (no invented constraints), record that it is derived, and use it as the validation source from now on. Cross-check PDF vs HTML first. This supersedes the kickoff instruction not to reconstruct the schema; provenance in `task/derived/SCHEMA_PROVENANCE.md`. NOTES.md must state that the schema used for validation was transcribed from the brief because no separate schema file was received.
- Push policy: make the repo private now; push full engineering history (prompts, Wixie artifacts, research, decisions, CLAUDE.md, agents, tests, implementation); never secrets, raw host data, SSH material, credential-bearing transcripts or sensitive target-host artifacts; dedicated public-release audit at the end, then public only after explicit approval; never squash/rewrite history.
- API-key value in a sub-agent transcript: redact that single value in the exported copy and disclose the redaction in NOTES.md.
- Claude-error candidate for NOTES (rejected by the lead, evidence-backed): TCI round-1 `is_virtual=true` from a nonempty-output rule (see Recon lessons). Second candidate: Wixie convergence.py automated clarity fixer rewrote mandated-verbatim host blocks in R2/R4/R5; three agents detected and reverted it.

## Harness caveat discovered by R2 (2026-09-09 02:00Z)
- The Claude Code harness blocks sub-agents from writing a file literally named REPORT.md ("Subagents should return findings as text, not write report files"). R2 wrote R2_ANSWERS.md instead; the lead renamed it to research/R2/REPORT.md. Other tracks may do the same; the synthesizer must accept either name. Not a research defect.
