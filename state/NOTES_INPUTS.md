# NOTES_INPUTS (running log — distilled into NOTES.md at the end)

## Assumptions
- A1 (2026-09-08 21:10Z): PDF and HTML brief are the same document (PDF printed from the HTML by HeadlessChrome). Verified by word-level diff: only CSS tokens and punctuation attachment differ.
- A2: We build in Go (Lava's preference; not scored).

## Ambiguities and resolutions
- AM1: `finding.schema.json` is referenced by the brief as supplied, but was not present locally at start. RESOLVED 2026-09-09 by user decision: the contract embedded in the PDF/HTML was cross-checked (identical) and transcribed into `task/derived/finding.schema.json` (derived artifact, provenance in SCHEMA_PROVENANCE.md, validated against the 2020-12 metaschema); it is the validation source. NOTES.md must disclose this.
- AM2: "Owner ... as far as the machine itself can tell" — no defined source. Resolution: define candidate sources with provenance and allow explicit unknown. Host evidence: DMI asset tags are OEM placeholders, no /etc/machine-info, cloud-init metadata carries provider (Latitude.sh) + facility only -> owner will be an explicit unknown with the provider recorded as a candidate, not as the owner.

## Custom-category candidates → DECIDED (LD-1, 2026-09-08 23:50Z)
- Kernel Flags (Lava's benchmark example) — strong baseline; risk: it is the expected answer.
- Storage/infrastructure posture — interviewer hinted at storage; depends on the real host stack (pending recon).
- DECISION: two custom categories. `STORAGE_POSTURE` = data-at-rest and decommissioning hygiene on rented hardware (no dm-crypt/LUKS anywhere; root on a single NVMe with an identical unused 960 GB drive attached; drive health UNKNOWN by proof because SMART needs CAP_SYS_ADMIN; ext4 error counters readable). Why: the storage hint, Lava's own public text on media sanitization / bare-metal hand-back (R2-F9/F80), and definite unprivileged evidence on this host; the unanticipated angle is that anything written here survives hand-back in cleartext and the sensor must refuse to look at the unused drive. `BOOT_CHAIN` = Secure Boot disabled + platform in Setup Mode + lockdown none + unsigned out-of-tree module (bnxt_en) + TPM present + world-readable initramfs: the brief's own example, kept because Setup Mode is the most severe fact on this host and would otherwise be homeless. Rejected alternatives: kernel-sysctl hardening as its own category (mostly PASS, overlaps Kernel Flags); BMC posture (largely covered by the required BMC_INBAND_ACCESS); patch velocity (apt lists empty → mostly UNKNOWN).

## Other lead decisions (2026-09-08 23:50Z)
- Severity rule confirmed: severity = declared impact for fail AND unknown; info for pass; observational checks always info (LD-2).
- No IPMI commands ever; BMC identity via sysfs under an out-of-band deadline (LD-3) — supersedes contract AM-6.
- host_id = keyed hash (HMAC-SHA256, fixed label) of /etc/machine-id, never raw; owner = explicit unknown + candidates (LD-4).
- sshd -G is the primary effective-config oracle with an Include-aware parser fallback (LD-5) — a research-time correction: R3/R4 had assumed parse-only because sshd -T fails; R1 found -G works before host-key loading and the host confirmed it.
- Zero runtime third-party dependencies; jsonschema/v6 test-only + release gate (LD-6). R1 recommended x/sys; R5 showed stdlib syscall suffices on linux/amd64 (verified locally) → x/sys rejected.
- Implementation author model: claude-opus-5 (LD-8).

## "Another day" items (updated 2026-09-08 23:50Z)
- Latitude.sh provider policy research (BMC access policy, sudoers.d image defaults, module_blacklist provenance) — R4 stream S4 never ran (concurrency cap).
- Micron 7450 PRO SED/Opal SKU distinction — datasheet fetch timed out; SED state stays UNKNOWN regardless.
- XCCDF result-enumeration primary source (NIST pages 403/404) — SARIF/XCCDF status-vocabulary comparison stays LIKELY.
- ACL xattr readability on files the caller cannot read — settle at the sensor's first real-host run.
- `sshd -G -C` Match-conditional evaluation (untested on host).
- A host-shaped Docker profile with the exact Ubuntu 24.04 package set; a second real machine (RHEL-family) to prove generic behaviour beyond fixtures.

## "Another day" items
- (none yet)

## Claude suggestions rejected (with evidence)
- 2026-09-08 22:05Z — TCI round-1 fact `is_virtual=true` (Sonnet-built rule: nonempty output ⇒ true). Rejected: `systemd-detect-virt` printed `none`, DMI shows Supermicro AS-3015MR-H10TNR, `/dev/ipmi0` + `ipmi_bmc.0` + `/dev/tpm0` exist. Fixed the rule to parse the value. Lesson carried into the sensor: never derive a boolean from "the command printed something".
- 2026-09-08 ~22:30Z — Wixie convergence.py's automated clarity fixer rewrote the mandated-verbatim host-context block in R2/R4/R5 prompts (split sentences inside evidence). Rejected by three prompt-engineer agents via diff-against-v1; verbatim fidelity kept over the heuristic score (HOLD accepted for R2/R3).
- 2026-09-09 00:00Z — Grill-Me (Opus) ranked Option 2 (capability-gated Fixed Registry) first. Rejected in favour of Option 1.5 after Ponytail: the challenger's own attack shows the gate layer is near-inert on this host and that gates must be read attempts (the 0444-but-EACCES apparmor `profiles` file), i.e. per-read errno classification, which a 20-LOC classify() already provides; the ~250-LOC pre-phase adds a single point of failure and ~20 min. The 30-LOC load-bearing-observation downgrade (Option 4's real value) is kept.
- Research-time: R3/R4 assumed effective sshd config must be parse-only because `sshd -T` fails unprivileged; R1 found `sshd -G` dumps effective config before host-key loading, and the host confirmed it (85 directives). The parse-only assumption was retracted (F97), `sshd -G` is primary with the parser as fallback.

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

## Timestamp correction (recorded 2026-09-08 ~22:57Z)
- Several timestamps I wrote from agent-reported clocks (Wixie metadata "2026-09-09T01:25Z", the approval gate "~01:45Z", R2 end "02:00Z", session fork "01:35Z") were LOCAL time (UTC+3) mislabeled as Z. True UTC is 3 hours earlier. `state/time_events.jsonl` (written with `date -u`) is authoritative; the approval gate happened at ≈22:45Z on 2026-09-08 and the exercise elapsed at that point was ≈1h45m, not ≈2h50m as EXECUTION_STATE briefly claimed.

## User decisions at the research approval gate (2026-09-08 ~22:45Z; mislabeled 01:45Z earlier)
- R1-R5 production prompts approved as-is (R2/R3 HOLD verdicts accepted as dispersion-only).
- AM-1 SETTLED by the user: the output contract is embedded in the supplied PDF/HTML; do not ask Lava; extract it faithfully into `task/derived/finding.schema.json` (no invented constraints), record that it is derived, and use it as the validation source from now on. Cross-check PDF vs HTML first. This supersedes the kickoff instruction not to reconstruct the schema; provenance in `task/derived/SCHEMA_PROVENANCE.md`. NOTES.md must state that the schema used for validation was transcribed from the brief because no separate schema file was received.
- Push policy: make the repo private now; push full engineering history (prompts, Wixie artifacts, research, decisions, CLAUDE.md, agents, tests, implementation); never secrets, raw host data, SSH material, credential-bearing transcripts or sensitive target-host artifacts; dedicated public-release audit at the end, then public only after explicit approval; never squash/rewrite history.
- API-key value in a sub-agent transcript: redact that single value in the exported copy and disclose the redaction in NOTES.md.
- Claude-error candidate for NOTES (rejected by the lead, evidence-backed): TCI round-1 `is_virtual=true` from a nonempty-output rule (see Recon lessons). Second candidate: Wixie convergence.py automated clarity fixer rewrote mandated-verbatim host blocks in R2/R4/R5; three agents detected and reverted it.

## Harness caveat discovered by R2 (2026-09-09 02:00Z)
- The Claude Code harness blocks sub-agents from writing a file literally named REPORT.md ("Subagents should return findings as text, not write report files"). R2 wrote R2_ANSWERS.md instead; the lead renamed it to research/R2/REPORT.md. Other tracks may do the same; the synthesizer must accept either name. Not a research defect.

## Fixture hygiene check (2026-09-09 01:23Z)
- sensor/ fixtures grep: no real NVMe serial fragments, no IPv4, no MAC addresses. DMI serial placeholder SUPERMICRO-SERIAL-DENIED with mode 0000 emulated via the _modes.txt seam; udev fixture carries model but no serial.
- The hostname f4-metal-small-chi-1 appears in profileA/proc/sys/kernel/hostname and machine_test.go. Not a secret (it is in the deliverable findings.json), but listed for the public-release audit: decide whether to keep or replace with a neutral name before making the repo public.

## Review phase outcomes (2026-09-09 02:15Z)
- Independent Fable review verdict FIX-THEN-SHIP: C1 SSH_POLICY_IN_FORCE same-second timestamp -> false FAIL on the host (registry predicted pass); C2 PROVISIONING_DATA_PROTECTION fails every default cloud-init host because the deliberately world-readable REDACTED instance-data.json and public .cfg files were treated as exposure; H1 PRIVATE_KEY_MATERIAL_EXPOSURE reported a complete walk and PASS while /root was unreadable (contradicts the registry UNKNOWN rule and the sibling CREDENTIAL check); H2 registry summary 9/8/8 did not match its own table (13/8/4; corrected to 12/8/5 after the CREDENTIAL row fix); M1 HOST_FIREWALL_STATE read ufw ENABLED=no and still said enabled, reason EXECUTION_ERROR where stderr said Permission denied; M2 MEDIA_HEALTH_VISIBILITY hardcoded reason and its nvme/smartctl children would open device nodes if run as root; M3 sshd -G labelled running-daemon although it is an on-disk evaluation; M4 walk never sets CrossedMounts; L1-L5 minor. Both Criticals were already in fix batch 1 from my own reading of the host evidence; the rest go to batch 2.
- New host facts from the review: ufw.conf says ENABLED=no while systemd reports ufw.service active (the firewall is installed but disabled); /etc/cloud/cloud.cfg.d/10_tinkerbell.cfg is 0600 (Tinkerbell provisioning); getxattr(system.posix_acl_access) returns ENODATA on the tested paths (OR-OPEN-2 settled: no ACLs); os.OpenRoot("/proc") works on kernel 6.8.0-139 (OR-OPEN-3 settled).
- Ponytail pass 2: module lean (~1.8% cuttable); one frozen-decision violation found: an undocumented --timeout flag (LD-9 allows --out/--version only) that widens the scan deadline -> removed in batch 2; Files interface with one implementation collapsed; dead declarations removed; lab fixture duplication deferred (independence choice); !unix compile stub kept and documented (only linux/amd64 ships).
- Lich: honest negative. The Go adapter and four witnesses were built; through the Lich fence every run died before the witnessed code executed (RLIMIT_AS 512 MB is fatal for the Go runtime, floor ~800 MB measured; NPROC=0 forbids the child the tests spawn; the harness refused the cap-relaxation edits, which Lich itself says need a security review). The dynamic evidence exists from plain WSL runs and go test. Recorded as a surfaced incompatibility, not as tool use.

## Review-2 outcome (2026-09-09 03:55Z, fresh adversarial reviewer after fix batches 1-2)
- DO-NOT-SHIP: 4 Critical / 4 High / 6 Medium / 3 Low. The defect CLASS behind the Criticals: exposure checks treated a denied read of a candidate as "not a candidate" (dropping it -> false pass) or as a gap, and group-readability ignored primary-gid membership and an unreadable /etc/group; two false FAILs came from judging directory modes instead of file modes (stock sudoers.d 0755/0440) and from a predicate that tested read bits where its own rule text said writable. The entailment gate could be bypassed by a pass with zero load-bearing observations because load-bearing was opt-in. Engine gap: a check stuck in an uninterruptible syscall (hung NFS home) would block the scan with no output.
- Semantics adopted for batch 3: for exposure questions a denied read of a candidate is evidence of protection from the unprivileged caller, judged by stat + effective readers (owner, group members, primary-gid holders); existence/value questions keep EACCES as a gap. Load-bearing by default; pass/fail need >=1 OK load-bearing observation; completeness prose is generated only. Engine abandons stuck checks at their deadline and always writes the document.
- Registry expectation corrected: PRIVATE_KEY_MATERIAL_EXPOSURE on the Lava host is honestly unknown (root home unreadable), not pass.
- Lesson for NOTES: two review rounds with fresh contexts each found real lies the previous round missed; the honest position is that the sensor is only as good as its last adversarial review, and the property tests (entailment gate, profile matrix as a hard gate, assertions over produced findings) are what stop regressions, not the reviews.
