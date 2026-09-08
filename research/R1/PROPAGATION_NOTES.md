# R1 — PROPAGATION NOTES

For every load-bearing fact: **if this is wrong or weakened, these conclusions must be re-checked.** Ordered by blast radius.

---

## Tier 1 — facts that would change the architecture

**R1-F47 — `sshd -G` works unprivileged (VERIFIED at source level, confidence 0.85, but NOT yet reproduced on the host).**
If wrong → the **REUSE** verdict for `sshd -G` collapses to **REJECT**, and the Include-aware parser (currently a cross-check) becomes the load-bearing component for the entire REMOTE_ACCESS category. Every effective-policy finding would then rest on our own re-implementation of OpenSSH semantics, which raises the cost of R1-F52 being right and makes SP-15 critical rather than merely important. **This is why R1-OR9 is the only `blocking: true` observation request in the track.** Weakened form (works but output shape differs from expectation): the oracle survives, only the parsing of its output changes.

**R1-F43 — a test-only import is not linked into the binary (VERIFIED, 0.90).**
If wrong → the entire "one runtime dependency" recommendation collapses. The schema validator would become a shipped dependency, adding `golang.org/x/text` and 15 packages to the customer-facing artifact, and the dependency-footprint argument in `BVB_MATRIX.md` §6 would need re-running. Everything in the recommended dependency list depends on this. Mitigation if it fails: validate output in a separate throwaway harness rather than in the sensor module at all.

**R1-F1 + R1-F2 — DMI identity attributes are 0400 and all raw SMBIOS routes are root-only (VERIFIED, 0.95/0.92).**
If wrong (i.e. some route *is* readable) → the REJECT verdicts on `u-root/pkg/smbios` and `digitalocean/go-smbios` reopen, and the machine-identity fallback ladder (B1a) could be shortened to use the DMI product UUID as a first-class stable id instead of falling through to `/etc/machine-id`. This would be a *better* outcome, so the risk is one of under-claiming rather than over-claiming. R1-OR2 closes it cheaply. Note the asymmetry: the host snapshot already observed EACCES on those attributes, so the fact is corroborated by observation even though the kernel-source reading was not reproduced locally (WSL2 has no DMI).

**R1-F48 — the 0444 BMC sysfs read triggers a live IPMI transaction with 5s+5s×10 KCS timeouts (VERIFIED, 0.90).**
If wrong (the read is cheap/cached) → SP-19's out-of-band deadline machinery is unnecessary complexity for the BMC category and could be dropped in favour of a plain context timeout. If **right and worse than modelled** (e.g. it also blocks other checks through a shared kernel lock) → the BMC check may need to run last, or behind an opt-out. R1-OR6 measures the real cost on a healthy BMC and is the cheapest way to size the constant from evidence rather than taste. **Under-reacting here is the failure mode that produces a sensor that hangs on someone's production box.**

---

## Tier 2 — facts that would change a category's design

**R1-F17 — POSIX ACLs are decodable in pure Go (VERIFIED, 0.90, byte-verified locally).**
If wrong → "who can read this" degrades from a proven answer to a mode-bits approximation across SECRETS_ON_DISK *and* BMC_INBAND_ACCESS (contract C5a and C6a both ask "who is permitted"). The `joshlf/go-acl` REJECT-as-dependency verdict would reopen. Known weakness already recorded: the `e_tag` constants are corroborated by a correct real-world decode but cited from `posix_acl_xattr.h` (struct layout) rather than `acl.h` (tag values), and `ACL_MASK` must be ANDed with `ACL_USER`/`ACL_GROUP` perms or the result over-states access.

**R1-F52 — Include expands inline, glob-sorted, first-match-wins, and Ubuntu's line-1 Include makes the drop-in win (VERIFIED, 0.90).**
If wrong → the REMOTE_ACCESS findings on this specific host would be **inverted**, since the drop-in and the main file disagree. This is the highest-consequence parsing fact in the track. It is partially insulated by R1-F47: if `sshd -G` is the oracle, the daemon resolves precedence for us and our parser only supplies provenance.

**R1-F30 + R1-F31 — efivars is world-readable with a 4-byte attribute prefix (VERIFIED, 0.95/0.90).**
If the prefix claim is wrong → the Secure Boot check reports the **opposite** value, confidently, with evidence that looks correct. If the world-readable claim is wrong → Secure Boot becomes `unknown` on every host and the custom Kernel-Flags category loses its strongest check. Both are corroborated by two independent primaries (kernel docs + osquery source) plus the host snapshot having already read the values as uid 1000, so confidence is high.

**R1-F26 — DMI entry directories are 0755 and listable while contents are 0400 (VERIFIED, 0.90).**
If wrong → SP-9 collapses and BMC_INBAND_ACCESS loses its firmware-corroboration check (SMBIOS type 38 / type 42 presence), falling back to module and sysfs evidence only. The category still works but is thinner. R1-OR7 closes it with one `ls`.

**R1-F15 + R1-F19 — gitleaks does not redact by default and content scanning structurally ingests key material (VERIFIED, 0.90/0.85).**
If wrong → the REJECT of content scanning as a *capability* weakens from a safety verdict to a preference, and the NOTES.md scope statement would need rewriting. It would not change the dependency list (we still would not embed a 144-module scanner), but it would change how we justify the omission to the customer.

---

## Tier 3 — facts that support a verdict but do not carry it alone

- **R1-F3/F4/F5 (ghw)** — if the source reading is wrong, ghw's REJECT weakens to a conditional one. The BUILD verdict for inventory survives regardless, because R1-F1/F2 mean no library can reach the privileged data anyway.
- **R1-F38/F39/F40/F41/F42 (validators)** — a mistake here changes *which* validator we pick, not whether we need one, and R1-F43 makes the choice nearly free either way.
- **R1-F27/F28/F29 (BMC prior art)** — these support the BUILD verdict; R1-F23 (the 0600 default) carries it alone.
- **R1-F33/F34/F35/F36 (kernel flags)** — individually cheap to re-verify; each supports one check rather than a design.
- **R1-F54 (socket activation)** — LIKELY only (0.70), because Debian's actual `ssh.socket` text could not be fetched. Weakens the listener check's evidence model, not its mechanism. R1-OR10 closes it.
- **R1-F57 (XCCDF nine result values)** — LIKELY only (0.60): **both** NIST primary URLs were blocked (403/404 in S2, landing-page-only in S6). It informs how we justify the three-value model in NOTES.md; nothing in the implementation depends on it.

---

## Contradictions resolved at the lead level

**CR-1 — Our own brief was wrong about gitleaks.** The R1 prompt asserted that gitleaks had been relicensed away from MIT. Stream S3 disproved it: MIT at HEAD (v8.30.1), `LICENSE` has three commits, newest 2019-12-04. **Resolution: the research wins over the brief.** The gitleaks REJECT stands on redaction-by-default and report-serialisation grounds [R1-F15], not licensing. Repeating the licence claim in NOTES.md would have been a checkable error in front of the customer — this is exactly the "one thing Claude got wrong that we rejected" material contract A4 asks for, except the wrong claim was in our own prompt.

**CR-2 — Our own briefing assumption about securityfs was wrong.** The S5 brief asserted `/sys/kernel/security` would be root-only; LOCAL_REPRO showed `dr-xr-xr-x`, traversable, with the lockdown file simply absent. **Resolution: the observation wins.** Consequence: lockdown's failure mode is ENOENT (feature absent) on some kernels, not EACCES, and the two must be reported differently [R1-F36].

**CR-3 — "ghw needs no root" (its README, line 14) vs its own source and its own later README text (lines 1045-1051).** **Resolution: the source wins**, and the pattern generalises — a library's claim about *unprivileged* behaviour is the claim most likely to be untested, because the author runs as root. Applied as a standing rule for the rest of the project.

**CR-4 — "`exec.CommandContext` handles the timeout" (universal Go folklore, and the first thing an LLM emits) vs the `os/exec` documentation's own explanation of why `WaitDelay` exists.** **Resolution: the documentation wins.** Recorded deliberately because the naive pattern is the default generated answer.

**CR-5 — `sshd -G -C` documented as supported (`sshd.8:157-165`) vs fataling in code (`sshd.c:1741-1747`).** **Resolution: the code wins.** Our ceiling is global effective config; Match-conditional policy is an explicit bounded unknown, not a silent omission [R1-F51].

**CR-6 — "Secure Boot needs root/mokutil" (common claim) vs kernel efivarfs layout + osquery's deliberate choice.** **Resolution: unprivileged efivars read wins**, on two independent primaries plus host observation. `mokutil` is demoted to optional cross-check [R1-F31].

---

## Cross-cutting observation: three independent tools commit the same critical failure

osquery's Secure Boot table silently emits no row on read failure [R1-F32]; ipmitool clobbers `errno` and reports EACCES as ENOENT [R1-F27]; Wazuh SCA's sshd rules run `sshd -T` with no unknown state and therefore emit **false FAILs** unprivileged [R1-F55]. Three mature, widely-deployed tools, three different ways of claiming to have checked when they could not.

If these three facts are right, they are the strongest available evidence that the UNKNOWN semantics are the actual engineering content of this exercise rather than a defensive detail — and they give NOTES.md a concrete, citable argument. **If any one of them is wrong, the argument survives on the other two**, which is why it is stated as a pattern across three independent sources rather than resting on any single reading.

---

## SUSPECTED_INJECTION

**None found.** All six streams (S1–S6) independently reported "none found" in their own `SUSPECTED_INJECTION` sections. No fetched page, README, commit message or code comment encountered in this track contained text resembling an instruction to the agent, in plain, encoded, or split form. No agent was asked to run `ssh`/`scp`/`rsync`, read `.env`, `~/.ssh` or `state/raw_host/`, print a credential, write outside `research/R1/`, or produce implementation code — and none did.
