# STREAM-F — Evidence/verdict semantics prior art + portability traps

## TOPIC 8 — Failure-mode taxonomy / verdict vocabularies

FACT: XCCDF (NIST IR 7275 Rev.4, XCCDF v1.2) defines a 9-value rule-result enumeration: `pass, fail, error, unknown, notapplicable, notchecked, notselected, informational, fixed` [S1][S2]. Confirmed directly against the NIST-hosted XSD enumeration (same 9 values, same order) [S2].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Our schema only has pass|fail|unknown. Map: XCCDF `error`→our `unknown` (reason=EXECUTION_ERROR), `notapplicable`→our `unknown` (reason=UNSUPPORTED, not `fail`), `notchecked`/`notselected`→ never emit (we always run every registered check), `informational`/`fixed`→ not used (no scoring/remediation state). Losing the pass/notapplicable/notchecked distinction means our `unknown` must carry `reason` to recover it — this is why `reason` is mandatory, not decorative.
IMPACT: Collapsing "doesn't apply here" and "couldn't tell" into one bucket without a reason code destroys the auditability XCCDF's richer vocabulary was designed to preserve.
SOURCES: S1 | https://csrc.nist.gov/pubs/ir/7275/r4/upd1/final | NIST IR 7275 Rev.4, XCCDF 1.2 spec (abstract/landing page; full PDF text extraction failed — binary/compressed streams, WebFetch could not render) | primary | webfetch(failed→search-corroborated) | S2 | https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd | NIST-hosted XCCDF 1.2 XML Schema (rule-result/TestResult enumeration) | primary | webfetch

FACT: OVAL defines a 6-value result enumeration for definitions/tests: `true, false, unknown, error, not evaluated, not applicable`, each with a precise defining sentence — e.g. `unknown` = "the characteristics being evaluated cannot be found in the system characteristic document (or ... collected object flag is 'not collected')"; `not evaluated` = "a choice was made not to evaluate the given definition or test" (distinct from `unknown`) [S3].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: OVAL cleanly separates "we chose not to look" (not evaluated) from "we looked and couldn't tell" (unknown) from "wrong platform" (not applicable). Our fixed registry runs every check, so we never need "not evaluated" — but the `unknown`/`notapplicable` split is exactly our UNKNOWN(UNSUPPORTED) vs UNKNOWN(EACCES/TIMEOUT/EXECUTION_ERROR) reason taxonomy; keep them as distinct `reason` values, never merge.
IMPACT: Merging "not applicable" into generic unknown makes a healthy host indistinguishable from a broken probe in downstream review.
SOURCES: S3 | https://oval-community-guidelines.readthedocs.io/en/latest/oval-schema-documentation/oval-results-schema.html | OVAL Core Results Schema (ResultEnumeration), community-hosted mirror of the MITRE OVAL Language schema documentation | primary | webfetch

FACT: SARIF 2.1.0 `result.kind` enumerates `notApplicable, pass, fail, review, open, informational`, with `fail` as the default when `kind` is omitted (this default-to-fail matters: a tool that forgets to set kind is *not* silently treated as passing) [S4]. SARIF also separates a run's own execution failures from its findings via `invocation` execution-status fields, i.e. "did the tool run successfully" is a distinct concern from "what did it find" — the general principle is directly confirmed by the schema structure; I could not obtain clean spec prose for the exact `toolExecutionNotifications` section text within the time box (GAP).
STATUS: VERIFIED (kind enum) / LIKELY (notifications section framing)
APPLIES_TO: both
PROBE/RULE: Our JSON should mirror this separation structurally: a check's own crash/timeout/panic must never be reported as a `fail` finding for that check nor silently dropped — it is an `unknown` finding for that check ID with reason=EXECUTION_ERROR/TIMEOUT, keeping "the check ran and said X" cleanly separate from "the harness couldn't get an answer."
IMPACT: If a probe's internal error is reported as `fail`, downstream consumers score a healthy host as broken; if dropped, they silently under-count (SILENT OMISSION class, see below).
SOURCES: S4 | https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json | OASIS SARIF 2.1.0 JSON Schema, `result.kind` property description and enum | primary | websearch-corroborated-by-schema-url

FACT: Lynis (CISOfy) reports a test it could not complete as `[WARNING]` or as a skip, and always attaches a `Suggestion:` line and/or an explicit skip reason (e.g. "No OpenSSL binary found") explaining *why*, retrievable via the log file / `lynis show details` workflow — it does not silently omit the test [S5].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Matches our rule that `unknown` requires a `reason` string with actionable content (missing utility, errno, timeout) rather than a bare status code.
IMPACT: A skip without a stated reason is undebuggable and indistinguishable from a tool bug.
SOURCES: S5 | https://cisofy.com/documentation/lynis/ | Lynis Installation and Usage Guide (CISOfy official docs) | primary | websearch

FACT: Wazuh SCA (Security Configuration Assessment) adds a third check outcome, `not applicable`, alongside `passed`/`failed`, explicitly triggered when "the file to scan is not present, permissions are insufficient to read a file or registry, or command execution times out" — note Wazuh's own docs bucket EACCES and ENOENT and TIMEOUT together under one label, which our CLAUDE.md explicitly forbids doing (EACCES ≠ absent, TIMEOUT ≠ false) [S6].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Do NOT copy Wazuh's merge of {ENOENT, EACCES, TIMEOUT} into one `not_applicable`/`unknown` bucket — keep distinct `reason` values (`ENOENT`, `EACCES`, `TIMEOUT`, `EXECUTION_ERROR`, `UNSUPPORTED`) so a permissions problem is never confused with genuine absence.
IMPACT: This is the concrete, citable example of a mature, widely-deployed tool committing exactly the false-equivalence our invariants are designed to prevent — useful as a negative prior-art example, not one to emulate.
SOURCES: S6 | https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html | Wazuh documentation — Creating custom SCA policies (rule aggregation / not-applicable triggers) | primary | websearch

FACT: CIS Benchmarks classify every recommendation's assessment status as `Automated` (tool can reach pass/fail unattended) or `Manual` (requires a human step; automated pass/fail cannot be produced), independent of the Level 1/Level 2 profile axis; some recommendations are additionally scoped out as not applicable to a given profile/environment [S7].
STATUS: LIKELY (CIS FAQ page located by URL but not directly fetched within time box; content corroborated via search snippet only)
APPLIES_TO: both
PROBE/RULE: Our fixed registry has no "Manual" bucket — every registered check must be fully automatable read-only; anything CIS marks "Manual" for the equivalent control should map to UNKNOWN(UNSUPPORTED) with a reason citing "requires interactive/manual judgement," not be silently excluded from the registry.
IMPACT: If we skip CIS "Manual" controls by omitting the check entirely (rather than emitting an explicit UNKNOWN), we've committed SILENT OMISSION.
SOURCES: S7 | https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq | CIS Benchmarks FAQ (official CIS site) | primary | websearch(url-located,not-fetched)

FACT: osquery is designed and documented to expect root; several tables (commonly cited: `process_open_sockets`, `shell_history`) return degraded, incomplete, or zero-row results under a non-root effective UID rather than raising a structured "insufficient privilege" error — i.e. the false-negative-by-silence class is real in a shipped, widely used tool. I could not find a single authoritative osquery.readthedocs.io sentence stating this in those exact terms within the time box; corroboration currently comes from official osquery Slack/GH-issue maintainer statements ("keep in mind that many tables may not show data/work correctly" without root), which is community-official but not a spec page (GAP: cite osquery table spec `observed_yield`/description fields if found later).
STATUS: LIKELY
APPLIES_TO: both
PROBE/RULE: This is the textbook justification for "EACCES ≠ absent": a check that lists sockets/processes and gets 0 rows back under uid 1000 must not report PASS("no listening sockets") — it must detect the permission boundary (e.g. compare against a known-present PID/socket, or check the read errno directly) and emit UNKNOWN(EACCES) instead of trusting an empty result set.
IMPACT: Silent under-collection masquerading as a clean pass is the single most dangerous false-PASS class for an unprivileged sensor — it actively hides the fact that the scan was incomplete.
SOURCES: S8 | https://chat.osquery.io/t/16918947/should-osquery-be-run-as-root-we-are-deploying-osquery-but-d | osquery official community Slack (chat.osquery.io), maintainer guidance on non-root table behavior | secondary | websearch

FACT: NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment) is the standard NIST reference establishing that security test results have inherent, bounded coverage and that testing methodology limitations (technique-specific benefits/limitations, need for validation of automated findings) must be documented alongside results, i.e. absence of a finding is not proof of absence of the condition. I was not able to extract a clean quotable sentence from the PDF within the time box (WebFetch could not parse the legacy nvlpubs PDF text layer) — GAP: needs a follow-up fetch with a PDF-capable extractor against `https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf`.
STATUS: LIKELY
APPLIES_TO: both
PROBE/RULE: Formal backing for the CLAUDE.md invariant "absence is only provable from a successful listing" — cite SP 800-115 in NOTES.md as the doctrinal source, but do not present it as a verbatim quote since extraction failed.
IMPACT: Without this doctrine, reviewers may assume no-finding == negative result, which is exactly the false-PASS-from-assumed-default failure class.
SOURCES: S9 | https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf | NIST SP 800-115, Technical Guide to Information Security Testing and Assessment | primary | webfetch(text-extraction-failed)

## TOPIC 9 — Portability traps

FACT: `os-release(5)`: `ID` is the lowercase distro identifier (e.g. `ubuntu`); `ID_LIKE` is a space-separated fallback list of IDs whose family the distro resembles, used only as a fallback when an exact `ID` match fails; `VERSION_ID` is a lowercase, mostly-numeric string with no spaces (chars limited to `0-9 a-z . _ -`), safe for scripts; official guidance is "use ID and VERSION_ID... possibly with ID_LIKE as fallback for ID," and PRETTY_NAME is for human display only, never for parsing [S10].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Parse `/etc/os-release` as shell-style `KEY=VALUE` (values may be quoted per shell quoting rules per the spec) — never regex PRETTY_NAME for distro logic. Use ID first, walk ID_LIKE only if ID is unrecognized.
IMPACT: Matching on PRETTY_NAME or assuming ID is always one of a fixed short list breaks on any derivative distro (e.g. Proxmox, Pop!_OS) that sets ID_LIKE=debian/ubuntu.
SOURCES: S10 | https://manpages.debian.org/bullseye/systemd/os-release.5.en.html | os-release(5), systemd project (Debian-hosted mirror of the freedesktop.org-authored man page; direct freedesktop.org fetch returned HTTP 403 in this session) | primary | websearch+webfetch(403 on freedesktop.org, Debian mirror used)

FACT: `sd_booted(3)`: the canonical "is this system running systemd as PID 1" test is checking for the existence of the directory `/run/systemd/system/`; on older systemd it checked `/sys/fs/cgroup/systemd` instead — implementations must not hardcode the legacy cgroup path [S11].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Use `os.Stat("/run/systemd/system")` (dir exists) as the systemd-booted test; treat as evidence, not proxy for "service X is running" (a masked/socket-activated unit still counts as systemd-booted).
IMPACT: Using process-table heuristics (`pgrep systemd`) instead of this canonical test misclassifies containers/chroots that share a systemd-booted host PID 1 namespace oddly, or vice versa.
SOURCES: S11 | https://www.freedesktop.org/software/systemd/man/latest/sd_booted.html | sd_booted(3), freedesktop.org/systemd official docs | primary | websearch

FACT: `systemd-detect-virt(1)`: exit code 0 means a virtualization technology (container or VM) WAS detected; non-zero means none detected (bare metal), which is the inverse of typical boolean-success intuition; `--container`/`--vm` restrict detection scope [S12].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: If shelling out to this binary as a fallback (prefer `/proc/1/cgroup`, `/.dockerenv`, DMI sysfs first per our "missing utility != missing capability" rule), treat exit-code 0 as "virtualized," and remember rc!=0 does not distinguish "bare metal" from "binary missing/errored" — check for ENOENT on the binary separately before trusting rc.
IMPACT: Confusing "non-zero" with "definitely bare metal" without ruling out exec failure is a TIMEOUT/EXECUTION_ERROR-treated-as-negative bug.
SOURCES: S12 | https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html | systemd-detect-virt(1), freedesktop.org official docs | primary | websearch

FACT: `/sys/kernel/security/lsm` is a comma-separated, read-only list of the active/enabled LSMs on the running kernel in hook-execution order, and "will always include the capability module" — this is the documented, generic (not distro-specific) way to enumerate active LSMs without parsing `dmesg` or guessing from `/etc/apparmor.d` presence [S13].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Prefer reading this sysfs file over shelling out to `aa-status`/`getenforce` (which may be absent even when the LSM is active) — direct instance of "missing utility != missing capability."
IMPACT: Relying on the presence of a CLI tool (aa-status, sestatus) to infer LSM state produces false negatives on minimal/hardened images that lack the userspace tool but still enforce the policy.
SOURCES: S13 | https://docs.kernel.org/admin-guide/LSM/index.html | Linux kernel documentation, admin-guide/LSM/index.rst | primary | webfetch

FACT: `kernel.unprivileged_userns_clone` is NOT an upstream Linux sysctl — it originates from a Debian-carried kernel patch (inherited by Ubuntu), and only affects unprivileged (non-root) `CLONE_NEWUSER`; the upstream-only equivalent knob is `user.max_user_namespaces` (also settable by Debian/Ubuntu kernels, which carry both), and `user.max_user_namespaces=0` differs semantically — it disables user namespaces even for root, whereas `unprivileged_userns_clone` does not. Debian has discussed deprecating the non-upstream sysctl (Debian bug #1024186) in favor of a newer `kernel.userns_group_range` [S14][S15]. LOCAL_REPRO on this session's WSL2 Ubuntu 26.04 (`ID=ubuntu`, `ID_LIKE=debian` in `/etc/os-release`) confirms the CONTESTED nature empirically: `sysctl kernel.unprivileged_userns_clone` → "cannot stat /proc/sys/kernel/unprivileged_userns_clone: No such file or directory" — i.e. this "Ubuntu" userspace does NOT expose the sysctl, because WSL2 runs Microsoft's own kernel build (`6.18.33.2-microsoft-standard-WSL2`), not an actual Ubuntu-packaged kernel; `/etc/os-release` ID/ID_LIKE describes userspace packaging only and says nothing about which kernel patches are present.
STATUS: CONTESTED
APPLIES_TO: generic
PROBE/RULE: Never gate a check on `ID=ubuntu`/`ID_LIKE=debian` to decide whether `kernel.unprivileged_userns_clone` will exist. Probe directly: try reading `/proc/sys/kernel/unprivileged_userns_clone`; if ENOENT, fall back to `/proc/sys/user/max_user_namespaces` (upstream-generic); if both ENOENT, report UNKNOWN(UNSUPPORTED) — do not report FAIL/absent-hardening from a single missing path.
IMPACT: This is the flagship example of "distro name ≠ kernel capability": a naive `if ID_LIKE contains debian then read unprivileged_userns_clone` check produces a false EXECUTION_ERROR/FAIL on any Debian-family userspace running a non-Debian-patched kernel (WSL2, custom/mainline kernel installs, some cloud images) — directly relevant since our own dev-repro environment hit exactly this.
SOURCES: S14 | https://lists.debian.org/debian-kernel/2022/11/msg00258.html | Debian bug #1024186, "linux: consider deprecating unprivileged_userns_clone" (debian-kernel mailing list) | primary | websearch | S15 | https://lists.debian.org/debian-doc/2021/07/msg00022.html | Debian bug #991426, "release-notes: Recommend user.max_user_namespaces over kernel.unprivileged_userns_clone?" | primary | websearch | S16 | LOCAL_REPRO this session, WSL2 Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2 | primary | bash

FACT: util-linux 2.27 added JSON output (via new `libsmartcols`) to `findmnt`, `losetup`, `lsblk`, `lslocks`, `sfdisk`, `lsipc` — this is the version floor below which `-J`/`--json` flags on these tools do not exist and must not be assumed [S17]. Locally installed util-linux in this session's WSL2 is 2.41.3 (`lsblk -V`, `findmnt -V`), far above the floor, confirming the flag works here but not proving anything about older-target hosts.
STATUS: VERIFIED
APPLIES_TO: generic
PROBE/RULE: Before invoking `lsblk -J`/`findmnt --json`, check `util-linux` version (e.g. via `lsblk --version` parsed defensively, or a documented minimum-version assumption for the target distro) and have a non-JSON fallback parser path; never assume `-J` exists just because the binary exists.
IMPACT: On old-but-still-supported enterprise distros (RHEL 7-era util-linux, e.g. 2.23) these flags are silently unrecognized, which is an EXECUTION_ERROR (bad flag), not a missing-data condition, and must not be reported as FAIL/absent.
SOURCES: S17 | https://cdn.kernel.org/pub/linux/utils/util-linux/v2.34/v2.34-ReleaseNotes | util-linux release notes (v2.34 notes citing the 2.27 JSON-output libsmartcols introduction); kernel.org-hosted, project-official | primary | websearch | S18 | LOCAL_REPRO this session, WSL2, `lsblk from util-linux 2.41.3`, `findmnt from util-linux 2.41.3` | primary | bash

FACT: iproute2 JSON output (`ip -j`/`-json`) rolled out progressively per-subcommand starting around iproute2 4.9–4.10 (`ip link show -json` patches dated ~2017, iproute2 4.14.1 announcement documents broad JSON coverage); `ss -J` full JSON support likewise landed via a dedicated patch series rather than atomically across all iproute2 tools — the exact version floor is subcommand-dependent, not a single iproute2 release number [S19]. This session's WSL2 `ip -V`/`ss -V` both report iproute2-6.19.0, far above any relevant floor.
STATUS: LIKELY
APPLIES_TO: generic
PROBE/RULE: Same rule as lsblk: verify `-j`/`-J` is accepted for the SPECIFIC subcommand being used (not just that the ip/ss binary supports JSON for some other subcommand) before parsing; treat unrecognized-flag exit as EXECUTION_ERROR, fall back to positional/text parsing only behind a documented, tested compatibility path — and per CLAUDE.md, never parse human-readable columns positionally as the primary path regardless.
IMPACT: A host with an old iproute2 (common on RHEL 7/8, Debian 9/10) rejects `-j` for some subcommands even though the binary answers `-j` fine for others, producing a partial, subcommand-shaped false EXECUTION_ERROR if not checked per-invocation.
SOURCES: S19 | https://lwn.net/Articles/738897/ | LWN.net, "iproute2 4.14.1" (community technical-press summary of the upstream announcement, not the raw git changelog) | secondary | websearch

FACT: The Linux kernel Lockdown LSM (`CONFIG_SECURITY_LOCKDOWN_LSM`) was merged for Linux 5.4, exposed via `security_locked_down()` hooks; user-visible effect and mode (`none`/`integrity`/`confidentiality`) is read from `/sys/kernel/security/lockdown` when the LSM is compiled in and enabled via the `lsm=` boot parameter [S20].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Gate any lockdown-mode check on kernel version AND on file existence — a <5.4 kernel or a kernel built without the LSM will simply lack `/sys/kernel/security/lockdown`; report UNKNOWN(UNSUPPORTED), not FAIL("lockdown disabled").
IMPACT: Matches our established host fact (lockdown=none on the Lava host) — but a generic target on an older kernel must not be scored as "insecure" for lacking a feature it structurally cannot have.
SOURCES: S20 | https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html | kernel_lockdown(7), Linux man-pages project | primary | websearch | S21 | https://kernelnewbies.org/Linux_5.4 | Linux kernel 5.4 changelog summary (kernelnewbies.org, community-maintained but sourced from kernel git log) | secondary | websearch

FACT: `kernel.unprivileged_bpf_disabled` accepts values 0 (allowed), 1 (disabled, cannot be re-enabled at runtime), and 2 (disabled by default via `CONFIG_BPF_UNPRIV_DEFAULT_OFF`, but an admin CAN still write 0/1 later, unlike value 1) [S22]. I could NOT pin down a single authoritative kernel-version number for when value "2" support landed within the time box — search results point to Ubuntu-specific kernel-team mailing-list activity from 2021 (~kernel 5.11/5.13 era Ubuntu kernels) discussing setting the sysctl DEFAULT to 2, which is different from the kernel *supporting* the value 2 at all; GAP: needs a direct `Documentation/admin-guide/sysctl/kernel.rst` git-blame/commit-hash check, not yet done.
STATUS: CONTESTED
APPLIES_TO: generic
PROBE/RULE: Do not hardcode "kernel >= 5.16 required for value 2" as a gate. Read the sysctl value directly (0/1/2/ENOENT) and report the literal value; only report UNKNOWN(UNSUPPORTED) if the path is ENOENT (kernel built without BPF sysctl support at all), never infer support/non-support from `uname -r` alone.
IMPACT: A version-gate that's off by even one kernel release either wrongly claims a hardened host is unhardened, or silently skips reading a value that's actually present.
SOURCES: S22 | https://access.redhat.com/solutions/6992315 | Red Hat Customer Portal, "How to change kernel.unprivileged_bpf_disabled" (vendor documentation, describes 0/1/2 semantics) | secondary | websearch

## SOURCES LIST
S1 https://csrc.nist.gov/pubs/ir/7275/r4/upd1/final — NIST IR 7275 Rev.4 (XCCDF 1.2) — primary — webfetch(pdf text extraction failed)
S2 https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd — NIST XCCDF 1.2 XSD — primary — webfetch
S3 https://oval-community-guidelines.readthedocs.io/en/latest/oval-schema-documentation/oval-results-schema.html — OVAL Core Results Schema — primary — webfetch
S4 https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json — OASIS SARIF 2.1.0 JSON Schema — primary — websearch
S5 https://cisofy.com/documentation/lynis/ — Lynis official docs (CISOfy) — primary — websearch
S6 https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html — Wazuh SCA custom policies docs — primary — websearch
S7 https://www.cisecurity.org/cis-benchmarks/cis-benchmarks-faq — CIS Benchmarks FAQ — primary — websearch(not directly fetched)
S8 https://chat.osquery.io/t/16918947/ — osquery official community chat — secondary — websearch
S9 https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-115.pdf — NIST SP 800-115 — primary — webfetch(extraction failed)
S10 https://manpages.debian.org/bullseye/systemd/os-release.5.en.html — os-release(5) — primary — websearch+webfetch(freedesktop 403, Debian mirror used)
S11 https://www.freedesktop.org/software/systemd/man/latest/sd_booted.html — sd_booted(3) — primary — websearch
S12 https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html — systemd-detect-virt(1) — primary — websearch
S13 https://docs.kernel.org/admin-guide/LSM/index.html — kernel admin-guide/LSM — primary — webfetch
S14 https://lists.debian.org/debian-kernel/2022/11/msg00258.html — Debian bug #1024186 — primary — websearch
S15 https://lists.debian.org/debian-doc/2021/07/msg00022.html — Debian bug #991426 — primary — websearch
S16 LOCAL_REPRO (this session, WSL2 Ubuntu 26.04 userspace / microsoft-standard-WSL2 kernel) — primary — bash
S17 https://cdn.kernel.org/pub/linux/utils/util-linux/v2.34/v2.34-ReleaseNotes — util-linux release notes — primary — websearch
S18 LOCAL_REPRO (this session, WSL2, util-linux 2.41.3) — primary — bash
S19 https://lwn.net/Articles/738897/ — LWN.net iproute2 4.14.1 coverage — secondary — websearch
S20 https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html — kernel_lockdown(7) — primary — websearch
S21 https://kernelnewbies.org/Linux_5.4 — kernelnewbies Linux 5.4 summary — secondary — websearch
S22 https://access.redhat.com/solutions/6992315 — Red Hat Customer Portal — secondary — websearch

## CONTRADICTIONS
- `kernel.unprivileged_userns_clone`: Debian/Ubuntu-only sysctl vs. upstream `user.max_user_namespaces` — confirmed CONTESTED/portability-critical; empirically reproduced in this session's own WSL2 environment (Ubuntu userspace, non-Ubuntu-patched kernel → sysctl absent). See FACT above; sensor must probe both paths, never gate on distro ID.
- `kernel.unprivileged_bpf_disabled` value-2 introduction version: sources disagree/are unclear whether "5.16" (as hypothesized in the task brief) is correct vs. an earlier Ubuntu-specific default change (~2021, pre-5.16 upstream); flagged CONTESTED, unresolved — do not cite a specific kernel version in NOTES.md without a follow-up commit-level check.
- Wazuh SCA merges ENOENT/EACCES/TIMEOUT into one "not applicable" bucket — this directly contradicts our own CLAUDE.md invariants; recorded as a negative example, not adopted.

## GAPS
- NIST IR 7275 Rev.4 and NIST SP 800-115: WebFetch could not extract text from the legacy nvlpubs.nist.gov PDFs (binary/compressed stream errors) in either case; XCCDF enumeration was instead confirmed via the primary NIST-hosted XSD (S2), which is authoritative but SP 800-115's "absence of evidence" doctrine still lacks a verbatim quote — needs a PDF-capable extraction pass (e.g. crawl4ai or a local pdftotext) if a verbatim citation is required for NOTES.md.
- SARIF `invocation.toolExecutionNotifications` exact spec section/text not confirmed within time box (structure inferred from schema presence, not quoted).
- osquery non-root degraded-table behavior: no single osquery.readthedocs.io spec-page sentence found; only community/Slack maintainer corroboration (secondary).
- CIS Benchmarks Automated/Manual FAQ page located by URL but not directly fetched (search-snippet corroboration only).
- iproute2 exact per-subcommand JSON version floors: only LWN secondary coverage found, not the raw iproute2 git changelog/man page version-added annotations.
- `/proc/device-tree` on non-DMI platforms and `/sys/class/dmi` absence on ARM/POWER: not researched this session (ran out of time budget) — still a GAP, no source cited.
