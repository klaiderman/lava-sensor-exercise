# Custom Health-Check Category Candidates -- Ranked

Ranked recommendation with evidence, per `prompts/R2/prompt.md` Q5. This is not a
decision -- the lead chooses the final custom category. Ranking logic: (a) how
directly the category traces to a VERIFIED_PUBLIC_FACT about Lava's own published
research/framework (see `facts.jsonl`, `LAVA_CONTEXT.md`), and (b) how much
differentiated, non-trivial evidence the category would actually produce on the
real target host per `state/HOST_SNAPSHOT.json` -- a thematically perfect category
that would report "not applicable" on this specific host is ranked lower than one
that is both on-thesis for Lava and produces real findings here.

## 1. Boot / firmware trust posture

**Rationale:** Secure Boot state, Setup Mode, TPM presence/accessibility, kernel
taint flags, and unsigned out-of-tree modules, reported as PASS/FAIL/UNKNOWN with
evidence (efivars, `/proc/sys/kernel/tainted`, `/sys/devices/system/*`,
`mokutil --sb-state` if present, else sysfs fallback).

**Supporting facts:** R2-F6 (FORGE's "Fleet Integrity" pillar is explicitly about
trust in hardware/firmware/software), R2-F7 (three-part firmware-integrity series:
chain of trust, SPDM/CoRIM attestation, real-world firmware rootkits).

**Why Lava would care:** This is Lava's own stated first pillar of risk (Fleet
Integrity) and the subject of a dedicated three-part blog series arguing that
"before we can trust the intelligence of the model, we must be able to trust the
safety of the metal running it." A sensor that reports Secure Boot/Setup
Mode/taint/lockdown state is answering exactly the question Lava's own research
says the industry is failing to ask.

**Host reality check:** Rich, differentiated findings exist on the actual host --
Secure Boot DISABLED *and* platform in Setup Mode, kernel lockdown `[none]`, tainted
(O+E) due to an unsigned out-of-tree `bnxt_en` module, TPM 2.0 present but
root-only. This is not a hypothetical category; it would surface the single most
interesting security-posture finding on this specific host.

## 2. Runtime / kernel hardening posture

**Rationale:** Kernel lockdown mode, module-signing enforcement, and the
hardening-relevant sysctls Lava's own writing names by name (`ptrace_scope`,
`kptr_restrict`, `dmesg_restrict`, `unprivileged_bpf_disabled`, `suid_dumpable`,
`protected_symlinks`/`protected_hardlinks`), plus an unexpected-taint / unexpected
out-of-tree-module cross-check.

**Supporting facts:** R2-F8 (three-part runtime-integrity series naming kernel
rootkits, eBPF backdoors, LD_PRELOAD implants, and exactly these mitigations by
name).

**Why Lava would care:** Lava's own runtime-integrity series states plainly that
"the chain of trust does not end at boot. It only begins there," and names the
precise sysctl-level mitigations (module signing, lockdown, eBPF restriction) this
check would report on. A sensor that can show these sysctls are already hardened
(or not) is directly answering the question that series poses.

**Host reality check:** Strong evidence already exists in `state/HOST_SNAPSHOT.json`
-- yama ptrace_scope 1, kptr_restrict 1, dmesg_restrict 1, unprivileged_bpf_disabled
2, protected_symlinks/hardlinks/fifos 1, protected_regular 2, suid_dumpable 0 are
all already hardened on this host, which itself is a reportable (mostly PASS)
finding with real values, not a null result.

## 3. Out-of-band management-plane (BMC/IPMI) exposure and hardening

**Rationale:** BMC presence/vendor/firmware version (sysfs, already readable
unprivileged), interface state (KCS vs. any IPMI-over-LAN NIC, up/down, addressed),
and presence/absence of vendor tooling (`ipmitool` et al.) as an unprivileged,
evidence-based posture check -- explicitly NOT an attempt to reach or authenticate
to the BMC.

**Supporting facts:** R2-F5 (Lava's single most publicized research result: 36,872
internet-exposed IPMI hosts, 24,650 leaking pre-auth hashes via CVE-2013-4786,
their own BMCRadar map), R2-F17 (host cross-reference).

**Why Lava would care:** This is literally Lava's flagship, most-publicized piece
of research -- the BMC/IPMI exposure work is the headline on their homepage and the
subject of their own interactive public map. A sensor category that reports BMC
posture would be immediately, obviously legible to anyone who has read Lava's own
front page.

**Host reality check -- the reason this is ranked #3, not #1:** Per
`state/HOST_SNAPSHOT.json`, this host's BMC is reachable only via an in-band KCS
interface (root-only `/dev/ipmi0`) and a USB-gadget out-of-band NIC that is
currently DOWN and unaddressed. Unlike the internet-exposed hosts in Lava's own
research, this host's BMC is **not** network-reachable at scan time, and the
sensor is unprivileged (cannot read `/dev/ipmi0`). The check would mostly report
"present, sysfs-readable metadata only, network path down/absent" -- correct and
still worth reporting (absence-of-exposure is itself a finding worth a PASS with
evidence), but less differentiated than #1 and #2, which surface actual, interesting
gaps on this specific host.

## 4. Management-plane / operations network attack surface (broader than BMC)

**Rationale:** Listening services bound to public vs. loopback interfaces, presence
of a firewall service and whether its ruleset is inspectable, absence of a
VPN/bastion path for administrative access -- read-only enumeration via `ss`/`ip`
and service state, never a scan of anything beyond the host itself.

**Supporting facts:** R2-F6 (FORGE's "Operations & Management Planes" pillar,
defined as "privileged systems controlling infrastructure").

**Why Lava would care:** Directly maps to FORGE's second named pillar. Broader and
less novel than #3, but complements it -- a management-plane exposure story is
incomplete without also describing what else is listening and how administrative
access is actually gated.

**Host reality check:** Real findings exist (`ufw` active but ruleset unreadable
without root, SSH is the only network-facing admin path and is key-only/hardened,
no VPN/tailscale/bastion present) -- moderately differentiated, but overlaps
conceptually with existing baseline network checks any generic sensor would already
plan to do.

## 5. Fleet hardware/firmware supply-chain freshness ("patch velocity")

**Rationale:** BIOS/firmware date+version, storage-controller firmware version,
and installed-vs-running kernel version, reported as an evidence-backed staleness
signal rather than a binary pass/fail (since "old firmware" alone is not
automatically a fail without a matched CVE).

**Supporting facts:** R2-F16 (FORGE's fifth pillar, "Evidence & Exposure
Management," explicitly defined around "provider transparency and patch
velocity").

**Why Lava would care:** This is Lava's own named fifth pillar, almost verbatim --
"patch velocity" is their term, not this project's invention. A sensor that reports
firmware/kernel currency with evidence (not just "is it patched" but "how stale,
against what reference") is answering the exact question FORGE's own taxonomy
poses.

**Host reality check:** Real, reportable evidence exists (BIOS 2.4a dated
2025-08-29; kernel drift -- running 6.8.0-139-generic while 7.0.0-31-generic is
installed and boot-linked, reboot pending; NVMe firmware E2MU200) -- solidly
differentiated, if slightly less "surprising" than #1/#2 since kernel-drift
detection is a fairly standard posture check.

## Would-not-anticipate: storage-media reuse/sanitization readiness signal

**Rationale:** For any unused/unpartitioned block device (this host has exactly
one: `nvme1n1`, no partitions, no filesystem, no holders), report read-only
metadata-only evidence of its state (partition-table presence/absence, filesystem
signature presence/absence, discard/TRIM support) as a "ready for reuse /
unknown-state" signal -- explicitly never reading or dumping device content, only
listing structural metadata already surfaced by `lsblk`/`blkid`-equivalent,
read-only sysfs paths.

**Supporting facts:** R2-F9 (Lava's own writing names "storage media
sanitization" and "hardware and device lifecycle... reuse, decommissioning" and
asks directly "what happens to a bare-metal machine before it moves from one
customer to another?").

**Why Lava would care:** This is the category "would not anticipate" because it
does not read as an obvious Linux-posture check (most generic scanners never look
at an *unused* disk at all) -- yet it maps almost word-for-word onto a question
Lava itself poses publicly about bare-metal reuse between customers. The Lava host
in this exercise is provisioned by Latitude.sh, a bare-metal-as-a-service provider
that plausibly reuses physical chassis across customers exactly as Lava's own
writing describes; a sensor that surfaces "here is a second, unused NVMe device
with no filesystem or partition table -- consistent with a clean reprovision, or
simply never-provisioned; cannot distinguish the two without more evidence" is
exactly the kind of evidence-with-honest-uncertainty Lava's own framework rewards
(R2-F15's ethics/scope-boundary writing style), and it directly reflects this
project's own PASS/FAIL/UNKNOWN discipline (absence is only provable from a
successful listing -- this check would explicitly not overclaim "sanitized," only
report structural absence of any prior filesystem/partition signature).

## Overall ranking (1 = strongest)

1. Boot / firmware trust posture (R2-F6, R2-F7)
2. Runtime / kernel hardening posture (R2-F8)
3. Out-of-band management-plane (BMC/IPMI) exposure and hardening (R2-F5, R2-F17)
4. Management-plane / operations network attack surface (R2-F6)
5. Fleet hardware/firmware supply-chain freshness / patch velocity (R2-F16)
6. (would-not-anticipate, not ranked in the 1-5) Storage-media reuse/sanitization
   readiness signal (R2-F9)
