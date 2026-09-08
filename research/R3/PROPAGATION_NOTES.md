# R3 — PROPAGATION_NOTES.md

Per load-bearing fact: what breaks downstream if the fact turns out to be wrong. Ordered by blast
radius, not by topic. "Blast radius" = how much of the sensor has to change if the fact is falsified.

## Tier 1 — falsification changes the architecture

**R3-F13 (Setpgid + group kill) / L09.** If wrong in the direction "Setpgid is not needed", nothing
breaks. If wrong in the direction "the group kill does not actually reach descendants" (e.g. a child
calls setsid() itself — GAP G-2, unproven), then the bounded-execution guarantee is not a guarantee
and the sensor can leave processes on Lava's host after exiting. Mitigation already chosen: the
registry forbids daemonising probes, and the fixture `grandchild-holds-stdout` asserts no descendant
survives. **If falsified:** every exec-based probe must be dropped in favour of sysfs/procfs only,
which L39 says is possible for every check on this host anyway. That is the fallback architecture.

**R3-F16b (file reads are not context-interruptible) / L14.** If wrong, the collector could simply
wait for all goroutines and the design gets simpler. If right (it is — the stdlib has a test for it),
then any implementation that does `wg.Wait()` before writing output can hang forever on a single
pathological file and produce NO findings.json at all. That is a total-loss failure, worse than any
individual wrong verdict, which is why L14 is in Tier 1.

**R3-F60/F62 (XCCDF/SARIF verdict vocabularies) / L34.** These do not describe our schema; they
justify its shape. If the lead's `finding.schema.json` turns out to have a richer status enum than
pass|fail|unknown, L34's "recover the distinctions in `reason`" becomes unnecessary and the reason
vocabulary should collapse into the schema's own values instead of shadowing them. **This is the one
fact whose resolution depends on an artifact we do not have yet** (the schema is still outstanding),
so L34 must be re-checked the moment `finding.schema.json` arrives.

## Tier 2 — falsification changes several checks

**R3-F01/F02 (DMI modes) / L01, L02, L33.** If a host ships 0444 serials (some cloud images do), the
identity chain's top tier becomes available and every identity finding gets stronger. The law already
handles this by requiring an actual read rather than a hardcoded UNKNOWN — but a sensor written to
"always report UNKNOWN for DMI serials" would silently under-claim on that host class forever, and
nothing in the Lava-host test run would reveal it. Fixture `dmi-serial-world-readable` exists
specifically to catch this. Open: R3-OR1.

**R3-F21/F20 (Include ordering) / L16.** If the Include line's real position on the host is at the
bottom rather than the top, the effective values of PasswordAuthentication and friends flip. The law
is position-agnostic (it resolves by order), so the LAW survives; but any hand-written expectation in
the test suite that assumes "drop-ins win" would be wrong. Do not encode "drop-ins win" anywhere —
encode "first occurrence wins". Open: R3-OR3.

**R3-F25 (UsePAM upstream vs Ubuntu) / L19.** If the distro-default position is wrong, every
absent-directive verdict for that keyword inverts. This is CONTESTED and the law explicitly follows
the distro table only when ID/ID_LIKE resolves. The propagation risk is not the single keyword — it
is the precedent: if the default table is wrong for UsePAM it is probably wrong for others, so the
table must carry a per-row citation and a per-row confidence, not one blanket footnote.

**R3-F46/F46b (lsblk via the udev database) / L29.** Established from a WSL2 repro plus the lsblk man
page. If the Lava host has no /run/udev/data (unlikely with systemd-udevd running), then filesystem
type genuinely is UNKNOWN unprivileged and L29's under-claim clause would wrongly force the sensor to
assert something it cannot know — turning an anti-under-claim law into a false-PASS generator. This
is the only law in the set whose failure mode is *the opposite* of its intent, so it must be verified
before implementation. Open: R3-OR4, R3-OR9.

**R3-F49 (mountinfo layout) / L31.** If parsed wrongly, every downstream verdict built on mount
options — nosuid, nodev, network storage, read-only root, the xdev boundary for the secrets walk
(L25) — is corrupted at once, and corrupted quietly, because a wrong fstype string still parses. This
is the highest ratio of "one small bug" to "many wrong findings" in the whole track.

## Tier 3 — falsification changes one check or one wording

**R3-F44 (/dev/ipmi0 default 0600).** Only LIKELY: no udev rule was located. The law (L26) is written
to report the OBSERVED mode rather than an assumed default, precisely so that this fact being wrong
cannot produce a wrong verdict — it would only make a sentence in NOTES.md inaccurate. Open: R3-OR5.

**R3-F47 (CRYPT- DM-UUID prefix) / L30.** If the prefix format changed in a newer cryptsetup, the
sensor would miss a LUKS mapping and report "no dm-crypt". Mitigation: the law requires the negative
to be worded as "no dm-crypt mapping detected", and the probe should treat ANY dm device it cannot
classify as UNKNOWN rather than as not-encrypted.

**R3-F33 (JKS/JCEKS/keytab magics).** LIKELY only. A wrong magic means a missed classification (a
keystore reported as `magic_class: unknown` with correct metadata) — an under-claim, not a leak and
not a false PASS, because the metadata finding stands on its own. Acceptable to ship at LIKELY.

**R3-F31 (outbound tunnels invisible) / L21.** If wrong, the sensor's stated blind spot is narrower
than reality, which is the safe direction. The risk is the reverse: over-stating the blind spot could
make a reviewer discount a legitimate PASS. Keep the wording factual ("listener enumeration cannot
see outbound tunnels"), not alarmist.

**R3-F72 (systemd-detect-virt polarity) / L38.** A single inverted boolean flips bare-metal vs
virtualized for the whole hardware section. Low probability (documented), high locality. The fixture
`detect-virt-polarity` is cheap and must exist regardless of confidence.

## Research limitations that cannot be closed by a host observation

- **NIST SP 800-115 (R3-F66)** — PDF text extraction failed; the absence-of-evidence doctrine is
  instead carried by XCCDF/OVAL/SARIF, which are stronger sources anyway. No law depends on it. This
  is a generic-knowledge gap, not a host gap.
- **osquery's non-root degradation (R3-F63)** — maintainer statements only, no spec page. Used as
  corroboration for L34, never as its basis.
- **unprivileged_bpf_disabled=2 kernel version** — CONTESTED and unpinned. The sensor should report
  the observed value without asserting when the value became available; do not put a version claim in
  NOTES.md.
- **PAM account/session behaviour** — no primary man page was fetched (mirror 404). No law rests on
  it; if a PAM-based check is ever added, this must be researched first.
- **ext4's policy on reading system.posix_acl_access without read permission** — xattr(7) defers to
  the filesystem, and we did not find ext4's answer. This is BOTH a generic gap and a host question
  (R3-OR2), and it blocks any ACL-based finding.
