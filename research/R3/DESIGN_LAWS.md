# R3 — DESIGN_LAWS.md

Numbered engineering laws for the sensor. Each restates FACT / LAW / PROBE / FIXTURE compactly; the
full 4-part blocks with citations live in `REPORT.md`, organised by topic. Every law here traces to
at least one primary source in `sources.jsonl` via the FACT id.

Numbering note: L04 and L06 are intentionally unallocated (their candidate facts, R3-F04 and
R3-F06, are folded into L07 and L05 respectively rather than standing as separate laws).

Confidence is 2-D: **support** = how well the underlying fact is sourced; **transfer** = how directly
it applies to THIS host (Go, unprivileged, Linux, Ubuntu 24.04 bare metal).

| Law | Support | Transfer | One-line rule |
|---|---|---|---|
| L01 | high | high | DMI serials/UUID: attempt, report UNKNOWN/EACCES, still read the 0444 asset tags |
| L02 | high | high | Never build a check whose only path is raw SMBIOS; use parsed sysfs objects |
| L03 | high | high | EPERM is not EACCES; record syscall + path with the errno |
| L05 | high | high | Read caps come from policy, never from FileInfo.Size(); st_size 0 is not empty |
| L07 | high | high | Closed reason vocabulary; never collapse two failure classes; check hidepid first |
| L08 | high | high | Read the sysctl; never attempt the restricted operation |
| L09 | high | high | Setpgid + process-group kill, in one runner; no other package builds an exec.Cmd |
| L10 | high | high | Every Cmd sets WaitDelay; ErrWaitDelay maps to UNKNOWN/TIMEOUT, never FAIL |
| L11 | high | high | Cancel normalises ESRCH to os.ErrProcessDone |
| L12 | high | high | read(cap+1) with a truncated flag; exactly one Wait() on every path |
| L13 | high | high | One open path: O_RDONLY\|O_NONBLOCK\|O_NOFOLLOW\|O_CLOEXEC then fstat the fd, IsRegular |
| L14 | high | high | Scan deadline bounds scheduling, not reads; no unconditional WaitGroup.Wait before output |
| L15 | high | high | /sys needs explicit symlink resolution; user trees use WalkDir with no following |
| L16 | high | high | Resolve sshd directives over the Include chain, first occurrence wins, emit shadowed ones |
| L17 | high | high | Match block present ⇒ evidence-only, not a host-wide verdict |
| L18 | high | high | Never depend on `sshd -T`; record its stderr as EXECUTION_ERROR and fall back to the walker |
| L19 | medium | high | Absent directive ⇒ cited, version-scoped, distro-aware default; unknown distro ⇒ UNKNOWN |
| L20 | medium | high | "What is listening" comes from the socket table; socket owner is UNKNOWN/EACCES |
| L21 | high | medium | Listener-based remote-access findings must state the outbound-tunnel blind spot |
| L22 | high | high | Group membership is fact; sudo policy and others' password state are UNKNOWN/EACCES; never run sudo |
| L23 | medium | high | Secrets: name → lstat → ≤64-byte header, classified and discarded; never store or hash a value |
| L24 | high | high | Use the software's own documented permission rule as the PASS/FAIL criterion |
| L25 | high | high | Enumeration findings carry their boundary (EACCES dirs, prunes, budgets) or they are invalid |
| L26 | high | high | BMC: capability_present and access_permitted are separate; never issue an IPMI command |
| L27 | high | high | Root-only type 42 ⇒ use the USB descriptor surface and produce a verdict, not UNKNOWN |
| L28 | high | high | Capacity = /sys/block/<d>/size * 512, never * logical_block_size |
| L29 | medium | high | udev DB answers fstype/identity without opening the device; empty field ≠ no filesystem |
| L30 | high | high | dm/uuid CRYPT- prefix answers dm-crypt; the negative is scoped; SMART is UNKNOWN/EPERM |
| L31 | high | high | mountinfo: split on the literal " - ", index from both ends |
| L32 | high | high | Never emit machine-id verbatim; emit an application-keyed derivation |
| L33 | high | high | Identity is a ranked chain with provenance; ENOENT (no DMI) ≠ EACCES (restricted DMI) |
| L34 | high | high | One finding per registered check, always; an unset verdict never defaults to PASS |
| L35 | high | high | Reason vocabulary strictly finer than "not applicable"; five classes stay five |
| L36 | n/a | high | Every check needs an under-claim fixture, not only a false-PASS fixture |
| L37 | high | high | Gate on observed paths/capabilities, never on distro ID, hostname or vendor |
| L38 | high | high | Capability gate before probe: systemd, detect-virt polarity, JSON flag floor, kernel version |
| L39 | high | high | Missing utility ≠ missing capability; exec is always a fallback behind sysfs/procfs |

---

## Compact restatements

**L01** — FACT R3-F01 [S39]: dmi-id.c v6.8 gives product_serial/product_uuid/board_serial/chassis_serial
mode 0400 and everything else, including both asset tags, 0444. LAW: attempt the reads, report
UNKNOWN/EACCES, never substitute a weaker identifier at equal confidence, and do read the asset tags.
PROBE: os.ReadFile each path; EACCES = root-only (expected), ENOENT on the directory = no DMI
platform (L37). FIXTURE: `dmi-serial-root-only`, under-claim `dmi-asset-tag-not-read`,
`dmi-serial-world-readable`.

**L02** — FACT R3-F02 [S49][S50]: /sys/firmware/dmi/entries/*/raw and tables/* are 0400 plus a runtime
CAP_SYS_ADMIN gate. LAW: no check may depend solely on raw SMBIOS; use parsed sysfs and report the
EACCES as the reason. PROBE: stat first; fall back to /sys/class/ipmi and the USB descriptors.
FIXTURE: `smbios-raw-eacces` (under-claim guard).

**L03** — FACT R3-F03/R3-F05 [S45][S51][S46][S52]: dmesg_restrict denies EPERM (CAP_SYSLOG);
protected_hardlinks denies EPERM while its three siblings deny EACCES. LAW: EPERM is a distinct
reason; record syscall + path. PROBE: read the sysctl, do not run dmesg. FIXTURE:
`dmesg-restrict-eperm`.

**L05** — FACT R3-F06/R3-F07 [S48][S42][S43]: sysfs uses a PAGE_SIZE buffer; sysfs stats 4096, procfs
stats 0; Go's readFileContents documents the /proc trap. LAW: caps come from policy, st_size 0 is not
empty. PROBE: os.ReadFile under /sys and /proc. FIXTURE: `zero-stat-size-file`, `oversize-sysfs-attr`.

**L07** — FACT R3-F08/R3-F04 [S53][S54][S44][S13]: distinct errno semantics; procfs hidepid changes
process visibility. LAW: closed reason vocabulary, no collapsing; read hidepid before any process
conclusion. PROBE: per-probe errno meaning documented in REPORT.md. FIXTURE: `hidepid2-empty-proc`,
under-claim `hidepid0-full-proc`.

**L08** — FACT R3-F09 [S45][S47]: the hardening sysctls are world-readable; ENOENT on yama means the
LSM is absent. LAW: read the knob, never attempt the restricted operation. PROBE: os.ReadFile.
FIXTURE: `sysctl-absent-not-permissive`.

**L09** — FACT R3-F10/F12/F13 [S56][S57][S58][S59][S60][S61]: CommandContext kills only the child; the
hang is in Wait's copy goroutines; group kill needs Setpgid and would otherwise kill the sensor. LAW:
Setpgid + group kill in one runner; no other package builds an exec.Cmd. PROBE: execution contract.
FIXTURE: `grandchild-holds-stdout` (asserts the sensor survives), negative `setpgid-omitted`.

**L10** — FACT R3-F11 [S57][S61]: WaitDelay is the only bound on open pipes after exit; ErrWaitDelay is
the signal. LAW: always set it; map to UNKNOWN/TIMEOUT, never FAIL. FIXTURE: `waitdelay-expired-not-fail`.

**L11** — FACT R3-F14 [S57]: Cancel semantics around os.ErrProcessDone. LAW: normalise ESRCH.
FIXTURE: `cancel-race-esrch` (200 iterations, zero EXECUTION_ERRORs).

**L12** — FACT R3-F15/F16 [S62][S57]: LimitReader signals the cap with EOF; Wait releases resources.
LAW: read cap+1 with a truncated flag, never PASS on a truncated read; exactly one Wait per path.
FIXTURE: `output-exactly-at-cap`, `zombie-after-timeout`.

**L13** — FACT R3-F17/F18 [S63][S53][S64]: FIFOs block on open; O_NONBLOCK is inert for regular files
and block devices; os.Root does not prohibit device-file access. LAW: one open path, fstat the fd,
assert IsRegular. FIXTURE: `fifo-at-config-path`, `chardev-at-path`.

**L14** — FACT R3-F16b [S66]: ordinary files do not support deadlines (os.ErrNoDeadline). LAW: the
scan deadline bounds scheduling and output, not reads; no unconditional WaitGroup.Wait.
FIXTURE: `stuck-read-does-not-block-output`.

**L15** — FACT R3-F19 [S65][S43]: Walk/WalkDir never follow symlinks, and /sys is symlinks. LAW: two
traversal strategies. FIXTURE: `sysfs-symlink-topology`, under-claim `sysfs-empty-is-unknown`,
adversarial `symlink-escape`.

**L16** — FACT R3-F20/F21 [S1][S3]: first-obtained-value-wins plus in-place Include with lexical glob
order. LAW: walk the chain, keep the first occurrence, emit winning and shadowed sources.
FIXTURE: the pair `sshd-dropin-shadows-main` / `sshd-include-at-bottom` (same inputs, opposite verdict).

**L17** — FACT R3-F24 [S1]: Match overrides the global section per connection. LAW: degrade to
evidence-only. FIXTURE: `sshd-match-user-root`.

**L18** — FACT R3-F23 [S4][S2]: sshd.c V_9_6_P1 loads host keys before the -T branch, so unprivileged
-T always exits "no hostkeys available". LAW: own walker is primary; record -T's stderr as
EXECUTION_ERROR. FIXTURE: `sshd-T-no-hostkeys` plus its under-claim variant.

**L19** — FACT R3-F25/F26 [S1][S5][S27]: documented upstream defaults, with UsePAM diverging on
Debian/Ubuntu (CONTESTED). LAW: cited, version-scoped, distro-aware default table; unknown distro ⇒
UNKNOWN. FIXTURE: `usepam-absent-ubuntu`, `usepam-absent-unknown-distro`.

**L20** — FACT R3-F27/F30 [S6][S12][S13][S14][S43]: socket activation decouples the config from the
listener; /proc/net/tcp gives uid but not pid across uids. LAW: socket table is the truth; owner is
UNKNOWN/EACCES. FIXTURE: `socket-activated-port-mismatch`, `listener-owner-unknown`.

**L21** — FACT R3-F31 [S15]: reverse tunnels have no inbound listener by design. LAW: state the blind
spot in the finding. FIXTURE: `outbound-tunnel-no-listener`.

**L22** — FACT R3-F28/F29 [S9][S43][S8][S10][S11]: shadow and sudoers are unreadable unprivileged.
LAW: membership is fact, policy is UNKNOWN, sudo is never invoked. FIXTURE:
`shadow-unreadable-not-passwordless`, `sudo-never-invoked`.

**L23** — FACT R3-F33 [S71][S72][S73]: PEM/OpenSSH/keytab/JKS headers identify secrets in ≤64 bytes.
LAW: name → lstat → bounded header, classified and discarded; never store or hash a value.
FIXTURE: `pem-key-world-readable`, build-breaking `no-secret-bytes-in-output`.

**L24** — FACT R3-F34 [S74][S1][S75][S76]: pgpass 0600-or-ignored, StrictModes, docker base64,
git plaintext. LAW: cite the software's own rule as the criterion. FIXTURE: `pgpass-0644`,
`pgpass-0600`, `docker-config-present`.

**L25** — FACT R3-F36 [S43]: an unreadable directory means unknown contents. LAW: every enumeration
finding carries its boundary. FIXTURE: `unreadable-home-not-clean`, `entry-cap-hit-is-unknown`.

**L26** — FACT R3-F40/F41/F42/F44 [S35]: kernel IPMI module split, discovery provenance, 5 s IPMB
timeout, bus-disturbance warning. LAW: capability and access are separate fields; never issue an IPMI
command. FIXTURE: `bmc-present-node-root-only`, under-claim `bmc-unknown-because-no-ipmitool`.

**L27** — FACT R3-F43 [S67]: DSP0270 type 42 sources its USB fields from the device descriptors.
LAW: use the derived USB surface and produce a verdict. FIXTURE: `bmc-usb-nic-detected`.

**L28** — FACT R3-F45 [S40][S41]: DEVICE_ATTR(size,0444) printing bdev_nr_sectors; undocumented in the
ABI file. LAW: multiply by 512, cite the source. FIXTURE: `4kn-device-capacity`.

**L29** — FACT R3-F46/F46b [S68][S43]: lsblk reads sysfs + udev DB; the fallback is partial. LAW: do
not say UNKNOWN when the udev DB answers; do not read an empty field as "no filesystem".
FIXTURE: `blockdev-eacces-fstype-known` (under-claim), `udev-record-partial`.

**L30** — FACT R3-F47/F48 [S69][S70]: CRYPT- DM-UUID prefix; nvme_cmd_allowed requires CAP_SYS_ADMIN.
LAW: dm-crypt answerable, negative scoped; SMART UNKNOWN/EPERM while identity is still reported.
FIXTURE: `no-dm-not-unencrypted`, `smart-eperm-identity-known`.

**L31** — FACT R3-F49 [S77]: variable optional fields terminated by " - ". LAW: split on the
separator, index from both ends. FIXTURE: `mountinfo-with-propagation-fields`.

**L32** — FACT R3-F50 [S37]: machine-id(5) declares the ID confidential and prescribes a keyed hash.
LAW: never emit it verbatim. FIXTURE: `machine-id-not-emitted-raw`, `machine-id-empty`.

**L33** — FACT R3-F01/F51/F52/F77 [S39][S37][S43]: asset tags readable, serials not; machine-id is
clone-vulnerable; DMI may be wholly absent. LAW: ranked identity chain with provenance; ENOENT ≠
EACCES. FIXTURE: `no-dmi-platform`, `placeholder-asset-tag`.

**L34** — FACT R3-F60/F61/F62 [S19][S20][S21][S22]: XCCDF's nine values, OVAL's six, SARIF defaulting
to fail. LAW: recover the distinctions in `reason`; one finding per registered check always; never
default to the safe answer. FIXTURE: `panicking-check`, `registry-count-invariant`.

**L35** — FACT R3-F64 [S24]: Wazuh SCA merges absent/unreadable/timeout into one label. LAW: keep the
five classes distinct. FIXTURE: `four-failure-classes-one-check` (four fixtures, four reasons).

**L36** — FACT derived: under-claiming is the drift direction of a cautious implementation. LAW: every
check needs an under-claim fixture. FIXTURE: `fixture-matrix-coverage` meta-test.

**L37** — FACT R3-F74/F73/F77 [S31][S32][S30][S43]: an ID=ubuntu system without Ubuntu's kernel patch,
observed live. LAW: gate on observed paths, never on distro ID or vendor. FIXTURE:
`ubuntu-id-non-ubuntu-kernel`.

**L38** — FACT R3-F71/F72/F75/F76 [S28][S29][S33][S34]: /run/systemd/system as the systemd test,
inverted detect-virt polarity, util-linux 2.27 JSON floor, Lockdown from 5.4. LAW: capability gate
before probe; never positional column parsing. FIXTURE: `detect-virt-polarity`, `no-json-flag`,
`no-systemd`.

**L39** — FACT derived from R3-F02/F26/F30/F35/F48: the host lacks ipmitool, smartctl, dmidecode,
getfacl, nft, aa-status, getenforce while sysfs answers all of them. LAW: exec is always a fallback;
UTILITY_MISSING only when no kernel path can answer. FIXTURE: `no-ipmitool-still-answers` and
siblings.
