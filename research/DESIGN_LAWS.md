# DESIGN_LAWS — reconciled engineering laws for the sensor

Reconciled from R3 `DESIGN_LAWS.md` (L01-L39, kept with their numbers so R3's FIXTURE_MATRIX stays valid) plus laws added from R1/R4/R5 facts (L40-L52). Each law cites reconciled fact ids from `research/FACTS.jsonl`; a law whose facts are CONTESTED is marked **PROVISIONAL**. Format per law: FACT -> LAW -> PROBE -> FIXTURE. Fixture names reuse R3 `FIXTURE_MATRIX.md` where one exists; new ones are marked (new).

Status legend: **FIRM** (facts VERIFIED, host-corroborated where host-relevant) · **PROVISIONAL** (rests on a CONTESTED/LIKELY fact) · **CHANGED** (R3 wording amended by reconciliation).

| Law | Status | Facts | One-line rule |
|---|---|---|---|
| L01 | FIRM | F3, F5 | DMI serials/UUID: attempt, report UNKNOWN/EACCES, still read the 0444 asset tags and vendor/model |
| L02 | FIRM | F4 | Never build a check whose only path is raw SMBIOS; entry directory names are the only unprivileged signal |
| L03 | FIRM | F8, F9 | EPERM is not EACCES; record syscall + path + policy-gate value with the errno |
| L05 | FIRM | F14, F15 | Read caps come from policy, never FileInfo.Size(); st_size 0 is not empty; read cap+1 |
| L07 | FIRM | F9, F12 | Closed reason vocabulary; never collapse failure classes; read hidepid before process conclusions |
| L08 | FIRM | F13 | Read the sysctl; never attempt the restricted operation; probe both knob spellings |
| L09 | FIRM | F21, F23 | Setpgid + process-group kill, in one runner; no other package builds an exec.Cmd |
| L10 | FIRM | F22 | Every Cmd sets WaitDelay; ErrWaitDelay maps to UNKNOWN/TIMEOUT, never FAIL |
| L11 | FIRM | F23 | Cancel normalises ESRCH to os.ErrProcessDone |
| L12 | FIRM | F15, F22, F23 | Capped writers on Stdout/Stderr, truncated flag, exactly one Wait() on every path |
| L13 | CHANGED | F16, F19 | One open path: O_RDONLY\|O_NONBLOCK\|O_CLOEXEC (O_NOFOLLOW outside /sys,/proc), fstat the FD, assert IsRegular — also inside an os.Root |
| L14 | FIRM | F17 | Scan deadline bounds scheduling and output, not reads; no unconditional WaitGroup.Wait before output |
| L15 | CHANGED | F18, F19 | /sys and /proc via os.Root (in-root symlink following, escape refused); user trees via WalkDir with budgets and no following |
| L16 | FIRM | F27 | Resolve sshd directives over the Include chain, first occurrence wins, emit shadowed ones |
| L17 | FIRM | F29 | Match block present => evidence-only, not a host-wide verdict |
| L18 | CHANGED | F24, F25, F26 | `sshd -G` (bounded, real rc) is the primary in-force oracle; own walker is the fallback and provenance/cross-check; never `sshd -T`; record any failed attempt as EXECUTION_ERROR |
| L19 | PROVISIONAL | F28 | Absent directive (fallback path only) => cited, version-scoped, distro-aware default; unknown distro => UNKNOWN |
| L20 | PROVISIONAL | F30, F31 | What listens comes from the socket table + effective socket unit; owner is UNKNOWN/EACCES without an independent signal |
| L21 | FIRM | F32 | Listener-based remote-access findings state the outbound-tunnel blind spot |
| L22 | FIRM | F33 | Group membership is fact; sudo policy and others' password state are UNKNOWN/EACCES; never run sudo |
| L23 | FIRM | F37 | Secrets: name -> lstat -> <=64-byte header, classified and discarded; never store or hash a value |
| L24 | FIRM | F39 | Use the software's own documented permission rule as the PASS/FAIL criterion |
| L25 | FIRM | F10 | Enumeration findings carry their boundary (EACCES dirs, prunes, budgets, xdev) or they are invalid |
| L26 | FIRM | F42, F43, F45, F46 | BMC: interface_declared, driver_bound+identified, access_permitted, host_interface are separate findings; never issue an IPMI command |
| L27 | FIRM | F47 | Root-only type 42 => use the USB descriptor surface and produce a verdict (INFO), not UNKNOWN; OOB exposure = UNKNOWN by construction |
| L28 | FIRM | F55 | Capacity = /sys/block/<d>/size x 512, never x logical_block_size |
| L29 | FIRM | F57 | udev DB answers fstype/identity without opening the device; empty field != no filesystem |
| L30 | FIRM | F58, F59 | dm/uuid CRYPT- prefix answers dm-crypt; negative scoped (SED, fscrypt named); SMART is UNKNOWN/CAP_SYS_ADMIN while identity is reported |
| L31 | FIRM | F20 | mountinfo: split on the literal " - ", index from both ends |
| L32 | FIRM | F6 | Never emit machine-id verbatim; emit a keyed derivation + host_id_source; label clone/re-image caveats |
| L33 | FIRM | F3, F6, F7 | Identity is a ranked chain with provenance; ENOENT (no DMI platform) != EACCES (restricted DMI) |
| L34 | FIRM | F66, F68 | One finding per registered check, always; an unset verdict never defaults to PASS; run-level errors live outside findings |
| L35 | FIRM | F65, F66 | Reason vocabulary strictly finer than "not applicable"; the five classes stay five |
| L36 | FIRM | derived | Every check needs an under-claim fixture, not only a false-PASS fixture |
| L37 | FIRM | F7, F13, F54 | Gate on observed paths/capabilities, never on distro ID, hostname or vendor |
| L38 | FIRM | F53 | Capability gate before probe: /run/systemd/system, detect-virt polarity, JSON flag floor, kernel version |
| L39 | FIRM | F43, F48, F50, F56, F57, F59 | Missing utility != missing capability; exec is always a fallback behind sysfs/procfs |
| L40 (new) | FIRM | F44, F17 | Out-of-band deadline for uncancellable reads: BMC sysfs (live KCS transaction) and any device-adjacent read run in their own goroutine with a timer; overrun => UNKNOWN/TIMEOUT, goroutine abandoned, scan continues |
| L41 (new) | FIRM | F1 | One observation per fact: never read an exit code through a pipeline; never let an aggregate status stand for a per-fact outcome |
| L42 (new) | FIRM | F8, F9, F50 | Mode bits are not authorisation: any "who can read X" finding pairs mode/owner/group/ACL with the kernel policy gate and the observed errno |
| L43 (new) | FIRM | F33 | Empty privileged groups turn group-mode into root-only in practice: a reusable membership helper feeds every device/log permission finding |
| L44 (new) | FIRM | F52 | Drift/patch checks: compare uname with the /boot default; absence of reboot-required is not evidence; empty apt lists => UNKNOWN, never PASS |
| L45 (new) | FIRM | F7, F85 | Establish execution context (container/VM/bare metal) before hardware inventory; annotate or downgrade findings when containerised |
| L46 (new) | FIRM | F49, F48 | Boot-chain checks decode kernel bit tables as data; Setup Mode is its own check; efivars absent = not-applicable, not disabled; taint E does not imply enforcement |
| L47 (new) | FIRM | F72 | Deterministic output: encoding/json v1, SetEscapeHTML(false), explicit RFC 3339 strings, int64 numerics, findings sorted (category, check_id) |
| L48 (new) | PROVISIONAL | F70, F69 | Validation: full-schema at test time and at the release gate (santhosh v6, format assertion on); stdlib invariants at runtime; never suppress output on failure |
| L49 (new) | FIRM | F71 | Zero runtime third-party dependencies: stdlib syscall for Setpgid/Kill/Getxattr/Statfs/Stat_t.Dev; x/sys only on a named reversal condition |
| L50 (new) | FIRM | F73, F74 | Static linux/amd64 cross-build, 0755 in the tar header + documented chmod, exit 0/1/2 policy independent of finding severity |
| L51 (new) | FIRM | F75, F63 | Test seams are unexported (fs.FS from Root.FS(), runner interface, now func); never an environment-variable root override |
| L52 (new) | FIRM | F41 | ACLs: decode system.posix_acl_access in pure Go; ENODATA = no ACL, EACCES/ENOTSUP = unknown; AND mask with USER/GROUP perms; byte-fixture unit test |

---

## Compact FACT -> LAW -> PROBE -> FIXTURE blocks

**L01** — FACT F3 (dmi-id.c v6.8 modes; host ls -l), F5 (placeholders). LAW: attempt reads, report UNKNOWN/EACCES for serials/UUID, read asset tags/vendor/model, treat OEM placeholders by pattern. PROBE: os.Root(/sys).ReadFile(class/dmi/id/<attr>) per attribute; EACCES expected on four; ENOENT on the directory => L33/L37. FIXTURE: `dmi-serial-root-only`, `dmi-asset-tag-not-read` (under-claim), `dmi-serial-world-readable`, `placeholder-asset-tag`.

**L02** — FACT F4. LAW: no check depends solely on raw SMBIOS; use parsed sysfs objects; report EACCES on raw as the reason, not as omission. PROBE: readdir /sys/firmware/dmi/entries for `38-*`/`42-*`; stat before reading any attribute. FIXTURE: `smbios-raw-eacces` (under-claim guard), `dmi-entries-listable-attrs-denied` (new).

**L03** — FACT F8, F9. LAW: EPERM distinct from EACCES; record syscall, path, errno, and the policy value. PROBE: read the sysctl; never run dmesg; stat before classifying a denied sysfs attribute (write-only case). FIXTURE: `dmesg-restrict-eperm`, `writeonly-sysfs-attr-not-alarming` (new).

**L05** — FACT F14, F15. LAW: caps from policy; st_size ignored; cap+1 read; truncated => never PASS. PROBE: bounded reader over os.Root. FIXTURE: `zero-stat-size-file`, `oversize-sysfs-attr`, `output-exactly-at-cap`.

**L07** — FACT F9, F12. LAW: closed reason vocabulary (EACCES, EPERM, ENOENT, EINVAL/ENODEV, EIO, TIMEOUT, UTILITY_MISSING, UNSUPPORTED, BUDGET, TRUNCATED, EXECUTION_ERROR); hidepid read first. FIXTURE: `hidepid2-empty-proc`, `hidepid0-full-proc`.

**L08** — FACT F13. LAW: read the knob; probe both userns spellings; ENOENT on yama => Yama absent. FIXTURE: `sysctl-absent-not-permissive`, `userns-knob-either-spelling` (new).

**L09/L10/L11/L12** — FACT F21, F22, F23, F15. LAW: single runner (Setpgid, group-kill Cancel with ESRCH normalisation, WaitDelay, capped writers, deferred Wait); ErrWaitDelay => UNKNOWN/TIMEOUT. FIXTURE: `grandchild-holds-stdout`, `setpgid-omitted` (negative), `waitdelay-expired-not-fail`, `cancel-race-esrch`, `zombie-after-timeout`, `no-surviving-descendant` (new; from R5-F14).

**L13** (CHANGED) — FACT F16, F19. LAW: open O_RDONLY|O_NONBLOCK|O_CLOEXEC, then Fstat the fd, IsRegular required; O_NOFOLLOW only outside /sys and /proc; lstat is a pre-filter, not the gate; os.Root does not exempt from the gate. Amends R3 wording ("O_NOFOLLOW everywhere") because /sys is symlinks (F18) and R1 SP-18 ("never rely on O_NONBLOCK") because the fd gate, not lstat, closes the TOCTOU. FIXTURE: `fifo-at-config-path`, `chardev-at-path`.

**L14** — FACT F17. FIXTURE: `stuck-read-does-not-block-output`.

**L15** (CHANGED) — FACT F18, F19. LAW: os.Root(/sys), os.Root(/proc) with deliberate symlink following and escape refusal; degrade to plain bounded reads + lstat gating if OpenRoot fails; WalkDir + budgets elsewhere. FIXTURE: `sysfs-symlink-topology`, `sysfs-empty-is-unknown`, `symlink-escape`, `openroot-unavailable-degrades` (new).

**L16/L17** — FACT F27, F29. FIXTURE: `sshd-dropin-shadows-main` / `sshd-include-at-bottom` (pair), `sshd-match-user-root`.

**L18** (CHANGED) — FACT F24 (host: `sshd -G` works), F25 (CONTESTED: `-G -C` fatals), F26 (`-T` fails). LAW: run `/usr/sbin/sshd -G` through the bounded runner and capture the real exit code; parse its lowercase `keyword value` lines as the in-force GLOBAL policy; run the own Include-aware walker in parallel for {path,line} provenance and as the fallback when sshd is absent/`-G` fails/output is malformed; report disagreement between oracle and walker as CONTESTED evidence; never `-T`; Match-conditional policy stays a bounded unknown (`-G -C` not relied upon). Note `-G` prints `without-password` for `prohibit-password`. FIXTURE: `sshd-G-oracle-primary` (new), `sshd-G-absent-walker-fallback` (new), `sshd-G-disagrees-with-walker` (new), `sshd-T-no-hostkeys` (+ under-claim variant).

**L19** (PROVISIONAL, F28 CONTESTED) — fallback-path defaults only; per-row citation, version and distro family; unknown distro => UNKNOWN. FIXTURE: `usepam-absent-ubuntu`, `usepam-absent-unknown-distro`.

**L20** (PROVISIONAL, F30 CONTESTED generically) — LAW: listeners from /proc/net/tcp{,6} (uid, inode) cross-checked with `systemctl show ssh.socket -p Listen` (effective) and the service state; sshd_config never decides the listen address; owner UNKNOWN across uids. FIXTURE: `socket-activated-port-mismatch`, `listener-owner-unknown`.

**L21** — FACT F32. FIXTURE: `outbound-tunnel-no-listener`.

**L22** — FACT F33. FIXTURE: `shadow-unreadable-not-passwordless`, `sudo-never-invoked`, `empty-privileged-group-root-only` (new).

**L23/L24/L25** — FACT F37, F39, F10. FIXTURE: `pem-key-world-readable`, `no-secret-bytes-in-output` (build-breaking), `pgpass-0644`, `pgpass-0600`, `docker-config-present`, `unreadable-home-not-clean`, `entry-cap-hit-is-unknown`.

**L26** — FACT F42, F43, F45, F46. LAW: four separable findings (firmware declares 38-0; driver bound + BMC identified; access_permitted from observed mode/ACL/groups; latent host interface); never open /dev/ipmi0 for commands; ipmitool presence is inventory. FIXTURE: `bmc-present-node-root-only`, `bmc-unknown-because-no-ipmitool` (under-claim), `proc-devices-ipmidev-name` (new).

**L27** — FACT F47. FIXTURE: `bmc-usb-nic-detected`, `oob-exposure-unknown-not-absent` (new).

**L28** — FACT F55. FIXTURE: `4kn-device-capacity`.

**L29** — FACT F57. FIXTURE: `blockdev-eacces-fstype-known` (under-claim), `udev-record-partial`.

**L30** — FACT F58, F59. FIXTURE: `no-dm-not-unencrypted`, `smart-eperm-identity-known`, `sed-unknown-regardless-of-model` (new).

**L31** — FACT F20. FIXTURE: `mountinfo-with-propagation-fields`.

**L32/L33** — FACT F6, F3, F7. FIXTURE: `machine-id-not-emitted-raw`, `machine-id-empty`, `no-dmi-platform`.

**L34/L35** — FACT F66, F65, F68. FIXTURE: `panicking-check`, `registry-count-invariant`, `four-failure-classes-one-check`.

**L36** — meta. FIXTURE: `fixture-matrix-coverage`.

**L37/L38/L39** — FACT F7, F13, F53, F54, F43, F48, F50, F56, F57, F59. FIXTURE: `ubuntu-id-non-ubuntu-kernel`, `detect-virt-polarity`, `no-json-flag`, `no-systemd`, `no-ipmitool-still-answers` and siblings, `aa-status-missing-not-apparmor-absent` (new).

**L40** (new) — FACT F44 (KCS 5 s x retries worst case; host 1-2 ms healthy), F17 (reads not interruptible). LAW: the BMC identity read (and any read of a device-adjacent sysfs attribute) runs in its own goroutine under a per-check timer independent of ctx; on overrun the collector records UNKNOWN/TIMEOUT with the attribute path, abandons the goroutine, and the scan proceeds; a cached/partial value never masquerades as fresh. The per-check budget constant is sized from the host timing (ms) with a safety factor, never from the worst case. PROBE: time each attribute read; record elapsed_ms as evidence. FIXTURE: `bmc-attr-read-hangs` (new; fake fs blocks), `bmc-attr-read-fast-path` (new; asserts elapsed recorded).

**L41** (new) — FACT F1. LAW: one observation per fact; the runner returns the child's own exit status; no shell pipelines; evidence carries per-command rc/errno/stderr. FIXTURE: `pipeline-rc-not-used` (new; static analysis or runner unit test that no `sh -c ... |` string exists).

**L42** (new) — FACT F8, F9, F50. LAW: "who can read X" = mode + owner + group + ACL + membership + policy gate + observed errno; a 0444 file that returns EACCES is reported as policy-denied, not as a mode contradiction. FIXTURE: `mode-readable-but-eacces` (new; apparmor/profiles shape).

**L43** (new) — FACT F33. LAW: a shared helper resolves group membership from /etc/group (and states its NSS caveat, F73) and annotates any group-mode device/log as effectively root-only when the group is empty. FIXTURE: `empty-privileged-group-root-only` (new).

**L44** (new) — FACT F52. FIXTURE: `kernel-drift-without-marker` (new), `apt-lists-empty-not-up-to-date` (new).

**L45** (new) — FACT F7, F85. FIXTURE: `container-sees-host-sysfs` (new; fixture with /.dockerenv or cgroup markers => findings annotated).

**L46** (new) — FACT F48, F49. FIXTURE: `efivars-attribute-prefix` (new; byte 0 vs byte 4), `setup-mode-own-check` (new), `no-efivars-not-applicable` (new), `taint-E-not-enforcement` (new).

**L47** (new) — FACT F72. FIXTURE: golden findings.json byte-stable across two runs except timestamps.

**L48** (new, PROVISIONAL on F70) — see C-06. FIXTURE: `schema-conformance-golden` (test-only import), `invalid-doc-still-written-exit-1` (new).

**L49** (new) — FACT F71. FIXTURE: `go-list-deps-zero-third-party` (new; asserts `go list -deps ./cmd/sensor` has no non-stdlib module).

**L50** (new) — FACT F73, F74. FIXTURE: `tarball-binary-mode-0755` (new), `exit-code-policy` (new).

**L51** (new) — FACT F75, F63. FIXTURE: `no-env-root-override` (new; grep-test that no os.Getenv selects a root).

**L52** (new) — FACT F41. FIXTURE: `acl-bytes-decode` (new; header 02 00 00 00 + entries), `acl-version-not-2-unknown` (new), `acl-enodata-is-no-acl` (new).

## Laws that R3 numbered but reconciliation changed (for the lead)
- L13, L15: os.Root replaces "O_NOFOLLOW everywhere"; symlink policy is path-scoped (F18, F19).
- L18: `sshd -G` becomes primary (F24); R3's "own walker is primary" is retracted (F97).
- L19, L20, L48: PROVISIONAL because F28, F30, F70 are CONTESTED.
