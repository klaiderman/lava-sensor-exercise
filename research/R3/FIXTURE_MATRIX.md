# R3 — FIXTURE_MATRIX.md

Every adversarial fixture produced by this track, mapped to the fault it injects, the law it
defends, and the sensor verdict the test must assert. "Under-claim" rows are the ones a cautious
implementation will fail; they are as load-bearing as the false-PASS rows (L36).

Legend for **Expected**: the verdict/behaviour the sensor MUST produce on that fixture.

## Topic 1 — unprivileged observation

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `dmi-serial-root-only` | DMI serial fields 0400 | L01 | UNKNOWN, reason EACCES, one finding per field |
| `dmi-asset-tag-not-read` (under-claim) | asset tags 0444 and populated | L01 | PASS/FAIL from the asset tag; UNKNOWN here is a failure |
| `dmi-serial-world-readable` (under-claim) | serials 0444 (some cloud images) | L01 | value reported; a hardcoded UNKNOWN is a failure |
| `smbios-raw-eacces` (under-claim) | /sys/firmware/dmi/tables 0400 | L02 | BMC checks still PASS/FAIL from parsed sysfs; EACCES recorded separately |
| `dmesg-restrict-eperm` | dmesg_restrict=1 | L03 | UNKNOWN reason EPERM (not EACCES); no dmesg subprocess spawned |
| `zero-stat-size-file` | procfs-like file, st_size 0 | L05 | non-empty value read |
| `oversize-sysfs-attr` | 5000-byte attribute, 4096 cap | L05, L12 | truncated=true and NOT PASS |
| `hidepid2-empty-proc` | /proc mounted hidepid=2 | L07 | UNKNOWN reason hidepid=2, not "no processes" |
| `hidepid0-full-proc` (under-claim) | /proc hidepid=0 | L07 | full enumeration returned |
| `sysctl-absent-not-permissive` | kernel/yama/ptrace_scope absent | L08 | UNKNOWN "Yama not present"; never PASS/FAIL from an assumed 0 |

## Topic 2 — bounded execution

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `grandchild-holds-stdout` | child spawns a grandchild holding stdout past the deadline | L09, L10 | returns within budget; UNKNOWN/TIMEOUT; no surviving descendant; **the sensor is still running** |
| `setpgid-omitted` (negative test) | Setpgid removed from the runner | L09 | the group kill demonstrably kills the harness — proves why L09 exists |
| `waitdelay-expired-not-fail` | child exits 0, grandchild holds the pipe | L10 | exit_code=0, status UNKNOWN, reason TIMEOUT, wait_delay_expired=true |
| `cancel-race-esrch` | child exits exactly at the deadline, x200 | L11 | zero EXECUTION_ERROR findings, stable verdict |
| `output-exactly-at-cap` | child emits exactly `cap` bytes | L12 | no PASS without evidence of EOF |
| `zombie-after-timeout` | forced timeout mid-run | L12 | no unreaped child remains |
| `fifo-at-config-path` | FIFO with no writer at a config path | L13 | returns within budget, UNKNOWN "non-regular file"; never blocks |
| `chardev-at-path` | /dev/zero symlinked into the fixture tree | L13 | never opened/read |
| `stuck-read-does-not-block-output` | a check blocks forever on a read | L14 | findings.json written on time; that check UNKNOWN/TIMEOUT; all others real |
| `sysfs-symlink-topology` | device dirs reachable only via symlinks | L15 | device enumeration non-empty |
| `sysfs-empty-is-unknown` (under-claim) | symlink depth cap hit | L15 | UNKNOWN/BUDGET_EXHAUSTED, not "no devices" |
| `symlink-escape` | /sys symlink pointing at /home/other | L15 | traversal refused and the refusal recorded |

## Topic 3 — sshd and remote access

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `sshd-dropin-shadows-main` | Include at line 1; drop-in `yes`, main file later `no` | L16 | effective=yes; drop-in as winning_source; main-file line listed as shadowed |
| `sshd-include-at-bottom` | identical files, Include on the last line | L16 | effective=no — same inputs, opposite verdict |
| `sshd-match-user-root` | global `PermitRootLogin no` + `Match User root` yes | L17 | not a bare PASS; the Match override present in evidence |
| `sshd-T-no-hostkeys` | unreadable 0600 host keys | L18 | walker still resolves the config; -T stderr recorded as EXECUTION_ERROR |
| `sshd-T-failure-not-blanket-unknown` (under-claim) | same | L18 | directives still resolved; blanket UNKNOWN is a failure |
| `usepam-absent-ubuntu` | UsePAM absent, ID=ubuntu | L19 | effective=yes with the Ubuntu citation in `default_source` |
| `usepam-absent-unknown-distro` | UsePAM absent, no /etc/os-release | L19 | UNKNOWN; a PASS with `defaulted:true` and no citation fails |
| `socket-activated-port-mismatch` | sshd_config Port 2222, socket table shows 22 | L20 | CONTESTED naming both; a silent pick fails |
| `listener-owner-unknown` | listening socket owned by another uid | L20 | listener PASS/FAIL; owner UNKNOWN/EACCES, never blank |
| `outbound-tunnel-no-listener` | established outbound tunnel, no new listener | L21 | not a bare PASS; evidence names the blind spot |
| `shadow-unreadable-not-passwordless` | /etc/shadow 0640 | L22 | no finding claims "no password set" for another account |
| `sudo-never-invoked` | any run | L22 | no sudo/su/doas process was spawned |

## Topic 4 — secrets

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `pem-key-world-readable` | 0644 file with PEM private-key armor | L23 | FAIL, magic_class=pem-private-key, zero content in output |
| `no-secret-bytes-in-output` (build gate) | any secret fixture | L23 | grep of findings.json for the key body or any 16+ byte substring finds nothing |
| `pgpass-0644` | .pgpass world-readable | L24 | FAIL citing PostgreSQL's own rule |
| `pgpass-0600` | .pgpass correctly restricted | L24 | PASS |
| `docker-config-present` | ~/.docker/config.json with auths | L24 | finding names base64-is-not-encryption, cites Docker, never decodes |
| `unreadable-home-not-clean` | 0700 other-user home containing a key | L25 | not PASS; unreadable_dirs names the home |
| `entry-cap-hit-is-unknown` | entry cap below the fixture's file count | L25 | BUDGET_EXHAUSTED and UNKNOWN, not "clean" |

## Topic 5 — BMC

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `bmc-present-node-root-only` | /sys/class/ipmi populated, /dev/ipmi0 0600 root:root | L26 | capability_present=true AND access_permitted=false; not a FAIL about presence |
| `bmc-unknown-because-no-ipmitool` (under-claim) | ipmitool absent, sysfs populated | L26, L39 | real BMC verdict; UNKNOWN/UTILITY_MISSING is a failure |
| `bmc-no-devintf` | /sys/class/ipmi present, /dev/ipmi* absent | L26 | "ipmi_devintf not loaded", not "no BMC" |
| `bmc-usb-nic-detected` | RNDIS gadget with a BMC manufacturer string | L27 | classified as a BMC host interface, produced without root |

## Topic 6 — storage

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `4kn-device-capacity` | logical_block_size 4096 | L28 | capacity = size * 512 (a 4096 multiplier over-reports 8x) |
| `blockdev-eacces-fstype-known` (under-claim) | /dev/<x> unreadable, udev record has ID_FS_TYPE | L29 | fstype reported, not UNKNOWN |
| `udev-record-partial` | udev record without ID_FS_UUID | L29 | UUID=UNKNOWN, never "unformatted" |
| `no-dm-not-unencrypted` | no dm devices present | L30 | wording scoped to dm-crypt; must not assert "unencrypted" |
| `luks2-dm-uuid` | dm/uuid = CRYPT-LUKS2-... | L30 | encryption detected without dmsetup or root |
| `smart-eperm-identity-known` (under-claim) | /dev/nvme0 root-only | L30 | health UNKNOWN/EPERM while model+serial are populated |
| `mountinfo-with-propagation-fields` | line with shared:1 master:2 propagate_from:3 | L31 | fstype and source parsed correctly |

## Topic 7 — identity

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `machine-id-not-emitted-raw` (build gate) | populated /etc/machine-id | L32 | the raw ID appears nowhere in findings.json |
| `machine-id-empty` | zero-length /etc/machine-id | L32 | finding names the uninitialised state, with a reason |
| `no-dmi-platform` | /sys/class/dmi absent entirely | L33, L37 | fall through to disk/MAC/machine-id with reason ENOENT; no EACCES wording |
| `placeholder-asset-tag` | asset tag "To be filled by O.E.M." | L33 | UNKNOWN quoting the placeholder; not a PASS naming it as the owner |

## Topic 8 — taxonomy

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `panicking-check` | a registered check panics | L34 | exactly one finding for its id, UNKNOWN/EXECUTION_ERROR; all other checks unaffected |
| `registry-count-invariant` | any run, including a timeout run | L34 | len(findings) == len(registry) |
| `four-failure-classes-one-check` | absent file / 0000 file / sleeping helper / helper removed | L35 | four DIFFERENT reasons; any two sharing a reason fails |
| `fixture-matrix-coverage` (meta) | the matrix itself | L36 | every registry check id has ≥1 PASS/FAIL row and ≥1 UNKNOWN row here |

## Topic 9 — portability

| Fixture | Fault injected | Defends | Expected |
|---|---|---|---|
| `ubuntu-id-non-ubuntu-kernel` | ID=ubuntu, neither userns knob present | L37 | UNKNOWN; no value inferred from the distro (observed live in this run) |
| `detect-virt-polarity` | stub exiting 0 with "kvm" | L38 | reports virtualized, not bare metal |
| `detect-virt-missing` | systemd-detect-virt absent | L38 | UNKNOWN/UTILITY_MISSING, never "bare metal" |
| `no-json-flag` | stub lsblk rejecting -J | L38 | UNKNOWN; must NOT fall back to positional column parsing |
| `no-systemd` | /run/systemd/system absent | L38 | every systemd check UNKNOWN "not systemd", not FAIL |
| `no-ipmitool-still-answers` (under-claim) | PATH without ipmitool | L39 | real verdict from sysfs |
| `no-smartctl-identity-still-known` (under-claim) | PATH without smartctl | L39, L30 | NVMe identity reported; only health is UNKNOWN |
| `no-getfacl-xattr-path` (under-claim) | PATH without getfacl | L39 | ACL presence attempted via the xattr syscall; UNKNOWN only if that also fails |

---

## Coverage summary

- 51 fixtures across 9 topics.
- 14 are explicitly **under-claim** cases (a cautious sensor fails them) — L36's quota.
- 2 are **build gates** that fail the build rather than a test (`no-secret-bytes-in-output`,
  `machine-id-not-emitted-raw`).
- 1 is a **negative/fault-injection** test that must be run in a sacrificial harness
  (`setpgid-omitted`).
- 1 is a **meta-test** over this document (`fixture-matrix-coverage`).
