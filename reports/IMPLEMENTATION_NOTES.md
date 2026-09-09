# IMPLEMENTATION_NOTES

Written by the implementation author alongside the code. It records what each
check observes, and every place the implementation departs from
`research/DECISIONS.md`, `research/CHECK_REGISTRY.md` or `research/R5/PATTERNS.md`,
with the reason. It is not a review and it makes no claim about the quality of
the code it describes.

## Custom categories (LD-1)

- **`STORAGE_POSTURE`** — data-at-rest and decommissioning hygiene on rented
  hardware: whether anything is encrypted at rest, whether `/` has any
  redundancy, whether an attached device is unused (and therefore never opened),
  and drive health as a *proved* unknown rather than a silence. No check in this
  category ever opens a block device; refusing to look at what is on an unused
  disk is part of the answer, and the artifact says so.
- **`BOOT_CHAIN`** — whether the machine's own boot path can be trusted: Secure
  Boot state, platform Setup Mode, kernel lockdown, unsigned/out-of-tree module
  taint, TPM presence, boot-artifact readability, and drift between the running
  kernel and the newest installed one.

## The run-level `scan` block

The artifact carries an extra top-level `scan` object: `started_at`,
`duration_ms`, `deadline_ms`, `checks_run`, `budget_cut`, `budget_cut_count`,
`euid`, `degradations`, `self_check` and, on failure, `self_check_failures`.
Run-level facts belong there and not inside a finding, so a reader can
distinguish "this control could not be verified" from "this run was cut short"
or "the sensor lost a capability at startup". Extra fields are welcome anywhere
in the output contract, and the block is what makes a budget cut visible instead
of silent.

## Checks

All 26 emit exactly one finding per run. Impact is declared per check; the
reported severity is derived centrally (impact when the status is fail or
unknown, `info` when it is pass, always `info` for an observational check).

### `REMOTE_ACCESS` (6)

| check_id | impact | evidence sources |
|---|---|---|
| `SSH_ROOT_LOGIN_POLICY` | high | bounded exec `sshd -G` (shared once per scan); Include-aware walk of `/etc/ssh/sshd_config`; `lstat` of every `authorizedkeysfile` path expanded for root, plus its parent |
| `SSH_AUTH_METHODS_POLICY` | high | the same single `sshd -G` run; the config chain for provenance; `lstat /etc/pam.d/sshd` |
| `SSH_POLICY_IN_FORCE` | medium | `lstat` mtime of every file in the resolved Include chain; `systemctl show ssh.service -p ActiveEnterTimestamp`; `systemctl show ssh.socket -p ListenStream`; `/run/systemd/system` as the systemd capability gate |
| `REMOTE_LISTENING_SURFACE` | medium | `/proc/net/{tcp,tcp6,udp,udp6}` decoded directly; socket inode to `/proc/<pid>/fd` where readable; `ss -tulnH` as a cross-check only |
| `LOGIN_AND_ESCALATION_SURFACE` | medium | `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`; `lstat` of `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`, `/root/.ssh`; `passwd -S` for the calling account only |
| `HOST_FIREWALL_STATE` | medium | `systemctl is-active` per candidate unit; `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/firewalld/firewalld.conf`; `nft list ruleset` / `iptables -S`; `/proc/modules` as a capability signal only |

### `SECRETS_ON_DISK` (4)

| check_id | impact | evidence sources |
|---|---|---|
| `PRIVATE_KEY_MATERIAL_EXPOSURE` | high | bounded xdev walk of 12 roots; name filter, then `lstat`, then a 64-byte header classified and discarded; POSIX ACL xattr; group membership |
| `CREDENTIAL_FILE_EXPOSURE` | high | `lstat` of a fixed relative path set inside every login home plus the `/etc` equivalents, each against the permission rule its own software documents |
| `PROVISIONING_DATA_PROTECTION` | medium | `lstat` and listings of the cloud-init, Ignition and kickstart locations; key *names* only from `cloud.cfg.d` drop-ins; redaction detection in `instance-data.json` |
| `SYSTEM_SECRET_STORE_PROTECTION` | high | `lstat` plus ACL xattr of `/etc/shadow`, `/etc/gshadow`, `/etc/ssl/private`, `/etc/pki/tls/private`, `/etc/sudoers`, `/etc/sudoers.d`, `random-seed`, `krb5.keytab` |

Nothing in this category reads a credential value. The only content read
anywhere is a 64-byte header used to classify a candidate and then dropped;
`TestNoSecretValuesInOutput` greps the produced artifact for PEM armour, key
prefixes, JWT shapes, unexplained long opaque runs and the raw machine-id.

### `BMC_INBAND_ACCESS` (5)

| check_id | impact | evidence sources |
|---|---|---|
| `BMC_INBAND_INTERFACE_PRESENT` | info (observational) | readdir of `/sys/firmware/dmi/entries`, `/sys/bus/acpi/devices`, `/sys/devices/platform`; one deliberate attribute read so the 0400 denial is recorded rather than implied |
| `BMC_RESPONDS_IN_BAND` | info (observational) | `/sys/devices/platform/ipmi_bmc.*/{ipmi_version,firmware_revision,manufacturer_id,product_id,device_id,guid}`, each under an out-of-band deadline; `/proc/modules` as a capability signal |
| `BMC_DEVICE_NODE_ACCESS` | high | `lstat` of `/dev/ipmi0`, `/dev/ipmi/0`, `/dev/ipmidev/0`; ACL xattr; group membership; udev and modprobe.d rules that could relax the default |
| `BMC_CLIENT_TOOLING_INVENTORY` | info (observational) | `lstat` of each candidate name across the standard binary directories, including the sbin ones an unprivileged PATH omits |
| `BMC_HOST_INTERFACE_EXPOSURE` | medium | `/sys/class/net/*/{operstate,carrier,address,device/driver}` and the USB parent chain's descriptors; existence of an SMBIOS type-42 entry |

No IPMI command is ever issued and no BMC device node is ever opened, not even
`O_RDONLY|O_NONBLOCK`. Both facts appear in the evidence as explicit, auditable
claims.

### `STORAGE_POSTURE` (4)

| check_id | impact | evidence sources |
|---|---|---|
| `DISK_ENCRYPTION_AT_REST` | high | `/sys/block/dm-*/dm/{uuid,name}`, `/dev/mapper` listing, `/proc/self/mountinfo`, backing-chain walk through `slaves/`; `/etc/crypttab`; named blind spots for Opal, fscrypt and ZFS/btrfs |
| `UNUSED_ATTACHED_BLOCK_DEVICES` | medium | `/sys/block/<d>/` partition children, `holders/`, `slaves/`, `/proc/swaps`, mountinfo, and the udev database record |
| `ROOT_FILESYSTEM_REDUNDANCY` | low | mountinfo for `/`, backing chain, `/sys/block/md*/md/{level,degraded,raid_disks}`, `/proc/mdstat`, PCI class `0104` controllers, idle-device inventory |
| `MEDIA_HEALTH_VISIBILITY` | medium | `/sys/fs/ext4/<dev>/{errors_count,first_error_time,lifetime_write_kbytes}`, `/sys/block/<d>/device/state`, md `degraded`; `smartctl -H -j` and `nvme smart-log` as fallbacks whose errno is itself the evidence |

### `BOOT_CHAIN` (7)

| check_id | impact | evidence sources |
|---|---|---|
| `SECURE_BOOT_ENABLED` | high | the `SecureBoot-<GUID>` efivar, value byte at index 4 after the 4-byte attribute prefix; `mokutil --sb-state` as a cross-check only |
| `UEFI_PLATFORM_SETUP_MODE` | critical | the `SetupMode-<GUID>` efivar, same offset arithmetic; existence (not contents) of the `PK`, `KEK`, `db`, `dbx` variables |
| `KERNEL_LOCKDOWN_MODE` | medium | `/sys/kernel/security/lockdown` bracketed selection; `/sys/kernel/security/lsm`; the `lockdown=` cmdline parameter as intent only |
| `UNSIGNED_OR_OUT_OF_TREE_MODULES` | medium | `/proc/sys/kernel/tainted` decoded as a full 19-bit table; per-module `/sys/module/<name>/taint`; `sig_enforce`; `CONFIG_MODULE_SIG*` from `/boot/config-<kernel>` |
| `TPM_PRESENCE` | info (observational) | `/sys/class/tpm/tpm0/{tpm_version_major,device/description}`; `lstat` of `/dev/tpm0`, `/dev/tpmrm0`; the event log's mode |
| `BOOT_ARTIFACT_READABILITY` | low | readdir `/boot` plus `lstat` per artifact; mountinfo for the ESP's `fmask`/`dmask`/`umask` |
| `BOOT_KERNEL_DRIFT` | medium | `/proc/sys/kernel/osrelease`; `/boot/vmlinuz-*`; `/lib/modules/*`; `/boot/vmlinuz` symlink target; the `reboot-required` marker as corroboration only |

## Machine description

Sources per field are in `internal/checks/machine.go` and are also emitted in
the artifact as `*_source` siblings. `host_id` is
`HMAC-SHA256("lava-sensor-host-id", <first source that yields bytes>)` over
`product_uuid` → `machine-id` → a keyed hash of stable hardware ids
(`/sys/block/*/wwid`, permanent NIC MACs gated on `addr_assign_type == 0`) →
the literal `"unknown"`. The raw `/etc/machine-id` is never emitted, and a test
greps the produced artifact for it.

## Deviations and resolved gaps

### 1. `finalize()` writes the artifact even when the self-check fails (Direction Lock over `R5/PATTERNS.md` §6)

`R5/PATTERNS.md` §6 shows the writer refusing to write when validation fails.
The Direction Lock and `DECISIONS.md` D-05 both require the opposite: write the
file, record the failure in it, print the failing JSON pointers to stderr and
exit 1. Implemented as the Direction Lock specifies. Suppressing the output
would turn a formatting bug into a silent omission of every finding.

### 2. `ObsStatus` stays at eight values; the finding-level `reason` vocabulary is wider

The Direction Lock freezes `ObsStatus` to eight values, while
`R3/EVIDENCE_MODEL.md` §7 defines eleven `reason` classes and `DESIGN_LAWS.md`
L03 requires `EPERM` to stay distinct from `EACCES`. Reconciled rather than
collapsed: `ObsStatus` is the coarse class, `Observation.Errno` carries the
exact symbolic errno, and `Observation.Reason()` prefers the errno when there is
one. `EPERM`, `EINVAL`, `ENODEV` and `EOPNOTSUPP` therefore survive into the
finding while the frozen enum stays eight values wide.

### 3. `probe.NewRootedReader` is an exported test seam

`R5/TEST_STRATEGY.md` §1.1 shows the fixture-root seam as an unexported
constructor in the reading package. The checks live in a different package from
the reader, so the constructor has to be exported. Compensated by
`TestNoRootOverrideInProduction`, which walks the whole production tree and
fails if any non-test file references `NewRootedReader`, calls `os.Getenv` /
`os.LookupEnv`, or defines a root/unsafe/no-timeout flag.

### 4. `prohibit-password` with root key material proven absent (lead-refined)

`CHECK_REGISTRY.md` §2.1 defines PASS only for `permitrootlogin no` and FAIL for
`prohibit-password` with root key material present. The state "prohibit-password
and no root key material" is unspecified. Per lead direction, this now passes —
but only on proof, not on the absence of a file at one conventional path. It
requires all of: `sshd -G` succeeded; `authorizedkeyscommand` is `none`;
`trustedusercakeys` is `none`; and every path in the daemon's effective
`authorizedkeysfile`, expanded for root (`%h`, `%u`, `%%`, relative paths
resolved against root's home from `/etc/passwd`), is proven absent by a
successful stat of its parent directory. Anything undetermined — the usual
EACCES on `/root/.ssh` — yields unknown. Absence proven by a completed listing
is evidence; absence assumed from a denial is not.

### 5. No daemon and no configuration means there is no policy to default

`DESIGN_LAWS.md` L19 permits a cited, distro-scoped compiled-in default when a
directive is absent. That is only meaningful when a daemon exists. When neither
an `sshd` binary nor a readable configuration chain is found, the SSH checks
report `unknown` / `UTILITY_MISSING` and state that the absence of an SSH
listener is not the absence of remote access to the machine (L21). Confirmed by
the lead and applied across the SSH family.

### 6. A `Match` block downgrades only when its verdict class differs

`CHECK_REGISTRY.md` requires that a `Match` block make a global verdict
evidence-only (L17). Implemented narrowly for `SSH_ROOT_LOGIN_POLICY`: a `Match`
occurrence downgrades only when its value falls in a *different* verdict class
than the global one (refused / key-only / permitted). A `Match` that is strictly
more restrictive does not rescue a global `fail`, and does not manufacture an
`unknown` out of a global `pass` it agrees with. `SSH_AUTH_METHODS_POLICY` is
stricter: any `Match` scoping one of its four verdict directives downgrades,
because those interact.

### 7. `AssetTag.Placeholder` is a pointer

"We could not read this tag" and "we read it and it is not a vendor
placeholder" are different facts. A non-pointer boolean reported the first as
the second. The field is omitted entirely when the tag was not read, and the tag
still appears with its `errno`.

### 8. `Check` gained an optional `Budget()` through a separate interface

The Direction Lock fixes the `Check` interface at `ID, Category, Title, Impact,
Observational, Run`. The engine needs a per-check deadline
(`CHECK_REGISTRY.md` §3.9 classifies checks cheap / medium / expensive), so
`scan.Budgeted` is a separate optional interface the engine type-asserts. The
`Check` interface itself is unchanged.

### 9. No temporary file is used for the output write

Invariant 1 requires any temporary file to live under `os.TempDir()`;
`R5/PATTERNS.md` §6 writes `<out>.tmp` next to the output and renames. Writing
`<out>.tmp` on the target would be a write outside the `--out` file, and a
cross-filesystem rename from `os.TempDir()` would fail. The document is instead
rendered fully in memory and written with a single `os.WriteFile`.

### 10. The derived schema is duplicated into `sensor/testdata/`

`go:embed` and test-relative reads cannot reach outside the module, and the
sensor's source tree has to be self-contained in the tarball.
`sensor/testdata/finding.schema.json` is a byte copy of
`task/derived/finding.schema.json`, and `TestShippedSchemaMatchesTheAuthoritativeOne`
fails if the two ever differ. There is still exactly one authored schema.

### 11. The BMC manufacturer id is not mapped to a vendor name

`CHECK_REGISTRY.md` §2.3 suggests an embedded IANA PEN table resolving, for
example, `0x002a7c` to a vendor name. Implemented as the raw sysfs value plus
the decoded decimal PEN only. A name table is a second thing to keep correct and
it introduces vendor strings into check logic, which the portability guard
(`TestNoIdentityGatingInCheckLogic`) rightly rejects. The number is the citable
fact an operator can look up.

### 12. Two runs differ in measured durations

`DESIGN_LAWS.md` L47 asks for byte-stable output between runs. The artifact is
byte-stable in structure, key order, field order and every value except the
measured `duration_ms` and `elapsed_ms` fields, which are real timings and are
genuinely volatile. `TestTwoRunsDifferOnlyInMeasuredDurations` normalises only
those fields and requires byte equality everywhere else.

### 13. `ROOT_FILESYSTEM_REDUNDANCY` impact is `low`

Per lead resolution of registry OPEN-4 (the registry itself argued for
`medium`). The finding still reports `fail` on a single-device root, and the
"may be a deliberate rebuild-on-failure choice" caveat lives in the reason
rather than in the severity.

## Bugs the tests found during implementation

- A binary that exists but is not executable was classified `EXECUTION_ERROR`
  rather than `EACCES`, collapsing two of the five failure classes.
  `TestFourFailureClassesStayDistinct` caught it; the runner now separates a
  child that ran and failed (`*exec.ExitError`) from a fork/exec that never
  started.
- `unresolvedReason` preferred a missing config file over a timed-out daemon,
  reporting `ENOENT` where `TIMEOUT` was the actionable fact.
- `REMOTE_LISTENING_SURFACE` marked `/proc/net/tcp6` load-bearing
  unconditionally, so an IPv6-less kernel downgraded a verdict the IPv4 table
  fully supported — an over-claimed unknown, which L36 treats as a bug of the
  same weight as a false pass.
- `ROOT_FILESYSTEM_REDUNDANCY` counted a partition and its containing disk as
  two devices, which would have hidden a single-device root behind an
  "unresolved" unknown.
- Three checks produced findings with no observations in evidence (they had
  recorded only derived fields). `TestEveryFindingHasActionableEvidence` caught
  it; the underlying stat and listing attempts are now recorded even when they
  return ENOENT, because a proven absence is only proven if the attempt is shown.

## Where it has been run

| environment | invocation | result |
|---|---|---|
| WSL Ubuntu 26.04, uid 1000 | `./bin/sensor scan --out bin/findings.wsl.json` | 26 checks in 3.7 s, exit 0, self-check pass |
| Docker profile A (Ubuntu 24.04 userspace, read-only rootfs, `--cap-drop ALL`, `--network none`, uid 1000) | `tooling/testlab/run_in_docker.sh A` | 26 checks in 200 ms, exit 0 |
| Docker profile B (alpine 3.20 — busybox, no systemd, no sshd, no DMI) | `tooling/testlab/run_in_docker.sh B` | 26 checks, exit 0 — the portability proof: the same binary produces a schema-valid, honest output |
| Docker profile C (profile A image with `PATH=/nonexistent`) | `tooling/testlab/run_in_docker.sh C` | 26 checks, exit 0 — every utility missing, and no check reports a capability as absent because of it |

All four artifacts validate against the derived schema with zero violations.
Every containerised run reports `execution_context: container:docker` and sets
`describes_host_kernel`, so no `/sys`-derived field is silently attributed to
the container.

## Not implemented

- The ACL decoder's entry-parsing loop is exercised against its `ENODATA` and
  version-mismatch branches only. `setfacl` is not available in the test
  environment, so no live multi-entry ACL was decoded; the decoder reports
  `EINVAL` and refuses to guess when the version field is not 2.
- No check in `REMOTE_ACCESS` has been exercised against a live sshd: the
  environments available here have no daemon installed, so the `sshd -G` oracle
  path is covered by a fake runner returning realistic output, and by the
  Include-aware walker against real config trees. The first real-host run is what
  settles it.
