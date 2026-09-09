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

## Fix batch 1 (from the test lab and the first real-host run)

Five wrong answers, each removed and each pinned by a regression test in
`internal/checks/fixbatch1_test.go`.

1. **`ROOT_FILESYSTEM_REDUNDANCY` called a diskless root a single disk.** A root
   backed by no local block device (NFS, diskless, overlay) took the same
   single-device FAIL as a real one disk, printing an empty device list. It is
   now `unknown` with reason `EINVAL`, naming the root's source and fstype and
   saying that redundancy for it lives on the other side of that boundary. The
   single-device FAIL is now reached only when exactly one disk really is there.
   Tests: `TestRootRedundancy_NetworkRootIsUnknownNotSingleDevice`,
   `TestRootRedundancy_OverlayRootIsUnknownButRealSingleDiskStillFails`.

2. **SMART health was sniffed, not parsed.** `smartctl -H -j` output was tested
   with `strings.Contains(v, "{")` and then for `"passed":false`, so a truncated
   or malformed report — which contains neither — read as healthy. The document
   is now unmarshalled into a struct: a parse failure or a missing
   `smart_status.passed` yields `unknown` / `PARSE_ERROR` with the parse error in
   evidence, and a health verdict is never inferred from the shape of the output.
   Unreachable on the Lava host (smartctl absent), which is exactly why it had to
   be fixed before shipping. Tests: `TestMediaHealth_TruncatedSmartJSONIsNotHealthy`,
   `TestMediaHealth_SmartJSONWithoutPassedFieldIsNotHealthy`,
   `TestMediaHealth_SmartJSONIsReadBothWays`, `TestParseSmartctlJSON`.

3. **`SSH_POLICY_IN_FORCE` ordered two events inside one second.** On the host
   the drop-in mtime was 17:37:29.291 and `ActiveEnterTimestamp` was 17:37:29,
   and the check reported FAIL with `delta_seconds: 0` — an assertion of drift
   that a whole-second timestamp cannot support. The comparison now resolves the
   unit's start as precisely as systemd will report it: the `*TimestampMonotonic`
   properties are microseconds since boot and are reconstructed against
   `/proc/uptime`, giving a 100 ms resolution; otherwise the rendered
   whole-second timestamp gives 1 s. A difference inside that resolution is
   `unknown` with the new reason **`TIMESTAMP_RESOLUTION`** — nothing disagrees,
   the instrument simply does not resolve the question, which is why it is not
   `CONTESTED`. Beyond it, newer config is FAIL and older is PASS. The evidence
   gains `service_start_source`, `comparison_resolution_ms` and `delta_ms`, and
   keeps the socket-activation note. Tests:
   `TestSSHPolicyInForce_SameSecondIsUndecidable` (four staged mtimes, end to
   end), `..._ClearlyNewerConfigStillFails`,
   `..._MonotonicSourceGivesSubSecondResolution`, `..._SocketActivationNoteIsKept`.

4. **`PROVISIONING_DATA_PROTECTION` failed every cloud-init host by design.**
   cloud-init publishes `instance-data.json` world-readable *on purpose* with its
   sensitive keys redacted (the check's own evidence showed
   `redaction_observed: true`), keeps the sensitive copy, user-data, vendor-data,
   seeds and `obj.pkl` root-only, and ships `.cfg` drop-ins as public
   configuration. Artifacts are now classified `payload` or `public-by-design`,
   and only a readable payload artifact is adverse; a `.cfg` drop-in is promoted
   to payload when it declares a credential-bearing key *name*. Instance
   directories are descended one level and their contents classified by name,
   because they are named after the instance id. `datasource_class` now comes
   from `/run/cloud-init/cloud-id`, falling back to `v1.cloud_name` /
   `v1.platform` parsed out of `instance-data.json`. Expected host result: pass,
   with the artifact table in evidence. Tests:
   `TestProvisioning_PublicByDesignArtifactsAreNotExposure`,
   `..._ReadablePayloadStillFails`, `..._InstanceDirectoryPayloadIsFoundByName`,
   `..._DropInDeclaringCredentialKeysIsPayload`, `TestCloudNameFrom`.

5. **`CREDENTIAL_FILE_EXPOSURE` walked service accounts' placeholder homes.**
   `homes_inspected` contained `/bin` and `unreadable_homes` contained `/` and a
   duplicated `/root`, because every `/etc/passwd` line with a home was walked.
   The set is now the deduplicated homes of accounts with a login-capable shell,
   plus root whatever its shell says, minus the placeholder directories
   distributions hand to service accounts (`/`, `/bin`, `/sbin`, `/dev`,
   `/usr/sbin`, `/nonexistent`, `/var/empty`, …), which are reported in a new
   `homes_skipped` field rather than silently dropped. Status semantics are
   unchanged: an unreadable home is still `unknown` with the boundary in
   evidence. Tests: `TestCredentialHomes_SkipsSystemDirsAndDeduplicates`,
   `TestCredentialExposure_HomesAreCleanAndDeduplicated`.

The closed reason vocabulary gained one class in this batch,
`TIMESTAMP_RESOLUTION` (item 3). It is documented in `sensor/README.md`.

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

## Fix batch 2 (independent review, external adversarial review, Ponytail pass 2)

Batch 1 fixed five wrong answers. Batch 2 closes the classes they belonged to.

### A. Evidence entails the verdict, mechanically (external #1, and the class H1/#2/#4/#10 belong to)

The recurring defect was never a typo. A check gathered observations, some
failed, and then it wrote a sentence asserting that everything had been seen —
"enumerated successfully", "proven by a successful listing", "every enumeration
completed" — with the structured evidence next to it saying otherwise. A reader
who trusts the sentence is wrong; a reader who trusts the evidence must distrust
the sensor.

`internal/scan/entailment.go` makes the link mechanical:

- `completenessOf()` generates the completeness account from the observations —
  totals, which load-bearing ones failed, and whether an absence is provable —
  and `finalize` attaches it to every finding as `evidence.completeness`.
- `claimsCompleteness()` holds the closed list of phrases that assert an
  enumeration finished. A detail that uses one while the observations do not
  support it is downgraded to `unknown`, annotated in place, and flagged
  `entailment_violation` so the fact is auditable from the artifact alone.
- This runs BEFORE the load-bearing downgrade, because once that has rewritten
  the detail the over-claim is no longer there to catch. The downgrade now
  appends its reason rather than replacing what the check said.
- `probe.Observation.AbsenceProven` distinguishes an ENOENT that IS the answer
  (a stat that resolved the path and found nothing) from one that is a gap in it.
  Without that distinction "the file is not there" and "we could not look"
  collapse into one status.
- `scan.Result.LoadBearingIf()` marks observations load-bearing per branch:
  a check that FOUND something stands on that positive observation, while a
  check about to say it found nothing stands on every listing having succeeded.
  Marking unconditionally would manufacture unknowns out of real findings.
- `scan.AuditEntailment()` applies the same rule in data mode to a finished
  findings.json, so a container or host artifact can be audited after the fact.

Tests: `TestEvidenceEntailsVerdict` (whole roster × profiles A/B/C × two
adversarial trees), `TestEntailmentGateDowngradesAnOverclaim`,
`TestEntailmentAuditorOnShippedArtifacts`.

### B. The walk that "completed" without entering the directory (H1, #1, #2, #17, #22, M4)

`WalkResult.Complete()` consulted only the root's own error, so a walk that
`filepath.WalkDir` had carried on past — denied subtree, pruned mount, exhausted
budget — counted as finished. On the real host that produced a `pass` for
`PRIVATE_KEY_MATERIAL_EXPOSURE` with `/root` and `/etc/ssl/private` unreadable,
directly contradicting `CREDENTIAL_FILE_EXPOSURE` on the same directory.

`Complete()` is now false on any of those; `Boundary()` renders why;
`CrossedMounts` is actually set when a mount is declined (it was a dead write);
and the counters `unreadable_dirs_count` / `dirs_pruned_count` are always
emitted, so a boundary dropped from a capped list does not vanish. In the check:
an exposed key is a positive observation and still fails even from an incomplete
search; no adverse plus any boundary is `unknown` with the boundary list; zero
inspected roots is `unknown` rather than a pass over nothing; and symlinks are
never candidates (the artifact previously listed 121 CA-bundle links).

Tests: `TestPrivateKey_UnreadableSubtreeIsUnknown` (also asserting the two
secrets checks no longer contradict each other),
`TestPrivateKey_AdverseFindingSurvivesAnIncompleteWalk`,
`TestPrivateKey_ZeroWalksIsNotPass`, `TestPrivateKey_SymlinksAreNotCandidates`,
`TestWalkBoundaryCountersSurviveEvidenceCap`, `TestWalkSetsCrossedMounts`.

### C. A denied ruleset is not an absent one (#3, M1, #13)

`HOST_FIREWALL_STATE` could emit a confident `fail` — "the machine is reachable
and unfiltered" — when the ruleset had merely been refused and the filtering was
loaded by something outside its five candidate units. It also read
`ufw.conf ENABLED=no` and then said "a filtering subsystem is enabled".

Now: a readable `ENABLED=no` while the unit reports active is a `fail` citing
the file and the value (the unit is a oneshot that exits early, so its state
proves nothing); a ruleset that could not be read is `unknown`; an implementation
this sensor does not recognise is `unknown` with the blind spot named, never a
fail. The runner classifies a tool's own "Permission denied" / "you must be
root" stderr as EACCES/EPERM rather than EXECUTION_ERROR, which is the least
actionable of the three.

Tests: `TestFirewall_DeniedRulesetIsUnknown`, `TestFirewall_UfwDisabledIsFail`,
`TestFirewall_UnknownImplementationIsUnknown`,
`TestExecPrivilegeDenialIsClassifiedAsEACCES`.

### D. BMC absence needs successful listings (#4, #10)

`BMC_INBAND_INTERFACE_PRESENT` guarded on an OR over three listings, so on a
kernel without `dmi-sysfs` — plenty of bare-metal Ubuntu installs — it reported
"no management-controller interface is declared" directly below an ENOENT
observation. `BMC_DEVICE_NODE_ACCESS` checked `!found` before `undetermined`, so
a denied `/dev/ipmi/0` read as an absent node — which is exactly why the check
stats all three spellings in the first place.

Absence now requires every load-bearing listing to have succeeded, undetermined
outranks not-found, and the completeness prose comes from the engine.

Tests: `TestBMC_ENOENTNotOverclaimed`, `TestBMC_DeniedPathIsNotAbsent`.

### E. What `sshd -G` is, and whether the daemon loaded it (#6, #7, #8, #9, M3)

`sshd -G` re-parses the files on disk with the installed binary's defaults. It
says nothing about the listening process. The artifact previously said in one
finding "the running daemon is enforcing something other than what is on disk"
and in the next "the running policy accepts public keys only" — from that same
on-disk parse.

The label is now "effective configuration as sshd would load it from disk now",
and the fix is not only a label. `daemonStateOf()` gathers the RAW in-force
facts — unit start time, newest config mtime, measured resolution, and the
resulting relation — and `SSH_ROOT_LOGIN_POLICY` and `SSH_AUTH_METHODS_POLICY`
both carry them as `daemon_state`. Where the chain is provably newer than the
daemon their verdict downgrades to `unknown`/`CONTESTED`; where the order cannot
be established the verdict stands with the caveat attached. **That caveat
observation is deliberately not load-bearing**: an undecidable ordering is not a
failed observation, and turning every SSH finding on every provisioned host into
an unknown would be its own dishonesty. No cross-check verdict state is stored —
Env caches only the raw `systemctl show` observation.

The resolution is now MEASURED rather than asserted (#7). The reconstruction
mixes CLOCK_BOOTTIME (`/proc/uptime`) with CLOCK_REALTIME, and their divergence
since boot is not observable from one sample. So the two uptime reads bracket
the wall-clock sample to measure the read skew, and the reconstruction is
cross-checked against systemd's own rendered timestamp: agreement within its
whole second bounds the clock-domain divergence, disagreement becomes the
resolution. Batch 1's fixed 100 ms floor is gone.

Also: an `Include` reached from inside a `Match` block now keeps that Match
scope (it was flattened into global scope, which either hid a Match-scoped root
login grant or fabricated a global one), and a truncated Include glob expansion
is recorded as a load-bearing observation so a verdict built on a partial
configuration chain cannot pass.

Tests: `TestSSHPolicy_SourceLabelIsOnDisk`,
`TestSSHPolicy_StaleConfigDowngradesPolicyVerdict`,
`TestSSHPolicy_UndecidableOrderKeepsVerdictWithCaveat`,
`TestInForce_ResolutionIsMeasuredNotAssumed`,
`TestSSHDConfig_IncludeInsideMatchStaysConditional`,
`TestSSHDConfig_TruncatedGlobIsLoadBearing`.

### F. Bounds that live in the operation, not in the caller (#5, #11, #12)

`resolveSocketOwners` took no context and consulted none. It listed up to 4096
PIDs and, for each, up to 1024 descriptors with a readlink apiece: about 4.2
million syscalls. The per-check deadline could not stop a loop that never looked
at it, and the scan is sequential, so on a busy customer machine the whole
60-second deadline would have been blown. It ran in 81 ms on the Lava host only
because that host is idle.

It now takes a context, checks it per PID, and carries its own budget of 2048
processes / 20000 syscalls / 2 s. When it stops early the boundary is recorded
in `owner_attribution` and the listeners it did not reach are reported as
unattributed rather than unowned. The other host-access loops were audited: the
directory listings are capped at the call site, `Walk` carries entry/depth/time
budgets, and the sshd Include chain is capped by depth and file count.

The budget arithmetic is documented in `scan.Run`: the declared per-check budgets
sum to far more than the scan deadline, so the deadline dominates — a check gets
`min(declared, remaining)` — and a slow early check cannot silently starve a
later one, because every later check still emits its own finding with
`BUDGET_EXHAUSTED` or `TIMEOUT`.

Tests: `TestSocketOwners_BudgetIsEnforcedAndVisible`,
`TestScanDeadline_DominatesPerCheckBudgets`.

### G. Safety (#13, #14, #15, #16)

- `resolveBinary` no longer falls back to the inherited PATH. A user-writable
  directory early on it could have supplied `mokutil`, and a planted `mokutil`
  printing "SecureBoot enabled" would have turned `SECURE_BOOT_ENABLED` into a
  pass. Same uid, so not an escalation — but the evidence would have been
  attacker-shaped. (`TestResolveBinary_IgnoresPATH`.)
- The ACL read uses `lgetxattr(2)`, issued directly because Go's `syscall`
  wraps only the symlink-following variant. On a symlink candidate the old call
  described the target, not the object whose mode was reported from `lstat` —
  and in a user-writable tree the target is attacker-chosen. The comment claimed
  the safe behaviour all along. (`TestReadACL_DoesNotFollowFinalSymlink`.)
- `MEDIA_HEALTH_VISIBILITY` no longer runs `nvme smart-log` or `smartctl -H`.
  Both make a CHILD open the drive character device and issue an admin
  passthrough. Denied at uid 1000 they were merely useless; run as root, or by a
  member of `disk`, they would send commands to a customer's drive. Reachability
  is now established from metadata — the node's mode, owner and group against
  our own uid and group set from `/proc/self/status`, plus the tool inventory
  and the sysfs health signals. The reason is derived: `EACCES` when the node is
  not openable by this identity, and the new `NOT_ATTEMPTED` when it would be
  openable and the sensor declines by design. Those are different facts and the
  artifact says which. The smartctl JSON parser from batch 1 had one caller and
  went with it. (`TestMediaHealth_NoDeviceOpeningChildren`,
  `TestMediaHealth_ReasonDerivedFromObservations`.)
- Every spawned goroutine now recovers: a panic in one takes the whole process
  down, and `runOne`'s recover cannot reach it.
  (`TestOOBGoroutinePanicDoesNotKillProcess`.)

### H. Ponytail pass 2

`probe.Files` — eleven methods, one implementation, no fake — is deleted;
`Env.Files` is `*probe.Reader` and the `ModTime` type assertion is gone. The
`--timeout` flag is removed (LD-9 allows `--out` and `--version`; a flag that
widens a safety bound is not a safety bound), `DefaultScanDeadline` stays a
constant. Dead declarations removed: `probe.Which`, `Observation.Failed`,
`KindConfigRes`, `KindDeviceProbe`, `ReasonENODEV`; the UPPER_SNAKE_CASE regexp
is compiled once. The `Budgeted` second interface is folded into a `Budget()`
member of `Check`, which the meta struct already provided. F2 (lab fixture
duplication) is deferred by the lead; it is another agent's file.

### Deviation 14: the `!unix` build stub

`internal/probe/sysdep_other.go` exists so the module compiles, vets and runs
its portable tests on a Windows workstation. It defines `openNoFollow = 0` and
`openDirectory = 0`, which on that platform would weaken the open flags — and it
is unreachable in anything that ships. The deliverable is a single static
`linux/amd64` binary built with `GOOS=linux`, where `sysdep_unix.go` provides
`O_NOFOLLOW`, `O_DIRECTORY`, `O_CLOEXEC`, `Setpgid`, the group kill and
`lgetxattr`. No shipped build lacks them, and the Linux-only tests are executed
against the cross-compiled binaries under WSL as uid 1000 rather than being
skipped and forgotten.

## Fix batch 3 (second adversarial review: DO-NOT-SHIP, 4 Critical / 4 High / 6 Medium)

The whole batch turns on one distinction the code had been getting backwards.

**An EXPOSURE question and an EXISTENCE question read a denial in opposite
directions.** When the question is "who can read this", being refused is
EVIDENCE, and it points towards protection: if this unprivileged account cannot
reach the object, no other unprivileged account with the same standing can
either. When the question is "does this exist" or "what is this set to", the same
refusal is a gap and the answer is unknown. The sensor had been treating every
denial as a gap, which made it drop a candidate it could not read
(`PRIVATE_KEY_MATERIAL_EXPOSURE` passed with "0 candidates classified" over a
group-readable key), and made it return `unknown` on every host with a 0700
`/root` (`PROVISIONING_DATA_PROTECTION`). `protectionFromDenial()` in
`secrets.go` is that reading: it walks up to the nearest stat-able ancestor and
asks whether that ancestor's own mode excludes other unprivileged accounts.
Where it does, the candidate is kept, counted as protected, and the denial is
opted out of the load-bearing set with the reason recorded — because the denial
answered the question rather than leaving it open.

### Rows 29, 33 — who is actually in a group

Membership was read from field 4 of `/etc/group` alone. An account whose PRIMARY
gid (field 4 of `/etc/passwd`) is the file's group is a member of it, reads
every file that group can read, and appears in no member list. So a 0640 key
owned by an "empty" group passed. `scan.Env.Groups()` now parses both databases
and builds the effective member set, `Env.Readers()` is the single place "who
can read this" is decided (secrets, BMC nodes and drive nodes all go through
it), and an unreadable `/etc/group` or `/etc/passwd` makes group reasoning
UNKNOWN rather than "every group is empty".

Tests: `TestEffectiveReaders_PrimaryGidCounts`, `TestGroupDBDenied_IsUnknownNotEmpty`.

### Row 30 — a listable directory is not exposure

`/etc/sudoers.d` ships `drwxr-xr-x` with 0440 files on stock Debian and Ubuntu.
Judging the directory's traverse bit failed every such machine at severity high.
The check now judges the FILES inside: it lists the directory and inspects each
child, fails only on a readable secret or an other-WRITABLE directory, and treats
a denied listing as protection or as a boundary depending on the ancestor.

Tests: `TestSecretStore_StockSudoersDIsNotExposure` (stock layout must not fail;
a 0644 drop-in inside the same directory must).

### Row 31 — the predicate is the rule that was cited

The rule text said "not group- or world-writable" for `~/.ssh/config` and the
code tested the READ bits, so the 0644 default every distribution ships failed.
`ruleKind` now generates both the sentence and the predicate from one
declaration, so they cannot drift apart: StrictModes objects to writability,
libpq to readability.

Tests: `TestCredentialRules_PredicateMatchesRuleText`.

### Row 32 — the gate was a phrase blacklist with an opt-in

Two holes. `LoadBearingIf` was opt-in, so the observations a check forgot to
mark — exactly the ones it had not thought about — carried no weight; and the
prose check matched fixed phrases, so "no exposed key material was found
anywhere on this machine" walked straight past it. Now: observations are
**load-bearing by default** and opting out requires a recorded reason that ships
in the evidence (`not_load_bearing_because`); a `pass` or `fail` with no
successful load-bearing observation behind it is downgraded to
`unknown`/**`NO_EVIDENCE`**; and absence prose is matched by regexp over the
whole class of enumeration and absence assertions, with the completeness
sentence generated instead.

The polarity flip is the substantive change in this batch. It forced every check
to state, in writing, which of its observations do not underwrite its verdict —
and it caught a real bug on the way: `nvmeController("nvme0n1")` searched
forward for "n", hit the one in "nvme", and returned the name unchanged, so
every NVMe controller lookup had been silently missing.

Tests: `TestEntailment_UnlistedAbsenceProseIsCaught`,
`TestEntailment_VerdictWithoutEvidenceIsNoEvidence`,
`TestEntailment_OptOutRequiresARecordedReason`, and the roster-wide
`TestEvidenceEntailsVerdict`.

### Row 34 (not in the batch) and the absence primitive

`probe.Reader` now answers "is this ENOENT the answer or a gap in it" itself: on
ENOENT it walks up to the nearest ancestor that stats and marks
`AbsenceProven` when one does. "Absence is only provable from a successful
listing" — so the listing is performed rather than assumed.

### Rows 36, 37, 38 — three narrower reversals

A truncated `/proc/net/tcp` no longer hides a telnet listener that was inside the
rows actually read: a listener SEEN is a positive observation, the table's
completeness is opted out when one is found, and a truncation with nothing
adverse is `unknown` naming how many rows were read. A `/dev/ipmi*` ENOENT after
a listable `/dev` is `AbsenceProven`, so a machine with no BMC stops reporting
"no node exists [downgraded from pass ... ENOENT]". And the cloud-init drop-in
matcher strips comments and matches YAML keys at line start, so a comment saying
"no password is set here" no longer promotes a public config file to payload.

Tests: `TestListeners_TruncatedTableKeepsPartialEvidence`,
`TestListeners_TruncationWithoutAdverseIsUnknown`,
`TestBMCNode_ProvenAbsenceIsAnAnswer`,
`TestProvisioning_CommentIsNotACredentialKey`, `TestDeclaredKeys`.

### Row 40 — a check that cannot be interrupted must not take the scan with it

A context deadline only helps a check that consults it. A D-state read of a hung
NFS home returns to nobody, so calling `c.Run` inline meant one such check took
the whole scan and the artifact was never written at all. Each check now runs in
its own goroutine and is ABANDONED at its deadline, exactly as `ReadOOB` already
did: the result arrives on a buffered channel the abandoned goroutine can always
finish sending to, the engine stops waiting, that check reports
`unknown`/`TIMEOUT` saying it was abandoned, and the scan carries on and writes
its output. Separately, walks now refuse to START on a network filesystem —
refusing to CROSS into one was never enough, because a scan root can be on one
already — with the skipped root and its fstype recorded.

Tests: `TestEngine_StuckCheckIsAbandonedAndOutputIsStillProduced` (a check that
sleeps 30 s ignoring its context, followed by another check that must still
report), `TestWalk_RefusesToStartOnNetworkStorage`.

### Row 41 and the Lows

`BMC_CLIENT_TOOLING_INVENTORY` derives its reason from the directory stats
instead of a hard-coded EACCES, and names the directories rather than printing
an empty list (`TestBMCTooling_ReasonComesFromTheStats`). L1: a symlink refused
by read policy is classified `ELOOP` instead of leaking "UNSUPPORTED" outside
the closed vocabulary (`TestSymlinkRefusalIsInTheClosedVocabulary`). L2: `passwd
-S` is the one setuid-root binary the sensor executes; it is read-only, reports
the calling account only, and its result is opted out of the load-bearing set —
documented here rather than removed, because the alternative (reading
`/etc/shadow`) is exactly the thing the sensor must not do. L3 belongs to the
lab package and its owner.

### Two batch-2 expectations that batch 3 supersedes, on purpose

`TestPrivateKey_UnreadableSubtreeIsUnknown` and the `/root` case in
`TestCredentialExposure_HomesAreCleanAndDeduplicated` asserted `unknown` for a
subtree this account cannot enter. Rows 28 and 35 reverse that for exposure
questions: a 0700 `/root` hides its contents from every unprivileged account,
which is the answer, not a gap. The tests are renamed and now assert what still
must hold — that the shielding is COUNTED and REPORTED rather than silently
assumed, and that the two secrets checks agree about the same directory.

## Where it has been run

| environment | invocation | result |
|---|---|---|
| WSL Ubuntu 26.04, uid 1000 | `./bin/sensor scan --out bin/findings.wsl.json` | 26 checks in 0.2 s, exit 0, self-check pass (batch 2) |
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
