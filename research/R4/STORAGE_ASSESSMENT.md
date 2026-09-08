# R4 — STORAGE_ASSESSMENT (priority branch)

All host claims cite probe ids from `state/HOST_SNAPSHOT.evidence.json`. Fact ids are `R4-F<k>` in
`facts.jsonl`. Where the snapshot prose and the evidence file disagree, the evidence file wins (R4-F02).

## 1. The storage stack of this host, built from evidence

```
PCI 02:00.0  [1344:51c3] Micron 7450 PRO NVMe SSD, driver nvme   -> /sys/class/nvme/nvme0 (state=live, transport=pcie, fw E2MU200)
   └── nvme-subsys0 (iopolicy=numa)  -> nvme0n1  1875385008 sectors x 512 = 960,197,124,096 B
         ├── nvme0n1p1  vfat FAT32  LABEL=EFI   UUID 6A9F-0FAA   -> /boot/efi  (rw,relatime,fmask=0022,dmask=0022,errors=remount-ro)
         └── nvme0n1p2  ext4        LABEL=ROOT  UUID c547dc8b-…  -> /          (rw,relatime,errors=remount-ro)
PCI 03:00.0  [1344:51c3] Micron 7450 PRO NVMe SSD, driver nvme   -> /sys/class/nvme/nvme1 (state=live, transport=pcie, fw E2MU200)
   └── nvme-subsys1 (iopolicy=numa)  -> nvme1n1  same size, NO partition table, NO filesystem, NO holders
PCI 06:00.0  [1b21:0622] ASMedia ASM106x AHCI  "Asmedia SATA6G ASM1061R", PCI class 0106 (SATA), driver ahci
   └── 12 scsi_host entries, proc_name=ahci, state=running, /proc/scsi/scsi -> "Attached devices:" (none)
loop0..loop7  size=0 (allocated, unbound)
No device-mapper (only /dev/mapper/control) · no md arrays · no multipath · no iSCSI/FC/SAS · no network fs · no swap
```

Sources: `storage.lspci_storage`, `storage.nvme_class`, `storage.nvme_sysfs_detail`, `storage.block_device_links`,
`storage.sysblock_loop`, `storage.partitions`, `storage.lsblk_fs`, `storage.lsblk_wide`, `storage.disk_by_id`,
`storage.disk_by_path`, `storage.findmnt`, `storage.fstab`, `storage.df`, `storage.dev_ls`, `storage.dev_mapper_ls`,
`storage.mdstat`, `storage.multipath`, `storage.iscsi`, `storage.scsi_hosts`, `storage.proc_scsi`,
`storage.net_fs_mounts`, `storage.configfs_bcache_btrfs`, `storage.swap`, `storage.ext4_sysfs`.

Queue attributes, identical on both namespaces (`storage.blk_queue_detail`):
`rotational=0`, `logical_block_size=512`, `physical_block_size=4096`, `discard_granularity=512`,
`write_cache=write through`, `scheduler=[none] mq-deadline`, `nr_requests=1023`, `ro=0`, `removable=0`.

Filesystem health counters (`storage.ext4_sysfs`): `/sys/fs/ext4/nvme0n1p2/errors_count=0`,
`first_error_time=0`, `lifetime_write_kbytes=2799165`. Capacity (`storage.df`): root 879 G with 1.9 G used (1 %).

Access control on the devices (`storage.dev_ls`, `users.priv_groups`):
`/dev/nvme0`, `/dev/nvme1`, `/dev/nvme-fabrics` are `crw------- root:root`;
`/dev/nvme0n1`, `p1`, `p2`, `/dev/nvme1n1` are `brw-rw---- root:disk`; **group `disk` has no members**.
Therefore no non-root account on this host has any path to the block devices or the NVMe admin passthrough (R4-F04, R4-F13).

## 2. Unprivileged-confidence table

| # | Posture question | Answerable now? | Evidence / why not | Probe ids |
|---|---|---|---|---|
| Q1 | Encryption at rest via dm-crypt/LUKS | **YES — provably absent** | `/dev/mapper` has only `control`; `/dev/dm-*` ENOENT; `/etc/lvm/*` ENOENT; every partition's FSTYPE is vfat/ext4, never `crypto_LUKS` | `storage.dev_mapper_ls`, `storage.dev_ls`, `storage.lvm_conf_ls`, `storage.lsblk_fs` |
| Q2 | Encryption at rest via SED / TCG Opal | **UNKNOWN BY CONSTRUCTION** | Opal locking state lives behind Identify-Controller / Security-Receive on the char device; `/dev/nvme0` is root-only and `nvme id-ctrl` returned `Permission denied` | `storage.nvme_smart_try`, `storage.dev_ls` |
| Q3 | Filesystem-level encryption (fscrypt) on ext4 | **UNKNOWN (unobserved)** | No probe read `/sys/fs/ext4/nvme0n1p2/feature*`; the directory itself is readable, so this is a gap, not a boundary → R4-OR6 | `storage.ext4_sysfs` |
| Q4 | RAID / mirroring present | **YES — provably absent** | `/proc/mdstat` → `unused devices: <none>`; `/dev/md*` ENOENT; no dm target; no PCI class 0104 RAID controller | `storage.mdstat`, `storage.dev_ls`, `storage.lspci_storage` |
| Q5 | RAID health / degraded state | **N/A here; UNKNOWN elsewhere without md** | With no array, there is nothing to degrade. On a host with md, `/sys/block/md*/md/degraded` is world-readable; hardware-RAID health needs a vendor CLI and is usually root-only | `storage.mdstat` |
| Q6 | Unmounted / foreign / unused devices | **YES — high confidence** | nvme1n1 has no partitions (`/proc/partitions`), no `-part*` by-id link, `parts=0`, `holders=` empty, `FSTYPE=""` | `storage.partitions`, `storage.disk_by_id`, `storage.blk_queue_detail`, `storage.lsblk_fs` |
| Q7 | Was the unused device securely erased / does it hold a prior tenant's data? | **UNKNOWN BY CONSTRUCTION, and must stay that way** | Reading the device to answer would require opening `/dev/nvme1n1` (EACCES) and would violate read-only-and-bounded intent even if permitted. `lsblk` only says udev recorded no signature | `storage.lsblk_fs`, `storage.dev_ls` |
| Q8 | World-readable data mounts | **YES** | `/boot/efi` mounted `fmask=0022,dmask=0022` ⇒ ESP contents world-readable; `/` has no `nodev`/`nosuid` (expected for a root fs, weak as a finding) | `storage.findmnt`, `storage.fstab` |
| Q9 | Network-storage exposure (NFS/CIFS/iSCSI/Ceph) | **YES — provably absent** | Full `findmnt` listing contains only local + virtual filesystems; `/proc/fs/nfsfs/*` ENOENT; `/sys/class/iscsi_*` ENOENT (transport never loaded); `/sys/kernel/config/target` ENOENT **while configfs is mounted** | `storage.net_fs_mounts`, `storage.findmnt`, `storage.scsi_hosts`, `storage.configfs_bcache_btrfs` |
| Q10 | Discard / TRIM behaviour | **PARTIAL** | `discard_granularity=512` (device supports discard) and `fstrim.timer` is scheduled weekly. Whether discards actually reach the device is not observable: the mount options show no `discard`, and fstrim's own results are in the root-only journal | `storage.blk_queue_detail`, `services.timers`, `storage.findmnt` |
| Q11 | Write-cache mode | **YES (as reported by the block layer)** | `queue/write_cache=write through`. This is the block layer's view, not proof of the device's internal volatile-cache or power-loss-protection state | `storage.blk_queue_detail` |
| Q12 | Firmware version visibility | **YES** | `firmware_rev=E2MU200` from sysfs and from `nvme list`, both unprivileged | `storage.nvme_sysfs_detail`, `storage.nvme_cli` |
| Q13 | Firmware currency (is E2MU200 current?) | **UNKNOWN — out of scope** | Requires an external vendor advisory feed; the sensor makes no network calls | — |
| Q14 | SMART / media health / wear / power-on hours | **NO — EACCES, and provably no unprivileged path** | `nvme smart-log` and `nvme id-ctrl` → `Permission denied`; smartctl UTILITY_MISSING; device nodes root-only and group `disk` empty | `storage.nvme_smart_try`, `storage.smartctl_scan`, `storage.dev_ls`, `users.priv_groups` |
| Q15 | Filesystem error history | **YES — partial health signal survives** | `/sys/fs/ext4/nvme0n1p2/errors_count=0`, `first_error_time=0` are world-readable; `lifetime_write_kbytes=2799165` gives a crude wear proxy | `storage.ext4_sysfs` |
| Q16 | Capacity pressure | **YES** | `df`: 1 % used on `/`, 2 % on `/boot/efi` | `storage.df` |
| Q17 | Multipath configured | **PARTIAL** | `multipath` binary UTILITY_MISSING and config ENOENT, so the *tool's* view is unavailable; but `/dev/mapper` containing only `control` proves **no active multipath maps**. Reporting "multipath absent" from the missing binary alone would be wrong reasoning with an accidentally right answer | `storage.multipath`, `storage.dev_mapper_ls` |

**Split summary.** Answerable now, high confidence: Q1, Q4, Q6, Q8, Q9, Q11, Q12, Q15, Q16 (and Q17 via
the dm fallback). Unknown by construction for an unprivileged account: Q2, Q7, Q14. Unknown merely
unobserved (fixable by one more probe): Q3, and the per-file modes under `/etc/ufw` and `/dev/i2c-*`
in other categories. Out of scope: Q13.

## 3. Traps specific to this stack

- **T-S1 — `/sys/module` is not `lsmod`.** `storage.storage_modules` lists `virtio_blk`, `virtio_scsi`,
  `virtio_net`, `dm_mod`, `md_mod`, `raid0/1/10/456` under `/sys/module` on a machine that is bare metal with
  no dm and no md. `/sys/module` also contains built-in and never-instantiated modules. Presence there is
  not presence of a device, an array, or even a loaded module.
- **T-S2 — `/proc/mdstat` always lists personalities.** `Personalities : [raid0] [raid1] …` with
  `unused devices: <none>` means the RAID personalities are compiled/loaded, not that arrays exist. The
  array-existence signal is the body of the file and `/dev/md*`.
- **T-S3 — lsblk's FSTYPE is the udev database, not the disk.** Our account cannot open `/dev/nvme1n1`
  (group `disk` is empty), so `FSTYPE=""` means "udev recorded no signature at the last uevent" (R4-F08).
  Evidence wording must say so. A filesystem created after the last uevent would be invisible.
- **T-S4 — `nvme smart-log` EACCES is not `nvme` missing and not "no SMART data".** Three distinct outcomes
  (EACCES / UTILITY_MISSING / device absent) all end in "no health data"; only the first is true here, and
  it is the one whose remediation is "grant group `disk` or run privileged".
- **T-S5 — a size-0 loop device is not a disk.** Enumerating `/sys/block/*` naively reports eight
  zero-byte "block devices". The machine-description storage list must exclude `loop`, `ram`, `zram` and,
  when a real disk exists, `dm`/`md` aggregates — but must not exclude them when they are all that exists.
- **T-S6 — sector size for `/sys/block/<d>/size` is fixed at 512 B**, regardless of
  `logical_block_size` (512 here) or `physical_block_size` (4096 here). Multiplying by
  `logical_block_size` happens to be correct on this host and would be wrong on a 4Kn drive.
  Verified arithmetically here: 1875385008 × 512 = 960,197,124,096 = the `nvme list` capacity.
- **T-S7 — controller naming lies about mode.** The SATA controller's DMI DeviceName is
  `Asmedia SATA6G ASM1061R` — the trailing "R" is the RAID-capable part — but its PCI class is **0106
  (SATA)**, not 0104 (RAID), and the bound driver is `ahci`. RAID-controller detection must gate on PCI
  class, never on a name substring.
- **T-S8 — twelve `scsi_host` entries with zero disks.** An AHCI controller registers a host per port
  whether or not a drive is attached. `state=running` describes the host, not a device.
  `/proc/scsi/scsi` → `Attached devices:` (empty) is the disambiguating read.
- **T-S9 — the NVMe *multipath* class exists with a single path.** `/sys/class/nvme-subsystem/nvme-subsys{0,1}`
  with `iopolicy=numa` is the standard NVMe subsystem layer, not evidence of multipathing. Two subsystems
  with one controller each is the opposite of a multipathed configuration.
- **T-S10 — "no partitions" is not "empty disk".** nvme1n1 could hold a whole-device filesystem, a former
  tenant's data, or a partition table that predates the last uevent. The honest statement is "no partition
  table and no filesystem signature known to udev".
- **T-S11 — `/etc/mdadm/mdadm.conf` exists** (contains `HOMEHOST <ignore>`), contradicting the snapshot
  prose (R4-F02). A "RAID configured?" check keyed on config-file existence would fire a false positive here.

## 4. Is a storage custom category materially strong on this host?

### 4.1 The case FOR

1. **The severe questions are answerable, and the answers are non-trivial.** Encryption at rest is provably
   absent (Q1), redundancy is provably absent (Q4), and a second identical 960 GB NVMe sits completely
   unused (Q6) — on a *rented bare-metal machine in someone else's data centre*, where re-imaging and
   tenant hand-back are routine. Three definite findings, each from a different evidence path.
2. **It produces the exercise's best-shaped UNKNOWN.** Drive health (Q14) is unknown for a reason the
   sensor can *prove* rather than merely assert: `nvme smart-log` → `Permission denied`, device node
   `crw------- root:root`, and group `disk` has zero members — so no unprivileged path exists on this host
   at all. That is exactly "the errno you got back" evidence the brief asks for, plus a remediation.
3. **One health signal survives the privilege boundary.** `/sys/fs/ext4/<dev>/errors_count` (Q15) means the
   category is not reduced to unknowns; the check that most obviously *should* be blocked has a partial
   answer through an unrelated interface.
4. **The blind spot is itself the finding.** Q7 — whether the unused device still holds a prior tenant's
   data — cannot and should not be answered by reading the device. A category that names this and refuses
   to answer it demonstrates precisely the judgment the brief says it is testing.
5. **Genericity is cheap here.** The same probes degrade cleanly: LUKS via `/sys/block/dm-*/dm/uuid`,
   md via `/proc/mdstat` + `/sys/block/md*/md/degraded`, network storage via `mountinfo` fstype —
   see GENERIC_FALLBACK_PLAN.md. The category does not become vacuous on a VM; it becomes a different set
   of definite answers.

### 4.2 The case AGAINST

1. **The stack is shallow — the depth the category would show off is absent.** No LVM, no LUKS, no md,
   no multipath, no iSCSI/FC/SAS, no network filesystems, no swap, no SATA disks. Most "deep" storage
   branches would emit pass-by-absence findings, which is close to the "twenty checks done thinly" the
   brief warns against.
2. **The flagship health check is unknown.** A reviewer skimming the output sees the most recognisable
   storage check (SMART) come back unknown. That is defensible and even desirable, but it is a weaker
   headline than a category whose checks resolve.
3. **A denser competitor exists on this host: boot chain / firmware trust.** Secure Boot **disabled**
   *and* the platform in **Setup Mode** (no PK enrolled — anyone with firmware access can enrol keys),
   kernel lockdown `[none]`, kernel tainted `O+E` by an unsigned out-of-tree module attributable to
   `bnxt_en`, a TPM 2.0 present but unused by the boot chain, world-readable initramfs images, `grub.cfg`
   0600. That is six checks, each resolving to a definite status with severity above "info", all
   unprivileged (`kernel.secureboot`, `kernel.mokutil_sbstate`, `kernel.lsm`, `kernel.module_taint`,
   `kernel.tpm`, `secrets.boot_artifacts_ls`).
   Counter-argument to the counter-argument: the brief *names* "Kernel Flags … boot chain verified" as its
   own example, so this category is anticipated and scores lower on "a category we did not anticipate".
4. **Update/drift is cheaper and nearly as strong.** Kernel drift is provable (R4-F14) and the empty apt
   index (R4-F15) is a genuinely subtle false-negative trap worth demonstrating — but it is two or three
   checks, not a category on its own.
5. **Overlap risk.** "World-readable ESP" and "world-readable initramfs" sit equally well in
   SECRETS_ON_DISK; "no encryption at rest" could be argued into a data-protection category. A storage
   category must be scoped so it does not simply re-file findings that belong elsewhere.

### 4.3 My position (the lead decides)

**Storage is materially strong on this host, but narrow, and it is strongest when scoped as data-at-rest
posture rather than as a storage-stack inventory.** Concretely: a category of roughly four checks —
(a) encryption at rest, scoped to dm-crypt/LUKS with the SED blind spot stated in the reason;
(b) redundancy for the filesystem holding `/`;
(c) attached-but-unused block devices, with the data-remanence question named and explicitly not answered;
(d) device health, which returns unknown with the EACCES-plus-empty-`disk`-group proof, backed by the
partial ext4 `errors_count` signal — yields four findings that are all evidence-dense, all unprivileged,
and none of which restate the machine description.

I do **not** claim it is the single strongest category available. By raw evidence density and severity,
**boot chain / firmware trust is stronger on this host** (§4.2 item 3), and its main weakness is that Lava
named it as their own example. The genuinely unanticipated angle in the storage branch is not RAID or
SMART; it is **decommissioning hygiene on rented hardware**: an unused, un-erasable-to-us second drive plus
no encryption at rest means anything written to this machine survives hand-back in cleartext, and the
sensor can establish the first half and must refuse the second.

The lead's call: (1) storage-as-data-at-rest as the custom category, with boot chain folded into a
Kernel Flags category if a second custom category is wanted; or (2) boot chain as the custom category with
the three high-confidence storage findings distributed into the required categories. I lean to (1) on
"unanticipated category" grounds and (2) on "evidence density" grounds — the tie-break is which signal
Lava weights more, and that is a judgment about the reader, not about the host.
