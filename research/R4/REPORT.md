# R4 — REPORT (host investigation, storage-priority)

Scope: what an unprivileged, read-only sensor can establish on the Lava host, what it cannot, and how the
same probes behave elsewhere. Host claims cite probe ids from `state/HOST_SNAPSHOT.evidence.json`;
research claims cite `R4-F<k>` / `R4-S<k>`. Companion artifacts: `TECHNOLOGY_INVENTORY.md` (what exists,
per-probe), `STORAGE_ASSESSMENT.md` (priority branch), `HOST_SPECIFIC_PLAN.md`, `GENERIC_FALLBACK_PLAN.md`,
`OBSERVATION_REQUESTS.md`, `PROPAGATION_NOTES.md`, `PROVENANCE.md`.

## 1. The finding that changes how everything else should be read

The recon snapshot's per-probe `status` field is a **coarse aggregate over a multi-command shell line**, and
it contradicts its own stdout in at least seven probes (R4-F01). `storage.dev_ls` is labelled `ENOENT` while
successfully listing seven NVMe device nodes. `storage.mdadm_conf` is labelled `ENOENT` while printing the
contents of a file that exists (R4-F02 — the one place where the snapshot prose is wrong and the evidence
file wins). `bmc.ipmi_dev_perms` is labelled `UTILITY_MISSING` although the `stat` half succeeded.
`network.sshd_test_config` records `rc=0` for a command that failed, because the probe piped through `head`
and read the pipeline's exit status.

Two consequences the implementation must inherit:

1. **No downstream document may propagate probe status as fact status.** `TECHNOLOGY_INVENTORY.md` §0 gives
   the corrected per-fact outcomes.
2. **The sensor must capture outcome per individual observation** — exit status, errno, and stderr text —
   and must never read an exit code through a shell pipeline.

## 2. Five host-specific findings that most affect the design

1. **Group `disk`, `adm` and `systemd-journal` all have zero members; only `sudo` has one** (`users.priv_groups`,
   R4-F13). This turns several mode-based observations into proofs: `brw-rw---- root:disk` means root-only *in
   practice*. It is a reusable evidence helper, not per-check logic.
2. **The BMC answers in band, but only root can talk to it** (R4-F09, R4-F46, R4-F48). The world-readable
   attributes under `/sys/devices/platform/ipmi_bmc.0` are served by a driver path that re-issues a live
   Get Device ID over KCS when its short cache expires, so `ipmi_version=2.0 / firmware_revision=1.5 /
   manufacturer_id=0x002a7c` (IANA PEN 10876 = Super Micro, R4-F47) is evidence that a BMC *responded* — with
   no `ipmitool`, no `/dev/ipmi0` access and no privilege. Meanwhile `/dev/ipmi0` is 0600 root:root, which is
   the plain kernel default with no capability gate behind it. The category therefore splits cleanly into
   three checks — interface declared, BMC responding, who may open it — producing pass + info + fail rather
   than one mushy unknown.
3. **`sshd -T` is unusable unprivileged and the listener is owned by systemd** (R4-F19, R4-F20). Host keys are
   loaded before the test-mode exit path (`sshd.c`, R4-S03), and `ssh.socket` carries the `ListenStream`
   entries while `ssh.service` also runs. Effective policy must be derived by parsing `sshd_config` with
   `Include` expanded at its position and first-value-wins semantics, then cross-checked against runtime
   listeners. A check that reports the listen address from `sshd_config` is simply wrong on this host.
4. **Kernel drift is provable without the Ubuntu marker file, and the patch-currency question is a trap**
   (R4-F14, R4-F15). Running 6.8.0-139 while `/boot/vmlinuz` points at 7.0.0-31 is established from three
   independent reads. But `/var/lib/apt/lists` is **empty**, so `apt list --upgradable` printing nothing means
   nothing. A patch check that returns `pass` here would be a false negative of exactly the kind the brief
   calls a critical failure.
5. **Owner is not determinable and must be an explicit unknown** (R4-F23). `/etc/machine-info` and `/etc/motd`
   are ENOENT, every DMI asset field is a vendor placeholder (`To be filled by O.E.M.`, `Chassis Asset Tag`,
   `0123456789`, `Family`), and the world-readable cloud-init `instance-data.json` has empty strings for
   hostname, plan and tags with `merged_cfg` literally `"redacted for non-root user"`. The placeholder test
   must be a *pattern* class, never a match against these literals.

## 3. Storage (priority branch) — the short version

Full argument in `STORAGE_ASSESSMENT.md`. Two 960 GB Micron 7450 PRO NVMe drives; `nvme0n1` carries a vfat ESP
and an ext4 root; `nvme1n1` has no partition table, no filesystem and no holders. No dm, no md, no multipath,
no iSCSI/FC/SAS, no network filesystems, no swap, no SATA disks behind the AHCI controller.

Answerable unprivileged with high confidence: dm-crypt/LUKS absence, redundancy absence, the unused second
device, world-readable ESP, network-storage absence, write-cache mode, firmware version, ext4 `errors_count`,
capacity. Unknown **by construction**: SED/Opal state (`block/sed-opal.c` gates every ioctl on CAP_SYS_ADMIN
and exposes nothing in sysfs — R4-F57), SMART/health (`nvme_cmd_allowed()` requires CAP_SYS_ADMIN for Get Log
Page — R4-F54), and whether the unused drive still holds a prior tenant's data (which the sensor must refuse
to answer rather than read the device).

**Verdict (the lead decides):** storage is **materially strong but narrow**, and strongest when scoped as
*data-at-rest posture* rather than storage-stack inventory — four checks: encryption at rest (scoped, with the
SED blind spot named), redundancy for `/`, attached-but-unused devices, and device health returning a *proved*
unknown. I do not claim it is the strongest category available: by evidence density and severity, **boot chain
/ firmware trust is denser on this host** (Secure Boot disabled *and* platform in Setup Mode, lockdown none,
kernel tainted `O+E` by one attributable unsigned module, TPM present but unused, world-readable initramfs) —
its weakness is that Lava named Kernel Flags as their own example, so it scores lower on "a category we did not
anticipate". The genuinely unanticipated angle in storage is **decommissioning hygiene on rented hardware**:
no encryption at rest plus an unused, un-inspectable second drive means anything written here survives
hand-back in cleartext, and the sensor can establish the first half and must refuse the second.

## 4. Traps most likely to produce a wrong finding

- **Bounded negatives read as proof.** `find / -xdev … 2>/dev/null` silently skips other filesystems
  (including the mounted ESP) and every unreadable directory; `world_writable_find` returning empty is a
  bounded negative (R4-F27). Every scan finding must publish its scope and say "none found within scope".
- **The empty apt index** (R4-F15) — the highest-value false negative on this host.
- **Containers see the host's `/sys/block` and `/sys/class/dmi`** (R4-F38, `sysfs(5)`). A containerised run
  would report the host's disks and vendor as its own. This is the largest cross-machine false positive.
- **`/sys/module` is not `lsmod`, and `lsmod` is not "device present"** (T-S1). `virtio_blk`, `dm_mod`,
  `md_mod` and `raid*` all appear under `/sys/module` on this bare-metal host with no dm and no arrays.
- **`/proc/mdstat` always prints a Personalities line** (T-S2, R4-F60). Proof of "no RAID" needs no `md<N>`
  lines, `unused devices: <none>`, no `/dev/md*`, and no PCI class 0104 device.
- **Mode bits are not authorisation.** `/dev/kmsg` is 0644 yet reads fail with EPERM under
  `dmesg_restrict=1` (R4-F12); `/var/log/journal` carries an ACL that `ls` reveals only as a `+` (R4-F28).
- **EACCES can mean "write-only file".** `/sys/module/ipmi_si/parameters/hotmod` denies reads because it is
  0200 (R4-F11) — `stat` before classifying a denial.
- **`size` is in fixed 512-byte units** (R4-F37). Correct on this host either way, wrong on 4Kn — a bug that
  ships undetected unless a fixture exercises it.
- **Name-based inference.** The SATA controller is named `ASM1061R` but is PCI class 0106 in AHCI mode
  (T-S7); Hyper-V synthetic disks are named `sd*` (R4-F45); `/.dockerenv` is a convention, not a fact.
- **Missing utility mistaken for missing capability.** `aa-status`, `getenforce`, `nft`, `smartctl`,
  `getfacl`, `ipmitool`, `dmidecode` are all absent here, and in every case either a sysfs path answers the
  question or the honest answer is unknown — never "absent".

## 5. Genericity

`GENERIC_FALLBACK_PLAN.md` carries every probe against RHEL-family, Debian, Alpine, VM and container, with
the exact UNKNOWN trigger for each. The recurring rules: gate on capability classes, never on literals; treat
ENOENT-on-the-parent as "capability not present on this platform" rather than "absent"; let systemd-dependent
checks degrade to unknown rather than to failure on Alpine/OpenRC; and establish execution context before
trusting any hardware read.

## 6. What is open

Ten observation requests (R4-OR1…R4-OR10), none blocking, each with a labelled assumption in the surrounding
text. The two most likely to change a recommendation are **R4-OR4** (AppArmor enforcement mode — likely one
read of a 0444 file) and **R4-OR7** (whether DMI entry attributes other than `raw` are readable at this
kernel). **R4-OR5** (sudo policy) will probably stay unknown permanently, and that is the correct outcome.

Research gaps, recorded honestly in `PROVENANCE.md`: stream **S4 never launched** (harness concurrency limit),
so provider fingerprinting to primary Latitude.sh sources, the provenance of the
`module_blacklist=af_alg,algif_*,sctp*` kernel cmdline, and the re-image stability comparison of host-id
candidates are **OPEN**. The Micron datasheet could not be fetched (timeouts with no data — not a 404, not
"unsupported"), so the SED-SKU ambiguity claim stands at LIKELY 0.6.
