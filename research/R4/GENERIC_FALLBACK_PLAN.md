# R4 — GENERIC_FALLBACK_PLAN

The same probes as HOST_SPECIFIC_PLAN.md, analysed against five named alternate targets:
**RHEL-family** (RHEL/Rocky/Alma 9), **Debian** stable, **Alpine** (musl, BusyBox, OpenRC),
**VM** (KVM/QEMU, VMware, Hyper-V), **Container** (Docker/K8s/LXC).
No claim here is about the Lava host; every row names its target. Sources: `sources.jsonl`
(R4-S15…R4-S23, R4-S35…R4-S39) plus the LOCAL_REPRO on WSL2 Ubuntu 26.04
(kernel 6.18.33.2-microsoft-standard-WSL2, unprivileged uid 1000), which is used only as a
*degraded environment* sample and never as a stand-in for the target.

## 0. The four outcomes, restated for every probe below

| Outcome | Meaning | What you may conclude |
|---|---|---|
| ENOENT **after a successful listing/stat of the parent** | the thing is not there | proven absent |
| ENOENT on the **parent itself** | the whole capability class is unavailable on this platform | not-applicable / unknown, never "absent" |
| EACCES | permission denied | presence unknown, state unknown |
| UTILITY_MISSING | the tool is not installed | the *subsystem* state is still unknown unless a sysfs/procfs fallback answers it |
| TIMEOUT | no answer within the budget | unknown; explicitly **not** "unsupported" and **not** "absent" |

## 1. `/etc/os-release`

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL 9 | `ID=rhel\|rocky\|almalinux`, `ID_LIKE` present; `/etc/redhat-release` also present | `/etc/redhat-release` free text | os-release and legacy file both unreadable for a reason other than ENOENT | `/etc/redhat-release` is prose, not key=value — do not feed it to the os-release parser |
| Debian | `ID=debian`, usually no `ID_LIKE`; `/etc/debian_version` present | `/etc/debian_version` | both absent | `debian_version` can read `trixie/sid` on a derivative whose `ID` is not `debian` — corroboration only |
| Alpine | `ID=alpine`; `/etc/alpine-release` holds a bare version | `/etc/alpine-release` | both absent | "no os-release ⇒ Alpine" is false; many minimal images simply lack it |
| VM | identical to whatever the guest runs | — | — | distro identity is orthogonal to virtualisation |
| Container | reflects the **image's** userland, not the host kernel's distro | — | — | never infer host OS posture from a container's os-release |

Spec note (R4-S15): only `ID`, `NAME`, `PRETTY_NAME` have defaults; `VERSION_ID` and `ID_LIKE` are optional.
`/etc/os-release` takes precedence over `/usr/lib/os-release` — do not merge them.

## 2. `/sys/class/dmi/id/*` (vendor, model, serials)

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian / Alpine on x86 bare metal | same world-readable subset; serial/UUID quartet root-only | none needed — `dmidecode` needs *more* privilege, not less | a specific readable-class file missing after a successful directory listing ⇒ that field only | the readable/root-only split is kernel-version dependent and has been contested upstream (R4-F36) — probe and classify by errno, do not hardcode |
| VM | directory present; `sys_vendor` = `QEMU` / `VMware, Inc.` / `Microsoft Corporation` / `Xen` | — | — | hypervisors may populate a stable synthetic UUID; that is not evidence of physicality either way |
| Container | **the host's real DMI values are visible** (sysfs is not namespaced for this subtree, R4-F38) | — | EACCES on a normally-0444 file ⇒ unusual hardening ⇒ unknown | the largest FP in this plan: a container on bare metal reports bare-metal hardware as its own |
| aarch64 devicetree-only / WSL | directory absent entirely (**LOCAL_REPRO: no DMI class at all**) | none | ENOENT on the directory ⇒ "hardware identification unavailable on this platform" | report unknown, never `fail` — the machine is not failing a control, the capability does not exist |

## 3. Virtualisation / execution-context detection

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian | `systemd-detect-virt` present and reliable | DMI `sys_vendor`; `hypervisor` flag in `/proc/cpuinfo` | — | nested layers report the innermost by default (R4-S19) |
| Alpine | tool usually **absent** (no systemd) | DMI strings, cpuinfo flag, `/sys/hypervisor/type` (Xen only) | tool missing AND DMI absent AND cpuinfo unreadable | UTILITY_MISSING ≠ "bare metal" |
| VM | cpuinfo `hypervisor` flag set; DMI vendor string | cross-check two independent signals | non-x86 with no DMI and no tool | DMI strings are settable — never the sole basis for *denying* a security property |
| Container | `/.dockerenv` (Docker convention), `/run/.containerenv` (Podman), `/proc/1/cgroup` shape, overlay root in mountinfo | `systemd-detect-virt --container` | none of the markers present and the cgroup path looks host-like | `/.dockerenv` is a convention, trivially absent in containerd/gVisor/Kata or a hardened image — its absence never proves "not a container" |
| WSL (LOCAL_REPRO) | `systemd-detect-virt` → `wsl`, **exit 0** | — | — | exit code convention is 0 = detected, non-zero = not detected (R4-F39); a naive `rc==1 ⇒ error` reading inverts the answer |

## 4. Block-device enumeration and sizing

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian | `/sys/block/*` with `device/model`, `device/vendor` for SCSI/SATA | `lsblk -J -O`, `/proc/partitions` | `/sys/block` unreadable | `lsblk` FSTYPE comes from the udev DB, so it can be stale or empty where the caller cannot read the device |
| Alpine | `/sys/block` identical (kernel feature); `lsblk` may be **absent** (util-linux not installed) | `/sys/block` walk + `/proc/partitions` | `/sys/block` unreadable | a check that requires `lsblk` degrades to unknown for no reason — sysfs already answers |
| VM (virtio) | devices named `vda`, `vdb`; `/sys/block/vda/device/model` often **does not exist** | `/sys/block/vda/device/../driver` symlink basename (`virtio_blk`) for transport | model source absent ⇒ device listed with `model: unknown` | never drop a device because its model is unreadable |
| VM (Hyper-V / WSL, LOCAL_REPRO) | synthetic disks named **`sd*`** with real-looking vendor/model strings | — | — | disproves "vd* = virtual, sd* = physical" (R4-F45); classify by driver and PCI class, never by name prefix |
| Container | the **host's** `/sys/block` is visible; the container's own root is an overlay with no block device of its own | `/proc/self/mountinfo` to see the overlay root | `/sys/block` masked by the runtime | reporting host disks as the container's storage is a false positive that also leaks host topology |
| All | `size` is in **fixed 512-byte units** regardless of `logical_block_size` (R4-F37, R4-S17) | — | — | multiplying by `logical_block_size` is correct on 512e devices and wrong on 4Kn — a bug that hides on most hardware |

NVMe specifics that generalise (R4-S35): identity attributes are `S_IRUGO` (0444) in v6.8, there is no
`Documentation/ABI` file for the class, and namespace attributes are **flat under `/sys/block/nvmeXnY/`**,
not under a `nvme/` subdirectory (R4-F56).

## 5. Mount and filesystem view

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian / Alpine | `/proc/self/mountinfo` is the authoritative per-process view (peer groups, propagation, root field) | `/proc/mounts`, `findmnt` | `/proc` masked | `/proc/mounts` is a compatibility view and loses the mount-namespace root — use `mountinfo` |
| VM | identical | — | — | — |
| Container | shows only the container's namespace; the root entry has a non-`/` root field and an overlay source | — | runtime masks parts of `/proc` | a container reporting "no NFS mounts" says nothing about the host |

## 6. Init system and service state

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian | `/run/systemd/system` exists (the documented `sd_booted(3)` test, R4-F40) | `/proc/1/comm` | neither readable | presence of the `systemctl` binary proves nothing |
| Alpine | OpenRC; `/run/systemd/system` absent, `/proc/1/comm` = `init` | `/run/openrc/`, `rc-status` | — | every systemd-dependent check must become unknown with reason "systemd not booted", never a failure |
| VM | as the guest distro | — | — | — |
| Container | PID 1 is the entrypoint; `/run/systemd/system` normally absent | — | — | a service-state check inside a container answers about the container, not the machine |
| WSL (LOCAL_REPRO) | `/run/systemd/system` present but empty; `sd_booted` true | — | — | "present but empty" is a third state a naive existence test mishandles |

## 7. sshd posture

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL 9 | `/etc/ssh/sshd_config` with an `Include /etc/ssh/sshd_config.d/*.conf`; different defaults (notably `PermitRootLogin`) | runtime listeners; `systemctl` unit state | the Include glob is unreadable, or a `Match` block cannot be evaluated | the Include is **not guaranteed** on in-place-upgraded RHEL (R4-F41, R4-S22) — a parser that assumes it will silently miss drop-ins |
| Debian | classic `sshd.service`, not socket-activated in older releases | same | same | do not assume socket activation; do not assume its absence either — read the unit |
| Alpine | may run **Dropbear**, which has *no config file* — options are command-line flags | process argv where readable; listener evidence | the daemon is Dropbear and argv is unreadable ⇒ policy unknown | a config-file parser returns "no config ⇒ defaults" — wrong twice: there is no file *and* the defaults differ |
| VM | as the guest distro | — | — | — |
| Container | usually no sshd at all | — | — | "no SSH listener" in a container is not "no remote access to the machine" |
| All | `sshd -T` requires privilege because host keys load before the test-mode exit path (R4-F19, R4-S03) | derive by parsing + runtime cross-check | — | never treat `sshd -T` failure as a configuration error |
| WSL (LOCAL_REPRO) | `sshd: command not found` (openssh-server not installed) | — | UTILITY_MISSING for the daemon while a listener could still exist | "sshd binary missing" and "no SSH service" are different findings |

## 8. BMC / IPMI

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian bare metal, driver loaded | `/sys/class/ipmi/ipmi0`, `/sys/devices/platform/ipmi_bmc.*` populated, `/dev/ipmi0` 0600 root:root by kernel default (R4-F48) | SMBIOS type-38 entry existence | `ipmi_bmc.*` absent while `38-0` exists ⇒ **interface declared, driver not bound** | this middle state is the one most often mis-reported as "no BMC" |
| Bare metal, driver **not** loaded | only `/sys/firmware/dmi/entries/38-0` exists | — | no DMI entries directory ⇒ unknown | UTILITY_MISSING on `ipmitool` says nothing about the BMC |
| Alpine | driver may not be built; the DMI entry still exists on the same hardware | DMI entry existence | — | absence of the driver is a *host configuration* fact, not a hardware fact |
| VM | no `/dev/ipmi*`, no `/sys/class/ipmi`, **no type-38 entry** — the three together are what prove "no BMC hardware" | `systemd-detect-virt` corroboration | any of the three unreadable | one missing signal alone is not proof |
| Container | inherits the host's `/sys/firmware/dmi/entries` (R4-F38) but has no `/dev/ipmi0` | — | — | a container on this hardware would claim a BMC it cannot reach — annotate with execution context |
| All | never issue a write-shaped IPMI operation; DSP0270 credential bootstrapping **creates an account** despite reading like a query (R4-F50) | — | — | "read-only" must be judged by effect, not by verb |

## 9. LSM / security-module state

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL 9 | `/sys/fs/selinux/enforce` (0/1), `/etc/selinux/config` | `/proc/self/attr/current`, `/sys/kernel/security/lsm` | `/sys/fs/selinux` absent ⇒ SELinux not enabled (proven, since the parent `/sys/fs` is readable) | `getenforce` missing ≠ SELinux absent |
| Debian / Ubuntu | `/sys/module/apparmor/parameters/enabled`; `/sys/kernel/security/apparmor/profiles` is **0444** (R4-F44) | `/sys/kernel/security/lsm` list | securityfs not mounted | enabled=Y proves the LSM is active, **not** that any profile is enforcing |
| Alpine | usually neither; `/sys/kernel/security/lsm` shows the compiled set | — | — | "no LSM" is a legitimate proven answer only if the securityfs read succeeded |
| VM | as the guest | — | — | — |
| Container | `/sys/kernel/security` typically not mounted or empty | `/proc/self/attr/*` for the effective profile | securityfs missing | absence in a container says nothing about the host's LSM |
| WSL (LOCAL_REPRO) | AppArmor **not compiled in** (`enabled`=`N`, no `/sys/kernel/security/apparmor`), lockdown absent, yet `aa-status` **is installed** | — | — | the exact inverse of the Lava host (kernel Y, tool missing) — tool presence and kernel capability are independent axes (R4-F42) |

## 10. Kernel/boot flags: `/proc/cmdline`, `tainted`, `lockdown`, `/sys/firmware/efi`

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL / Debian on UEFI | `/sys/firmware/efi/efivars/SecureBoot-<GUID>` readable; value is the **5th byte** after a 4-byte attribute prefix | `mokutil --sb-state` (works unprivileged) | efivarfs not mounted | "SecureBoot=0" and "no efivars at all" are different findings; the latter is not-applicable/unknown |
| Legacy BIOS boot | `/sys/firmware/efi` absent entirely | — | — | reporting `fail: Secure Boot disabled` on a BIOS machine is a false positive |
| Alpine | same kernel interfaces; `mokutil` usually absent | efivarfs direct read | — | UTILITY_MISSING on `mokutil` must not turn a readable efivar into unknown |
| VM | often no efivars (BIOS-mode guests); lockdown usually `[none]` | — | — | — |
| Container | `/sys/firmware` normally absent; `/proc/sys/kernel/tainted` may still be readable and describes the **host** kernel | — | `/sys/kernel/security` absent | taint and cmdline read inside a container describe the host — attribute them correctly or suppress them |
| All | per-module taint attribution via `/sys/module/<name>/taint` letters | `/proc/sys/kernel/tainted` bitmask only | `/sys/module` unreadable | taint letter `E` records an unsigned module even where signature enforcement is off — never infer enforcement from taint; DKMS is a common benign source of `O` |

## 11. Package / patch state

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL | `rpm -qa`, `dnf needs-restarting -r`; `/var/lib/dnf/history` | `/boot/vmlinuz-*` vs `uname -r` | package DB unreadable | `needs-restarting` requires the `dnf-utils` package |
| Debian / Ubuntu | `dpkg -l`; `/var/lib/apt/lists` freshness; `/var/run/reboot-required` | `/boot` symlink vs `uname -r` (R4-F14) | apt index empty or stale | **an empty `/var/lib/apt/lists` makes "nothing upgradable" meaningless** (R4-F15); the marker file's absence is not evidence because the package that creates it may not be installed (R4-F34) |
| Alpine | `apk list --upgradable`; `/lib/apk/db/installed` | filesystem kernel comparison | — | no reboot-required convention at all |
| VM / Container | as the distro; a container has no kernel of its own | — | — | comparing a container's userland packages to the host kernel is meaningless |

## 12. Secrets-surface scanning

| Target | Expected evidence | Fallback | UNKNOWN trigger | Trap |
|---|---|---|---|---|
| RHEL | `/etc/pki/tls/private`, `/etc/pki/entitlement`, `/root/.ssh` | — | EACCES on a store ⇒ "present, contents unknown" | path sets differ per distro; a Debian-shaped path list under-reports on RHEL |
| Debian / Ubuntu | `/etc/ssl/private`, `/etc/ssh`, cloud-init dirs | — | same | cloud-init's readable `instance-data.json` self-redacts — an empty field may be redaction (R4-F24) |
| Alpine | far smaller surface; BusyBox `find` lacks some GNU predicates | walk in-process rather than shelling out to `find` | — | relying on GNU `find` flags silently fails on BusyBox |
| VM | same as the guest distro | — | — | — |
| Container | the image's secrets, plus mounted secret volumes and `/run/secrets` | `/proc/self/mountinfo` for tmpfs secret mounts | — | scanning a container and reporting on "the machine" conflates two scopes |
| All | ACL presence is visible as a trailing `+` in a long listing; read `system.posix_acl_access` directly rather than depending on `getfacl` (R4-F28) | — | xattr unreadable | mode bits alone do not answer "who can read this" where an ACL or a kernel policy gate exists (R4-F12) |
