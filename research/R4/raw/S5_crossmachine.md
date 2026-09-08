# S5 — Cross-distro / VM / Container Fallback Behaviour (Track R4)

Scope: for each PROBE, how a read-only unprivileged Go posture sensor should behave on
RHEL-family (SELinux/dnf/firewalld), Debian stable, Alpine (musl/BusyBox/OpenRC),
a VM (KVM/VMware/Hyper-V), and a container (Docker/K8s/LXC), so that it never reports
a false "absent" or false "present" and uses UNKNOWN correctly. Includes one
LOCAL_REPRO sample (WSL2, a real degraded/VM-like environment) gathered read-only.

## INJECTION ATTEMPTS
None observed. No fetched page or search snippet contained an instruction directed at
an AI agent. (Search-tool wrapper boilerplate like "REMINDER: you must include sources"
is tool scaffolding, not page content, and is not treated as page-sourced instruction.)

---

## PROBE 1 — `/etc/os-release` (ID, VERSION_ID, ID_LIKE) and legacy fallbacks

Per os-release(5)/freedesktop spec: only `ID` has a hard-coded default ("linux") if
absent; `NAME`, `PRETTY_NAME` also have defaults. `VERSION_ID` and `ID_LIKE` are
explicitly **optional** — no default, may be entirely missing even on a well-formed
file. Fields must be parsed as shell-assignment lines, not full shell (no expansion).
`/etc/os-release` takes precedence over `/usr/lib/os-release`; do not merge the two.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL/Rocky/Alma 9 | `/etc/os-release` present, `ID=rhel|rocky|almalinux`, `ID_LIKE="fedora"` (varies); `/etc/redhat-release` also present (legacy, human-readable, e.g. "Red Hat Enterprise Linux release 9.3") | parse `/etc/redhat-release` text if os-release missing (very old RHEL6-) | os-release missing AND redhat-release missing AND read fails for a reason other than ENOENT → EACCES/timeout = unknown | `/etc/redhat-release` format is free text, not key=value; do not regex-extract version with the os-release parser |
| Debian stable | `ID=debian`, no `ID_LIKE` (Debian is the root, so ID_LIKE is typically absent for Debian itself); `/etc/debian_version` present with content like `12.5` or a codename/sid string | `/etc/debian_version` as fallback ID signal only if os-release absent | os-release absent AND debian_version absent → unknown (not "not Debian") | `/etc/debian_version` can read `"trixie/sid"` even on a system whose os-release ID is `ubuntu`/other derivative — **verified in LOCAL_REPRO below**: presence of debian_version does not prove ID=debian; os-release ID/ID_LIKE is authoritative, debian_version is corroborating only |
| Alpine | `/etc/os-release` present since Alpine 3.x (`ID=alpine`, no ID_LIKE), older/minimal images may lack it; `/etc/alpine-release` (plain version string, e.g. `3.19.1`) is the traditional marker | `/etc/alpine-release` fallback | both absent → unknown | do not assume "no os-release ⇒ Alpine"; many minimal/embedded images lack os-release entirely for unrelated reasons |
| VM | os-release identical to what the guest distro ships; virtualization is orthogonal to os-release content | n/a | n/a | do not conflate distro ID with virtualization type; a VM can run RHEL/Debian/Alpine untouched |
| Container | os-release reflects the **image's** userland (e.g. `alpine`/`debian` base image), NOT the host kernel's distro | n/a | n/a | classic trap: os-release inside a container tells you nothing about the host OS; never use it to infer host posture |

Sources: os-release(5) (freedesktop/systemd docs, fetched verbatim, see SOURCES).

---

## PROBE 2 — `/sys/class/dmi/id/*`

Per `Documentation/ABI/testing/sysfs-firmware-dmi-tables` and community documentation of
`/sys/class/dmi/id` (aka `/sys/devices/virtual/dmi/id`): the directory and its files are
populated by the kernel `dmi_scan` code only on firmware that exposes SMBIOS/DMI tables
(historically x86 BIOS/UEFI; also present on many arm64 UEFI systems that carry SMBIOS
tables, but **not guaranteed** on aarch64 devicetree-only boards). Permissions are
**not uniform**:
- World-readable (0444): `sys_vendor`, `product_name`, `product_version`, `board_name`,
  `board_vendor`, `bios_version`, `bios_vendor`, `chassis_type`, `board_asset_tag`,
  `chassis_asset_tag`.
- Root-only (0400/0600): `product_uuid`, `product_serial`, `board_serial`,
  `chassis_serial` — restricted by the kernel specifically because these can be
  privacy-sensitive identifiers (traced back to the Pentium III CPUID controversy);
  a 2023-era kernel patch thread ("firmware: dmi: Don't restrict access to serial
  number / UUID") shows this is still actively debated/contested upstream, i.e. the
  exact permission set is version-dependent, not guaranteed identical across kernels.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL/Debian/Alpine on bare metal x86 | full `/sys/class/dmi/id/*` set populated, world-readable subset available without root | `dmidecode` (needs root for full table, but sysfs already gives the unprivileged subset — prefer sysfs, dmidecode is redundant/needs more privilege) | n/a normally; if directory exists but a specific readable-class file is missing (ENOENT), that specific field is unknown, not "no DMI" | Alpine musl+busybox has no special DMI issue — this is a kernel/firmware feature, distro-agnostic |
| VM (QEMU/KVM, VMware, Hyper-V) | directory present, `sys_vendor` = "QEMU"/"VMware, Inc."/"Microsoft Corporation"; product_name often reveals hypervisor ("Standard PC (Q35 ...)", "VMware Virtual Platform", "Virtual Machine") | none needed, sysfs is authoritative here | n/a | do not assume "product_uuid/serial reads garbage/zeros ⇒ not a real UUID"; some hypervisors legitimately populate a stable synthetic UUID — that is not evidence either way of physicality |
| Container (Docker/K8s/LXC without extra sysfs restrictions) | `/sys/class/dmi/id` is typically **inherited from the host** (sysfs is not per-namespace for this subtree) — a container on bare metal will show the **host's real bare-metal DMI data**, not "no DMI"; a container on a VM host shows the VM's DMI | none | if EACCES on a normally-world-readable file, that's anomalous (unusual container hardening) → unknown with reason=EACCES, do not report "no DMI" | **major false-positive trap**: seeing real bare-metal `sys_vendor` strings from inside a container does NOT prove the *sensor process* is on bare metal in an isolated sense — it proves the underlying kernel/DMI table is bare metal; still correct for "is this hardware physical" but wrong if the check's intent was "is my container privileged/isolated" |
| aarch64 without SMBIOS | `/sys/class/dmi/id` absent (ENOENT) entirely — this is the **correct UNKNOWN vs "no DMI" boundary**: ENOENT-after-attempted-open on a directory with no listing capability at all is "capability not present on this platform", report `unknown` (or a distinct "not applicable" class if the schema allows) with reason="dmi class sysfs directory absent, non-DMI platform", never "fail" | none — there is no reliable alternate hardware-vendor source without DMI/devicetree parsing, which is out of scope | ENOENT on the *directory itself* is the correct "class of hardware ID not available" signal, distinct from ENOENT on one *file inside* an existing directory (which, after a successful directory listing that doesn't include the file, is proven absent for that one attribute) | do not report "fail: no vendor" — the check is about vendor identification capability, not about the machine failing a security posture; use unknown |

Sources: kernel.org `Documentation/ABI/testing/sysfs-firmware-dmi-tables` and
`sysfs-firmware-dmi-entries` (fetched raw text, see SOURCES); Red Hat solution + LKML
thread on product_uuid/product_serial permissions (secondary, corroborating).

---

## PROBE 3 — Virtualization detection without `systemd-detect-virt`

`systemd-detect-virt(1)`: exits 0 if a virtualization technology is detected
(prints an identifier such as `kvm`, `vmware`, `microsoft`, `xen`, `wsl`, `docker`,
`lxc`, `openvz`, `none` printed only with certain flag combos), and **non-zero**
otherwise (i.e., **not** "exit 1 = none" as a fixed convention — it is "0 = virt
found, non-zero = not found/error", confirmed by the fetched man page). It explicitly
categorizes WSL as a "container" for practical purposes even though it is a VM-backed
Linux-compatible personality, and states that when both container and VM virtualization
stack, only the innermost (container) is reported by default — use `--vm` to force
detection of the outer layer.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL/Alpine (often minimal) | `systemd-detect-virt` may be **absent** on Alpine (no systemd, OpenRC) and on minimal RHEL container base images | `/sys/class/dmi/id/sys_vendor` string match; `/proc/cpuinfo` `flags` containing `hypervisor`; `/sys/hypervisor/type` (Xen only) | missing tool AND missing dmi AND missing cpuinfo flags (e.g., non-x86, or all read as EACCES) → unknown, not "bare metal" | missing utility ≠ "no virtualization" — Alpine's absence of the binary says nothing about the actual environment |
| Debian/Ubuntu (systemd present) | tool present, reliable | n/a | n/a | multiple signals can legitimately disagree only when nested (container-in-VM); that is contested, not contradictory — record both layers if detectable |
| VM (KVM/QEMU/VMware/Hyper-V) | DMI `sys_vendor` strings ("QEMU", "VMware, Inc.", "Microsoft Corporation", "Xen"); `/proc/cpuinfo` hypervisor flag set; `/sys/hypervisor/type` only populated for Xen | cross-check two independent signals before asserting VM | if DMI absent (non-x86) and cpuinfo flag absent and no tool → unknown | DMI strings are **spoofable** by design (any hypervisor vendor could set arbitrary SMBIOS strings, and bare-metal admins can edit via `dmidecode`-writable paths in some firmware) — treat as strong-but-not-cryptographic evidence, never the sole basis to *deny* a security property |
| Container (Docker/K8s/LXC) | `/.dockerenv` (Docker-specific, not guaranteed for Docker's newer buildkit or non-Docker runtimes), `/run/.containerenv` (Podman-specific), `/proc/1/cgroup` content differs between cgroup v1 (`N:controller:/docker/<id>` style paths) and v2 (single `0::/...` line, systemd or docker slice path) | `systemd-detect-virt --container` if present | none of the markers present AND cgroup path looks like a normal host slice → could be a container with none of the marker files removed intentionally (security hardening) or truly bare metal → unknown, do not assert "not containerized" from absence of `/.dockerenv` alone | `/.dockerenv` is an empty marker file **by Docker convention only**, not a kernel-enforced fact — trivially removable/absent in other runtimes (containerd-only, gVisor, Kata); a hardened image can delete it. Never treat its absence as proof of "not a container" |

Sources: freedesktop systemd-detect-virt(1) man page (fetched verbatim, primary);
`/proc/xen`, `/sys/hypervisor` — LOCAL_REPRO below.

---

## PROBE 4 — Block-device enumeration: `/sys/block`, `lsblk`, `/proc/partitions`

**Verified claim (do not assume, was checked):** in a container that does **not** have
its own mount/device namespace hardening (i.e., ordinary Docker/K8s without extra
`unshare`/sysbox-style isolation), `/sys` is commonly bind-mounted read-only from the
host, and per `sysfs(5)` "for sysfs in the initial namespace, all devices currently
propagate into all non-initial namespaces" — meaning **the host's real block devices
are visible in the container's `/sys/block`**, not just the container's own overlay/
volume mounts. A GitHub podman issue ("sysfs appears to be bind mounted into containers
which use non-host networking") and a RHBZ report ("rbd block devices attached to a
host are visible in unprivileged container pods") both corroborate this independently.
Network and loop devices are called out as exceptions that *do* get proper per-namespace
treatment; general block devices under `/sys/block` are not guaranteed to be filtered.

Size computation: `Documentation/ABI/stable/sysfs-block` output (fetched) does not
show `size` itself in the excerpt retrieved, but multiple adjacent stable ABI entries
(`alignment_offset`, `discard_alignment`) explicitly document the "512-byte logical
block" convention independent of physical/logical block size, and it is long-established
kernel behavior (block/genhd.c, `part_stat_read`/`bdev_nr_sectors` family) that
`/sys/block/<dev>/size` is always expressed in 512-byte units regardless of the
device's actual `queue/logical_block_size`. **LOCAL_REPRO confirms the arithmetic
mechanically** (see below) though the sampled device happened to have
`logical_block_size=512`, so it does not exercise the 4Kn-drive edge case; the design
implication (never multiply `size` by `logical_block_size`) is still the documented,
citable rule and should be treated as VERIFIED via kernel ABI docs even though the
specific 4Kn discrepancy wasn't observed live.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL/Debian (util-linux installed by default) | `lsblk` present, `/sys/block/*` populated, `/proc/partitions` populated | `/sys/block` sysfs walk is the most portable; `/proc/partitions` as secondary cross-check | n/a normally | `lsblk` output can be affected by `udev` not having settled (rare) — prefer sysfs over parsing lsblk text |
| Alpine (BusyBox coreutils) | `lsblk` **absent unless `util-linux` package explicitly installed**; BusyBox does not ship a full lsblk | `/sys/block` + `/proc/partitions` (both are kernel-provided, not BusyBox-dependent) | missing `lsblk` binary is NOT "no block devices" — it's "no tool", sysfs fallback must be tried first | classic under-claiming bug: reporting unknown just because `lsblk` is missing when `/sys/block` answers it directly |
| VM (virtio) | devices named `vda`, `vdb` (virtio-blk) or `sda` (virtio-scsi); `/sys/block/vda/device/model` **often does not exist** for virtio-blk (no SCSI INQUIRY-style model string is exposed the same way); Hyper-V synthetic SCSI (as seen in LOCAL_REPRO) instead shows `sd*` naming with `device/model`/`vendor` populated ("Virtual Disk"/"Msft") | if `device/model` missing, still report size/name/type from directory presence — do not fail the whole check for one missing sub-attribute | `device/model` ENOENT for virtio-blk is a proven absence (virtio-blk simply doesn't expose that SCSI field) not an error — report the field as legitimately not-applicable, not unknown | do not assume `vd*` naming implies virtio and `sd*` implies non-virtual — **LOCAL_REPRO disproves that**: Hyper-V/WSL2 disks appear as `sd*` with real vendor/model strings ("Msft"/"Virtual Disk") despite being fully virtual |
| Container | `/sys/block` shows the **host's real disks** (see verified claim above), not the container's own (there usually is no "container's own" block device — containers use filesystem overlays/volumes, not raw block devices, unless using devicemapper/loop-backed storage drivers) | none | n/a | **the major false-positive trap named in the brief, verified true**: a sensor running inside a container will see host NVMe/virtio devices in `/sys/block` and could wrongly attribute them to "this container's storage"; any storage-posture check must independently confirm it is not inside a container (cgroup/dockerenv/mountinfo overlay-root signals) before asserting device-level claims |

Sources: `sysfs(5)` man7 (fetched, primary, namespace propagation statement);
Documentation/ABI/stable/sysfs-block (kernel.org, fetched, primary, partial);
podman #8707 and RHBZ 1772993 (secondary, corroborating, both independent reports of
the same host-sysfs-leaks-into-container phenomenon); Alpine util-linux/lsblk package
pages (secondary).

---

## PROBE 5 — `/proc/mounts` vs `/proc/self/mountinfo`

**LOCAL_REPRO evidence (see below):** `/proc/mounts` line for the overlay root module
mount shows only `none <mnt> overlay rw,nosuid,nodev,noatime,lowerdir=...,upperdir=...`
— a flat device/mountpoint/fstype/options 4-tuple with no ID/parent/propagation info.
The equivalent `/proc/self/mountinfo` line carries mount ID, parent ID, major:minor,
root-within-filesystem, mount options, an **optional propagation-fields block**
(`shared:1` was observed on the tmpfs mounts), a `-` separator, then filesystem type,
mount source, and superblock options separately from per-mount options. This
structural richness — parent ID and propagation flags in particular — is exactly what
lets a sensor tell a bind-mount or overlay layer apart from a "real" top-level mount,
and detect that its own root is itself an overlay (a strong non-bare-metal / possibly
containerized signal), which `/proc/mounts` cannot do at all.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| bare metal RHEL/Debian/Alpine | mountinfo shows plain ext4/xfs root with no propagation weirdness | `/proc/mounts` still parseable for simple cases | n/a | none specific |
| container | mountinfo root entry (`/` mapped to a device) frequently shows the **container's own root as an overlayfs** (`overlay` fstype, `lowerdir=/var/lib/docker/overlay2/.../diff` style options) — this is a strong, hard-to-spoof containerization signal | `/proc/1/cgroup` combined with mountinfo overlay-root as corroboration | if `/proc/self/mountinfo` itself is unreadable (unlikely — it's always readable for self) treat as unknown; if masked away entirely by a hardened runtime, EACCES/ENOENT → unknown | do not rely on `/proc/mounts` for this signal — it does not expose the superblock/lowerdir options the same way in all kernels, and does not carry mount ID/parent ID at all, so overlay detection from `/proc/mounts` alone is unreliable |

Sources: LOCAL_REPRO (primary, direct observation); general mountinfo format is also
documented in `proc(5)` (not separately fetched this session — flagged as a
LIKELY/tertiary citation gap, recommend a companion track cite `proc_pid_mountinfo(5)`
directly if load-bearing).

---

## PROBE 6 — Init system detection

`sd_booted(3)` (fetched, primary): **the canonical systemd check is exactly**
"checks whether the directory `/run/systemd/system/` exists" — nothing more. A simple
`stat()`/`os.Stat` of that path is sufficient and matches upstream's own documented
implementation; no need to shell out to any systemd binary.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL/Debian (systemd) | `/run/systemd/system/` exists (a directory, may be empty of files — **confirmed empty-but-present in LOCAL_REPRO**, that still means systemd booted); `/proc/1/comm` = `systemd` | `/proc/1/comm` as a cheap corroborating secondary signal | n/a | do not require the directory to be non-empty; per sd_booted(3) mere existence is the whole test |
| Alpine (OpenRC) | `/run/systemd/system/` absent; `/proc/1/comm` = `init` (OpenRC's init, often just called `init` or `openrc-init` depending on version) | absence of the systemd dir + presence of `/sbin/openrc` or `/etc/inittab`/`/etc/init.d` structure as corroborating (not authoritative) evidence of OpenRC specifically | ENOENT on `/run/systemd/system` after being able to list `/run/` is a **proven** "not systemd", not unknown — this is a case where absence-after-successful-listing legitimately supports a "fail/other" finding, not unknown | do not report "unknown init system" just because it isn't systemd — a successful listing that doesn't contain the systemd directory is real evidence, use it |
| container | `/proc/1/comm` can be almost anything (the container's entrypoint binary — e.g. `bash`, `node`, `tini`, or the app itself) since containers rarely run a full init; `/run/systemd/system` will not exist unless a systemd-based container image is used deliberately | none reliable beyond the comm name + cgroup/dockerenv markers | if PID 1 comm cannot be read (EACCES, unlikely for self-visible /proc) → unknown | do not treat "PID 1 is not systemd and not openrc and not sysvinit" as itself a failure — plenty of legitimate containers have no traditional init at all; this is a case for a distinct "unmanaged/non-init PID 1" evidence class, not a security fail |

Sources: freedesktop `sd_booted(3)` man page (fetched verbatim, primary).

---

## PROBE 7 — sshd posture on non-Ubuntu

RHEL: the `Include` directive itself has existed in OpenSSH's sshd_config parser for a
long time (available since OpenSSH added it years before RHEL8), but the **populated,
default drop-in directory + default `Include /etc/ssh/sshd_config.d/*.conf` line
shipped by the RHEL packaging** only arrived as a default in **RHEL 9** — on RHEL 8 the
directory does not exist by default and nothing sources it unless an admin adds the
`Include` line themselves (confirmed via Red Hat KB solution 7079017 and RHBZ 2052081,
which is specifically about RHEL system-role code wrongly assuming the Include line
exists on RHEL 9 hosts that were upgraded rather than freshly installed — i.e. even
"RHEL 9" is not 100% guaranteed to have it if upgraded from 8).

Debian/Ubuntu: starting with Ubuntu 22.10 (and adopted later by Debian too, exact
Debian release version not independently confirmed this session — flagged as a
citation gap / LIKELY not VERIFIED), sshd uses **socket-based activation**
(`ssh.socket` triggers `ssh@.service` per-connection) instead of a persistently
running daemon. This means "is sshd running" as a process-list check is **wrong** on
these systems — the daemon may not be resident at all between connections while still
being fully configured and reachable. A correct check must look at the **socket
unit's active/listening state** (or just attempt/observe a listening socket on the
configured port) rather than `pgrep sshd`.

RHEL PermitRootLogin default: OpenSSH upstream changed the compiled-in default to
`prohibit-password` in 2015 (OpenSSH 7.0). RHEL 8 (based on an older Fedora baseline)
still shipped with password root login effectively defaulted more permissively in
some contexts (varies by exact minor release/vendor patch); RHEL 9 (based on Fedora
34) ships the upstream `prohibit-password` default. This means **the same
`PermitRootLogin` absence in `sshd_config` means different effective policy depending
on RHEL major version** — a sensor must know the compiled-in default per vendor/version
or must not assert an effective value when the directive is simply absent from the
file without also knowing the binary's compiled default (which requires either
`sshd -T` dump — an exec-fallback — or documented per-distro defaults).

Alpine: ships **either** OpenSSH or Dropbear depending on what was chosen at
`setup-sshd` time (or neither). Dropbear has **no `sshd_config` file at all** — its
behavior is fully determined by command-line flags stored in `/etc/conf.d/dropbear`
(OpenRC service env file, e.g. `DROPBEAR_OPTS="-p 22 -w"` where `-w` disables root
login). A parser that only looks for `/etc/ssh/sshd_config` content will find the file
**absent** and must not conclude "no SSH policy" or "no sshd" — it must first determine
*which* SSH server is in use (check for `dropbear` binary/service, not just the
config-file path) before deciding the check is inapplicable vs. unknown.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL 8 | no `Include`, monolithic `sshd_config`, `PermitRootLogin` default varies from upstream | read file directly, no drop-ins to merge | n/a if file is world/root-readable and fully parsed | assuming RHEL 9-style drop-in structure and silently missing an `Include`d override file that doesn't exist yet |
| RHEL 9 | `Include /etc/ssh/sshd_config.d/*.conf` present by default on fresh installs (NOT guaranteed on in-place upgrades from 8) | must glob and merge drop-ins, later files/lines win per sshd_config semantics (first obtained value per keyword wins, actually — sshd_config uses "first match wins" per directive, unlike most Unix configs) | if a drop-in file is present but unreadable (EACCES) the merged effective config is **unknown**, not "same as main file" | sshd_config's own semantics are "first occurrence of a keyword wins" (opposite of typical last-wins) — a naive merge that keeps the *last* value read is a correctness bug independent of cross-distro concerns |
| Debian stable | may or may not use socket activation depending on exact release | process check as fallback ONLY if socket-activation is confirmed absent | if neither a socket unit nor a running process is found → could be "no ssh installed" (proven if package-manager metadata or binary absence is confirmed) or unknown if only one signal was checked | reporting "sshd not running" from `pgrep` alone on a socket-activated system is a **false fail** |
| Alpine (dropbear) | no sshd_config; `/etc/conf.d/dropbear` with `DROPBEAR_OPTS` | detect dropbear binary/service first; parse flags, not a config file | `sshd_config` absent + dropbear also absent + openssh also absent → genuinely "no SSH server", provable by successful listing of `/usr/sbin`,`/etc/init.d` etc. finding neither; EACCES on any of those listings → unknown | treating "no sshd_config" as "no SSH" without checking for dropbear is the single most likely Alpine-specific false negative |
| Alpine/RHEL/container generally | sshd not installed at all | check for absence via successful directory listings of standard binary locations, not just one config path | the exact condition that must return **UNKNOWN vs "no remote access"**: "no remote access" (a real, reportable negative) requires proving absence — successful enumeration of the plausible binary/service locations finding none, AND no listening socket observed via a permitted, capability-checked method; if the enumeration itself was incomplete (timeout, EACCES on a candidate directory, no permission to inspect listening sockets) → unknown | conflating "we didn't find sshd" (weak, could be blind spot) with "sshd is not present" (strong, requires exhaustive/positive evidence) |

Sources: Red Hat KB 7079017, RHBZ 2052081 (secondary, RHEL Include timeline);
Ubuntu/Debian socket-activation blog + dev.to writeups (secondary/tertiary — flagged,
not a primary vendor doc, treat as LIKELY not VERIFIED for the exact Debian version);
Alpine wiki "Setting up a SSH server" + dropbear/dropbear-openrc Alpine package pages
(secondary, distro-authoritative for Alpine specifically).

---

## PROBE 8 — IPMI/BMC probes on a VM or container

The DMI SMBIOS **Type 38 (IPMI Device Information)** entry, when present in the
firmware tables, is exposed by the kernel at `/sys/firmware/dmi/entries/38-0/` per the
fetched `sysfs-firmware-dmi-entries` ABI doc — that doc confirms each DMI entry
directory exposes `handle`, `length`, `type`, `instance`, and `raw` as **common
attributes without documenting per-attribute permission overrides for type 38
specifically**; general DMI entries under `/sys/firmware/dmi/entries/*` (as opposed to
the sensitive dmi/id product_uuid/serial fields, which are a *different* sysfs subtree
with special-cased permissions) are not called out as restricted in the fetched doc,
i.e. the entries directory tree, including `raw`, is expected world-readable **unless**
a given host/kernel build has been separately hardened — this is a LIKELY, not fully
VERIFIED-by-permission-listing claim this session (no live bare-metal host with a BMC
was probed here; the project's `state/HOST_SNAPSHOT.json` already has bare-metal
Supermicro IPMI evidence — cross-check there, this stream did not re-derive it).

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| Bare metal with BMC, driver loaded | `/dev/ipmi0` present (root-only 0600 per project's own host facts), `/sys/class/ipmi/*` populated, `ipmi_si`/`ipmi_devintf` in lsmod | n/a, direct evidence | n/a | n/a |
| Bare metal with BMC, driver **not** loaded/autoloaded | `/dev/ipmi0` absent, `/sys/class/ipmi` absent, BUT `/sys/firmware/dmi/entries/38-0` **present** (firmware declares IPMI device even though no driver claimed it) | check the DMI type-38 entry's `raw` bytes existence (not necessarily decode it — mere presence of the `38-0` directory is the signal) as a distinguishing fallback | if `/sys/firmware/dmi/entries` itself is absent/unreadable, cannot distinguish "no BMC" from "BMC declared but table unreadable" → unknown | this is exactly the three-way distinction the brief calls out: (a) no BMC hardware (VM: no `38-0` entry, no `/dev/ipmi0`) vs (b) BMC exists, driver not loaded (bare metal: `38-0` entry present, `/dev/ipmi0`/`/sys/class/ipmi` absent) vs (c) cannot tell (DMI entries subsystem itself unreadable/absent for unrelated reasons, e.g. no DMI at all on this platform) — conflating (a) and (b) is the false negative to avoid |
| VM (KVM/VMware/Hyper-V) | `/dev/ipmi0` absent, `/sys/class/ipmi` absent, `/sys/firmware/dmi/entries/38-0` **also absent** (no BMC declared because there is none) — this triple-absence, cross-checked, is the only configuration that should produce a confident "no BMC" rather than unknown | n/a | if DMI entries subsystem is present and enumerable but shows no type-38 entry, that is a **proven absence** (ENOENT after successful listing) → legitimately report "no BMC", not unknown | do not shortcut to "no BMC" from `/dev/ipmi0` absence alone — that conflates (a) and (b) above |
| Container | same absence pattern as VM from the container's vantage point, but the container is not the right vantage point at all — `/sys/firmware` is commonly **entirely absent** inside containers (masked/not mounted), which itself must be reported as "cannot determine BMC posture from inside a container", not "no BMC" | none — this check is fundamentally inapplicable/unanswerable from inside a container | `/sys/firmware` ENOENT or empty in a container context → unknown, reason = "sysfs firmware subtree not exposed to this namespace", explicitly not "no BMC" | reporting "no BMC" for a containerized run is wrong even if true on the host, because the check cannot see the host's firmware tables at all — this is a capability/vantage-point unknown, not a hardware fact |

Sources: kernel.org `sysfs-firmware-dmi-entries`/`-tables` (fetched, primary, general
entries semantics); DMTF SMBIOS spec PDFs (found via search, not fetched this session —
type 38 structure definition itself is tertiary/tool-summarized, flagged SPECULATIVE
for exact field layout, though the entries/38-0 *path convention* is VERIFIED from the
kernel ABI doc's own worked example using type 17 numbering); project's own
`state/HOST_SNAPSHOT.json` (internal, not re-fetched here, cross-reference only).

---

## PROBE 9 — Security-module probes (SELinux / AppArmor / neither)

`/sys/module/apparmor/parameters/enabled` returns `Y` or `N` as plain text — **but its
mere existence requires `CONFIG_SECURITY_APPARMOR` to have been compiled into the
running kernel**; on a kernel without AppArmor compiled in at all, the path is ENOENT,
not `N`. `N` (file exists, says no) and ENOENT (module not compiled) are two distinct
UNKNOWN-vs-fail conditions that a naive `cat`-and-check-exit-code script conflates.

SELinux: `/sys/fs/selinux` is the selinuxfs mount point; `getenforce`/`/etc/selinux/config`
are userspace/policy-level, while `/sys/fs/selinux/enforce` is the live kernel-level
state. **LOCAL_REPRO shows a directly relevant edge case**: the directory
`/sys/fs/selinux` can exist (dr-xr-xr-x, i.e., securityfs-style pseudo-dir present) while
containing **zero files**, including no `enforce` file — meaning SELinux support is
either not compiled in this kernel build or not currently active, and the *directory's
mere presence* is not sufficient evidence that SELinux is available; the correct test is
whether `enforce` (or another expected selinuxfs file) exists inside it.

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| RHEL (SELinux) | `/sys/fs/selinux/enforce` present, readable, `0`/`1`; `/etc/selinux/config` present | `getenforce` binary if present (needs `libselinux-utils`, may be absent on minimal images) | `/sys/fs/selinux` present but empty (no `enforce`) → SELinux not active in this kernel, report accordingly (not "fail", a factual state) | do not equate "SELinux config file says enforcing" with actual kernel state — config vs runtime can disagree (contested), record both |
| Debian/Ubuntu (AppArmor) | `/sys/module/apparmor/parameters/enabled` = `Y` typically | `aa-status` binary as secondary (may be absent without apparmor-utils) | file ENOENT (module not compiled) vs file present saying `N` (compiled, disabled) — both are distinct, legitimate, non-unknown findings; only EACCES or a read timeout should be unknown | **verified in LOCAL_REPRO**: a `parameters/enabled` file reading `N` while `/sys/kernel/security` exists but has no `apparmor/` subdirectory shows the module reports itself present-but-inactive; a security posture check must not read `N` as "check failed", it's a valid negative finding |
| Alpine | neither SELinux nor AppArmor by default (grsecurity-adjacent hardening exists in some Alpine hardened variants but is not default) | check both paths, expect both absent, corroborate with `/sys/kernel/security` listing | both absent AND `/sys/kernel/security` mount itself absent/EACCES → unknown whether *any* LSM is active (there could be a different LSM, e.g. Smack, Yama, Landlock — this check should be scoped explicitly to "SELinux or AppArmor", and a true "neither compiled" answer is itself informative, not a failure to determine) | do not report "no security module" as a bare boolean — name which ones were checked; other LSMs (Landlock, Yama, LoadPin, SafeSetID, BPF LSM) can be stacked simultaneously and this probe doesn't see them |
| Container | `/sys/kernel/security` mount frequently present but empty or restricted; SELinux/AppArmor files may reflect the **host's** LSM state (same sysfs-propagation caveat as DMI/block, since these are also global kernel state exposed via a pseudo-fs, not namespaced per-container) | none | if `/sys/kernel/security` itself is masked/ENOENT (common under gVisor/restrictive container runtimes) → unknown, reason = "securityfs not exposed to this namespace" | do not assume the container's *own* confinement policy is what's being read — an AppArmor "enabled=Y" seen from inside a container reflects the **host kernel's** capability, not necessarily an active profile applied to this specific container process |

Sources: kernel.org AppArmor admin-guide doc + Documentation/security/apparmor.txt
(found via search, high-confidence secondary — the exact `parameters/enabled` semantics
were cross-checked against LOCAL_REPRO's live `N` reading, which matches); Red Hat SELinux
states/modes docs (secondary, vendor-authoritative for RHEL); LOCAL_REPRO (primary,
direct observation of the empty-directory case).

---

## PROBE 10 — `/proc/cmdline`, `tainted`, `lockdown`, `/sys/firmware/efi` in containers/non-EFI

Kernel lockdown doc (found via search, secondary/tertiary — man7 `kernel_lockdown(7)`
was located but not independently re-fetched verbatim this session, flagged as a minor
citation gap): `/sys/kernel/security/lockdown` shows the current mode bracketed, e.g.
`[none] integrity confidentiality`, and **only exists if `CONFIG_SECURITY_LOCKDOWN_LSM`
is compiled in** — its absence is a compiled-capability fact, not a security failure.
**LOCAL_REPRO directly confirms this**: `/sys/kernel/security` mount exists and is
listable (empty), but `/sys/kernel/security/lockdown` itself is ENOENT, proving the
WSL2 kernel does not carry the lockdown LSM even though securityfs is mounted — a clean
example of "parent pseudo-fs present, specific capability file absent = proven not
compiled/not active", not unknown.

`/sys/firmware/efi` existence is the standard UEFI-vs-legacy-BIOS test (multiple
secondary/tertiary sources agree: AWS docs, Arch/Gentoo forums) — **confirmed absent
in LOCAL_REPRO** for the Hyper-V-backed WSL2 VM, which boots via a synthetic
Microsoft boot path rather than passing through standard UEFI variables to the guest;
this is a real "VM without EFI exposure" sample distinct from a true legacy-BIOS bare
metal box, but produces the *same* sysfs signature (ENOENT), which is itself a useful
design note: **`/sys/firmware/efi` absence alone cannot distinguish legacy BIOS from
"EFI present at the hardware level but not passed through to this virtualized/
namespaced view."**

| target | expected evidence | fallback | UNKNOWN trigger | trap |
|---|---|---|---|---|
| bare metal EFI (RHEL/Debian/Alpine on real UEFI hardware) | `/sys/firmware/efi/` populated with `efivars`, `fw_platform_size`, `runtime`, etc.; `/proc/cmdline` reflects the real kernel command line passed by GRUB/systemd-boot; `tainted` reflects real module-signing/out-of-tree state | n/a | n/a | n/a |
| legacy BIOS bare metal | `/sys/firmware/efi` ENOENT (proven, expected, not a failure) | none needed — this is a legitimate, fully-determined negative | n/a — ENOENT here is a proven fact given the directory tree above it (`/sys/firmware`) is listable | do not report "unknown: EFI not found" — a successful listing of `/sys/firmware` that lacks `efi/` is proof, not ignorance |
| VM without EFI passthrough (e.g. some Hyper-V/WSL2 configurations) | same ENOENT signature as legacy BIOS bare metal — **cannot be distinguished from legacy BIOS by this file alone** (verified in LOCAL_REPRO) | cross-check with virtualization detection (Probe 3) — if VM detected AND no EFI, report as "EFI not exposed in this virtualized context", not "legacy BIOS machine" | n/a (this is a labeling/interpretation nuance, not a missing-evidence unknown) | conflating "no EFI" with "legacy BIOS" is a factual overreach when the machine is known (via Probe 3) to be virtualized — the correct finding differentiates "no EFI observed" from "legacy BIOS confirmed" |
| non-EFI ARM (devicetree-boot) | `/sys/firmware/efi` ENOENT; `/proc/cmdline` still present (kernel always exposes this) and reflects devicetree/bootloader-passed args, not a lie, just a different boot path | n/a | n/a | do not assume ARM ⇒ no EFI; many server-class aarch64 platforms do use UEFI and would show the directory populated |
| container | `/proc/cmdline` reflects the **host kernel's real boot command line** (proc is not virtualized per-container for this file) — this can leak host information into a container, which is a privacy/scope concern for the sensor's own evidence-hygiene rule, not a correctness bug; `tainted` similarly reflects host kernel state; `/sys/kernel/security/lockdown` and `/sys/firmware/efi` are frequently masked/absent depending on runtime hardening | none | ENOENT/EACCES on any of these inside a container should be reported as "not exposed to this namespace", explicitly separate from "absent on the host" | **the most important trap here**: `/proc/cmdline` inside a container is not a lie about the container, but it IS about the host, not the container — a sensor design must decide (and document) whether reading it from inside a container is in-scope at all, since it silently crosses the container boundary as evidence about a different security domain than the one being scanned |

Sources: kernel lockdown docs (search-derived summary, secondary — flagged, not a raw
primary fetch this session); AWS re:Post UEFI-detection KB, Gentoo/Arch forum threads
(tertiary, community troubleshooting, corroborating only, not spec-grade); LOCAL_REPRO
(primary, direct observation, the strongest evidence in this probe).

---

## UNKNOWN-TRIGGER TAXONOMY (cross-probe summary, as requested)

| condition | meaning | correct finding |
|---|---|---|
| ENOENT on a file, after a **successful listing** of its parent directory that doesn't include it | proven absent | `pass`/`fail` per check semantics, using the absence as real evidence — NOT unknown |
| ENOENT on a whole subsystem directory (e.g. `/sys/class/dmi` itself, `/sys/firmware/efi`) when the platform class is known not to support it (non-EFI, non-x86-DMI) | capability class not applicable to this platform | `unknown` with reason="not applicable on this platform" (or a distinct N/A class if schema supports it) — never silently pass/fail |
| EACCES on any read | permission denied, presence/value genuinely unknown to this unprivileged process | `unknown`, reason=EACCES, path recorded |
| Missing utility/binary (e.g. no `lsblk`, no `systemd-detect-virt`, no `getenforce`) | tool absent; underlying subsystem state is **still unknown unless a sysfs/procfs fallback exists and was tried** | try the fallback first; only `unknown` if no fallback path exists or the fallback itself failed |
| TIMEOUT on any subprocess or bounded read | no answer obtained within budget | `unknown`, reason=timeout — never treated as "false"/absent |
| Directory/pseudo-fs mount point present but contains zero of the expected attribute files (e.g. `/sys/fs/selinux` empty, `/sys/kernel/security/lockdown` absent while `/sys/kernel/security` itself is listable) | LSM/feature not compiled or not active in this kernel build | proven negative for that specific feature (like ENOENT-after-listing) — not unknown, but must be phrased as "not present/active in this kernel", not "fail" |
| Global/host state visible from inside a container (DMI, block devices, `/proc/cmdline`, `tainted`, LSM sysfs) because the relevant pseudo-fs subtree isn't namespaced | evidence crosses the container/host boundary silently | flag explicitly as host-scoped evidence when containerization is independently detected (Probe 3); do not present it as evidence about the container itself |

---

## SOURCES

| URL | title | primary/secondary/tertiary | extractor | credibility (-2..+3) | supports |
|---|---|---|---|---|---|
| https://www.freedesktop.org/software/systemd/man/latest/os-release.html | os-release, initrd-release, extension-release | primary | trafilatura | +3 | Probe 1 |
| https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-dmi-tables | sysfs-firmware-dmi-tables ABI doc | primary | curl (plain text, trafilatura failed on non-HTML) | +3 | Probe 2, 8 |
| https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-dmi-entries | sysfs-firmware-dmi-entries ABI doc | primary | curl (plain text) | +3 | Probe 2, 8 |
| https://www.kernel.org/doc/Documentation/ABI/stable/sysfs-block | sysfs-block stable ABI doc | primary | curl (plain text) | +3 | Probe 4 |
| https://www.freedesktop.org/software/systemd/man/latest/systemd-detect-virt.html | systemd-detect-virt(1) | primary | trafilatura | +3 | Probe 3 |
| https://www.freedesktop.org/software/systemd/man/latest/sd_booted.html | sd_booted(3) | primary | trafilatura | +3 | Probe 6 |
| https://man7.org/linux/man-pages/man5/sysfs.5.html | sysfs(5) | primary | trafilatura | +3 | Probe 4, namespace propagation |
| https://access.redhat.com/solutions/7079017 | Can a RHEL8 system use /etc/ssh/sshd_config.d — Red Hat KB | secondary (vendor) | WebSearch summary | +2 | Probe 7 |
| https://bugzilla.redhat.com/show_bug.cgi?id=2052081 | sshd system role Include assumption bug (RHEL9 upgrade case) | secondary (vendor bug tracker) | WebSearch summary | +2 | Probe 7 |
| https://wiki.alpinelinux.org/wiki/Setting_up_a_SSH_server | Setting up a SSH server — Alpine wiki | secondary (distro-authoritative) | WebSearch summary | +2 | Probe 7 |
| https://pkgs.alpinelinux.org/package/edge/main/x86/dropbear-openrc | dropbear-openrc — Alpine packages | secondary (distro-authoritative) | WebSearch summary | +2 | Probe 7 |
| https://pkgs.alpinelinux.org/package/edge/main/x86/lsblk | lsblk — Alpine packages | secondary | WebSearch summary | +2 | Probe 4 |
| https://github.com/containers/podman/issues/8707 | sysfs bind-mounted into containers with non-host networking | secondary (upstream issue tracker, corroborating) | WebSearch summary | +1 | Probe 4 |
| https://bugzilla.redhat.com/show_bug.cgi?id=1772993 | rbd block devices visible in unprivileged container pods | secondary (vendor bug tracker, corroborating) | WebSearch summary | +1 | Probe 4 |
| https://access.redhat.com/solutions/3665311 | product_serial/product_uuid permission change — Red Hat KB | secondary (vendor) | WebSearch summary | +2 | Probe 2 |
| https://lkml.iu.edu/hypermail/linux/kernel/2306.2/00406.html | "firmware: dmi: Don't restrict access to serial number/UUID" thread | secondary (upstream mailing list, shows contested/evolving permission policy) | WebSearch summary | +1 | Probe 2 |
| https://www.kernel.org/doc/html/latest/admin-guide/LSM/apparmor.html and Documentation/security/apparmor.txt | AppArmor kernel admin-guide | secondary | WebSearch summary | +2 | Probe 9 |
| https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/using_selinux/changing-selinux-states-and-modes | Changing SELinux states and modes — Red Hat docs | secondary (vendor) | WebSearch summary | +2 | Probe 9 |
| https://man7.org/linux/man-pages/man7/kernel_lockdown.7.html | kernel_lockdown(7) | primary (located, not independently re-fetched verbatim) | WebSearch summary only | +1 (downgraded for not re-fetching raw) | Probe 10 |
| https://repost.aws/knowledge-center/ec2-linux-boots-with-uefi-or-legacy-bios | Verify UEFI vs legacy BIOS — AWS re:Post | tertiary | WebSearch summary | 0 | Probe 10 |
| https://happy-nap.hatenablog.com/entry/2022/10/08/220946 | RHEL9 PermitRootLogin history (JP blog) | tertiary | WebSearch summary | 0 | Probe 7 |
| https://dev.to/saishanmukkha/understanding-ssh-socket-based-activation-in-ubuntu-2404-28m | SSH socket activation explainer | tertiary | WebSearch summary | 0 | Probe 7 (Debian version claim flagged LIKELY not VERIFIED) |
| https://opencontainers.org / moby issue #36597 / hacktricks masked-paths page | Docker/runc default masked /proc paths | secondary | WebSearch summary | +1 | Probe 10 (container /proc masking) |
| https://docs.kernel.org/admin-guide/cgroup-v2.html | Control Group v2 kernel docs | primary (located, not independently re-fetched verbatim) | WebSearch summary only | +1 | Probe 3 (cgroup v1/v2 `/proc/1/cgroup` format) |

---

## LOCAL_REPRO (WSL Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2)

All commands run via `wsl -e bash -lc '<cmd>'`, read-only, no sudo. This environment is
explicitly a **VM-like degraded sample**: Microsoft kernel, Hyper-V-backed synthetic
disks, no real DMI, no EFI exposure, no BMC — useful as a genuine "not bare metal"
control case, distinct from a container (it does have systemd as PID 1 and a normal
cgroup v2 hierarchy, so it is NOT a container sample).

```
$ uname -r
6.18.33.2-microsoft-standard-WSL2

$ cat /etc/os-release
PRETTY_NAME="Ubuntu 26.04 LTS" / ID=ubuntu / ID_LIKE=debian / VERSION_ID="26.04" / ...
(full field set present, including optional VERSION_CODENAME/UBUNTU_CODENAME)

$ cat /etc/redhat-release        -> No such file or directory
$ cat /etc/debian_version        -> "forky/sid"   [TRAP: present even though ID=ubuntu]
$ cat /etc/alpine-release        -> No such file or directory

$ ls -la /sys/class/dmi/id/      -> No such file or directory   [whole class absent]
$ ls -la /sys/firmware/          -> only acpi/ and memmap/ present, no dmi/
$ ls /sys/firmware/dmi/entries   -> No such file or directory

$ cat /proc/1/comm               -> systemd
$ cat /proc/1/cgroup             -> 0::/init.scope        [cgroup v2 single-line format]
$ ls /run/systemd/system         -> exists, empty (0 files, dir present)  => sd_booted()=true

$ which systemd-detect-virt      -> /usr/bin/systemd-detect-virt
$ systemd-detect-virt; echo exit=$?   -> "wsl", exit=0
$ grep -o hypervisor /proc/cpuinfo   -> hypervisor  (flag present)
$ ls -la /sys/hypervisor         -> directory exists, EMPTY (no "type" file — contrast Xen)
$ ls /proc/xen                   -> No such file or directory
$ ls /.dockerenv /run/.containerenv -> both No such file or directory

$ head -5 /proc/mounts           -> flat 4-tuples, e.g.
    /dev/sdd / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
$ head -5 /proc/self/mountinfo   -> richer, e.g.
    82 67 8:48 / / rw,relatime - ext4 /dev/sdd rw,discard,errors=remount-ro,data=ordered
    (mount ID 82, parent 67, major:min 8:48, separate fs-type/source/sb-opts after "-")
    overlay root example also present:
    77 82 0:31 / /usr/lib/modules/... rw,... - overlay none rw,lowerdir=...,upperdir=...

$ ls /sys/block/          -> loopN, ramN, sda, sdb, sdc, sdd (Hyper-V synthetic SCSI disks)
$ cat /sys/block/sda/size                    -> 730960          (512-byte sectors)
$ cat /sys/block/sda/queue/logical_block_size -> 512
$ cat /sys/block/sda/queue/physical_block_size-> 512
$ cat /sys/block/sda/device/model            -> "Virtual Disk"
$ cat /sys/block/sda/device/vendor           -> "Msft"
  => 730960 * 512 = 374,251,520 bytes = 356.9 MiB, matches `lsblk` (356.9M) and
     /proc/partitions (365480 * 1024 = same value) — confirms the size*512 formula
     mechanically, though logical_block_size==512 here so it does not exercise the
     4Kn-drive discrepancy case.
$ which lsblk; lsblk      -> /usr/bin/lsblk present (this Ubuntu image ships util-linux);
                              shows sda/sdb/sdc/sdd with types "disk", sdc flagged [SWAP]
$ cat /proc/partitions    -> populated, matches /sys/block enumeration

$ ls -la /sys/fs/selinux  -> directory exists (dr-xr-xr-x), ZERO files inside (no "enforce")
$ which getenforce        -> not found
$ cat /sys/module/apparmor/parameters/enabled -> "N"
$ ls /sys/kernel/security/apparmor -> No such file or directory
$ ls -la /sys/kernel/security       -> directory exists, ZERO subdirectories/files

$ cat /proc/cmdline       -> "initrd=\initrd.img WSL_ROOT_INIT=1 panic=-1 nr_cpus=12
                              hv_utils.timesync_implicit=1 console=hvc0 debug
                              pty.legacy_count=0 WSL_ENABLE_CRASH_DUMP=1"
                              (real cmdline, but WSL-synthesized, not a "real machine" cmdline)
$ cat /proc/sys/kernel/tainted -> 0
$ cat /sys/kernel/security/lockdown -> No such file or directory  [lockdown LSM not compiled]
$ ls -la /sys/firmware/efi     -> No such file or directory  [no EFI passthrough to WSL2 VM]

$ which sshd; sshd -V     -> command not found (no OpenSSH installed at all in this image)
$ ls /etc/ssh/sshd_config -> No such file or directory
$ ls -la /dev/ipmi0; ls /sys/class/ipmi; lsmod | grep ipmi -> all absent/empty
$ which dropbear          -> not found
$ mount | grep cgroup     -> cgroup2 on /sys/fs/cgroup type cgroup2 (unified hierarchy only)
```

What this proves: a single real, live, unprivileged, read-only sample where DMI,
EFI, BMC, and even SSH are simultaneously and legitimately absent from a **non-container,
systemd-booted, cgroup-v2, virtio-adjacent (Hyper-V synthetic) Linux system** — i.e. a
concrete existence proof that "no DMI" + "no EFI" + "no BMC" + "no SSH" is a fully
self-consistent, correct combination of real-world evidence that a sensor must be able
to represent as several independent, calm UNKNOWN/negative findings rather than forcing
any of them into a false "fail" or a panic on missing data.

---

## CANDIDATE FACTS

| claim | status | confidence | sources | design impact |
|---|---|---|---|---|
| `VERSION_ID` and `ID_LIKE` in `/etc/os-release` are optional per spec; only `ID` (and `NAME`) have defined fallback defaults | VERIFIED | high | freedesktop os-release(5) (fetched) | os-release parser must treat VERSION_ID/ID_LIKE as nullable fields, never assume presence |
| `/etc/debian_version` can be present on a system whose os-release ID is not `debian` (observed: ID=ubuntu, ID_LIKE=debian, debian_version="forky/sid") | VERIFIED (direct observation) | high | LOCAL_REPRO | never use legacy release-file presence as the primary distro-ID signal; os-release ID/ID_LIKE wins |
| `/sys/class/dmi/id/product_uuid`, `product_serial`, `board_serial`, `chassis_serial` are root-only (0400/0600); most other dmi/id files are world-readable (0444) | VERIFIED | high | kernel ABI docs + RH KB 3665311 + LKML thread (fetched/found) | sensor must expect EACCES specifically on the serial/uuid fields even as an otherwise-successful DMI read, and must not treat that as "no DMI" |
| exact DMI file permission set has shifted/been contested across kernel versions (2023 LKML thread proposing loosening restrictions) | CONTESTED | medium | LKML thread (secondary) | do not hard-code an exact permission expectation as a pass/fail gate; treat EACCES on any one field as that field's own unknown, independent of the others |
| `systemd-detect-virt` exits 0 when virtualization IS detected and non-zero otherwise (not literally "exit 1 = none" as a fixed code) | VERIFIED | high | freedesktop systemd-detect-virt(1) (fetched) | do not hardcode "exit code 1" as the none-detected sentinel; treat "non-zero" generically, and prefer stdout identifier string over exit code alone |
| WSL is explicitly categorized by systemd-detect-virt as a "container" class for practical purposes despite being a full VM under the hood | VERIFIED | high | freedesktop systemd-detect-virt(1) (fetched) | sensor's own VM-vs-container classification should not naively trust systemd-detect-virt's category label as ground truth for architectural assumptions (e.g., "container ⇒ no real block devices" would be wrong for WSL) |
| in ordinary (non-hardened) containers, `/sys/block` and `/sys/class/dmi/id` reflect the **host's** real devices/firmware data, not a container-scoped view | VERIFIED | high | sysfs(5) (fetched, general namespace-propagation statement) + podman #8707 + RHBZ 1772993 (corroborating reports) | any storage/hardware-posture check must gate on "is this process containerized" (Probe 3/6 signals) before trusting sysfs hardware data as describing "this machine" in the container case |
| `/sys/block/<dev>/size` is always in fixed 512-byte units regardless of `queue/logical_block_size` | LIKELY (mechanically consistent with LOCAL_REPRO, but repro's device had logical_block_size=512 so the discrepancy case itself wasn't exercised) | medium-high | kernel ABI docs (fetched, adjacent attributes) + long-standing kernel convention (not independently fetched from genhd.c source this session) | never multiply `size` by `logical_block_size`; always use the fixed 512 constant — flag for R-track code review to find a live 4Kn-drive citation if this becomes load-bearing |
| `/proc/self/mountinfo` carries mount ID/parent ID/propagation-fields/superblock-options that `/proc/mounts` does not | VERIFIED (direct observation) | high | LOCAL_REPRO + sysfs/proc conventions | sensor must read mountinfo, not /proc/mounts, for any check needing overlay-root detection or propagation state |
| `sd_booted()`'s entire test is "does `/run/systemd/system/` exist" — no file-count or content requirement | VERIFIED | high | freedesktop sd_booted(3) (fetched) | implement as a single stat/exists call; do not require the directory to be non-empty (confirmed empty-but-valid in LOCAL_REPRO) |
| Alpine's Dropbear has no `sshd_config`; its config is entirely via `/etc/conf.d/dropbear` `DROPBEAR_OPTS` flags under OpenRC | VERIFIED | high | Alpine wiki + dropbear-openrc package page (secondary, distro-authoritative) | sshd-posture check must special-case "no sshd_config found" by first probing for a dropbear installation before concluding "no SSH server" |
| RHEL 9's default `Include /etc/ssh/sshd_config.d/*.conf` is not guaranteed present on hosts upgraded from RHEL 8 rather than freshly installed | VERIFIED | medium-high | RHBZ 2052081 (secondary, vendor bug tracker) | never assume "major version RHEL9 ⇒ Include line present"; check for the actual line before globbing drop-ins |
| Debian/Ubuntu socket-activated sshd (ssh.socket) means "no resident sshd process" is not evidence of "ssh disabled" | LIKELY (Ubuntu 22.10+ confirmed; exact Debian stable release version not independently primary-sourced this session) | medium | dev.to/Medium explainer posts (tertiary) | sensor must check the socket unit / listening state, not just process presence, before reporting "ssh not running" |
| SMBIOS Type 38 (IPMI Device Information) entry at `/sys/firmware/dmi/entries/38-0` is the correct evidence to distinguish "BMC declared by firmware, driver not loaded" from "no BMC hardware" | LIKELY (path convention VERIFIED from kernel ABI doc's own type-17 worked example; type-38-specific permission behavior not independently observed live this session) | medium | kernel ABI docs (fetched) + project's own prior bare-metal IPMI evidence (not re-derived here) | recommend the implementation track independently confirm live permission on a type-38 entry if/when tested against the real Lava host, since this stream did not have SSH access to verify it directly |
| `/sys/kernel/security/lockdown` absence while `/sys/kernel/security` itself is mounted and listable proves the lockdown LSM is not compiled into this kernel, not merely "unknown" | VERIFIED (direct observation) | high | LOCAL_REPRO + general kernel lockdown doc summary (secondary) | treat "parent pseudo-fs present, specific file absent" as a proven-negative pattern usable across DMI/security-module/lockdown checks alike |
| `/sys/firmware/efi` absence cannot by itself distinguish legacy-BIOS bare metal from a VM whose hypervisor doesn't pass EFI through to the guest | VERIFIED (direct observation, WSL2/Hyper-V case) | high | LOCAL_REPRO | EFI-presence check's finding text must be phrased as "EFI not observed" and cross-referenced with virtualization detection before asserting "legacy BIOS" as a machine-class fact |
| Docker/runc default masked paths (`/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/acpi`, etc.) are container-runtime-imposed, not kernel-universal absences | VERIFIED (secondary, corroborated by moby issue + hacktricks masked-paths reference) | medium-high | moby #36597, hacktricks masked-paths page, runc security advisories (secondary) | a sensor seeing these paths ENOENT/EACCES inside a container should attribute it to "container runtime masking", not "kernel doesn't support this", when containerization is independently confirmed |
