# R4 — HOST_SPECIFIC_PLAN

For every probe: **(1)** strongest unprivileged evidence, **(2)** fallback, **(3)** what EACCES means *here*,
**(4)** what a missing utility means *here* (not the same thing), **(5)** exact UNKNOWN conditions,
**(6)** false-positive / false-negative traps, **(7)** cross-machine pointer (details in
GENERIC_FALLBACK_PLAN.md). Every "expected evidence" line cites a probe id from
`state/HOST_SNAPSHOT.evidence.json`. Host-specific literals below are **illustrative evidence, never
matching conditions** — every recommended trigger gates on a capability or evidence class.

---

## A. MACHINE DESCRIPTION

### A1 — Hardware vendor / model
1. `/sys/class/dmi/id/{sys_vendor,product_name,board_vendor,board_name,board_version,bios_vendor,bios_version,bios_date,chassis_type}` — all 0444 here (`identity.dmi_ls`); values `Supermicro` / `AS -3015MR-H10TNR` / `H13SRE-F` / AMI `2.4a` `08/29/2025` (`identity.dmi`).
2. Fallback: `/sys/firmware/dmi/entries/<n>-<m>/` directory listing for *existence* of a record type; `hostnamectl` (`identity.hostnamectl`) as a cross-check. `dmidecode` is **not** a fallback: it is absent here and would need root anyway.
3. **EACCES** on a DMI attribute means the kernel restricts that specific attribute (the serial/UUID quartet is 0400) — the value exists, we may not read it. It says nothing about the other attributes on the same directory.
4. **UTILITY_MISSING** (`dmidecode`, `lshw`) means we lost a *convenience decoder*, not a data source: sysfs already carries the unprivileged subset. Reporting "vendor unknown because dmidecode is missing" would be wrong here.
5. **UNKNOWN when**: `/sys/class/dmi/id` itself is absent (non-SMBIOS platform), or the specific attribute read fails with anything other than ENOENT-after-a-successful-listing.
6. Traps: DMI values are frequently **placeholders**, not blanks — `To be filled by O.E.M.`, `Chassis Asset Tag`, `Default string`, `0123456789`, `Family`, `Not Specified` (all five families present here). Treating a placeholder as a value is the main FP. Gate on a *placeholder-pattern* test, not on these literals. Second trap: values are firmware-settable, so they are identification, not attestation (R4-F39).
7. Cross-machine: absent on devicetree-only aarch64; inherited from the **host** inside a container (R4-F38).

### A2 — Stable host identifier
1. `/etc/machine-id`, 0444, 32 hex chars (`identity.machine_id_files`).
2. Fallback chain: DMI `product_uuid` (EACCES here) → machine-id → hashed stable hardware ids (NVMe `wwid`/`eui`, NIC permanent MAC) → explicit unknown. Record `host_id_source`.
3. **EACCES** on `product_uuid` (0400, `identity.dmi_ls`) means the preferred source exists and is denied — the finding must say "fell back to machine-id because product_uuid is root-only", not "product_uuid absent".
4. UTILITY_MISSING is not applicable — this is a pure file read.
5. **UNKNOWN when**: machine-id is absent, empty, or the documented uninitialised placeholder, *and* no readable hardware identifier exists.
6. Traps: (a) machine-id(5) states the value is confidential and should not be exposed — emit a keyed hash, not the raw value (R4-F32); (b) machine-id is regenerated on re-image, so it is stable across reboots but **not** across provider re-provisioning — the provenance field must say which guarantee is being made; (c) `/var/lib/dbus/machine-id` is a symlink here, so it is not an independent second source.
7. Cross-machine: identical mechanism everywhere systemd is present; on Alpine/OpenRC `/etc/machine-id` may be absent → fallback chain applies.

### A3 — Owner
1. Evidence classes only: DMI asset tags / SKU (`identity.dmi`), `/etc/machine-info` (**ENOENT**, `identity.machine_info`), `/etc/motd` (**ENOENT**) and `/etc/issue` (stock text, `identity.motd`), world-readable cloud-init `instance-data.json` (`identity.cloud_init_instance_data`).
2. Fallback: the datasource *class* (`/run/cloud-init/cloud-id` → `ec2`) and any populated metadata field (here only `facility`).
3. **EACCES**: `instance-data-sensitive.json`, `combined-cloud-config.json` and `/etc/cloud/ds-identify.cfg` are 0600 (`identity.cloud_init_dirs`) — the machine holds richer identity we are not permitted to read. That is itself reportable.
4. UTILITY_MISSING: not applicable.
5. **UNKNOWN when**: every source is a placeholder, an empty string, or EACCES — which is the actual state here (R4-F23). Owner must be an explicit unknown with an `owner_candidates` list.
6. Traps: (a) the readable `instance-data.json` self-redacts for non-root readers, so an empty-looking field may be redaction, not absence; (b) inferring a customer from a hostname pattern or an sshd drop-in filename is a guess — record it as a candidate, never as the owner; (c) never encode a provider name in the check logic.
7. Cross-machine: no cloud-init on plain Debian/Alpine; container inherits nothing useful.

### A4 — Block devices, models and sizes
1. Walk `/sys/block/*`, exclude `loop|ram|zram` (and dm/md aggregates when real disks exist); size = `size` × **512** (R4-F37); model from `device/model` or `/sys/class/nvme/*/model` (`storage.sysblock_loop`, `storage.nvme_class`).
2. Fallback: `lsblk -J -O` (`storage.lsblk_json`) and `nvme list` (`storage.nvme_cli`) — both worked unprivileged here.
3. **EACCES**: not encountered for sysfs enumeration. It *is* encountered on the device nodes (`/dev/nvme*`), which only blocks content-level questions, never enumeration.
4. **UTILITY_MISSING** (`lsblk`, `nvme`) costs nothing: sysfs already answers the question. A check that reports "storage unknown, lsblk missing" is under-claiming.
5. **UNKNOWN when**: `/sys/block` is unreadable, or a device exists but every model source is absent — then list the device with `model: unknown`, never drop the device.
6. Traps: T-S5 (loop devices), T-S6 (fixed 512-byte units), T-S1 (`/sys/module` ≠ loaded ≠ present), T-S7 (RAID-sounding controller name in AHCI mode), T-S9 (nvme-subsystem is not multipath). See STORAGE_ASSESSMENT.md §3.
7. Cross-machine: containers see the **host's** `/sys/block` (R4-F38) — the single largest FP in this plan.

---

## B. REMOTE_ACCESS

### B1 — What is actually listening
1. `ss -tulnp` (`network.ss_listen`): tcp/22 on v4 and v6, plus systemd-resolved on loopback :53.
2. Fallback: `/proc/net/tcp{,6}` and `/proc/net/udp{,6}` parsed directly (no tool dependency).
3. **EACCES**: not on the socket list itself; the **Process column is empty** because we cannot attribute other users' sockets (R4-F21). Partial denial, not total.
4. **UTILITY_MISSING** (`ss`, `netstat`): fall back to `/proc/net/*`; the answer is still obtainable.
5. **UNKNOWN when**: `/proc/net/*` unreadable (hardened/containerised) and no tool available.
6. Traps: (a) attributing a listener to a service without evidence — pair with the systemd unit, do not guess; (b) an inactive-but-installed daemon is not a listener, and a socket-activated one *is* a listener with no running daemon; (c) `[::]:22` with `BindIPv6Only=ipv6-only` (`network.ssh_socket_cat`) means two distinct listeners, not a dual-stack one.
7. Cross-machine: `/proc/net` may be masked in containers.

### B2 — Effective sshd policy
1. Parse `/etc/ssh/sshd_config` honouring `Include` **at its position** (first non-comment line here), first-value-wins, and `Match` scoping; drop-in `00-latitude-instant-deploy.conf` therefore wins for the keywords it sets (`network.sshd_effective_lines`, `network.sshd_config_d`, R4-S04).
2. Fallback: runtime cross-checks — socket unit `ListenStream`, observed listeners, PAM config (`network.pam_config`), our own session's auth method.
3. **EACCES**: not encountered — `sshd_config` and the drop-in are 0644 here. On a host where they are not, the answer is unknown, never "defaults apply".
4. **UTILITY_MISSING**: irrelevant; do not shell out to `sshd`. `sshd -T` fails unprivileged by design because host keys are loaded before the test-mode exit path (R4-F19, R4-S03).
5. **UNKNOWN when**: a referenced Include glob is unreadable, a `Match` block cannot be evaluated for the requester context, or the running daemon's `-f` path differs from the default and cannot be read.
6. Traps: (a) reporting the *last* occurrence of a keyword — OpenSSH takes the *first*; (b) assuming a compiled-in default without saying so — the evidence must list which defaults were applied; (c) **`ss`/`systemctl` show the truth about the listener, `sshd_config` does not** on socket-activated Ubuntu (R4-F20, R4-F31); (d) `PermitRootLogin prohibit-password` plus an unreadable `/root/.ssh` (EACCES, `network.other_home_ssh_ls`) means root key login is **unknown**, not disabled.
7. Cross-machine: no `Include` on older RHEL/in-place upgrades; Dropbear has no config file at all (R4-F41).

### B3 — Who may log in, and how
1. `getent passwd` for shells (`users.login_shells`: only root and ubuntu), `passwd -S` for our own account (`L` = locked ⇒ key-only), `getent group` for privileged groups (`users.priv_groups`), our own `~/.ssh/authorized_keys` metadata (`network.other_home_ssh_ls`).
2. Fallback: `/etc/passwd`, `/etc/group` direct reads; `/etc/nsswitch.conf` to prove there is no directory backend (`users.nsswitch`).
3. **EACCES**: `/root/.ssh` and other users' home directories → those accounts' key material is UNKNOWN. `/etc/shadow` is 0640 root:shadow → password hashes unknown (and must never be read even if readable).
4. **UTILITY_MISSING** (`getent`): read the files. The `nsswitch` check tells you whether the files are the whole story — here they are.
5. **UNKNOWN when**: nsswitch names a non-`files` backend we cannot query, or a home directory is unreadable.
6. Traps: (a) counting `nologin` accounts as login-capable; (b) treating an empty privileged group as absent — `disk`, `adm`, `systemd-journal` exist here with zero members, which is a *stronger* statement than absence (R4-F13); (c) `passwd -S` reports only our own account unprivileged — do not generalise it to other users.
7. Cross-machine: `wheel` instead of `sudo` on RHEL; BusyBox `getent` differences on Alpine.

### B4 — Firewall actually in force
1. `systemctl is-active` for the candidate services (`network.firewall_active`: ufw `active`, three others `inactive`).
2. Fallback: readable config under `/etc/ufw/` (the directory listed successfully) — enough to say "a policy file exists", not what is loaded.
3. **EACCES**: `iptables -S` → `Could not fetch rule set generation id: Permission denied (you must be root)`; `ufw status` → `ERROR: You need to be root to run this script`. The rules **exist and are unreadable** — the finding is unknown with that exact errno text as evidence.
4. **UTILITY_MISSING** (`nft`): means we cannot query the nftables backend; it does **not** mean no nftables rules exist. `iptables` here is the nf_tables variant, so a missing `nft` binary is only a tooling gap.
5. **UNKNOWN when**: the ruleset cannot be read by any available path — which is the state here. Never report "no firewall rules".
6. Traps: (a) `is-active` = the unit is running, not that any rule is loaded; (b) an active ufw with a default-allow policy is not protection — and we cannot see the policy; (c) the observed listener set is *not* a substitute for the ruleset, since a filtered port still appears in `ss`.
7. Cross-machine: firewalld on RHEL, no firewall service on Alpine by default.

---

## C. SECRETS_ON_DISK

### C1 — Credential material present and its protection
1. Bounded walk of a fixed root set, metadata only: mode/owner/group/size/mtime. Here: `/etc/shadow` 640 root:shadow, our `authorized_keys` 600, two world-readable public CA bundles (`secrets.sensitive_file_find`).
2. Fallback: none needed; this is `stat`, not `open`. **The sensor must never read content.**
3. **EACCES** on a directory (`/etc/ssl/private` 0710, `secrets.tls_private_ls`; `/root`, `users.root_home_ls`) is a first-class result: "credential store present, contents unknown". It is never "no secrets here".
4. **UTILITY_MISSING** (`getfacl`) blocks only the ACL question. Read the `system.posix_acl_access` xattr directly instead (R4-F28) — `/var/log/journal` shows `drwxr-sr-x+`, proving an ACL exists that `ls` alone cannot decode.
5. **UNKNOWN when**: a root in the scan set is unreadable, the walk hits its entry/time budget, or a filesystem boundary is crossed.
6. Traps: **T-U2 — bounded negatives.** `find / -xdev … 2>/dev/null` skips other filesystems (including the mounted ESP) and every unreadable directory (R4-F27). Report "none found within scope" and print the scope. Second trap: a 0-byte `user-data.txt` (`secrets.cloud_userdata_ls`) is not proof that no user-data was supplied — the sibling `.i` file is 308 bytes and 0600.
7. Cross-machine: paths differ (`/etc/pki` on RHEL); the boundedness discipline is identical.

### C2 — Boot artefacts as a secrets surface
1. `stat` on `/boot/*`: both initramfs images world-readable 0644 at 67 MB / 71 MB, `grub.cfg` 0600, `vmlinuz`/`System.map` 0600 (`secrets.boot_artifacts_ls`, `kernel.boot_ls`); `/boot/efi` mounted `dmask=0022` ⇒ world-readable ESP (`storage.findmnt`).
2. Fallback: `findmnt` options if `/boot/efi` cannot be stat-ed.
3. **EACCES** on `/boot` would make the whole check unknown; not the case here.
4. UTILITY_MISSING: not applicable.
5. **UNKNOWN when**: `/boot` is a separate unreadable mount, or the running kernel's initramfs cannot be identified.
6. Traps: (a) do not open the initramfs to look for embedded secrets — that is expensive, unbounded and outside read-only intent; report mode and size; (b) world-readable initramfs is common on Debian/Ubuntu, so severity should be `info`/`low` with the reason explaining *why it matters here* (provisioning material is often injected on bare-metal provider images).
7. Cross-machine: RHEL ships initramfs 0600 by default — the same check yields a different, correct answer.

---

## D. BMC_INBAND_ACCESS

### D1 — Does firmware declare a BMC interface?
1. Existence of `/sys/firmware/dmi/entries/38-0` (IPMI device) and `42-0` (management-controller host interface), both world-traversable directories (`bmc.dmi_smbios_entries`); plus ACPI `IPI0001:00` and the `dmi-ipmi-si.0` platform device (`bmc.ipmi_acpi_devices`).
2. Fallback: the ACPI/platform device path alone.
3. **EACCES**: the `raw` attribute (and, per kernel v6.8 source, every attribute in the entry directory) is 0400 (R4-F49) ⇒ the interface **type, base address and IRQ are unknown**. Existence is still proven.
4. **UTILITY_MISSING** (`dmidecode`): irrelevant — it could not read the table unprivileged either.
5. **UNKNOWN when**: `/sys/firmware/dmi/entries` itself is absent (no SMBIOS) — then this sub-check is unknown while D2 may still answer.
6. Traps: (a) do not claim to have decoded type-38 fields we could not read; (b) an entry directory existing is a *firmware declaration*, which can outlive a BMC that has been disabled — pair it with D2.
7. Cross-machine: absent on VMs and on non-SMBIOS platforms; **present inside a container on this hardware** (R4-F38).

### D2 — Is the BMC actually answering in band?
1. Read `/sys/devices/platform/ipmi_bmc.0/{ipmi_version,firmware_revision,manufacturer_id,product_id,device_id,guid}` — world-readable, and each read re-triggers a live Get Device ID over KCS once the driver's short cache expires (R4-F46, R4-S24). Values here: IPMI 2.0, fw 1.5, mfr `0x002a7c` = Super Micro per the IANA PEN registry (R4-F47).
2. Fallback: `/sys/class/ipmi/ipmi0` existence + `lsmod` refcounts (`bmc.ipmi_class_ls`, `bmc.ipmi_modules`).
3. **EACCES**: not encountered on these attributes. If it were, the answer is unknown — not "no BMC".
4. **UTILITY_MISSING** (`ipmitool`, FreeIPMI, ipmiutil, all absent): means we cannot *issue our own* IPMI command. It does **not** mean the BMC is unreachable — the sysfs path already established a response. Conflating these two would be the single worst error in this category.
5. **UNKNOWN when**: `ipmi_bmc.*` is absent while `/sys/firmware/dmi/entries/38-0` exists (interface declared, driver not bound) — that is exactly the "present but not usable" state.
6. Traps: (a) a loaded `ipmi_si` module is not proof of a responding BMC; the populated identity attributes are; (b) `provides_device_sdrs=0` and `additional_device_support=0xbf` are capability bitmaps, not health; (c) never run an IPMI command that writes — including DSP0270 credential bootstrapping, which creates a BMC account despite reading like a query (R4-F50).
7. Cross-machine: on a VM none of this exists; distinguishing "no BMC" from "driver not loaded" needs D1.

### D3 — Who may use the in-band path?
1. `stat` `/dev/ipmi0` → `crw------- root:root` (0600) (`bmc.ipmi_dev_ls`, `bmc.ipmi_dev_perms`), plus group membership (`users.priv_groups`) and the `system.posix_acl_access` xattr.
2. Fallback: udev rules and modprobe.d greps (both empty here) to show nothing relaxes the default (`bmc.udev_rules_ipmi`, `bmc.modprobe_ipmi`).
3. **EACCES** would be on the ACL read; the mode read itself succeeds.
4. **UTILITY_MISSING** (`getfacl`) must not turn this into unknown — read the xattr directly (R4-F28).
5. **UNKNOWN when**: the ACL cannot be read by any means, or `/dev/ipmi0` exists but `stat` fails.
6. Traps: (a) 0600 root:root is the plain kernel default with no capability gate (R4-F48) — so the finding is precise and actionable, not "hardened by policy"; (b) our account is in group `sudo`, but the sudo policy is unreadable (R4-F22) and **the sensor must not run `sudo` to find out**; report group membership as an escalation *path* whose policy is unknown; (c) `/dev/ipmidev/` being ENOENT is not evidence about `/dev/ipmi0`.
7. Cross-machine: on RHEL the OpenIPMI package may ship different device handling; on Alpine the driver may not be built.

### D4 — Latent host-interface exposure
1. USB gadget identity: `manufacturer=Linux 5.4.62 with aspeed_vhub`, `product=RNDIS/Ethernet Gadget`, `0b1f:03ee`, driver `rndis_host`, `operstate=down` (`bmc.usb_nic_identity`, `bmc.usb_cdc_net`, `network.nic_info`).
2. Fallback: SMBIOS type-42 entry existence (D1).
3. **EACCES**: none.
4. UTILITY_MISSING: none.
5. **UNKNOWN when**: the interface exists but neither `operstate` nor `carrier` can be read; note that reading `speed` on a down link returns EINVAL (`Invalid argument`), which is normal behaviour and must not be recorded as a failure.
6. Traps: (a) `down` is the *current* state — the interface can be brought up by anyone with the capability, so this is an INFO finding about latent exposure, not a pass; (b) a USB NIC is not automatically a BMC NIC — the gadget's manufacturer/product strings plus a type-42 entry are what make the inference; gate on "USB network gadget whose parent is a management controller declared by firmware", never on a vendor id literal.
7. Cross-machine: absent on VMs; present on many modern BMC-equipped servers.

---

## E. CANDIDATE CUSTOM CATEGORY — DATA-AT-REST / STORAGE POSTURE

Checks, probes and traps are specified in **STORAGE_ASSESSMENT.md** (§2 unprivileged-confidence table,
§3 traps T-S1…T-S11, §4 the category argument). Summary of the four recommended checks and their
seven-point treatment:

| Check | Strongest evidence (probe) | Fallback | EACCES here | UTILITY_MISSING here | UNKNOWN when | Key trap |
|---|---|---|---|---|---|---|
| Encryption at rest (dm-crypt/LUKS class) | `/dev/mapper` contents + `/sys/block/dm-*/dm/uuid` prefix + FSTYPE (`storage.dev_mapper_ls`, `storage.lsblk_fs`) | `/proc/crypto`, `/etc/crypttab` presence | n/a | `cryptsetup` absent is irrelevant — sysfs answers it | `/dev/mapper` unreadable | SED/Opal is a different question and is unknown (R4-F06) |
| Redundancy for the root filesystem | `/proc/mdstat` + `/dev/md*` + dm holders + PCI class (`storage.mdstat`, `storage.lspci_storage`) | `/sys/block/*/holders`, `slaves` | n/a | `mdadm` present but unnecessary | `/proc/mdstat` unreadable | T-S2 personalities line; T-S7 RAID-named AHCI controller |
| Attached-but-unused devices | partitions + by-id links + holders + FSTYPE (`storage.partitions`, `storage.disk_by_id`) | `/sys/block/<d>/{holders,slaves}` | n/a — enumeration needs no device access | none | `/sys/block` unreadable | T-S3 (udev DB, not the disk) and T-S10 ("no partitions" ≠ "empty") |
| Device health | `/sys/fs/ext4/<dev>/errors_count` (`storage.ext4_sysfs`) as the surviving signal | none for SMART | `nvme smart-log` → `Permission denied`, device root-only, group `disk` empty (R4-F04) | `smartctl` absent — a *separate* fact that would not have helped, since it needs the same device | always unknown for SMART on this host | T-S4: three different causes, one symptom |

---

## F. CANDIDATE CUSTOM CATEGORY — BOOT CHAIN / KERNEL FLAGS (the denser alternative)

1. Secure Boot + Setup Mode from efivarfs bytes (skip the 4-byte attribute prefix, read byte 5) with `mokutil --sb-state` as a fallback — both worked unprivileged (`kernel.secureboot`, `kernel.mokutil_sbstate`, R4-F16). Lockdown from `/sys/kernel/security/lockdown` (`[none]`). Taint from `/proc/sys/kernel/tainted` with per-module attribution via `/sys/module/*/taint` (`OE` on one module) (R4-F17). TPM presence from `/sys/class/tpm/tpm0/tpm_version_major` (`kernel.tpm`). Build-time options from world-readable `/boot/config-$(uname -r)` (R4-F25).
2. Fallbacks: `mokutil` for Secure Boot; `/proc/cmdline` for `lockdown=`/`module.sig_enforce` hints; `/boot/config-*` for compiled-in policy.
3. **EACCES**: `/dev/tpm0` is root-only ⇒ TPM *usage* (PCR values, event log) is unknown while *presence* is proven. `/sys/kernel/security/tpm0/binary_bios_measurements` is expected to be root-only — treat a denial as unknown, not as "no measured boot".
4. **UTILITY_MISSING** (`aa-status`, `getenforce`): read `/sys/module/apparmor/parameters/enabled` and `/sys/kernel/security/apparmor/profiles` (0444, R4-F44) and `/sys/fs/selinux/enforce` directly. Never report an LSM as absent because its CLI is missing (R4-F42).
5. **UNKNOWN when**: efivarfs is absent (legacy BIOS or non-EFI) — that is "Secure Boot not applicable", distinct from "disabled"; or when `/sys/kernel/security` is not mounted.
6. Traps: (a) `SecureBoot=0` and "no efivars at all" are different findings; (b) Setup Mode is the more severe fact and needs its own check — Secure Boot cannot be enforcing while the platform is in Setup Mode, so the three observations here are one consistent state, not three independent failures; (c) taint letter `E` records an unsigned module even on a kernel that does not enforce signatures — do not infer enforcement from taint; (d) DKMS modules are a common benign source of `O`.
7. Cross-machine: no efivars on VMs booted in BIOS mode; `/sys/kernel/security` often unavailable in containers.

---

## G. CANDIDATE CUSTOM CATEGORY — UPDATE / DRIFT

1. Running kernel vs. boot default: `uname -r` (`kernel.osrelease_modules`) vs `/boot/vmlinuz` symlink target vs `/lib/modules/*` (`kernel.boot_ls`) — proves drift here without the marker file (R4-F14).
2. Fallback: `dpkg -l 'linux-image-*'`; `/proc/cmdline` `BOOT_IMAGE=`.
3. **EACCES**: `/boot` is readable here; if it were not, drift becomes unknown.
4. **UTILITY_MISSING** (`dpkg`/`rpm`): fall back to the filesystem evidence, which is what actually determines the next boot.
5. **UNKNOWN when**: `/boot` holds no `vmlinuz*` (some images boot from an ESP-resident kernel), or `/lib/modules` is unreadable.
6. Traps: **T-U1 — the empty apt index.** `/var/lib/apt/lists` is empty and there is no `update-success-stamp`, so `apt list --upgradable` prints nothing (R4-F15). Reporting "fully patched" here would be a false pass and is the highest-value trap in this category. Second trap: `/var/run/reboot-required` absence is not evidence — the package that creates it may not be installed (R4-F34).
7. Cross-machine: `dnf needs-restarting` / `needs-restarting -r` on RHEL; `apk` on Alpine; none of these should be *required*.
