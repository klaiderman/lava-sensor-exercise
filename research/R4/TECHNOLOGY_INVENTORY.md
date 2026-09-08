# R4 — TECHNOLOGY_INVENTORY

Every row cites a probe id from `state/HOST_SNAPSHOT.evidence.json`. The **Probe status** column is the
status recorded verbatim in that file. The **Per-fact outcome** is my classification of the individual
fact, because the TCI probe status is a coarse per-probe aggregate and in several cases disagrees with
the line-level evidence (see §0).

## 0. Reading rule: probe status is an aggregate; per-fact outcome is what matters

The TCI probes are multi-command shell lines and the recorded `status` is one label for the whole line.
Downstream readers **must not** propagate probe status as fact status. Demonstrated cases:

| Probe id | Probe status | What stdout actually shows | Correct per-fact outcome |
|---|---|---|---|
| `storage.dev_ls` | `ENOENT` | `ls: cannot access '/dev/sd*' … '/dev/md*' … '/dev/dm-*' … '/dev/vd*' … '/dev/xvd*': No such file or directory` **and** a successful listing of 7 `/dev/nvme*` nodes | ENOENT (proven absent) for sd/md/dm/vd/xvd; **OK (present)** for nvme |
| `storage.mdadm_conf` | `ENOENT` | prints `HOMEHOST <ignore>` (content of `/etc/mdadm/mdadm.conf`), then `cat: /etc/mdadm.conf: No such file or directory` | `/etc/mdadm/mdadm.conf` **EXISTS**; only `/etc/mdadm.conf` is ENOENT — see CONTESTED fact R4-F02 |
| `bmc.ipmi_dev_perms` | `UTILITY_MISSING` | `stat` succeeded (`crw------- 600 root:root /dev/ipmi0`); only `getfacl` was missing | OK for the mode; UTILITY_MISSING for the ACL question only |
| `network.firewall_active` | `ENOENT` | `systemctl is-active ufw` → `active`; the ENOENT comes from other paths on the same line | OK: ufw active; ENOENT for firewalld/nftables/fail2ban config paths |
| `storage.smartctl_scan` | `UTILITY_MISSING` (rc=0) | `smartctl: command not found` | UTILITY_MISSING — and rc=0 is a pipeline artifact, not the tool's exit code |
| `network.sshd_test_config` | `OK` (rc=0) | `sshd: no hostkeys available -- exiting.` then `rc=0` | The probe was `cmd \| head; echo rc=$?`, so **rc is `head`'s exit code**. The exit code here is not evidence |
| `services.watchdog` | `ENOENT` | `ls /sys/class/watchdog` emitted no error (directory exists, empty); only the `identity` cat failed | Directory exists and is empty ⇒ no watchdog device registered (proven by a successful listing) |

**Design consequence:** the sensor must capture per-command outcome (exit status + errno + stderr text),
never a per-check aggregate label, and must never run a probe through a pipe whose exit code it then reads.

## 1. Platform / identity

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| Bare metal (not virtualised) | DETECTED | OK | `identity.virt` | `systemd-detect-virt` → `none`, `rc=1`. Corroborated by DMI + `/dev/ipmi0` + TPM |
| DMI/SMBIOS readable subset | DETECTED | OK | `identity.dmi`, `identity.dmi_ls` | `sys_vendor`, `product_name`, `board_vendor`, `board_name`, `board_version`, `bios_*`, `chassis_type/vendor/asset_tag`, `product_sku/family/version` are all `-r--r--r--` (0444) |
| DMI serial/UUID quartet | EACCES | OK (probe) | `identity.dmi`, `identity.dmi_ls` | `product_serial`, `product_uuid`, `board_serial`, `chassis_serial` are `-r--------` (0400 root) → EACCES; **presence proven** by the directory listing |
| DMI placeholder values | DETECTED | OK | `identity.dmi` | `product_sku=To be filled by O.E.M.`, `board_asset_tag=To be filled by O.E.M.`, `chassis_asset_tag=Chassis Asset Tag`, `product_version=0123456789`, `product_family=Family` |
| `/sys/firmware/dmi/tables/DMI` (raw SMBIOS) | EACCES | OK | `bmc.dmi_smbios_entries` | `-r-------- 1 root root 3962 … DMI`; existence proven, content denied |
| dmidecode | UTILITY_MISSING | EXECUTION_ERROR | `services.utility_inventory` | absent from the `which` output. Irrelevant anyway: it needs root to read the DMI table |
| cloud-init, EC2-shaped datasource | DETECTED | OK | `identity.cloud_init_dirs`, `identity.cloud_init_instance_data` | `/run/cloud-init/cloud-id -> cloud-id-ec2` (4 bytes); `instance-data.json` 0644 readable; `instance-data-sensitive.json` 0600; `combined-cloud-config.json` 0600; `/etc/cloud/ds-identify.cfg` 0600 |
| Provider metadata content | MOSTLY EMPTY | OK | `identity.cloud_init_instance_data` | only `facility` is populated; `hostname`, `plan`, `public-ipv4`, `tags`, `operating-system.*` are empty strings; `merged_cfg`/`merged_system_cfg` = `"redacted for non-root user"` |
| `/etc/machine-id` | DETECTED | OK | `identity.machine_id_files` | `-r--r--r-- 1 root root 33` (0444), 32 hex chars; `/var/lib/dbus/machine-id` is a symlink to it |
| `/etc/machine-info` | ENOENT (proven absent) | ENOENT | `identity.machine_info` | `cat: /etc/machine-info: No such file or directory` |
| `/etc/motd` | ENOENT (proven absent) | OK | `identity.motd` | `/etc/issue` and `/run/motd.dynamic` are stock Ubuntu text — no owner/tenant string anywhere |
| systemd as PID 1 | DETECTED | OK | `services.pid1_cgroup` | `/proc/1/cgroup` → `0::/init.scope` (cgroup v2 unified); `/proc/1/comm` → `systemd` |

## 2. CPU / memory

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| AMD EPYC 4484PX, 1 socket / 12 cores / 24 threads | DETECTED | OK | `cpu.lscpu`, `cpu.cpuinfo_summary`, `cpu.nproc_smt` | `nproc`=24, `/sys/devices/system/cpu/smt/active`=1 |
| MemTotal 97938032 kB; SwapTotal 0 | DETECTED | OK | `cpu.meminfo`, `storage.swap` | `/proc/swaps` printed the header and no entries ⇒ **swap proven absent by a successful read** |
| CPU vulnerability sysfs | DETECTED | OK | `cpu.vulnerabilities` | all entries `Not affected` or mitigated; world-readable |
| 25 IOMMU groups; THP `madvise` | DETECTED | OK | `kernel.iommu_thp` | |

## 3. Storage (full analysis in STORAGE_ASSESSMENT.md)

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| 2× NVMe controllers (PCIe) | DETECTED | OK | `storage.nvme_class`, `storage.block_device_links`, `storage.lspci_storage` | `/sys/class/nvme/{nvme0,nvme1}`, `state=live`, `transport=pcie`; PCI `[1344:51c3]` "Micron 7450 PRO NVMe SSD" at `02:00.0` and `03:00.0`, `Kernel driver in use: nvme` |
| Namespaces nvme0n1 / nvme1n1 | DETECTED | OK | `storage.sysblock_loop`, `storage.partitions` | `size=1875385008` sectors each (× 512 = 960,197,124,096 B) |
| nvme-subsystem class present | DETECTED | OK | `storage.nvme_sysfs_detail` | `nvme-subsys0/1`, `iopolicy=numa` — the NVMe *multipath* class exists with one path each |
| Partition table on nvme0n1 | DETECTED | OK | `storage.lsblk_fs`, `storage.disk_by_id` | p1 vfat FAT32 `EFI` (UUID 6A9F-0FAA), p2 ext4 `ROOT`; by-id has `-part1/-part2` only for nvme0n1 |
| nvme1n1 unpartitioned, no filesystem | PROVEN ABSENT (bounded) | OK | `storage.lsblk_fs`, `storage.partitions`, `storage.disk_by_id`, `storage.blk_queue_detail` | `FSTYPE=""`; no `nvme1n1p*` in `/proc/partitions`; no `-part*` by-id link; `parts=0`, `holders=` empty. **Caveat:** lsblk FSTYPE comes from the udev DB, not a device read — trap T-S3 |
| ext4 on `/` | DETECTED | OK | `storage.findmnt`, `storage.ext4_sysfs` | `/ /dev/nvme0n1p2 ext4 rw,relatime,errors=remount-ro`; `/sys/fs/ext4/nvme0n1p2/errors_count=0`, `first_error_time=0`, `lifetime_write_kbytes=2799165` |
| vfat ESP at `/boot/efi` | DETECTED | OK | `storage.findmnt`, `storage.fstab` | `fmask=0022,dmask=0022` ⇒ **world-readable ESP** |
| device-mapper / LVM / LUKS | PROVEN ABSENT | OK | `storage.dev_mapper_ls`, `storage.dev_ls`, `storage.lvm_conf_ls` | `/dev/mapper/` contains only `control`; `/dev/dm-*` ENOENT; `/etc/lvm/{lvm.conf,backup,archive}` ENOENT |
| md RAID arrays | PROVEN ABSENT | OK | `storage.mdstat`, `storage.dev_ls` | `/proc/mdstat`: personalities listed, `unused devices: <none>`; `/dev/md*` ENOENT |
| `/etc/mdadm/mdadm.conf` | **PRESENT** (contradicts snapshot prose) | ENOENT (probe) | `storage.mdadm_conf` | stdout is `HOMEHOST <ignore>` — the file exists and was read. Only `/etc/mdadm.conf` is ENOENT. See R4-F02 |
| multipath | UTILITY_MISSING + ENOENT (config) | UTILITY_MISSING | `storage.multipath`, `storage.dev_mapper_ls` | `multipath: command not found`; `/etc/multipath.conf`, `/etc/multipath/` ENOENT. Subsystem state is **UNKNOWN by tool**, but `/dev/mapper` holding only `control` proves **no active maps** |
| iSCSI | UTILITY_MISSING + ENOENT (class) | UTILITY_MISSING | `storage.iscsi`, `storage.scsi_hosts` | `iscsiadm: command not found`; `/sys/class/iscsi_session`, `/sys/class/iscsi_host` ENOENT ⇒ transport module never loaded |
| FC / SAS transports | PROVEN ABSENT | OK | `storage.scsi_hosts` | `/sys/class/fc_host`, `/sys/class/sas_host` ENOENT |
| SATA/AHCI controller, no disks | DETECTED (controller) / PROVEN ABSENT (disks) | OK | `storage.lspci_storage`, `storage.scsi_hosts`, `storage.proc_scsi` | ASMedia `[1b21:0622]`, DeviceName `Asmedia SATA6G ASM1061R`, PCI class **0106 SATA** (not 0104 RAID), driver `ahci`; 12 `scsi_host` entries `proc_name=ahci state=running`; `/proc/scsi/scsi` → `Attached devices:` with none |
| ZFS / btrfs / bcache / LIO target | UTILITY_MISSING / ENOENT | UTILITY_MISSING, ENOENT | `storage.zpool`, `storage.configfs_bcache_btrfs` | `zpool: command not found`; `/sys/fs/btrfs`, `/sys/fs/bcache`, `/sys/kernel/config/target` ENOENT — and configfs **is** mounted (`storage.findmnt`), so the target ENOENT is a real proof |
| Network filesystems mounted | PROVEN ABSENT | ENOENT (probe) | `storage.net_fs_mounts`, `storage.findmnt` | grep over `/proc/mounts` matched only `fusectl`; `/proc/fs/nfsfs/*` ENOENT; the full `findmnt` listing contains only local/virtual filesystems |
| 8 loop devices, size 0 | DETECTED | OK | `storage.sysblock_loop` | `size=0` for loop0–7 ⇒ allocated, unbound |
| NVMe admin passthrough (SMART) | EACCES | OK (probe) | `storage.nvme_smart_try`, `storage.dev_ls`, `users.priv_groups` | `/dev/nvme0n1: Permission denied`, `/dev/nvme0: Permission denied`; `/dev/nvme0` is `crw------- root:root`, `/dev/nvme0n1` is `brw-rw---- root:disk`; **group `disk` has no members** (`disk:x:6:`) |
| smartctl | UTILITY_MISSING | UTILITY_MISSING | `storage.smartctl_scan` | `smartctl: command not found` |
| nvme-cli 2.8 / libnvme 1.8 | DETECTED | OK | `storage.nvme_cli` | `nvme list` succeeded **unprivileged** and printed model, FW, namespace usage |
| fstrim.timer, e2scrub_all.timer | DETECTED | OK | `services.timers` | |

## 4. BMC / in-band management

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| KCS interface declared by firmware | DETECTED | OK | `bmc.ipmi_acpi_devices`, `bmc.platform_ipmi_devices` | ACPI `IPI0001:00`, path `\_SB_.PCI0.SBRG.SIKC`; platform devices `dmi-ipmi-si.0` and `ipmi_bmc.0` |
| ipmi_si / devintf / msghandler / ssif / acpi_ipmi | LOADED | OK | `bmc.ipmi_modules` | `ipmi_si … 1` (in use); `ipmi_devintf … 0` ⇒ **nothing currently has the char device open**; `ipmi_msghandler … 4` |
| BMC identity via sysfs | DETECTED, READABLE | OK | `bmc.bmc_sysfs_attrs` | `ipmi_version=2.0`, `firmware_revision=1.5`, `manufacturer_id=0x002a7c`, `product_id=0x1d6e`, `device_id=32`, `revision=1`, `additional_device_support=0xbf`, `provides_device_sdrs=0`, `aux_firmware_revision=0x00 0x00 0x03 0x03`, `guid` readable; `/sys/class/ipmi/ipmi0/dev=238:0` |
| `/dev/ipmi0` | PRESENT, not openable by us | OK | `bmc.ipmi_dev_ls`, `bmc.ipmi_dev_perms` | `crw------- 1 root root 238, 0`; `stat` → `600 root:root`. Denial is **mode-based**, not policy-based |
| POSIX ACL on `/dev/ipmi0` | UNKNOWN | UTILITY_MISSING | `bmc.ipmi_dev_perms` | `getfacl: command not found`. `ls -l` showed no trailing `+`, which is weak counter-evidence only → R4-OR1 |
| `/dev/ipmidev/` | ENOENT (proven absent) | OK | `bmc.ipmi_dev_ls` | `ls: cannot access '/dev/ipmidev/': No such file or directory` |
| ipmitool / freeipmi / ipmiutil | UTILITY_MISSING | UTILITY_MISSING | `bmc.ipmitool_which`, `bmc.ipmitool_mc_info` | `ipmitool: command not found` (`rc=127` printed inside the line) |
| IPMI-related services | PROVEN INACTIVE | EXECUTION_ERROR | `bmc.ipmi_services` | three `inactive` results; no ipmi unit files listed |
| udev rules / modprobe.d for ipmi | PROVEN ABSENT | OK | `bmc.udev_rules_ipmi`, `bmc.modprobe_ipmi` | both greps ran (rc=0) and matched nothing |
| SMBIOS type 38 + type 42 | DIRECTORY PRESENT / CONTENT EACCES | OK | `bmc.dmi_smbios_entries`, `bmc.dmi_entry_38_raw` | `drwxr-xr-x … 38-0` and `42-0` are world-traversable; `raw` inside is root-only (the od dump is the hex of `cat: …/raw: Permiss…`) |
| BMC USB network gadget | DETECTED, link DOWN | OK | `bmc.usb_nic_identity`, `bmc.usb_cdc_net`, `network.nic_info` | interface name `enx<mac-derived suffix, redacted here>`, `manufacturer=Linux 5.4.62 with aspeed_vhub`, `product=RNDIS/Ethernet Gadget`, `idVendor=0b1f idProduct=03ee`, `driver=rndis_host`, `state=down`; reading `speed` gave `Invalid argument` (EINVAL — the documented result for a down link) |
| `/dev/i2c-0..2` | PRESENT, mode not probed | OK | `bmc.i2c_devices` | `ls` listed all three; `-l` was not used ⇒ permissions UNKNOWN → R4-OR2 |
| `/dev/mem`, `/dev/port` | PRESENT, EACCES | OK | `bmc.mem_port_kmsg_ls` | `crw-r----- 1 root kmem` for both |
| `/dev/kmsg` | PRESENT, mode-readable, **policy-denied** | OK | `bmc.mem_port_kmsg_ls`, `kernel.dmesg_head` | `crw-r--r-- 1 root root 1, 11` (0644) but `dmesg: read kernel buffer failed: Operation not permitted` because `kernel.dmesg_restrict=1` |
| `ipmi_si` module parameters | PARTIAL EACCES | OK | `bmc.ipmi_si_params` | `bt_debug=0`, `kcs_debug=0`, `smic_debug=1` readable; `hotmod` → `Permission denied` because it is a **write-only (0200) parameter**, not a restricted secret |

## 5. Network / remote access

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| OpenSSH_9.6p1 Ubuntu-3ubuntu13.19 | DETECTED | OK | `network.sshd_version` | with `OpenSSL 3.0.13` |
| Dual activation: `ssh.socket` + `ssh.service` | DETECTED | OK | `network.ssh_socket_cat`, `network.sshd_service_status` | socket unit `ListenStream=0.0.0.0:22` and `[::]:22`, `Accept=no`, `FreeBind=yes`, `ConditionPathExists=!/etc/ssh/sshd_not_to_be_run`; both units `active`; runtime `Listen=` lines confirm |
| sshd_config + drop-in | DETECTED | OK | `network.sshd_config`, `network.sshd_config_d`, `network.sshd_effective_lines` | `Include /etc/ssh/sshd_config.d/*.conf` is the **first** non-comment line; drop-in `00-latitude-instant-deploy.conf` (58 B, 0644, mtime **Sep 8 17:37**, well after the Sep 7 19:2x boot) sets `PasswordAuthentication no`, `KbdInteractiveAuthentication no` |
| `sshd -T` unprivileged | FAILS | OK (probe) | `network.sshd_test_config` | `sshd: no hostkeys available -- exiting.` ⇒ effective config must be derived by parsing |
| Listening sockets | DETECTED | OK | `network.ss_listen` | tcp/22 v4+v6; systemd-resolved on loopback :53. **Process column empty** — `ss -p` cannot attribute other users' sockets without privilege |
| ufw active, rules unreadable | MIXED | ENOENT / UTILITY_MISSING | `network.firewall_active`, `network.firewall_rules` | `systemctl is-active ufw` → `active`; `nft: command not found`; `iptables … Could not fetch rule set generation id: Permission denied (you must be root)`; `ufw status` → `ERROR: You need to be root to run this script`. `/etc/ufw/` **is listable** (`user.rules`, `before.rules`, `ufw.conf`, …) but per-file modes were not captured → R4-OR3 |
| firewalld / nftables / fail2ban | PROVEN INACTIVE + ENOENT | ENOENT | `network.firewall_active` | four `inactive` results; `/etc/nftables.conf`, `/etc/firewalld`, `/etc/fail2ban` ENOENT |
| `/root/.ssh` | EACCES | EACCES | `network.other_home_ssh_ls` | `ls: cannot access '/root/.ssh': Permission denied` ⇒ root's authorized_keys are **UNKNOWN**, not absent |
| our `authorized_keys` | DETECTED | EACCES (probe) | `network.other_home_ssh_ls` | `-rw------- 1 ubuntu ubuntu 98 Sep 8 17:37` (98 B ⇒ one key; mtime = provisioning time) |
| NICs: 2× ixgbe up, 1× rndis_host down | DETECTED | OK | `network.nic_info`, `network.ip_addr` | `speed=10000` on both `eno*` |
| VPN / tunnel / RDP / VNC / container sockets | PROVEN ABSENT | OK / ENOENT | `network.vpn_dirs_ls`, `network.remote_access_procs`, `secrets.sockets_ls` | `/etc/wireguard`, `/etc/openvpn`, `/etc/tailscale`, `/var/lib/tailscale` ENOENT; docker/containerd/libvirt sockets ENOENT |
| PAM chain for sshd | DETECTED | OK | `network.pam_config` | stock Ubuntu `common-auth` / `common-account` / `common-session` |
| nsswitch: files only | DETECTED | OK | `users.nsswitch`, `users.sssd_krb5_ls` | no ldap/sss/winbind; `/etc/sssd`, `/etc/krb5.conf`, `/etc/krb5.keytab` ENOENT |

## 6. Kernel / boot chain / LSM

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| UEFI + efivarfs mounted rw | DETECTED | OK | `kernel.secureboot`, `storage.findmnt` | `/sys/firmware/efi/{efivars,esrt,fw_platform_size,mok-variables,runtime,systab,…}`; `efivarfs … rw,nosuid,nodev,noexec,relatime` |
| Secure Boot **disabled** | DETECTED | OK | `kernel.secureboot`, `kernel.mokutil_sbstate` | `SecureBoot-8be4df61-…` bytes `6 0 0 0 0` → 4-byte LE attribute prefix `0x00000006`, then value byte `0`; `mokutil --sb-state` (unprivileged) → `SecureBoot disabled` |
| UEFI **Setup Mode** | DETECTED | OK | `kernel.secureboot`, `kernel.mokutil_sbstate` | `SetupMode-…` bytes `6 0 0 0 1` → value `1`; `mokutil` → `Platform is in Setup Mode` |
| Kernel lockdown `[none]` | DETECTED | OK | `kernel.lsm` | `/sys/kernel/security/lockdown` → `[none] integrity confidentiality`; securityfs mounted and **readable unprivileged** |
| LSM stack | DETECTED | OK | `kernel.lsm` | `lockdown,capability,landlock,yama,apparmor`; securityfs also exposes `evm`, `ima`, `integrity`, `tpm0` |
| AppArmor enabled, mode UNKNOWN | PARTIAL | UTILITY_MISSING (probe) | `kernel.selinux_apparmor` | `/sys/module/apparmor/parameters/enabled` → `Y`; `aa-status: command not found`. Enforcement mode unresolved → R4-OR4 |
| SELinux | ENOENT (proven absent) | UTILITY_MISSING (probe) | `kernel.selinux_apparmor` | `/sys/fs/selinux/enforce` → `No such file or directory`; `getenforce` UTILITY_MISSING — two different outcomes on one probe line |
| Taint O+E attributed to `bnxt_en` | DETECTED | OK | `kernel.module_taint` | `/proc/sys/kernel/tainted` = `12288`; `/sys/module/bnxt_en/taint:OE`; grep count 1 ⇒ exactly one tainting module |
| TPM 2.0 | DETECTED; device EACCES | OK | `kernel.tpm` | `/sys/class/tpm/tpm0 -> …/MSFT0101:00/tpm/tpm0`, `tpm_version_major`=2 readable; `/dev/tpm0`, `/dev/tpmrm0` `crw------- root root` |
| Kernel cmdline hardening | DETECTED | OK | `identity.cmdline` | `module_blacklist=af_alg,algif_hash,algif_skcipher,algif_rng,algif_aead,sctp,sctp_diag`, `nomodeset`, `console=tty1 console=ttyS1,115200n8`, `root=UUID=…` |
| sysctl hardening set | DETECTED | OK | `users.kernel_hardening` | `ptrace_scope=1`, `kptr_restrict=1`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=2`, `modules_disabled=0`, `randomize_va_space=2`, `unprivileged_userns_clone=1`, `protected_regular=2`, `suid_dumpable=0`, `perf_event_paranoid=4` |
| `/boot/config-<ver>` world-readable | DETECTED | OK | `kernel.boot_ls` | `-rw-r--r-- … config-6.8.0-139-generic` and `config-7.0.0-31-generic` ⇒ kernel build options are unprivileged-readable |
| Kernel drift (running ≠ default) | DETECTED | OK | `kernel.osrelease_modules`, `kernel.boot_ls`, `identity.cmdline` | running `6.8.0-139-generic`; `/boot/vmlinuz -> vmlinuz-7.0.0-31-generic`, `vmlinuz.old -> …-6.8.0-139-…`; `/lib/modules` has both; `BOOT_IMAGE=/boot/vmlinuz-6.8.0-139-generic` |
| `/var/run/reboot-required` | ENOENT (proven absent) | ENOENT (probe) | `services.apt_state_ls` | `ls: cannot access '/var/run/reboot-required*': No such file or directory` |
| watchdog device | PROVEN ABSENT | ENOENT (probe) | `services.watchdog` | `ls /sys/class/watchdog` succeeded and listed nothing |

## 7. Secrets surface / accounts / ops

| Technology | Per-fact outcome | Probe status | Probe id(s) | Evidence |
|---|---|---|---|---|
| Login-capable accounts: root, ubuntu | DETECTED | OK | `users.login_shells`, `users.passwd_status` | `root:0:/bin/bash`, `ubuntu:1000:/bin/bash`; `passwd -S` → `ubuntu L` (locked ⇒ key-only) |
| Privileged group membership | DETECTED | OK | `users.priv_groups`, `users.sudo_group` | `sudo:x:27:ubuntu`; **`disk:x:6:`, `adm:x:4:`, `systemd-journal:x:999:`, `kvm`, `video`, `input`, `shadow`, `tty`, `dialout` all have no members** |
| sudo policy | UNKNOWN (EACCES) | EACCES | `users.sudoers_ls`, `users.sudo_group` | `/etc/sudoers` `-r--r----- root:root 1800 Jan 29 2024` (package default mtime); `/etc/sudoers.d` `drwxr-x---` → `Permission denied` on listing ⇒ **existence of `90-cloud-init-users` cannot be confirmed** → R4-OR5 |
| SUID binaries: 11, all stock | DETECTED (bounded) | OK | `secrets.suid_find` | `ssh-keysign`, `dbus-daemon-launch-helper`, `passwd`, `gpasswd`, `umount`, `newgrp`, `su`, `chsh`, `sudo`, `mount`, `chfn`. Bounded: `find / -xdev … 2>/dev/null` silently skips other filesystems (including `/boot/efi`) and unreadable directories |
| File capabilities | DETECTED (bounded) | OK | `secrets.getcap_scan` | only `/usr/bin/ping cap_net_raw=ep`; same boundedness caveat |
| World-writable files | NONE FOUND (bounded) | OK | `secrets.world_writable_find` | empty stdout, rc=0 — a *bounded* negative, not proof |
| Credential material found | 4 files | OK | `secrets.sensitive_file_find` | `/etc/shadow` 640 root:shadow (EACCES for us), our `authorized_keys` 600, two public CA bundles 644 |
| `/etc/ssl/private` | EACCES | OK (probe) | `secrets.tls_private_ls` | `ls: cannot open directory '/etc/ssl/private': Permission denied` ⇒ contents UNKNOWN |
| initramfs world-readable | DETECTED | OK | `secrets.boot_artifacts_ls`, `kernel.boot_ls` | `-rw-r--r-- … initrd.img-6.8.0-139-generic` (67 MB) and `…-7.0.0-31-generic` (71 MB); `grub.cfg` 0600; `vmlinuz-*` and `System.map-*` 0600 |
| cloud-init user-data | DETECTED, EACCES | OK | `secrets.cloud_userdata_ls` | `user-data.txt` 0 bytes 0600 root; `user-data.txt.i` 308 B 0600 root |
| Journal / auth logs | EACCES | OK | `services.journal_usage`, `secrets.varlog_ls` | journal 8.0 M; `/var/log/journal` is `drwxr-sr-x+` — **the `+` proves a POSIX ACL exists** — and we are in neither `adm` nor `systemd-journal`; `cloud-init.log` root:adm 0640; `btmp` root:utmp 0660; `wtmp` 0664 |
| apt state | EMPTY LISTS | ENOENT (probe) | `services.apt_state_ls`, `services.apt_upgradable` | `/var/lib/apt/lists` contains only `.` and `..`; no `update-success-stamp`; `apt list --upgradable` prints only `Listing...` ⇒ **"nothing upgradable" is meaningless here** (trap T-U1) |
| Time sync | DETECTED | UTILITY_MISSING (probe) | `services.time_sync` | `timedatectl` worked unprivileged: `System clock synchronized: yes`, `NTP service: active`, TZ UTC; only `chronyc` was missing |
| Go toolchain | ENOENT (proven absent) | ENOENT (probe) | `services.build_tools` | `/usr/local/go/bin/go` and `/snap/bin/go` ENOENT; gcc, cc, make, tar, gzip, xz, curl, wget, rsync all present |

## 8. Sanitiser artifacts in the evidence file (read before quoting evidence verbatim)

The snapshot sanitiser rewrote several **non-secret** strings, which downstream readers must not mistake
for real values:

- PCI addresses became `<ip>`: `storage.nvme_sysfs_detail` shows `address=<ip>.0`, and `network.nic_info`
  shows `dev=/sys/devices/pci0000:00/<ip>.1/<ip>.1`. The true value is visible unsanitised in
  `bmc.usb_cdc_net` (`/sys/devices/pci0000:00/0000:00:08.1/0000:07:00.3/usb1/1-1/1-1.2/1-1.2:2.0`) and in
  `storage.disk_by_path` (`pci-0000:02:00.0-nvme-1`).
- Error-message **paths** became `<serial>`: `identity.dmi` shows `product_serial=cat: <serial> Permission denied`,
  where the original text was `cat: /sys/class/dmi/id/product_serial: Permission denied`.
- An `lsblk` **column header** (`WWN`) was replaced by `<serial>` in `storage.lsblk_wide`.
- The cloud-init `instance-id` and the `/var/lib/cloud/instances/<…>` directory name became `<mac>`.

None of these are host secrets; they are sanitiser false positives. Any downstream fixture that copies
evidence strings verbatim must strip or regenerate them rather than treat `<ip>` / `<serial>` as observed data.
