#!/usr/bin/env python3
"""Build the agent-visible, sanitized HOST_SNAPSHOT.json (+ evidence file) from the TCI raw snapshot.

Usage: python tooling/build_snapshot.py
Reads:  state/HOST_SNAPSHOT.raw.json (TCI output; lead-only)
Writes: state/HOST_SNAPSHOT.evidence.json (all probe evidence, scrubbed)
        state/HOST_SNAPSHOT.json (structured lead synthesis + pointers to probe IDs)
The structured part is maintained by the lead by hand in this file; evidence scrubbing is mechanical.
"""
import datetime
import json
import re

RAW = "state/HOST_SNAPSHOT.raw.json"
EVID = "state/HOST_SNAPSHOT.evidence.json"
OUT = "state/HOST_SNAPSHOT.json"

raw = json.load(open(RAW, encoding="utf-8"))
ev = raw["evidence"]

SERIALS = ["24034671F8C6", "24034671FB2E", "4671f8c6", "4671fb2e"]
ipv4 = re.compile(r"\b(?!0\.0\.0\.0\b)(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b")
mac = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)


def scrub(t):
    if not t:
        return t
    for s in SERIALS:
        t = t.replace(s, "<serial>")
    t = ipv4.sub("<ip>", t)
    t = mac.sub("<mac>", t)
    return t


for k, e in ev.items():
    e["stdout"] = scrub(e.get("stdout"))
    if len(e["stdout"] or "") > 20000:
        e["stdout"] = e["stdout"][:20000] + "\n...[truncated for snapshot]"
raw["sanitization"] = ("IPv4, MAC and NVMe serial substrings scrubbed; identity-class probes pre-scrubbed by TCI; "
                       "raw retained lead-only in state/raw_host/")
json.dump(raw, open(EVID, "w", encoding="utf-8"), indent=1)

DISK_BYTES = 1875385008 * 512

snap = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "source": ("tooling/tci Tiny Custom Investigator, registry v1 (175 probes), rounds 1-2 on 2026-09-08 21:52-22:08Z; "
               "169 probes executed; per-probe evidence in state/HOST_SNAPSHOT.evidence.json (sanitized); raw lead-only in state/raw_host/"),
    "recon_window": {"budget_min": 15, "actual_min": 17,
                     "over_budget_reason": "two registry fixes (is_virtual rule, ipmi dev probe) + follow-up round"},
    "statuses_summary": raw["statuses_summary"],
    "tci_facts": raw["established_facts"],
    "contested": raw.get("contested"),
    "established": {
        "provider": {"value": "Latitude.sh bare-metal",
                     "evidence": ["network.sshd_config_d (00-latitude-instant-deploy.conf)",
                                  "identity.cloud_init_instance_data (facility=CHI, EC2-style metadata 2009-04-04)",
                                  "identity.hostname (f4-metal-small-chi-1)"],
                     "confidence": "high"},
        "hardware": {"vendor": "Supermicro", "product": "AS -3015MR-H10TNR", "board": "H13SRE-F v1.01",
                     "bios": "2.4a 2025-08-29", "chassis_type": "1 (Other)", "virtualization": "none (bare metal)",
                     "evidence": ["identity.dmi", "identity.hostnamectl", "identity.virt"]},
        "cpu": {"model": "AMD EPYC 4484PX 12-Core Processor", "sockets": 1, "cores_per_socket": 12,
                "threads_per_core": 2, "logical_cpus": 24, "smt_active": True,
                "evidence": ["cpu.lscpu", "cpu.cpuinfo_summary", "cpu.nproc_smt"]},
        "memory": {"MemTotal_kB": 97938032, "SwapTotal_kB": 0, "evidence": ["cpu.meminfo", "storage.swap"]},
        "os": {"name": "Ubuntu", "version": "24.04.4 LTS (Noble Numbat)", "version_id": "24.04",
               "kernel_running": "6.8.0-139-generic",
               "kernel_installed_newer": "7.0.0-31-generic (vmlinuz/initrd symlinks point to it; no reboot-required marker)",
               "init": "systemd",
               "evidence": ["identity.os_release", "identity.uname", "kernel.osrelease_modules", "kernel.boot_ls",
                            "services.apt_state_ls"]},
        "account": {"user": "ubuntu", "uid": 1000, "groups": ["ubuntu", "sudo"], "password_status": "L (locked)",
                    "sudo_policy": "UNKNOWN (sudoers 0440 root:root, sudoers.d 0750 unreadable)",
                    "login_shell_users": ["root", "ubuntu"],
                    "evidence": ["identity.id", "users.passwd_status", "users.sudoers_ls", "users.sudo_group",
                                 "users.login_shells"]},
        "remote_access": {
            "sshd": "OpenSSH_9.6p1 Ubuntu-3ubuntu13.19",
            "activation": "systemd ssh.socket (0.0.0.0:22, [::]:22) + ssh.service active",
            "effective_directives": ["Include /etc/ssh/sshd_config.d/*.conf", "PermitRootLogin prohibit-password",
                                     "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM yes",
                                     "X11Forwarding yes", "PrintMotd no", "AcceptEnv LANG LC_*",
                                     "Subsystem sftp /usr/lib/openssh/sftp-server"],
            "dropins": ["00-latitude-instant-deploy.conf: PasswordAuthentication no, KbdInteractiveAuthentication no"],
            "sshd_T_unprivileged": "fails: no hostkeys available",
            "listeners": ["tcp/22 v4+v6 sshd", "udp+tcp/53 systemd-resolved loopback/stub"],
            "firewall": "ufw is-active=active; rulesets unreadable (nft absent, iptables/ufw need root)",
            "root_authorized_keys": "UNKNOWN (/root/.ssh EACCES)",
            "other_remote_paths": "none detected (no vnc/rdp/telnet/tailscale/wireguard/openvpn/cockpit/tunnels/docker socket)",
            "evidence": ["network.sshd_effective_lines", "network.sshd_config_d", "network.ssh_socket_cat",
                         "network.sshd_service_status", "network.ss_listen", "network.firewall_active",
                         "network.firewall_rules", "network.other_home_ssh_ls", "network.remote_access_procs",
                         "network.vpn_dirs_ls", "secrets.sockets_ls"]},
        "storage": {
            "disks": [
                {"dev": "nvme0n1", "model": "Micron_7450_MTFDKCC960TFR", "size_bytes": DISK_BYTES, "transport": "pcie",
                 "fw": "E2MU200", "lbs": 512, "pbs": 4096, "write_cache": "write through",
                 "partitions": ["p1 vfat EFI 512M /boot/efi", "p2 ext4 ROOT 893.8G /"]},
                {"dev": "nvme1n1", "model": "Micron_7450_MTFDKCC960TFR", "size_bytes": DISK_BYTES, "transport": "pcie",
                 "fw": "E2MU200", "partitions": [], "filesystem": None, "holders": [], "note": "unused device"}],
            "device_mapper": "absent (only /dev/mapper/control) => no LVM, no LUKS/dm-crypt",
            "md_raid": "modules loaded, no arrays (/proc/mdstat unused, no /dev/md*); /etc/mdadm/mdadm.conf EXISTS (content: HOMEHOST <ignore>) — an earlier snapshot version wrongly listed it as absent (R4-F02 correction; the probe combined two paths and only /etc/mdadm.conf was ENOENT)",
            "multipath": "absent (utility + config missing)",
            "iscsi_fc_sas": "absent (no /sys/class/iscsi_*/fc_host/sas_host; iscsiadm missing)",
            "network_fs": "none mounted; /proc/fs/nfsfs absent",
            "zfs_btrfs_bcache": "absent",
            "sata": "ASMedia ASM1061 AHCI present, 12 empty scsi_hosts, no SATA disks",
            "loop": "8 empty loop devices", "swap": "none",
            "root_mount_opts": "rw,relatime,errors=remount-ro (no nodev/nosuid/noexec)",
            "smart": "nvme smart-log/id-ctrl EACCES (/dev/nvme* root:disk 0660 / root 0600); smartctl absent",
            "ext4_sysfs": "/sys/fs/ext4/nvme0n1p2 errors_count=0 readable",
            "timers": ["fstrim.timer weekly", "e2scrub_all.timer"],
            "evidence": ["storage.lsblk_wide", "storage.lsblk_fs", "storage.lsblk_json", "storage.sysblock_loop",
                         "storage.blk_queue_detail", "storage.nvme_class", "storage.nvme_sysfs_detail", "storage.nvme_cli",
                         "storage.nvme_smart_try", "storage.dev_ls", "storage.dev_mapper_ls", "storage.mdstat",
                         "storage.multipath", "storage.iscsi", "storage.scsi_hosts", "storage.lspci_storage",
                         "storage.mounts", "storage.findmnt", "storage.fstab", "storage.swap", "storage.ext4_sysfs",
                         "services.timers"]},
        "bmc_inband": {
            "kcs_interface": "present: ACPI IPI0001 (\\_SB_.PCI0.SBRG.SIKC) + dmi-ipmi-si.0 platform device",
            "modules": ["ipmi_si (used by 1)", "ipmi_devintf", "ipmi_msghandler", "ipmi_ssif", "acpi_ipmi"],
            "device_node": "/dev/ipmi0 crw------- root:root (0600); /dev/ipmidev absent",
            "who_can_open": "root only by mode; ACLs unknown (getfacl absent); user ubuntu is in group sudo (escalation path exists, policy unknown)",
            "bmc_identity_sysfs": {"ipmi_version": "2.0", "firmware_revision": "1.5",
                                   "manufacturer_id": "0x002a7c (Supermicro)", "product_id": "0x1d6e", "device_id": 32,
                                   "guid": "readable"},
            "client_tools": "ipmitool/freeipmi/ipmiutil absent",
            "smbios": "type 38 (IPMI) and type 42 (Redfish host interface) entries exist; raw root-only",
            "usb_host_interface": "BMC virtual NIC enx... (Linux 5.4.62 with aspeed_vhub, RNDIS/Ethernet Gadget 0b1f:03ee, rndis_host) operstate DOWN, no address",
            "mem_port": "/dev/mem, /dev/port root:kmem 0640",
            "udev_modprobe": "no ipmi rules/config",
            "evidence": ["bmc.ipmi_acpi_devices", "bmc.platform_ipmi_devices", "bmc.ipmi_modules", "bmc.ipmi_dev_ls",
                         "bmc.ipmi_dev_perms", "bmc.bmc_sysfs_attrs", "bmc.ipmitool_which", "bmc.ipmitool_mc_info",
                         "bmc.dmi_smbios_entries", "bmc.dmi_entry_38_raw", "bmc.usb_nic_identity", "bmc.usb_cdc_net",
                         "bmc.mem_port_kmsg_ls", "bmc.udev_rules_ipmi", "bmc.modprobe_ipmi"]},
        "kernel_boot_security": {
            "firmware": "UEFI",
            "secure_boot": "DISABLED; platform in Setup Mode (SecureBoot=0, SetupMode=1; mokutil agrees)",
            "lockdown": "[none]",
            "lsm": "lockdown,capability,landlock,yama,apparmor",
            "apparmor": "enabled=Y (aa-status absent)",
            "tainted": "12288 = O+E: out-of-tree unsigned module bnxt_en",
            "tpm": "TPM 2.0 present (/dev/tpm0, /dev/tpmrm0 root-only 0600)",
            "cmdline_flags": ["module_blacklist=af_alg,algif_hash,algif_skcipher,algif_rng,...", "nomodeset",
                              "console=ttyS1,115200n8"],
            "sysctl": {"kernel.yama.ptrace_scope": 1, "kernel.kptr_restrict": 1, "kernel.dmesg_restrict": 1,
                       "kernel.unprivileged_bpf_disabled": 2, "kernel.modules_disabled": 0,
                       "kernel.randomize_va_space": 2, "kernel.unprivileged_userns_clone": 1,
                       "fs.protected_symlinks": 1, "fs.protected_hardlinks": 1, "fs.protected_fifos": 1,
                       "fs.protected_regular": 2, "fs.suid_dumpable": 0, "kernel.perf_event_paranoid": 4},
            "cpu_vulnerabilities": "all Not affected or Mitigated",
            "evidence": ["kernel.secureboot", "kernel.mokutil_sbstate", "kernel.lsm", "kernel.selinux_apparmor",
                         "kernel.module_taint", "users.kernel_hardening", "kernel.tpm", "identity.cmdline",
                         "cpu.vulnerabilities"]},
        "secrets_surface": {
            "found_by_bounded_find": ["/etc/shadow 640 root:shadow", "/home/ubuntu/.ssh/authorized_keys 600",
                                      "two public CA bundles (.pem, 644)"],
            "provisioning_data": "cloud-init user-data.txt 0600 root (0 B) + user-data.txt.i 308 B 0600",
            "tls_private": "/etc/ssl/private EACCES (0710)",
            "boot": "grub.cfg 0600; initrd.img-6.8.0-139/7.0.0-31 world-readable 0644",
            "suid": "11 standard binaries", "capabilities": "/usr/bin/ping cap_net_raw=ep",
            "world_writable_files": "none found in reachable dirs", "histories": "none",
            "cloud_cli_creds": "none in /home; /root unreadable",
            "evidence": ["secrets.sensitive_file_find", "secrets.cloud_userdata_ls", "secrets.tls_private_ls",
                         "secrets.boot_artifacts_ls", "secrets.suid_find", "secrets.getcap_scan",
                         "secrets.world_writable_find", "secrets.home_history_ls", "secrets.cloud_cred_dirs_ls"]},
        "identity_owner": {
            "machine_id": "/etc/machine-id 0444 world-readable (32 hex); dbus id symlinks to it",
            "dmi_serials_uuid": "product_serial/product_uuid/board_serial/chassis_serial 0400 root-only (EACCES)",
            "asset_tags": "placeholders: To be filled by O.E.M. / Chassis Asset Tag",
            "machine_info": "/etc/machine-info absent",
            "owner_hints": ["provider Latitude.sh (drop-in name, metadata endpoint)", "facility CHI",
                            "host key comments root@259S052315 (image/provisioning host)", "no tenant/org tag readable"],
            "evidence": ["identity.machine_id_files", "identity.dmi", "identity.dmi_ls", "identity.machine_info",
                         "identity.cloud_init_instance_data", "network.host_key_fingerprints"]},
        "ops_drift": {
            "time": "systemd-timesyncd active, synchronized, UTC",
            "timers": ["apt-daily", "apt-daily-upgrade", "dpkg-db-backup", "motd-news", "fstrim", "e2scrub_all",
                       "systemd-tmpfiles-clean"],
            "logging": "journal 8 MB, unreadable to us (not adm/systemd-journal); no rsyslog remote",
            "packages": 355,
            "evidence": ["services.time_sync", "services.timers", "services.journal_usage", "services.rsyslog_remote",
                         "services.pkg_counts"]},
        "utilities": {
            "present": ["nvme", "mdadm", "lsblk", "findmnt", "lspci", "ss", "netstat", "ip", "iptables(root)",
                        "ufw(root)", "getcap", "python3", "perl", "gcc", "cc", "make", "tar", "gzip", "xz", "curl",
                        "wget", "rsync", "mokutil"],
            "absent": ["go", "ipmitool", "smartctl", "dmidecode", "getfacl", "nft", "docker", "lshw", "jq", "multipath",
                       "iscsiadm", "zpool", "chronyc", "aa-status", "getenforce"],
            "evidence": ["services.utility_inventory", "services.build_tools", "bmc.ipmitool_which",
                         "storage.smartctl_scan", "bmc.ipmi_dev_perms"]},
    },
    "unresolved": [
        {"fact": "DMI product_uuid / serials", "status": "EACCES (0400 root)",
         "alternatives": "none unprivileged; host_id must fall back to machine-id (+ provenance)"},
        {"fact": "sudo policy for ubuntu (NOPASSWD? ALL?)", "status": "EACCES on sudoers/sudoers.d",
         "alternatives": "group membership only; do not run sudo -l (would exercise the privilege path)"},
        {"fact": "root authorized_keys presence", "status": "EACCES /root/.ssh",
         "alternatives": "none; report PermitRootLogin prohibit-password + unknown key presence"},
        {"fact": "firewall rules in force", "status": "ufw active but rules root-only; nft absent",
         "alternatives": "listener view via ss; report rules UNKNOWN"},
        {"fact": "NVMe SMART / health", "status": "EACCES on device ioctls; smartctl absent",
         "alternatives": "ext4 sysfs errors_count, nvme sysfs state=live"},
        {"fact": "BMC user/channel/LAN config", "status": "no client tool; /dev/ipmi0 root-only",
         "alternatives": "BMC identity via sysfs only"},
        {"fact": "SMBIOS type 38/42 contents", "status": "raw root-only",
         "alternatives": "ACPI IPI0001 + platform devices prove KCS; USB gadget proves a Redfish-style host interface"},
        {"fact": "/dev/i2c-* permissions", "status": "ANSWERED 23:08Z: crw------- root:root (0600) x3 (bmc.i2c_dev_modes)", "alternatives": "n/a"},
        {"fact": "dmesg / kernel log", "status": "EPERM (dmesg_restrict=1)", "alternatives": "none"},
    ],
    "technologies": {
        "detected": ["NVMe (2 PCIe SSDs)", "ext4", "vfat EFI", "systemd socket-activated sshd", "ufw (active, opaque)",
                     "AppArmor", "TPM 2.0", "IPMI KCS (ipmi_si) + BMC USB RNDIS gadget", "UEFI without Secure Boot",
                     "cloud-init (Latitude.sh datasource)", "netplan + systemd-networkd/resolved/timesyncd",
                     "Intel ixgbe 10GbE x2", "out-of-tree bnxt_en module", "AMD IOMMU"],
        "proven_absent": ["device-mapper/LVM/LUKS", "md RAID arrays", "multipath", "iSCSI/FC/SAS", "NFS/CIFS/Ceph",
                          "ZFS/btrfs/bcache", "swap", "docker/containerd/libvirt", "VPNs/tunnels", "SELinux",
                          "LDAP/SSSD/Kerberos", "config management agents", "Go toolchain"],
        "unresolved": ["SATA disks behind ASM1061 (none visible; controller present)",
                       "BMC network reachability via USB NIC (down)"]},
    "research_questions": [
        "R3/R4: stable host_id chain when product_uuid is root-only: machine-id (0444) vs hashed NIC MAC / NVMe EUI / board identifiers; which is stable across reimage/reboot on Latitude.sh?",
        "R4: Latitude.sh instant-deploy images: what does 90-cloud-init-users / sudoers.d typically contain (NOPASSWD?); we cannot read it.",
        "R3/R4: Ubuntu 24.04 socket-activated sshd: what is in force when ssh.socket ListenStream differs from sshd_config Port/ListenAddress; sshd -T fails unprivileged; derive effective config by parsing with Include + first-match semantics.",
        "R4: BMC in-band posture on Supermicro H13 with /dev/ipmi0 0600 root, no ipmitool, sudo-group user, USB RNDIS gadget down: what should PASS/FAIL/INFO be? Is the down virtual NIC a latent Redfish host interface (SMBIOS 42)?",
        "R4 storage: unused second NVMe (no fs), no encryption at rest (no dm), write-through cache, no redundancy for root; SMART unreadable: which are findings vs info; generic fallbacks (dm uuid CRYPT-LUKS*, md/degraded, zfs)?",
        "R3/R4 kernel: Secure Boot disabled + Setup Mode + lockdown none + tainted OE bnxt_en: exact semantics of efivars SecureBoot/SetupMode bytes, lockdown file format, /sys/module/*/taint letters; false-positive traps.",
        "R4: pending kernel (7.0.0-31 installed, 6.8 running, no reboot-required flag): reliable unprivileged detection of running kernel != newest installed and its semantics.",
        "R1/R5: JSON schema validation and bounded exec patterns in Go; cross-compiled static binary since the host lacks Go.",
        "R2: Latitude.sh as a bare-metal provider; does owner/tenant information ever exist on such hosts?",
    ],
    "follow_up_observations": ["ALL EXECUTED in recon round 3 (23:04-23:13Z): i2c modes, USB NIC operstate, dmi 42-0 attribute modes, sshd_config.d mtime vs boot, group membership, udev data, mountinfo, sysfs symlink shape, sshd -G, BMC read timing, securityfs modes, st_size pattern — answers in research/OBSERVATION_ANSWERS.md"],
}
json.dump(snap, open(OUT, "w", encoding="utf-8"), indent=1)
print("HOST_SNAPSHOT.json written:", len(json.dumps(snap)), "bytes; evidence file:", len(json.dumps(raw)), "bytes")
