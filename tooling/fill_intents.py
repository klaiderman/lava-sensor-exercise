#!/usr/bin/env python3
"""Fill {{HOST_SUMMARY}} in prompts/raw/R*.intent.md from state/HOST_SUMMARY.md and refresh the CLAUDE.md host facts block."""
import re

hs = open("state/HOST_SUMMARY.md", encoding="utf-8").read().strip()
for n in range(1, 6):
    p = f"prompts/raw/R{n}.intent.md"
    s = open(p, encoding="utf-8").read()
    if "{{HOST_SUMMARY}}" in s:
        open(p, "w", encoding="utf-8").write(s.replace("{{HOST_SUMMARY}}", hs))
        print("filled", p)
    else:
        print("already filled", p)

c = open("CLAUDE.md", encoding="utf-8").read()
start = c.index("## Host facts established so far")
new = """## Host facts established so far (details in `state/HOST_SNAPSHOT.json`; compact text in `state/HOST_SUMMARY.md`)
- Latitude.sh bare-metal Supermicro AS-3015MR-H10TNR (H13SRE-F), AMD EPYC 4484PX 12c/24t, ~93 GiB RAM, no swap; Ubuntu 24.04.4, running kernel 6.8.0-139-generic with 7.0.0-31 installed (reboot pending).
- Login user uid 1000 `ubuntu`, groups `ubuntu sudo`; sudoers unreadable; key-only SSH (OpenSSH 9.6p1, socket-activated, PermitRootLogin prohibit-password, PasswordAuthentication no).
- Storage: 2x Micron 7450 PRO NVMe; nvme0n1 = EFI + ext4 root; nvme1n1 unused (no partitions/fs); no dm/LVM/LUKS/md/multipath/network storage; SMART needs root.
- BMC: KCS via ipmi_si (ACPI IPI0001), `/dev/ipmi0` root-only 0600, BMC sysfs attrs readable (IPMI 2.0, Supermicro), no ipmitool; BMC USB NIC (aspeed_vhub RNDIS) present but DOWN.
- Boot/kernel: Secure Boot disabled + Setup Mode, lockdown none, tainted OE (unsigned out-of-tree `bnxt_en`), TPM 2.0 root-only, AppArmor on, dmesg_restrict 1.
- Host has gcc/make/tar/curl/rsync but NO Go: we cross-compile a static linux/amd64 binary locally and upload it (`scp`/`rsync` per Lava cheatsheet).
"""
open("CLAUDE.md", "w", encoding="utf-8").write(c[:start] + new)
print("CLAUDE.md host facts updated")
