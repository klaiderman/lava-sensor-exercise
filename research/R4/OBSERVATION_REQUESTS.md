# R4 — OBSERVATION_REQUESTS

Every request below has a matching **explicitly labelled assumption** stating how the research proceeded
without the answer. All suggested probes are read-only, non-destructive and unprivileged; none uses
`sudo`, writes, or opens a device node.

---

`{"id":"R4-OR1","question":"Does /dev/ipmi0 carry a POSIX ACL that grants access beyond its 0600 root:root mode?","why_it_matters":"BMC_INBAND_ACCESS's 'who is permitted' check is answered by mode+owner+group+ACL+group membership. Mode alone says root-only; an ACL could contradict that, and getfacl is not installed.","acceptable_evidence":"The value (or absence) of the system.posix_acl_access extended attribute on /dev/ipmi0, or a long listing showing whether a '+' suffix is present.","suggested_safe_probe":"ls -l /dev/ipmi0; python3 -c \"import os;print(os.listxattr('/dev/ipmi0'))\"","blocking":false}`

**ASSUMPTION carried:** no ACL is present, because `ls -l` in `bmc.ipmi_dev_ls` showed no `+` suffix.
This is weak evidence (the probe was not designed to test it) and the plan therefore recommends reading
the xattr directly rather than relying on the assumption (R4-F28).

---

`{"id":"R4-OR2","question":"What are the permissions and owners of /dev/i2c-0, /dev/i2c-1 and /dev/i2c-2?","why_it_matters":"I2C character devices are an alternative in-band path to platform management controllers. Their existence is proven (bmc.i2c_devices) but the probe used `ls` without -l, so the access question is entirely open. If any were group- or world-accessible it would materially change the BMC_INBAND_ACCESS conclusion.","acceptable_evidence":"A long listing of /dev/i2c-*.","suggested_safe_probe":"ls -l /dev/i2c-*","blocking":false}`

**ASSUMPTION carried:** they follow the kernel default of 0600 root:root, consistent with every other
management device node on this host. The BMC conclusion is written so that it does not depend on this.

---

`{"id":"R4-OR3","question":"What are the file modes of the entries under /etc/ufw/ (ufw.conf, user.rules, before.rules, after.rules and their v6 variants)?","why_it_matters":"ufw is active but every rule-query path is root-only. If ufw.conf is world-readable it would at least establish the configured default policy and the ENABLED flag, upgrading a total unknown to a partial answer in REMOTE_ACCESS.","acceptable_evidence":"A long listing of /etc/ufw/ and, if readable, the non-comment lines of ufw.conf.","suggested_safe_probe":"ls -l /etc/ufw/; grep -Ev '^\\s*(#|$)' /etc/ufw/ufw.conf 2>&1","blocking":false}`

**ASSUMPTION carried:** the firewall ruleset is unknown and the check returns unknown with the observed
`iptables`/`ufw` permission-denied strings as evidence. If the modes turn out to be readable, the check
gains a partial answer; nothing already written becomes wrong.

---

`{"id":"R4-OR4","question":"What are the contents of /sys/kernel/security/apparmor/profiles, and how many profiles are in enforce versus complain mode?","why_it_matters":"AppArmor is enabled (kernel flag Y) but its enforcement mode is unresolved, and aa-status is not installed. This determines whether an LSM-posture check can claim active enforcement or only presence.","acceptable_evidence":"The contents of /sys/kernel/security/apparmor/profiles (or its errno), plus a count by mode.","suggested_safe_probe":"cat /sys/kernel/security/apparmor/profiles 2>&1 | head -50; cat /sys/kernel/security/apparmor/profiles 2>/dev/null | awk '{print $NF}' | sort | uniq -c","blocking":false}`

**ASSUMPTION carried:** enforcement mode is UNRESOLVED (R4-F18). Stream S3 established the file is
created with mode 0444 (R4-F44), so this is very likely answerable in one read — but it has not been read
on this host, and the plan says unknown until it is.

---

`{"id":"R4-OR5","question":"Does /etc/sudoers.d/90-cloud-init-users exist on this host, and what sudo policy applies to the ubuntu account?","why_it_matters":"Group membership in `sudo` is established; the policy is not. It bears on both REMOTE_ACCESS (what a compromised key grants) and BMC_INBAND_ACCESS (whether an escalation path to /dev/ipmi0 exists).","acceptable_evidence":"A directory listing of /etc/sudoers.d, or the file's mode. NOT the file contents, and explicitly NOT `sudo -l`.","suggested_safe_probe":"ls -ld /etc/sudoers.d; ls -l /etc/sudoers.d 2>&1","blocking":false}`

**ASSUMPTION carried:** the policy is UNKNOWN (R4-F22) and reported as such. Cloud-init's source shows it
writes that exact filename at mode 0440 (R4-F33), but a vendor default is not evidence about this host.
**`sudo -l` must never be run** — it exercises the privilege path the exercise forbids.

---

`{"id":"R4-OR6","question":"Which ext4 features are enabled on nvme0n1p2, in particular filesystem-level encryption (fscrypt)?","why_it_matters":"The encryption-at-rest conclusion currently covers dm-crypt/LUKS (provably absent) and SED/Opal (unknown by construction). fscrypt is a third class that is probably answerable unprivileged and was simply never probed.","acceptable_evidence":"A listing of /sys/fs/ext4/nvme0n1p2/ and of /sys/fs/ext4/features/, plus the value of any encryption-related feature file.","suggested_safe_probe":"ls /sys/fs/ext4/features/ 2>&1; ls /sys/fs/ext4/nvme0n1p2/ 2>&1","blocking":false}`

**ASSUMPTION carried:** fscrypt is not in use, because no `/etc/crypttab`, no dm target and no
encryption-related mount option were observed. This is an inference from adjacent evidence, not an
observation, and STORAGE_ASSESSMENT.md Q3 marks it "unknown (unobserved)" rather than answered.

---

`{"id":"R4-OR7","question":"Are the non-`raw` attributes under /sys/firmware/dmi/entries/38-0 and 42-0 (type, length, handle, instance, position) readable by an unprivileged user on this kernel?","why_it_matters":"Stream S1/S2 found that in Linux v6.8 every attribute in a DMI entry directory is declared admin-read-only (0400), not just `raw`. Only the directory listing was probed on this host. If `type` were readable it would let a check name the declared interface type without root; if not, all field-level claims must be unknown.","acceptable_evidence":"A long listing of /sys/firmware/dmi/entries/38-0/ and the result of reading its `type` file.","suggested_safe_probe":"ls -l /sys/firmware/dmi/entries/38-0/ /sys/firmware/dmi/entries/42-0/; cat /sys/firmware/dmi/entries/38-0/type 2>&1","blocking":false}`

**ASSUMPTION carried:** only the *existence* of the entry directories is usable unprivileged (R4-F49);
every field-level claim is treated as EACCES/unknown. This is the conservative reading and cannot become
wrong — it can only become less restrictive.

---

`{"id":"R4-OR8","question":"Does /run/udev/data/ exist and is it readable by the unprivileged account?","why_it_matters":"The claim that lsblk's FSTYPE/LABEL columns come from the udev database rather than from a device read (R4-F08) is currently LIKELY, inferred from the fact that the account cannot open the block device. Confirming the udev DB is readable would make the inference solid and would give the sensor a direct, tool-free source for filesystem-signature metadata.","acceptable_evidence":"A listing of /run/udev/data and a read of one b259:* entry (metadata only — no device content is involved).","suggested_safe_probe":"ls -ld /run/udev/data; ls /run/udev/data 2>&1 | head","blocking":false}`

**ASSUMPTION carried:** lsblk's filesystem columns are udev-derived, so "no filesystem on nvme1n1" is
phrased as "no signature known to udev" (trap T-S3) rather than as a statement about the disk.

---

`{"id":"R4-OR9","question":"What is the mtime of /etc/ssh/sshd_config.d/00-latitude-instant-deploy.conf relative to system boot time, and are there other post-boot modifications under /etc/ssh?","why_it_matters":"The drop-in and our authorized_keys share an mtime about 22 hours after boot, suggesting provisioning rewrote remote-access configuration after the machine was up. It supports a 'configuration changed since boot' observation, currently LIKELY (R4-F29).","acceptable_evidence":"Boot time (uptime -s or /proc/stat btime) alongside a long listing of /etc/ssh and /etc/ssh/sshd_config.d.","suggested_safe_probe":"uptime -s; ls -l --time-style=full-iso /etc/ssh /etc/ssh/sshd_config.d","blocking":false}`

**ASSUMPTION carried:** the mtime difference is real (both values come from the same evidence file) but
its cause is not established. The finding is written as an observation with severity `info`, and it
states that mtime is not proof of authorship and can be set arbitrarily.

---

`{"id":"R4-OR10","question":"Confirm the exact stderr text and exit code that nvme-cli 2.8 returns for `nvme smart-log` as an unprivileged user on this host.","why_it_matters":"The evidence file shows the message 'Permission denied' followed by usage text, but the probe piped the command through `head`, so the recorded rc is head's, not nvme's (R4-F01). A check that reports an exit code needs the real one.","acceptable_evidence":"The command run without a pipe, with its exit status captured directly.","suggested_safe_probe":"nvme smart-log /dev/nvme0n1 >/dev/null 2>/tmp/.r4err; echo rc=$?; cat /tmp/.r4err | head -3","blocking":false}`

**NOTE on this probe:** the suggested form writes a temporary file, which conflicts with the sensor's
read-only rule. A lead running it manually should instead capture stderr in the shell without a
temporary file (`nvme smart-log /dev/nvme0n1 2>&1 1>/dev/null; echo rc=$?`). The sensor itself must
capture the child's exit status through its own process API and never through a shell pipeline.

**ASSUMPTION carried:** the errno is EACCES and the exit code is non-zero but unrecorded. Findings quote
the observed stderr text, not a numeric code.
