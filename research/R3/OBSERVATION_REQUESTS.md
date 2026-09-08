# R3 — OBSERVATION_REQUESTS.md

Host-fact gaps hit during R3. R3 has no SSH; only the lead's TCI executor observes the host.
Each entry is one JSON object. `blocking:true` means at least one DESIGN LAW cannot be validated
against the real host until it is answered.

```json
{"id":"R3-OR1","question":"What are the actual modes and owners of every file under /sys/class/dmi/id on the Lava host, and does /sys/class/dmi/id exist at all?","why_it_matters":"L01 and L33 branch on 0400-vs-0444 per field and on ENOENT-vs-EACCES for the whole directory. The kernel source says 0400 for the four serials, but a host could carry a distro patch or a udev rule, and we must never hardcode 'always root-only'.","acceptable_evidence":"One line per file: mode, uid, gid, name, plus the exit status of a read attempt as uid 1000.","suggested_safe_probe":"stat -c '%a %U:%G %n' /sys/class/dmi/id/* 2>&1; for f in /sys/class/dmi/id/*; do printf '%s ' \"$f\"; head -c 0 \"$f\" 2>&1 && echo READABLE || true; done","blocking":true}
```

```json
{"id":"R3-OR2","question":"Can the unprivileged account read the system.posix_acl_access extended attribute of a file it cannot read the contents of (e.g. /etc/shadow) on this host's ext4 root?","why_it_matters":"xattr(7) says access to system.* attributes is filesystem-policy-defined, and getfacl is absent on the host. If the xattr is readable, the sensor can report ACL presence unprivileged; if not, every ACL-dependent finding is UNKNOWN by construction and must say so.","acceptable_evidence":"The return of a getxattr(2) call for system.posix_acl_access on /etc/shadow and on a 0644 file, with errno. python3 is present on the host.","suggested_safe_probe":"python3 -c \"import os;\\nfor p in ('/etc/shadow','/etc/hostname'):\\n    try: print(p,'len',len(os.getxattr(p,'system.posix_acl_access')))\\n    except OSError as e: print(p,'errno',e.errno,e.strerror)\"","blocking":true}
```

```json
{"id":"R3-OR3","question":"What is the exact byte-for-byte content and file order of the sshd Include chain on the host: the position of the Include line in /etc/ssh/sshd_config, and the lexical listing of /etc/ssh/sshd_config.d/?","why_it_matters":"L16's verdict for PasswordAuthentication/PermitRootLogin depends entirely on whether the Latitude.sh drop-in is read before or after the main file's own settings. The snapshot records the effective directive list but not the Include line's position.","acceptable_evidence":"grep -n on the Include line, plus ls -1 of the drop-in directory and the non-comment lines of each drop-in.","suggested_safe_probe":"grep -n '^[Ii]nclude' /etc/ssh/sshd_config; ls -1 /etc/ssh/sshd_config.d/; grep -vE '^\\s*(#|$)' /etc/ssh/sshd_config.d/*.conf","blocking":true}
```

```json
{"id":"R3-OR4","question":"Does /run/udev/data exist on the host and does it contain records for the NVMe block devices (b259:*), including ID_FS_TYPE and ID_FS_UUID?","why_it_matters":"L29 forbids reporting fstype as UNKNOWN when the udev database can answer it. If the udev database is absent or sparse on this host, the law's under-claim clause does not apply here and the fixture expectations change.","acceptable_evidence":"A directory listing and the ID_FS_* keys (names only, values are non-secret and safe) for the root device's udev record.","suggested_safe_probe":"ls /run/udev/data 2>&1 | head; grep -h '^E:ID_FS' /run/udev/data/b259:* 2>&1 | head -20","blocking":false}
```

```json
{"id":"R3-OR5","question":"What are the exact modes, owners and groups of /dev/ipmi0, /dev/i2c-0..2, /dev/tpm0, /dev/tpmrm0 and /dev/mem on the host, and is there any ACL on /dev/ipmi0 (trailing '+' in ls -l)?","why_it_matters":"L26 reports access_permitted from the observed node metadata rather than an assumed distro default (R3-F44 is only LIKELY). An ACL widening access to /dev/ipmi0 would flip the BMC posture verdict and is invisible to a mode-only check.","acceptable_evidence":"ls -l output for those nodes (the '+' suffix is the ACL indicator) plus id of the probing account.","suggested_safe_probe":"ls -l /dev/ipmi0 /dev/i2c-* /dev/tpm0 /dev/tpmrm0 /dev/mem 2>&1; id","blocking":false}
```

```json
{"id":"R3-OR6","question":"Do /proc/sys/kernel/unprivileged_userns_clone and /proc/sys/user/max_user_namespaces both exist on the host's running 6.8.0-139-generic kernel, and what are their values?","why_it_matters":"R3-F74 is CONTESTED and L37 is written around it. The snapshot records unprivileged_userns_clone=1 but not whether the upstream knob is also present, and the sensor must probe both spellings rather than assume the Debian one.","acceptable_evidence":"cat of both paths with the errno on failure.","suggested_safe_probe":"for p in /proc/sys/kernel/unprivileged_userns_clone /proc/sys/user/max_user_namespaces; do printf '%s=' \"$p\"; cat \"$p\" 2>&1; done","blocking":false}
```

```json
{"id":"R3-OR7","question":"What is the mode of /proc on the host (is hidepid= set in /proc/self/mountinfo), and can uid 1000 read /proc/1/status and /proc/1/comm?","why_it_matters":"L07 requires reading hidepid before drawing any conclusion from a process enumeration; if hidepid is set, the entire process-based portion of the remote-access check (L21) becomes UNKNOWN on this host.","acceptable_evidence":"The /proc line from /proc/self/mountinfo, plus the result of reading /proc/1/comm as uid 1000.","suggested_safe_probe":"grep ' /proc ' /proc/self/mountinfo; cat /proc/1/comm 2>&1; ls -d /proc/1 2>&1","blocking":false}
```

```json
{"id":"R3-OR8","question":"What exact stderr text and exit code does `sshd -T` produce on the host as uid 1000, and what does `command -v sshd` return?","why_it_matters":"L18 prescribes recording that stderr verbatim as EXECUTION_ERROR evidence. The snapshot reports the message but not the exit code, and UTILITY_MISSING (sshd not on PATH for a non-root user, since it usually lives in /usr/sbin) is a different reason that must not be conflated.","acceptable_evidence":"The command's stderr and exit code, plus whether sshd is resolvable on the unprivileged PATH.","suggested_safe_probe":"command -v sshd; /usr/sbin/sshd -T 2>&1 | head -3; echo \"exit=$?\"","blocking":false}
```

```json
{"id":"R3-OR9","question":"On the host, does `lsblk -J -o NAME,SERIAL,WWN,FSTYPE,UUID` populate SERIAL/WWN/FSTYPE for nvme0n1 and nvme1n1 as uid 1000, given the account is not in group disk?","why_it_matters":"R3-F46 is a WSL2 LOCAL_REPRO and WSL2's block layer is virtual. L29's under-claim clause needs confirmation on real NVMe with a real udev database before the sensor is required to produce a non-UNKNOWN fstype there.","acceptable_evidence":"The JSON output, plus the errno of a 1-byte read of /dev/nvme0n1.","suggested_safe_probe":"lsblk -J -o NAME,SERIAL,WWN,FSTYPE,UUID 2>&1; dd if=/dev/nvme0n1 bs=1 count=1 of=/dev/null 2>&1 | tail -1","blocking":false}
```

```json
{"id":"R3-OR10","question":"What are the st_size values reported by stat for a representative set of the sysfs and procfs paths the sensor will read on the host (e.g. /sys/class/dmi/id/sys_vendor, /sys/block/nvme0n1/size, /proc/cpuinfo, /proc/self/mountinfo, /sys/devices/platform/ipmi_bmc.0/guid)?","why_it_matters":"L05 forbids sizing reads from st_size. Confirming the 0/4096 pattern on the actual target kernel (6.8.0-139) rather than only on 6.18-microsoft removes the last dependence on the WSL2 repro for this law.","acceptable_evidence":"stat -c '%s %n' for each path.","suggested_safe_probe":"stat -c '%s %n' /sys/class/dmi/id/sys_vendor /sys/block/nvme0n1/size /proc/cpuinfo /proc/self/mountinfo /sys/devices/platform/ipmi_bmc.0/guid 2>&1","blocking":false}
```
