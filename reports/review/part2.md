
### H2 - HIGH - Registry prediction summary is arithmetically wrong; per-check disagreement analysis
- `research/CHECK_REGISTRY.md:1593` says "9 pass / 8 fail / 8 unknown" but its own 5.3 column A sums to 13/8/4 (25 checks).
  Against the table, reality (26 checks, 10/11/5) differs in exactly four rows:

  | check | predicted | real | verdict |
  |---|---|---|---|
  | SSH_POLICY_IN_FORCE | p | f | sensor bug (C1) |
  | PROVISIONING_DATA_PROTECTION | p | f | sensor bug (C2) |
  | CREDENTIAL_FILE_EXPOSURE | p | u (EACCES /root) | registry error: its 2.2 UNKNOWN rule says unreadable home => unknown while 5.3 said pass; the sensor is right by the law. Fix the row and make H1 consistent with it. |
  | BOOT_KERNEL_DRIFT | (absent) | f | new check (OPEN-3 adopted); the fail is supported (6.8.0-139 running, 7.0.0-31 installed, /boot symlink -> 7.0). |

- New host information surfaced by the run (not in HOST_SUMMARY): `/etc/ufw/ufw.conf ENABLED=no` (ufw unit active, ufw itself
  disabled); `/etc/cloud/cloud.cfg.d/10_tinkerbell.cfg` is 0600 (the only restricted drop-in); the ACL xattr on /dev/ipmi0,
  /etc/shadow and /etc/sudoers.d is ENODATA (OR-OPEN-2 settled: no ACLs); os.OpenRoot("/proc") works on 6.8.0-139
  (degradations: [], OR-OPEN-3 settled); `sshd -G` reports `authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2`.

### M1 - MEDIUM - HOST_FIREWALL_STATE detail contradicts its own evidence (ufw ENABLED=no read and ignored)
- `remote_access.go:892-894, 984-988`: anyActive comes from `systemctl is-active ufw == active`; the parsed
  config_values.ENABLED = "no" is emitted but never consulted. Real-host detail: "a filtering subsystem is enabled but its
  effective ruleset is not readable" - ufw's own config says it is NOT enabled (the unit is a oneshot that exits early when
  ENABLED=no). Reason EXECUTION_ERROR although iptables' stderr in evidence says "Permission denied (you must be root)".
- ADV-6 reproduced. unknown is still the right status (the kernel ruleset is unreadable; something else could have loaded
  rules), but the detail asserts a false fact and the reason is the least actionable of the three available.
- Patch: `ufwEnabled := s.ConfigValues["ENABLED"] == "yes"`; when the unit is active and ufw is not enabled, say "ufw unit
  active but ufw.conf ENABLED=no: ufw loads no rules; kernel ruleset unreadable (iptables: Permission denied)"; map a stderr
  containing "Permission denied" to reason EACCES; Stat /etc/ufw/user.rules to record the 0640 boundary the registry cites.
- Live tree: NOT addressed. Test: ADV-6 verbatim.

### M2 - MEDIUM - MEDIA_HEALTH_VISIBILITY: reason not derived from an observation; children open device nodes
- `storage.go:727/732`: Unknown(scan.ReasonEACCES, ...) is hard-coded while the observations are smartctl -> UTILITY_MISSING and
  `nvme smart-log` -> EXEC_ERROR exit 1 (stderr "Permission denied"). Take the reason from the observation (reasonOf(nobs)),
  or use EACCES only when the errno/stderr says so.
- Safety: `nvme smart-log /dev/nvme0n1` and `smartctl -H -j /dev/...` make a CHILD open the device and issue an admin
  passthrough (Get Log Page). Denied at uid 1000, but run as root or by a `disk` member the behaviour changes in the unsafe
  direction. The CLAUDE.md invariant "only regular files are opened (never device nodes)" holds for the sensor process, not
  its children; the registry permits the exec, so either state it in evidence (device_opened_by_child) or gate on EUID != 0.
- Live tree: smartctl JSON is now parsed rather than sniffed (good); the reason and device-open points are NOT addressed.

### M3 - MEDIUM - `sshd -G` is labelled "running daemon" but is an on-disk evaluation
- `remote_access.go:169`, `ssh_root_login.go:70`: source "sshd -G (running daemon)". -G parses the current files with the
  installed binary's defaults; it says nothing about the listening process. The real-host artifact therefore says in one
  finding "the running policy accepts public keys only" and in the next "the running daemon is enforcing something other than
  what is on disk". Rename to "sshd -G (on-disk configuration as the installed sshd resolves it)" and leave the in-force claim
  to SSH_POLICY_IN_FORCE.

### M4 - MEDIUM - Walk never sets CrossedMounts=true; WalkResult.Complete() is too narrow
- `probe/walk.go:124` assigns false on prune (decorative field). Fold into H1: Complete() should also require
  len(UnreadableDirs)==0 (or expose Clean()), and the root-unreadable case should set Errno instead of landing in
  UnreadableDirs with entries_scanned 1.

### L1 - LOW - `probe/acl.go:120` comment says "without following the final symlink" but syscall.Getxattr follows symlinks
- Use syscall.Lgetxattr to match the lstat-based metadata, or fix the comment. ReadACL also bypasses os.Root for /sys and /proc
  paths (no caller does that today).

### L2 - LOW - resolveBinary falls back to exec.LookPath, i.e. the sensor's inherited PATH
- `probe/exec.go:260`; the comment says "without consulting the caller's PATH". A user-writable dir early in PATH could supply
  nvme, iptables, ss, mokutil once the four system dirs miss. Not an escalation (same uid) but it lets a local user shape
  evidence. Drop the fallback; the system dirs plus /usr/local/{sbin,bin} are the honest search set.

### L3 - LOW - CREDENTIAL_FILE_EXPOSURE unreadable_homes = ["/", "/root", "/root"]; /bin inspected as a home
- parentDir(parentDir("/root/.pgpass")) = "/" plus duplicates; `sync:/bin` was treated as a login home. ADDRESSED in the live
  tree (credentialHomes: dedup, placeholder homes skipped).

### L4 - LOW - PRIVATE_KEY_MATERIAL_EXPOSURE lists 121 CA-bundle symlinks (mode 0777, not-a-regular-file) as candidates
- Noise in private_key_files; filter symlinks into a separate skipped_non_regular count.

### L5 - LOW - Staticcheck: 2x U1000 in internal/lab/support_test.go - already removed per TEST_REPORT (live diff confirms).
