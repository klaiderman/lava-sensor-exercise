# REVIEW_FINDINGS — independent review of `sensor/` (code-reviewer, Fable 5.1, 2026-09-09 ~05:10Z)

Reviewed: the working tree as of 05:01Z (test binaries cross-compiled then; `go vet` clean; probe/scan/checks/cmd
test binaries all PASS under WSL as uid 1000) plus `reports/real_host/findings.json` (26 checks, 10/11/5, exit 0),
which was produced by the pre-fix binary. During the review the author landed UNCOMMITTED edits to
`remote_access.go` (05:04), `scan/check.go` (05:04), `storage.go` (05:03), `secrets.go` (05:06) and a new
`fixbatch1_test.go` (05:08). Those edits were read, not tested; each finding says whether the live tree already
addresses it. Six adversarial fixtures of my own were run under WSL (uid 1000) from a scratch copy of the module
(`reports/review/sensorcopy`, never `sensor/`); results are in the Adversarial fixtures section.

## Findings (ranked)

### C1 - CRITICAL - SSH_POLICY_IN_FORCE reports FAIL on the real host from a sub-second precision artefact
- `sensor/internal/checks/remote_access.go` (05:01 tree, lines 291-303): `delta := started.Sub(newest); if newest.After(started) -> Fail`.
  `started` comes from `systemctl show -p ActiveEnterTimestamp` (whole seconds); `newest` is an lstat mtime (nanoseconds).
- Real host: newest_config_mtime = 2026-09-08T17:37:29Z, service_active_enter = 2026-09-08T17:37:29Z, delta_seconds = 0,
  detail "modified 0s after ActiveEnterTimestamp ... the running daemon is enforcing something other than what is on disk".
  The evidence carries no ordering; the verdict asserts one. Registry 5.3 predicted pass. Sensor bug, not a host fact.
- Violates L41 (an ordering derived from two instruments of different resolution) and the evidence-supports-verdict rule:
  a false fail (medium) on a healthy machine.
- Live tree: ADDRESSED - `serviceStartTime()` uses `*Monotonic + /proc/uptime` (100 ms resolution); a same-resolution delta
  yields unknown / TIMESTAMP_RESOLUTION (new constant in scan/check.go). Not re-run here. Nit: TIMESTAMP_RESOLUTION widens
  the closed reason vocabulary (L07/L35) - record it in EVIDENCE_MODEL section 7.
- Regression test: Chtimes(sshd_config, T+0.4s) with stub ActiveEnterTimestamp = T (whole second) must not be fail.
- Consequence: `reports/real_host/findings.json` contains a false fail and must be regenerated.

### C2 - CRITICAL - PROVISIONING_DATA_PROTECTION fails every default cloud-init host
- `secrets.go` (05:01 tree) `inspect()` lines 401-433: any other-readable artifact is Adverse; the fail branch fired on
  `/run/cloud-init/instance-data.json` (0644 by cloud-init design - the redacted copy; the sensor itself recorded
  redaction_observed: true), the package-shipped `/etc/cloud/cloud.cfg.d/*.cfg` (0644 by design; no injection key names were
  found - no `injection_key_names_in_*` field was emitted), even `README`, and the 0755 `/var/lib/cloud/instances/<id>` dir.
- Registry 2.2 FAIL condition is "artifact that can carry injected credentials ... non-empty user-data, seed data, or a drop-in
  containing an ssh_authorized_keys/password/chpasswd key name"; it predicted pass on this host and lists instance-data.json
  0644 self-redacting as acceptable. L24 (the software's own documented permission rule) violated.
- ADV-2 reproduced: default Ubuntu layout -> fail POLICY naming README. False fail (medium) on every Ubuntu cloud image.
- Live tree: ADDRESSED - payload vs public-by-design classes; drop-ins promoted only on key names. Not re-run here.
- Regression test: ADV-2 (`TestADV_Provisioning_DefaultCloudInitLayoutIsNotAFail`) verbatim.

### H1 - HIGH - PRIVATE_KEY_MATERIAL_EXPOSURE passes while a scan root (/root) was unreadable
- `probe/walk.go:46` `Complete()` = BudgetExhausted=="none" && Errno=="" - it ignores UnreadableDirs. `secrets.go:163` relies
  on it, so the /root walk (entries_scanned: 1, unreadable_dirs: ["/root"]) counts as complete and the detail says "every
  enumeration completed". Real host: pass with /root and /etc/ssl/private unreadable.
- Registry 2.2 UNKNOWN condition: "a scan root is unreadable (EACCES - e.g. /root: present, contents unknown, never clean)";
  DESIGN_LAWS fixture unreadable-home-not-clean; L25. In the same category and for the same /root, CREDENTIAL_FILE_EXPOSURE
  reports unknown/EACCES - the two checks contradict each other on one fact.
- ADV-3 reproduced: a world-readable /root/.ssh/id_ed25519 behind a 0000 /root -> pass, "every enumeration completed".
- The registry's own 5.3 row says "p (scope printed)", contradicting its 2.2 rule; the sensor followed the weaker one.
- Patch (secrets.go, privateKeyMaterialExposure.Run): `if !res.Complete() || len(res.UnreadableDirs) > 0 { incomplete = true }`
  and report reason EACCES (not BUDGET_EXHAUSTED) when the cause is a denied directory; keep the walk table as the scope.
  Or add the condition to WalkResult.Complete() itself after auditing its other callers.
- Live tree: NOT addressed (live secrets.go:164 unchanged).
- Regression test: ADV-3 verbatim.

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

## Verified as correct (spot checks that could have lied and did not)
- Runner: Setpgid + killGroup(-pid) + ESRCH->ErrProcessDone + WaitDelay 2 s + capped writers that kill on overflow + stdin
  /dev/null + fixed env; ErrWaitDelay -> TIMEOUT never FAIL; ExitError vs fork-error split (EACCES on a non-executable binary).
- Reader: O_RDONLY|O_NONBLOCK|O_CLOEXEC (+O_NOFOLLOW outside the roots), fstat-on-fd IsRegular, cap+1 truncation, caps from
  policy never st_size; os.Root for /sys and /proc with the degradation recorded; ReadOOB abandons (never joins) its goroutine.
- Engine: one finding per check under panic / deadline cut / early return; load-bearing downgrade before LD-2; sort by
  (category, check_id); self-check never suppresses output (writes, exit 1); exit codes 0/1/2 independent of verdicts.
- Machine: host_id = HMAC-SHA256 over machine-id and the raw id is absent from the artifact (ADV-5 + author test);
  size_bytes = sectors x 512; loop/ram/zram excluded; cores basis sysfs-topology; unknown strings are the literal "unknown"
  with a *_source sibling; missing size -> 0 with size_source "none (ENOENT)".
- No hostname/vendor/customer string in check logic (grep clean; Debian/Ubuntu only selects a cited default per L19).
- Real host: BMC_* (5 pass), BOOT_CHAIN fails (SecureBoot byte 4 = 0, SetupMode = 1, lockdown [none], taint 12288 ->
  bnxt_en OE, initrd 0644 + ESP fmask 0022), STORAGE_POSTURE (no CRYPT- mapping, single backing disk, nvme1n1 idle),
  SSH_ROOT_LOGIN unknown (EACCES on both authorizedkeysfile expansions), LOGIN_AND_ESCALATION unknown - each verdict is
  supported by its own observation rows.

## Adversarial fixtures run (WSL, uid 1000; scratch copy of the module)
| id | fixture | expected by laws/registry | observed | status |
|---|---|---|---|---|
| ADV-1 | sshd_config mtime T+0.4 s, ActiveEnterTimestamp = T | not fail | my stub was keyed to the 05:01 systemctl argv; the live check asks for *Monotonic properties, so the harness returned unknown/UTILITY_MISSING. The 05:01 code path is proven by the real-host artifact itself (delta 0 -> fail). | reproduced via the real host |
| ADV-2 | default cloud-init layout: instance-data.json 0644 redacted, drop-ins 0644, user-data 0600 | pass | fail POLICY naming README | bug C2 (fixed in live tree, unverified) |
| ADV-3 | /root 0000 hiding a 0644 private key; /etc/ssh host key 0600 | unknown EACCES | pass "every enumeration completed" | bug H1, open |
| ADV-4 | PasswordAuthentication no + Match Address ... yes; oracle says no | unknown CONTESTED | unknown CONTESTED; SSH_ROOT_LOGIN pass (no root Match) | correct |
| ADV-5 | /sys/block/sda with no size; raw machine-id in fixture | size 0 + source says why; no raw id | size_bytes 0, size_source "none (ENOENT)", raw id absent | correct |
| ADV-6 | ufw unit active, ufw.conf ENABLED=no, global :22 listener | unknown; detail must not say enabled | unknown EACCES, detail "a filtering subsystem is enabled" | misleading, M1, open |

## What I could not verify and why
- The 05:03-05:08 uncommitted edits (remote_access.go, secrets.go, storage.go, scan/check.go, fixbatch1_test.go): read only,
  not built or run. The test binaries under sensor/bin/review/ predate them; reports/real_host/findings.json predates them too.
- ADV-1 against the live code (stub key mismatch, see table). The new logic reads correctly (delta within resolution -> unknown).
- Live ACL decoding with named entries (no setfacl in WSL/Docker; the author notes the same gap).
- Behaviour as root (skipIfRoot fixtures; nothing privileged was run) - M2's device-open concern is from reading only.
- internal/lab (in flux, excluded by instruction). Docker profiles A/B/C not re-run (TEST_REPORT's claim accepted).
- The background WSL run of the full original suite produced no captured output; the foreground re-run of all four binaries
  (probe, scan, checks, cmd) printed PASS.

## Verdict: FIX-THEN-SHIP
Blocking before the tarball:
1. Regenerate reports/real_host/findings.json with a binary containing the C1 and C2 fixes and re-validate; the current
   artifact carries two false fails (SSH_POLICY_IN_FORCE, PROVISIONING_DATA_PROTECTION).
2. H1: PRIVATE_KEY_MATERIAL_EXPOSURE must report unknown/EACCES when any walk root or subtree was denied (consistent with
   CREDENTIAL_FILE_EXPOSURE and registry 2.2); add ADV-3 as a regression test.
3. M1: stop calling ufw "enabled" when ENABLED=no; derive the reason from the iptables denial; add ADV-6.
4. M2: take MEDIA_HEALTH's reason from the observation; state in evidence that the SMART fallbacks open the device via a child
   (or gate them on EUID != 0).
5. Fix the registry summary line (13/8/4) and the CREDENTIAL_FILE_EXPOSURE 5.3 row; record TIMESTAMP_RESOLUTION in the
   reason vocabulary.
Non-blocking: M3 label, M4/L1/L2/L4 hygiene.
