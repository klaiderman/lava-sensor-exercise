
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
