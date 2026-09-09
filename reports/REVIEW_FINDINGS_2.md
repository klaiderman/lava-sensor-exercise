# REVIEW_FINDINGS_2 — independent adversarial review after fix batches 1+2

Reviewer: `code-reviewer` (fresh context; did not write the code). Date: 2026-09-09.
Method: read `internal/probe`, `internal/scan` and every check against CHECK_REGISTRY; `go vet` +
`go test ./... -count=1` on Windows; every test binary and the sensor cross-compiled for linux/amd64 and run
under WSL as uid 1000 (incl. a real scan of the WSL host); 11 new adversarial fixtures compiled from a scratch
copy of the module (never inside `sensor/`), log in `reports/review2/r2_adversarial.log`.
Scratch artifacts: `reports/review2/` (win_vet_test.log, *.wsl.log, lab.mntc.log, findings.wsl.json, r2checks.test).

Verdict: **DO-NOT-SHIP**. Counts: Critical 4 · High 4 · Medium 6 · Low 3.

## Critical — the sensor lies: false PASS on exposed secrets, false FAIL on healthy stock machines

### C1. PRIVATE_KEY_MATERIAL_EXPOSURE drops any candidate it cannot read itself — false PASS
- `sensor/internal/checks/secrets.go:213-219` (`classifyHeader` returns "unknown" on EACCES, then `continue`).
- Scenario: `/etc/ssl/app.key` mode 0040 (or 0640 root:ssl-cert with members): readable by the group, not by the
  sensor uid. The Stat succeeded (mode and gid are known), the 64-byte sniff got EACCES, the candidate is silently
  dropped: not a hit, not a boundary. Output: `pass` "0 candidate(s) classified". Reproduced by fixture R2-A.
- Violates: EACCES is not absent (CLAUDE.md evidence semantics, L39); absence only from a successful listing (L25).
- Patch: when `cObs.Status != OK` keep the hit with `MagicClass: "unclassified (<errno>)"`, run `effectiveReaders`
  on the stat metadata and either fail (adverse mode) or append a boundary (`p+" header ("+errno+")"`) so the
  verdict becomes unknown. Never `continue` on a non-OK sniff.
- Regression: R2-A `TestR2_PrivateKey_UnreadableGroupReadableKeyIsDropped` expects fail or unknown, never pass.

### C2. Group readability ignores primary-group membership — false PASS across SECRETS_ON_DISK and BMC
- `secrets.go:98-120` (`effectiveReaders`), same logic in `bmc.go:302-316` and `storage.go:802-830`.
- "The group has members" is computed from `/etc/group` field 4 only. An account whose PRIMARY gid (passwd
  field 4) is the file group is a member and reads the file. Fixture R2-B: `mallory:x:1001:<gid>` in passwd,
  `secret:x:<gid>:` in group, key 0640 → "group secret is empty, so this is owner-only in practice" → `pass`.
- Violates: L42/L43 as cited by the code (the empty-group shortcut is only valid when primary gids are counted).
- Patch: in `Env.Groups()` (`scan/check.go:462`) also parse `/etc/passwd` and add every account to the effective
  member set of its primary group; use that set in `effectiveReaders`, `openableByUs` and the BMC node check.
- Regression: R2-B `TestR2_PrivateKey_PrimaryGroupMemberInvisible` expects fail.

### C3. SYSTEM_SECRET_STORE_PROTECTION fails stock Debian/Ubuntu on `/etc/sudoers.d` 0755 — false FAIL, severity high
- `secrets.go:757` (`{"/etc/sudoers.d", "not other-readable or other-writable", true}`) and `secrets.go:803-810`
  (dirTravel: adverse on `o+x`).
- The sudo package ships `/etc/sudoers.d` as `drwxr-xr-x root:root` with 0440 files inside. Verified on the real
  WSL host (Ubuntu 26.04, sudo 1.9.17p2-1ubuntu3): the sensor reports **fail / high** "a system secret store is
  reachable beyond root: /etc/sudoers.d (other-traversable)" (`reports/review2/findings.wsl.json`). Fixture R2-D2
  reproduces. The Lava host has 0750, so the host run hides this; the next customer machine will show it.
- Violates: fail on a healthy machine; the rule text itself (readable/writable) does not match the code (traversable).
- Patch: for directory stores fail on `o+w`, or on `o+x` together with at least one other-readable child (list the
  directory; a denied listing is the boundary, not a pass). Drop the traversable rule for `/etc/sudoers.d`.
- Regression: R2-D2 `TestR2_SystemStore_StockSudoersDirIsNotExposure` expects not fail; add a 0644 drop-in case that expects fail.

### C4. CREDENTIAL_FILE_EXPOSURE fails `~/.ssh/config` 0644 — false FAIL, severity high
- `secrets.go:317` declares the rule "not group- or world-writable"; `secrets.go:392-403` derives `adverse` from the
  READ bits via `effectiveReaders`. Every user with a 0644 `~/.ssh/config` (the usual default) produces `fail`
  "readable by any local user — OpenSSH StrictModes". Reproduced by R2-C.
- Patch: add a `kind` to `credentialRule` (readable vs writable); for `.ssh/config` set adverse only when `mode&0o022 != 0`.
- Regression: R2-C `TestR2_Credential_SSHConfigWorldReadableIsNotAViolation` expects pass; a 0664 sibling expects fail.

## High

### H1. The entailment gate is a phrase blacklist; a PASS with zero load-bearing observations bypasses both gates
- `sensor/internal/scan/entailment.go:47-68` (`completenessClaims`), `finalize.go:30` (fires only on a listed phrase),
  `finalize.go:44-45` (downgrade needs at least one load-bearing observation). `LoadBearingIf` (`check.go:55`) is opt-in.
- Fixture R2-G: `Pass("no exposed key material was found anywhere on this machine")` plus one EACCES observation that
  is not load-bearing → `pass`, `entailment_violation=false`. In the real WSL artifact SYSTEM_SECRET_STORE_PROTECTION
  passes with `load_bearing_total: 0`, so rule (a2) can never fire for it.
- Violates: the claim in entailment.go that over-claims are impossible; L07/L39.
- Patch: in `finalize`, treat `Status==pass && LoadBearingTotal==0` as a violation (flag it and downgrade), and add
  a roster test asserting each check marks at least one load-bearing observation on every pass path. Consider
  regex claims (`no .* (found|exists|present)`) in addition to the fixed phrases.
- Regression: R2-G `TestR2_Engine_AbsenceProseWithoutListedPhrasePasses` expects a violation flag or status != pass.

### H2. An unreadable `/etc/group` is treated as "every group is empty" — false PASS
- `secrets.go:104` iterates `env.Groups().Groups` and never consults `env.Groups().Obs.Status` (`scan/check.go:462-486`).
- Fixture R2-D: `/etc/group` mode 0000, `/etc/shadow` 0640 → "group is empty, so owner-only in practice" → `pass`.
- Patch: `effectiveReaders` returns `desc="unknown (/etc/group <reason>)"` and an `undetermined` flag when
  `Groups().Obs.Status != OK`; every caller routes it to unknown. Regression: R2-D expects unknown.

### H3. The lab hard gate is RED on the current source while TEST_REPORT.md says green
- Windows `go test ./... -count=1`: `internal/lab` FAILS (`TestProfileMatrix_ProfilesBC_HardGate/profileC`;
  `reports/review2/win_vet_test.log`). Under WSL from the repo path, `TestProfileMatrix_ProfileA_HardGate` and
  `ProfilesBC_HardGate` fail for my cross-compiled binary and for the author-built `sensor/bin/lab/lab.test` (06:47);
  only the older `sensor/bin/wsltest/lab.test` (05:53, before fix batch 2) passes (`reports/review2/lab.mntc.log`).
  Profile A: 10/9/7 (author binary), 9/9/8 and 5/1/20 (mine, two runs; see "could not verify").
  Concrete mismatches: PROVISIONING_DATA_PROTECTION (H4), PRIVATE_KEY_MATERIAL_EXPOSURE (M4),
  BMC_DEVICE_NODE_ACCESS (M2), and profile C SSH checks pass from the oracle where §5.3 still says unknown (registry stale).
- Violates: process gate (tests must pass); `reports/TEST_REPORT.md:22-24,43-61` describes a state that no longer exists.
- Patch: re-run the lab under WSL after every fix batch; reconcile `research/CHECK_REGISTRY.md §5.3` with the
  behaviour the fix batches changed on purpose; make the lab fixture builder deterministic (see "could not verify").

### H4. PROVISIONING_DATA_PROTECTION is `unknown` on every host with a 0700 `/root` — under-claim, contradicts the registry
- `secrets.go:522` (`/root/anaconda-ks.cfg` in the fixed list) and `secrets.go:579-586` (any non-OK stat → undetermined).
- On WSL (`findings.wsl.json`) and, by the same logic, on the Lava host, the only failing load-bearing observation is
  `/root/anaconda-ks.cfg (EACCES)`. A stat-able 0700 root:root `/root` proves nothing beneath it is readable beyond
  root: the fallback exists (stat the parent) and is not used. CHECK_REGISTRY §2.2 predicts **pass** on the host.
  Fixture R2-E2 reproduces (`unknown/EACCES`).
- Patch: on EACCES for a payload path, stat the nearest existing ancestor; if it is not traversable by other (and by
  a populated group), record a clean load-bearing observation "not exposed beyond owner (parent <dir> mode <m>)".
- Regression: R2-E2 `TestR2_Provisioning_RootDir0700MakesWholeCheckUnknown` expects pass.

## Medium

### M1. REMOTE_LISTENING_SURFACE hides a found adverse listener when the table is truncated — under-claim
- `remote_access.go:557` marks the tcp table load-bearing whenever it read OK; a >1 MiB `/proc/net/tcp` is
  `Truncated`, so `finalize` (a2) downgrades even a **fail** built on a telnet listener that was inside the prefix.
  Fixture R2-F: telnet on 0.0.0.0:23 in the read prefix → `unknown / BUDGET_EXHAUSTED`.
- Patch: like the other checks, `r.LoadBearingIf(len(adverse)==0, tcpSources...)`; a positive observation stands.
- Regression: R2-F `TestR2_Listeners_TruncatedTableHidesFoundTelnet` expects fail.

### M2. BMC_DEVICE_NODE_ACCESS turns a proven absence into `unknown` with a self-contradicting detail
- `bmc.go:353` marks the three ENOENT stats load-bearing but never sets `AbsenceProven`, so `clean()` rejects them
  and the pass is downgraded: detail reads "no in-band BMC device node exists ... [downgraded from pass: ...
  (/dev/ipmi0: ENOENT)]" (`findings.wsl.json`; fixture R2-I; also the lab profile B gate). Any machine without a BMC.
- Patch: `st.AbsenceProven = st.Status == probe.StatusENOENT` at `bmc.go:279`, mirroring `secrets.go:573`.
- Regression: R2-I `TestR2_BMCNode_ProvenAbsentIsDowngraded` expects pass.

### M3. PROVISIONING_DATA_PROTECTION promotes a public drop-in to payload on a COMMENT — false FAIL
- `secrets.go:537` (`injectionKeys` includes the bare word `password`) and `secrets.go:646-651` (substring match on
  the whole file body, comments included). A 0644 `/etc/cloud/cloud.cfg.d/*.cfg` whose comment says
  "ssh_pwauth is left at the default; no password is set here" becomes payload and fails. Fixture R2-E reproduces.
- Patch: strip `#` comments before matching and match keys only at line start (`^\s*key\s*:`).
- Regression: R2-E expects pass; a drop-in with a real `ssh_pwauth: true` line expects fail.

### M4. PRIVATE_KEY_MATERIAL_EXPOSURE on the Lava host will now be `unknown` (EACCES on /root) — registry says pass
- `secrets.go:198-200,268-275`: `/root` is a walk root, its listing is denied, the boundary makes the verdict unknown.
  This is the honest answer (the pre-fix `pass` with "121 candidates" was the lie); but CHECK_REGISTRY §2.2/§5.3 still
  predicts pass and the lab gate encodes it. Reconcile the registry, or split the check into a covered-scope verdict
  plus a `/root` boundary. Not a sensor bug; a shipping-consistency blocker.

### M5. A walk root on a hung network filesystem blocks the whole scan and produces no output at all
- `secrets.go:130-133` puts `/home`, `/srv`, `/opt` in `keyWalkRoots`; `walk.go:127-182` refuses to CROSS into another
  filesystem but happily STARTS on one; `read.go:158-215` and `Stat` have no deadline (only `ReadOOB` does). A D-state
  NFS/CIFS home (server down) hangs `Lstat`/`open`, `scan.Run` never returns and `main.go:112-154` never writes the file.
  The 60 s scan deadline "bounds scheduling", not a stuck syscall. Not observable on the Lava host (no network
  storage) but a real customer-host bound.
- Patch: read `/proc/self/mountinfo` fstype of each walk root and skip network/fuse types with a recorded boundary;
  or run each Walk in a goroutine with a timer like `ReadOOB` and abandon it.

### M6. BMC_CLIENT_TOOLING_INVENTORY: all six binary dirs ENOENT → `unknown / EACCES` with an empty "( )"
- `bmc.go:469-472`: `unreadable` is empty when every dir was ENOENT, yet the reason is hard-coded EACCES.
  Lab profile B shows it. Use `reasonOf(...)` over the stats (ENOENT) and list `scanned`/absent dirs.

## Low

### L1. `errSymlinkDenied` is not classified: reason "UNSUPPORTED" leaks outside the closed vocabulary
- `read.go:32,229-230` returns `errSymlinkDenied`; `observation.go:134-181` has no case for it → `StatusUnsupported`
  with empty errno → `Reason()` = "UNSUPPORTED" (not in the check.go:86-107 vocabulary). Triggered by a symlinked
  `/etc/ssh/sshd_config` (NixOS-style layouts) read with a non-Follow policy. Add a case mapping to `ELOOP`/`POLICY`.

### L2. The one privileged child: `passwd -S` is a setuid-root binary (`remote_access.go:939`)
- Harmless (reports the caller only, read-only) but it is the single place the sensor executes code as root.
  Document it, or read `/etc/shadow` status via the existing unknown path instead.

### L3. Windows `go test ./...` is red (profile C hard gate) and TEST_REPORT.md:43-54 says all five packages pass
- `reports/review2/win_vet_test.log`. Cause: profile C relies on chmod 0000, which Windows ignores; the test should
  `requireLinux` or the report should say the Windows run is not authoritative for that package.

## Verified and found sound (attacks that did not land)
- Exec bounding (`probe/exec.go`): Setpgid + group SIGKILL, WaitDelay, capped writers that kill on overflow,
  stdin /dev/null, fixed `PATH`/`LC_ALL` env, binary resolution from a fixed directory list (inherited PATH ignored),
  UTILITY_MISSING vs EACCES vs EXEC_ERROR separated, stderr-based privilege denial reclassification.
- Read gating (`probe/read.go`): O_NONBLOCK|O_CLOEXEC(|O_NOFOLLOW outside os.Root), fstat-on-fd IsRegular,
  cap from policy with cap+1 detection, user-writable-tree symlink refusal, short reads classified not trusted.
- `ReadOOB` abandons the goroutine, never joins; BMC attributes are the only device-adjacent reads.
- No device node is opened by the sensor or by any child (`nvme`/`smartctl` are inventoried by stat only).
- No hostname/vendor/customer string in check logic (grep clean; the only distro gate is os-release ID for sshd defaults).
- host_id is an HMAC over machine-id/product_uuid, never the raw value; `size_bytes = sectors x 512`;
  loop/ram/zram excluded; no empty string in `machine` (WSL artifact).
- Engine: one finding per check under panic/deadline (`engine.go:77-122`), deterministic ordering, self-check never
  suppresses output, exit codes as documented.
- Fixture R2-H (Include written inside a Match block, included file sets PermitRootLogin yes, oracle says no) →
  `unknown / CONTESTED`. Correct.

## Adversarial fixtures run (`reports/review2/r2_adversarial.log`; source in a scratch copy, not in sensor/)
| id | fixture | expected | observed |
|---|---|---|---|
| R2-A | key 0040, group with 2 members, sniff EACCES | fail/unknown | **pass** |
| R2-B | key 0640, group empty in /etc/group, user with that primary gid | fail | **pass** |
| R2-C | ~/.ssh/config 0644 | pass | **fail** |
| R2-D | /etc/group 0000, /etc/shadow 0640 | unknown | **pass** |
| R2-D2 | /etc/sudoers.d 0755 with 0440 README (stock sudo) | pass | **fail** |
| R2-E | cloud.cfg.d drop-in 0644 with a comment mentioning ssh_pwauth/password | pass | **fail** |
| R2-E2 | /root 0700 (every normal host) | pass | **unknown/EACCES** |
| R2-F | /proc/net/tcp > 1 MiB with telnet 0.0.0.0:23 in the prefix | fail | **unknown/BUDGET_EXHAUSTED** |
| R2-G | synthetic pass with unlisted absence prose, 0 load-bearing obs, EACCES present | violation | **pass, no flag** |
| R2-H | Include inside Match, included PermitRootLogin yes | unknown/CONTESTED | unknown/CONTESTED (ok) |
| R2-I | no BMC: /dev listable, all node spellings ENOENT | pass | **unknown/ENOENT** |

## What I could not verify and why
- The real host: no SSH from this role. The pre-fix `reports/real_host/findings.json` (old binary) was used only for
  host shape. Predicted post-fix host deltas from code reading: PROVISIONING_DATA_PROTECTION → unknown (H4),
  PRIVATE_KEY_MATERIAL_EXPOSURE → unknown (M4), SSH_POLICY_IN_FORCE → pass or TIMESTAMP_RESOLUTION; the remaining 23
  should match the registry.
- Lab profile A distribution is not reproducible for my binary (5/1/20 in a full-suite run from a /tmp copy, 9/9/8
  isolated from the repo path; author binary 10/9/7). Suspect: fixture materialisation on drvfs or cross-test
  interference in `internal/lab` — not diagnosed within the time box. Whatever the cause, the gate is red in every run.
- Hung-network-filesystem behaviour (M5) is argued from code, not reproduced (no NFS in WSL).
- Whether `/etc/sudoers.d` is 0750 or 0755 on Ubuntu 24.04.4 specifically: the Lava host has 0750 (HOST_SUMMARY);
  Ubuntu 26.04 (WSL) has 0755; the false FAIL is proven for the latter.

## Verdict: DO-NOT-SHIP
Blocking: C1, C2, C3, C4 (false PASS on exposed keys; false FAIL on stock machines), H1 (gate bypass), H3 (red test
gate + stale TEST_REPORT), H4/M4 (registry vs sensor disagreement must be reconciled before the final host run).
After those: FIX-THEN-SHIP with M1, M2, M3 fixed; M5/M6 and the Lows can follow.
