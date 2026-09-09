# REVIEW_FINDINGS_4 — fresh re-verification after fix batch 4 (checkpoint 18, HEAD a17501d)

Reviewer: `code-reviewer` (review 4; fresh context; did not write the code). Date: 2026-09-09.
Scope: closure of every REVIEW_FINDINGS_3 item (C1, H1-H3, M1-M5, L1-L6) by reading the diffed code AND re-running the review-3 fixtures re-keyed to the current code; new attacks on the batch-4 semantics; roster-wide entailment gate against HOST_SUMMARY facts and stock Ubuntu 24.04 / RHEL 9 / Alpine.

Gates run (scratch copy `reports/review4/sensorcopy/`, never inside `sensor/`): `go vet ./...` clean; cross-compiled `probe/scan/checks/cmd` test binaries under WSL (kernel 6.18, uid 1000, tmpfs `/tmp`): all 4 PASS; production `sensor.linux` run as uid 1000: 26 checks, exit 0, 2.3 s, output 0600, 9 pass / 2 fail / 15 unknown, `self_check: pass`, every reason inside `scan.ReasonVocabulary`, 0 `entailment_violation` (`reports/review4/findings.wsl.json`). Review-3 fixtures R3-A..I, R2-A..I, ADV-1..6 ported (NOT "unmodified" as IMPLEMENTATION_NOTES claims: `gidStr`, `TestR3A_*`, `TestR3D_*` collide with `fixbatch4_test.go` and had to be renamed) plus 10 new R4 fixtures: log `reports/review4/r4_adversarial.log`, sources `reports/review4/sensorcopy/internal/checks/zz_r4_test.go`.

## Verdict: FIX-THEN-SHIP

CURRENT CRITICAL: 0, CURRENT HIGH: 3

Every review-3 blocking item is closed and re-verified by fixture. None of the new findings is false on the Lava host as described in `state/HOST_SUMMARY.md` (nsswitch files-only, no uid alias, `/root` 0700, `/etc/ssl/private` a real 0710 directory) nor on a stock Ubuntu/RHEL/Alpine image, so the host run can proceed. The three Highs are false confident verdicts in realistic administrator configurations and block calling the sensor generic: H-A, H-B, H-C.

## Closure table for REVIEW_FINDINGS_3 (observed on the CURRENT code, WSL uid 1000)

| item | status | observed evidence (r4_adversarial.log) |
|---|---|---|
| C1 owner counted as reader (0440 root:root) | CLOSED | R3-C: SECRET_STORE `pass` "3 inspected"; PRIVATE_KEY (0640 key, owner sole member) `pass`. `check.go:681-693` subtracts `OwnerName`. Residual: subtraction is by NAME (H-B). |
| H1 undetermined group model -> fail | CLOSED | R3-B x4: SECRET_STORE `unknown/EACCES` "(undetermined: the file is group-readable and the account model is unavailable (/etc/passwd EACCES))"; PRIVATE_KEY `unknown/ENOENT` naming the candidate. `secrets.go:405,1151`, `bmc.go:318` gate on `Determined`. |
| H2 read bit used for ancestor protection | CLOSED | R3-A: PRIVATE_KEY `unknown/EACCES` "1 directory/ies under /etc/ssl could not be read", `scan_roots_protected` empty; SECRET_STORE `unknown/EACCES` "the 1 effective member(s) of group sslcert other than the owner can traverse it (postgres)"; `protected_by_ancestor`=0. Residual: ACLs ignored (H-A). |
| H3 SECRET_STORE never opted the denial out | CLOSED | R3-I: `pass` "2 inspected, 1 shielded", no downgrade text; `recordProtection` `secrets.go:179-194`. WSL artifact: SYSTEM_SECRET_STORE_PROTECTION `pass` lb 15/15. |
| M1 walk obs copied before Truncated cleared | CLOSED | `secrets.go:368` `r.Add(obs)` now after the boundary loop; R3-A no longer says BUDGET; R3-I pass without downgrade. |
| M2 mountinfo EACCES hides a found key | CLOSED | R3-E: `fail/POLICY` "any local user can read it (mode 0644)"; `secrets.go:445-448` includes `/proc/self/mountinfo`. |
| M3 symlinked /home not walked, ENOTREG leak | CLOSED (follow path); residual M-B | R3-G: `fail/POLICY` naming `/data/homes/alice/.ssh/id_rsa`; `NormalizeReason` `check.go:133-147`; 0 vocabulary leaks in the WSL artifact. Refusal path reason class wrong (M-B). |
| M4 /root 0550 under-claim | CLOSED | R3-D: PROVISIONING `pass`, CREDENTIAL `pass` "11 shielded". Prose problem carried into M-C. |
| M5 protection decisions not observations | PARTLY CLOSED | `protectionFromDenial` returns ancestor stats and `recordProtection` adds them load-bearing (`secrets.go:180-182`); but PRIVATE_KEY's unreadable-dirs loop opts them out (`:348`) and the protected-root shortcut opts its own stat out (`:285`). R4-9: pass whose OK load-bearing observations are `/proc/self/mountinfo` + 11 ENOENT root stats; `/root status=OK lb=false`. Low (L-A). |
| L1 NFS refusal reason class | CLOSED for network; NOT CLOSED for the symlink refusal | R3-F both variants `unknown/NOT_ATTEMPTED`. R4-5/R4-5b (symlink root refused): `unknown/BUDGET_EXHAUSTED` (M-B). The "both refusal paths" claim holds at `probe.Observation.Reason()` but not at `secrets.go:464-472`. |
| L2 prose gate bypass | CLOSED | R3-H: `unknown/PARSE_ERROR`, `entailment_violation=true`, statement names the excused refused search. Side effect: the widened regexp flags the sensor's OWN honest boundary sentence (M-B). |
| L3 SSH_POLICY_IN_FORCE reason vs detail | CLOSED | ADV-1: `unknown/UTILITY_MISSING`; detail agrees. |
| L4 bmc/storage not on the shared model | CLOSED | `bmc.go:311-321` `Env.Accessors`, `!who.Determined` before `who.BeyondOwner`; `storage.go:802` `openableByUs` answers "could THIS identity open it" and says so. |
| L5 absent credential candidates dropped | CLOSED | `secrets.go:637-640` records ENOENT stats; WSL CREDENTIAL lb 24/24. |
| L6 mode-bit rules judged by membership | CLOSED | `secrets.go:551-556` tests `m&0o044` for read rules; only the writability rule consults the model. |
| ADV-3 (/root 0000 hiding a 0644 key -> pass) | by design (row 39) | still `pass` "1 shielded". The design is only sound while the ancestor's mode is the whole story; H-A shows it is not. |

Review-3 "verified sound" items re-checked after the diff: NO_EVIDENCE gate (`finalize.go:61-68`) unchanged, 0 NO_EVIDENCE in the WSL artifact; abandonment shared state (`engine.go`, `Env` sync.Once caches) untouched by batch 4; network-FS refusal (R3-F) still refuses both a root on nfs4 and a diskless nfs4 root.

## New findings (ranked)

### H-A. protectionFromDenial and the protected-root shortcut trust st_mode alone: a POSIX ACL granting a named user `--x` on a 0700-class ancestor is recorded as "cannot be traversed by anyone beyond its owner" — false PASS in all four exposure checks
- `sensor/internal/checks/secrets.go:135-172` (`protectionFromDenial` asks `env.Traversers(st.Meta.Mode, ...)` and never `env.Files.ReadACL(dir)`), `:281-289` (walk-root shortcut, same), consumers `:346-356`, `:647-651`, `:907-911`, `:1123-1127`, `:1204-1206`. `probe/acl.go:41,122-133`: `GrantsNonOwner` is READ-only, so wiring ReadACL in as-is would still miss a traverse-only grant on a directory.
- Reproduction (R4-3, `zz_r4_test.go:93-149`): `/home/alice` mode 0000 + ACL `user:1500:--x` (mask `--x`; kernel shows st_mode 0010), `/home/alice/.ssh/id_rsa` 0644. Observed: PRIVATE_KEY `pass` "1 root(s) or subtree(s) shielded", `scan_roots_protected=[/home/alice (the ancestor /home/alice (mode 010) cannot be traversed by anyone beyond its owner ...)]`, completeness 13/13. Same on `/etc/ssl/private`: SECRET_STORE `pass` "1 shielded", `protected_by_ancestor=1`. Same on `/root` holding `anaconda-ks.cfg`, `.aws/credentials`, `.ssh/id_rsa` all 0644: PRIVATE_KEY `pass`, PROVISIONING `pass`, CREDENTIAL `pass` "11 shielded".
- Expected: not pass; uid 1500 traverses via the ACL and reads a 0644 file. Realistic: `setfacl -m u:www-data:x /home/alice` is the textbook way to serve a home directory; an ACL for a service user on a secrets directory is common. Not the Lava host (`/root` 0700 shows no mask bits).
- A reader is misled by a protection basis that asserts nobody beyond the owner can pass, while the directory's own ACL says otherwise.
- Patch: in `protectionFromDenial` (and the `:281` shortcut) call `env.Files.ReadACL(dir)`; add `GrantsNonOwnerExec` to `probe.ACL` (named `user`/`group`/`other` entry with `Exec`, masked); if set, the ancestor does not shield (record the entry); if `!Determined && Errno != ENODATA`, return `Undetermined` with the errno. Regression: R4-3a/b/c must not pass; a variant with ACL `user:1500:r--` (no x) may remain protected.

### H-B. The owner is subtracted by NAME and non-numeric uid/gid fields parse as 0: a NIS-compat `+::::::` line or any uid-0 alias makes root "another reader" of 0440 root:root — false FAIL on /etc/sudoers
- `sensor/internal/scan/check.go:566-568` (`atoi64("")` -> 0; `g.byUID[uid] = name`, last wins), `:750-759` (`atoi64` returns 0 for any non-digit input), `:681-686` (subtraction compares `name == r.OwnerName`).
- Reproduction (R4-1, R4-2, `zz_r4_test.go:55-90`, `Env.Readers` direct): passwd `root:x:0:0:...` + `+::::::`, group `root:x:0:`; `Readers(0440, uid 0, gid 0)` observed `determined=true beyond=true owner="+" members=[root] desc="the 1 effective member(s) of group root other than the owner can read it (root)"`. passwd with `root` and `toor` both uid 0: `beyond=true owner="toor" members=[root]`. Either feeds `secrets.go:1151` -> `fail/POLICY` "a system secret store is reachable beyond its owner: /etc/sudoers (...)", and `:405` for a 0640 root:root key.
- Expected: owner-only in both. Realistic: `+::::::` / `+@netgroup` compat lines exist on NIS/`compat` enterprise hosts (the code whitelists the `compat` backend at `remote_access.go:1034`); duplicate-uid aliases exist (`toor`, recovery admin accounts). The `+:::` mirror in /etc/group is harmless only by accident (R4-1b: it overwrites group 0's name; `beyond=false`).
- A reader is misled by `root` being named as a non-owner reader of a root-owned file.
- Patch: `byUID map[int64][]string`; parse uid/gid with `strconv.ParseInt` and `continue` on error so compat lines never become gid-0 members; subtract every name whose uid equals the owner uid. Regression: R4-1, R4-2 expect `BeyondOwner=false`; add a `+@netgroup::::::` variant.

### H-C. A directory store that is a SYMLINK is judged by the symlink's own lstat mode (0777): false FAIL "is other-writable"
- `sensor/internal/checks/secrets.go:1178-1193`: `Files.Stat` is an lstat (`read.go:275-283`); `dirHit.FileType = "dir"` is hard-coded at `:1185`; `*st.Meta.Mode&0o002 != 0` at `:1190` fires on a symlink's 0777. `protectionFromDenial` (`:143`) gives the same wrong basis for a symlink ancestor.
- Reproduction (R4-6, `zz_r4_test.go:197-215`): `/etc/ssl/private -> /secure/private`, target 0000 containing a key. Observed: SYSTEM_SECRET_STORE_PROTECTION `fail/POLICY` "a system secret store is reachable beyond its owner: /etc/ssl/private is other-writable"; boundary "the ancestor /etc/ssl/private (mode 0777) does not shield ...: any local user can traverse it (mode 0777)". Expected: judged on the target directory (here shielded -> pass), or `unknown/EINVAL` saying the store is a symlink.
- Realistic: relocating `/etc/ssl/private` or `/etc/sudoers.d` onto an encrypted or shared volume through a symlink is a known hardening pattern; NixOS-style store symlinks are the same shape. Not the Lava host (real directories).
- A reader is misled into a remediation (`chmod o-w`) that cannot be applied to a symlink, on a store that is in fact protected.
- Patch: when `st.Meta.FileType == "symlink"`, follow-stat the target (existing follow policy, local target only), judge the target's mode, record `symlink_target`; in `protectionFromDenial` treat a symlink ancestor the same way. Regression: R4-6 expects not fail, basis naming the target.

### M-A. A walk-listed candidate whose stat is denied is silently filed as "non-regular" and dropped
- `sensor/internal/checks/secrets.go:371-380`: when `st.Status != OK`, `hit.FileType == ""` so `nonRegularSkipped++; continue`; the candidate reaches neither `hits`, `boundaries` nor the observations.
- Reproduction (R4-4, `zz_r4_test.go:151-167`): `/etc/ssh` 0410 (owner lists, group traverses; `mallory` has that primary gid), `ssh_host_rsa_key` 0644. Observed: `pass` "0 candidate(s) across 1 searched root(s)", `non_regular_skipped=1`, `boundaries=nil`, completeness 13/13. Expected: fail (mallory reads the key) or unknown naming the denied stat. Rare layout, hence Medium; the class ("a denial filed under an unrelated bucket") is what the evidence model forbids.
- Patch: branch on `st.Status` first; a non-OK stat becomes a boundary with the stat recorded load-bearing. Regression: R4-4 must not pass.

### M-B. A refused symlinked walk root is reported as BUDGET_EXHAUSTED, and the engine flags its own honest boundary sentence as an entailment violation
- `sensor/internal/checks/secrets.go:464-472` (only `networkSkipped` selects NOT_ATTEMPTED; `anyDenied` looks for EACCES/EPERM text, so a refusal falls through to `ReasonBudget`); `:330` writes "was not enumerated (...)"; `scan/entailment.go:64` `absenceProse` matches `enumerat\w*` inside that negated sentence.
- Reproduction (R4-5, R4-5b, `zz_r4_test.go:169-196`): `/home -> /data/homes` with target 0777; `/home -> /nonexistent`. Observed both: `unknown/BUDGET_EXHAUSTED`, `entailment_violation=true`, detail "...[engine: this detail claims "enumerated", which its own observations do not support — ... not observed: /home (NOT_ATTEMPTED)]". Expected: `unknown/NOT_ATTEMPTED`, no flag. `TestSymlinkedWalkRootToAWritableTargetIsRefusedInWords` (`fixbatch4_test.go:320`) asserts only not-pass and the wording, so it cannot see this.
- A reader is misled twice: a budget that was never spent, and a "the sensor caught itself over-claiming" flag (README: the suite fails the build on any such flag) on a finding that did not over-claim.
- Patch: derive the reason from the refused root observation (`res.SkipReason != ""` -> `ReasonNotAttempted`); reword the boundary ("/home was skipped: ...") or exempt negated forms in `absenceProse`. Regression: R4-5/R4-5b expect NOT_ATTEMPTED and `EntailmentViolation=false`.

### M-C. PROVISIONING_DATA_PROTECTION says "this machine carries no provisioning artifact" when a payload existed but was denied (and counted as protected)
- `sensor/internal/checks/secrets.go:923` sets `present` only on `StatusOK`; the denied+protected branch `:907-921` increments `protectedCount` without marking presence; `:1043-1045` then emits the absence sentence.
- Reproduction: R3-D (re-run) and R4-3c: `/root/anaconda-ks.cfg` exists, stat EACCES -> `pass` "this machine carries no provisioning artifact at any cloud-init, Ignition or kickstart location". Expected: "1 payload candidate shielded by an ancestor; nothing else present". EACCES ≠ absent, violated in prose; RHEL 9 with `/root` 0550 and a real kickstart hits it on every host (verdict right, sentence wrong).
- Patch: `present = present || protectedCount > 0` (or a third branch). Regression: the detail never contains "no provisioning artifact" when `protected_by_ancestor > 0`.

### Low
- L-A. `secrets.go:285` opts the protected-root stat out, so a PRIVATE_KEY pass whose roots are all protected rests on `/proc/self/mountinfo` plus ENOENT stats (R4-9: `/root status=OK lb=false`). Record the shielding stat load-bearing (it succeeded), basis as Detail.
- L-B. `bmc.go:324` uses `acl.GrantsNonOwner`, which is read-only (`acl.go:41`): a `user:x:-w-` ACL on `/dev/ipmi0` (write is what an IPMI request needs) reports "root only". Summarise write/exec too.
- L-C. `walk.go:232` `depth(root, host)` after following a symlinked root strips the LINK path from TARGET paths, so the depth budget is consumed by the target's own depth. Use the resolved base as the prefix.
- L-D. IMPLEMENTATION_NOTES "copied into the package unmodified" is false (three identifier collisions). The fixture table otherwise reproduces.

## Roster-wide gate (26 checks: does any CURRENT path yield a confident verdict the evidence does not entail on Lava facts or on stock Ubuntu 24.04 / RHEL 9 / Alpine?)

| check | confident-verdict sites | result |
|---|---|---|
| PRIVATE_KEY_MATERIAL_EXPOSURE | `secrets.go:451-481` | sound on Lava/stock; H-A (ACL ancestor), H-B (model), M-A, M-B, L-A in non-stock configs |
| CREDENTIAL_FILE_EXPOSURE | `:698-710` | sound on Lava (/root 0700 -> 11 shielded -> pass); H-A |
| PROVISIONING_DATA_PROTECTION | `:1035-1051` | verdict sound; M-C prose on the RHEL 0550 layout |
| SYSTEM_SECRET_STORE_PROTECTION | `:1225-1237` | Lava/Ubuntu shape reproduced (R4-8: `pass`, 6 inspected, 2 shielded: sudoers.d 0750-analog, ssl/private 0710-analog); H-B (NIS/alias), H-C (symlink store) |
| BMC_DEVICE_NODE_ACCESS | `bmc.go:311-345` | sound; `Determined` gated before `BeyondOwner`; L-B |
| BMC_INBAND_INTERFACE_PRESENT / RESPONDS_IN_BAND / HOST_INTERFACE_EXPOSURE / CLIENT_TOOLING | `bmc.go` | not re-attacked this round; WSL artifact unknown/ENOENT with proven listings; R2-I pass by proven absence |
| LOGIN_AND_ESCALATION_SURFACE | `remote_access.go:1011-1042` | pass requires readable shadow, sudoers and every home -> Lava unknown/EACCES as the registry predicts; adverse only for docker/lxd/disk/kmem; sound |
| SSH_ROOT_LOGIN_POLICY / SSH_AUTH_METHODS_POLICY / SSH_POLICY_IN_FORCE | `sshd -G` oracle + Include-aware fallback | R2-H, ADV-1, ADV-4 hold; not exercised against a live daemon |
| REMOTE_LISTENING_SURFACE / HOST_FIREWALL_STATE | | R2-F, ADV-6 hold; WSL unknown with correct classes |
| DISK_ENCRYPTION_AT_REST | `storage.go:134-148` | default `fail` scoped to dm-crypt with named blind spots; matches registry f on Lava |
| UNUSED_ATTACHED_BLOCK_DEVICES | `:539-555` | fail only after mounts, swaps and udev read OK; sound for nvme1n1 |
| ROOT_FILESYSTEM_REDUNDANCY / MEDIA_HEALTH_VISIBILITY | | not re-attacked; WSL unknown with honest reasons |
| SECURE_BOOT / UEFI_SETUP_MODE / KERNEL_LOCKDOWN / UNSIGNED_MODULES / TPM_PRESENCE / BOOT_ARTIFACT / KERNEL_DRIFT | `bootchain.go:87-104,158-166,245-252,386-409,458-476,504-621,732-740` | TPM "no TPM" pass only after an OK listing (`:446-462`); efivar byte 4 after the attribute prefix; taint bits 12/13; registry f/f/f/f/p/f/f consistent with the paths read; not re-attacked with new fixtures |

## Verified sound (fixture or test that proves it)
- Undetermined account model never becomes pass or fail in PRIVATE_KEY, CREDENTIAL, PROVISIONING, SECRET_STORE, BMC node: R3-B (4 variants), `TestUndeterminedGidIsNeitherExposureNorSafety`, `TestR3L4_BMCNodeUsesTheSharedAccountModel`; a world-readable key still fails with the model unavailable (R4-7 `fail/POLICY`).
- Owner subtraction for the stock shapes: R3-C; primary-gid members still count: R2-B `fail (mallory)`.
- Traverse-bit protection with a populated group is not protection: R3-A; `/root` 0550 analog is: R3-D.
- Shared protection opt-out and the SECRET_STORE pass on the Ubuntu layout: R3-I, R4-8; WSL artifact SYSTEM_SECRET_STORE_PROTECTION `pass` 15/15.
- Found exposure beats incompleteness (walk and mountinfo): R3-E; file ACL behind a mask: R4-10 `fail` "an ACL grants a non-owner principal read" while the mode said owner-only.
- Symlinked root followed one hop to a non-writable local target: R3-G `fail` naming the target; writable and dangling targets refused: R4-5/R4-5b (unknown; reason class wrong, M-B).
- Network-FS refusal is NOT_ATTEMPTED for a root on nfs4 and a diskless nfs root: R3-F.
- Closed vocabulary at the artifact: 0 leaks in `findings.wsl.json`; NO_EVIDENCE and prose gates: R2-G, R3-H flagged.
- Safety in the production run: output 0600, `degradations` empty, `euid 1000`, exit 0, `self_check pass`.

## Could not verify
- The Lava host itself (no SSH from this role). Predictions from code + HOST_SUMMARY: SYSTEM_SECRET_STORE_PROTECTION pass (R4-8 is the same shape; requires `ssl-cert` to have no member beyond root, which HOST_SUMMARY does not state), PRIVATE_KEY pass with `/root` shielded, CREDENTIAL pass with 11 shielded, PROVISIONING pass.
- Whether any directory on the Lava host carries a POSIX ACL (H-A): `getfacl` is absent there; the sensor reads the xattr directly for files but not for ancestors, so the final artifact cannot show it.
- Docker profiles A/B/C not re-run (instruction); `internal/lab` and `tooling/testlab` untouched.
- REMOTE_ACCESS checks against a live sshd; BOOT_CHAIN and the four BMC inventory checks were read, not re-attacked with new fixtures (time box).
- ACL fixtures were built with `syscall.Setxattr` on WSL tmpfs (no `setfacl`); the kernel recomputed st_mode to 0010/0640 as logged; no ACL with more than one named entry was tried.
