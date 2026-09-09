# REVIEW_FINDINGS_3 — fresh re-verification after fix batch 3 (checkpoint 16, HEAD ab0a959)

Reviewer: `code-reviewer` (fresh context; did not write the code). Date: 2026-09-09.
Scope: CLOSURE_TABLE rows 1-41 re-attacked as claims; REVIEW_FINDINGS(_2) fixtures re-run; new fixtures under `reports/review3/`.
Gates run: `go vet ./...` (native + GOOS=linux) clean; Windows `go test ./... -count=1` all 5 packages ok; cross-compiled probe/scan/checks/cmd/lab test binaries under WSL Ubuntu 26.04 uid 1000: all PASS; cross-compiled sensor run on the WSL host as uid 1000: 26 checks, exit 0, 162 ms (`reports/review3/findings.wsl.json`); 9 new R3 fixtures + 10 R2 ports + 6 R1 ADV fixtures compiled from a scratch copy (`reports/review3/sensorcopy`, never inside `sensor/`), log `reports/review3/r3_adversarial.log`.

Verdict: **DO-NOT-SHIP** (one Critical false-FAIL class that hits the Lava host itself; three Highs in the batch-3 semantics). Counts: Critical 1 - High 3 - Medium 5 - Low 6.

## Critical

### C1. The owner is counted as a reader of its own file: false FAIL on /etc/sudoers 0440 root:root (every Debian/Ubuntu/RHEL host, including the Lava host)
- `sensor/internal/scan/check.go:511-558` (`Groups()` adds every account to the effective member set of its primary group, so root becomes a member of group root), `check.go:578-633` (`Readers(mode, gid)` has no owner uid and never subtracts the owner). Consumers: `secrets.go:1020-1023` (`hit.Adverse = readers.BeyondOwner`), `secrets.go:318-319`, `:810`, `:871`, `:136`, `:230`.
- Scenario: `/etc/sudoers` mode 0440 root:root (HOST_SUMMARY line 5 says exactly this for the Lava host). GroupRead set, group root, effective members [root] via primary gid, BeyondOwner=true, verdict `fail/POLICY` "reachable beyond its owner: /etc/sudoers (the 1 effective member(s) of group root (root))". Reproduced on the real WSL host (`reports/review3/findings.wsl.json`, SYSTEM_SECRET_STORE_PROTECTION detail) and by fixture R3-C (SYSTEM_SECRET_STORE_PROTECTION and PRIVATE_KEY_MATERIAL_EXPOSURE with a 0640 root:root key both fail). On WSL and on Lava the FAIL is masked into `unknown/EACCES` only because an unrelated denial (`/etc/ssl/private`, `/etc/sudoers.d` listing) triggers the load-bearing downgrade; the detail still asserts the false exposure and CHECK_REGISTRY 5.3 predicts pass. The final host run would disagree with the registry because of a sensor bug.
- Same root cause makes `/root` 0550 root:root (Fedora/RHEL default) "not protected" (M4) and `/etc/sudoers.d` 0750 root:root a boundary instead of protection on Lava.
- Violates: fail on a healthy machine (CLAUDE.md evidence semantics); L42/L43 as cited in the code; registry 2.2.
- Patch: `Readers(mode, uid, gid *int64)`; in `Groups()` also record a uid-to-name map from passwd; effective OTHER readers = members minus the owner account name(s); BeyondOwner only when that set is non-empty; thread uid through `effectiveReaders`, `protectionFromDenial`, `ruleKind.violated` and the call sites; `group_effective_members` in evidence lists non-owner members.
- Regression: R3-C (`TestR3C_OwnerIsNotAnotherReader_Sudoers0440`, both parts pass), R3-D passes, and `TestSecretStore_StockSudoersDIsNotExposure` must use a passwd that contains the owner account with the file gid (today it passes only because its passwd has no such account).

## High

### H1. Undetermined group model is reported as FAIL, not unknown
- `check.go:601-622` returns Determined=false, BeyondOwner=true (conservative) when `/etc/group` or `/etc/passwd` is unreadable OR the gid is in neither database; `secrets.go:318-319` and `:1023` then treat BeyondOwner as Adverse, so the file lands in `exposed` and the verdict is `fail/POLICY` with a detail that literally says "unknown: ... the group model is unavailable". Fixture R3-B: `/etc/passwd` 0000 and `/etc/group` 0000 each give FAIL for `/etc/shadow` 0640 and for a 0640 host key. Realistic trigger: a group served by SSSD/LDAP (nsswitch not files) owning a 0640 secret, gid absent from `/etc/group`, false FAIL.
- Row 33 is therefore NOT closed: "never empty" was implemented as "always exposed". `TestGroupDBDenied_IsUnknownNotEmpty` asserts only status != pass.
- Patch: every consumer branches on !Determined: record a boundary and return unknown with r.Reason; Adverse only when Determined && BeyondOwner. Regression: R3-B expects unknown for both checks; add an unknown-gid variant.

### H2. protectionFromDenial() ignores group traversal: a 0710 ancestor with a populated group is called "protected from every unprivileged account"
- `secrets.go:135-146`: for a directory without o+x it asks `Readers` (READ bits) and accepts protection when !BeyondOwner or the group-x bit is clear. Mode 0710 has no group-read bit, so `Readers` says "owner only" and Protected=true although the group can traverse and read a 0640 file inside. Ubuntu ships `/etc/ssl/private` as 0710 root:ssl-cert and adds postgres to ssl-cert when PostgreSQL is installed. Same hole in the root-level shortcut `secrets.go:230-231` (tests !r2.BeyondOwner only).
- Fixture R3-A (dir 0010 = owner denied, group x, group has a member): evidence records `scan_roots_protected=[/etc/ssl/private (mode 010) is not traversable by other ...]` and `protected_by_ancestor=1`. The check-level status is pass; it ships as unknown today only because two unrelated defects (M1, H3) downgrade it. Fix either of those without fixing this and the false PASS ships. The evidence basis is already wrong.
- Patch: a group-traversable ancestor is protection only if the group has no non-owner effective member (needs the C1 `Readers`); world-traversable never; record the deciding stat as an observation. Regression: R3-A must never record protection for that directory; status unknown (or fail once the file mode is known).

### H3. SYSTEM_SECRET_STORE_PROTECTION counts a denial as protection but never opts the denied observation out: permanent unknown on every Ubuntu host (Lava included), contradicting its own detail and the registry
- `secrets.go:998-1010` (judge, protected branch) and `:1075-1082` (directory listing) increment protectedCount but leave st/dirObs load-bearing; finalize (a2) then downgrades: "... 1 shielded by an unreadable ancestor [downgraded from pass: a load-bearing observation did not succeed (/etc/ssl/private: EACCES)]", visible in the WSL artifact and fixture R3-I. HOST_SUMMARY: `/etc/ssl/private` EACCES (0710) on Lava, so this check can never pass there; registry says pass. CREDENTIAL (`:537`) and PROVISIONING (`:795`) do opt out; this check was left inconsistent, so rows 28/30 are only partially closed.
- Patch: mirror `:537`/`:795` (OptOut = "the denial itself answers the exposure question: " + prot.Basis) in both branches; add the ancestor stat to the observations. Regression: R3-I expects pass with protected_by_ancestor=1 and no "downgraded" text.

## Medium

### M1. PRIVATE_KEY walk observation is appended before it is corrected: protected subtrees always downgrade the pass with a wrong reason
- `secrets.go:262` `r.Add(obs)` copies the struct; `:285` `obs.Truncated = false` mutates the local copy only. Any walk with a protected unreadable subtree stays truncated, so the verdict is `unknown/BUDGET_EXHAUSTED` "hit its byte cap and is a prefix" (R3-A output): misleading text and an under-claim; also one of the two masks over H2. Patch: decide before adding, or set OptOut with the protection reason instead of clearing Truncated. Regression: `/etc/ssl/private` 0000 with nothing else gives pass, no downgrade.

### M2. Unreadable /proc/self/mountinfo downgrades a FOUND world-readable key to unknown
- `secrets.go:196` adds mounts.Obs load-bearing; the positive-finding opt-out at `:353` covers only the walk sources. Fixture R3-E: key 0644 found, result `unknown/EACCES` "[downgraded from fail ... (/proc/self/mountinfo: EACCES)]". Patch: include mounts.Obs.Source in the exposed-found opt-out. Regression: R3-E expects fail.

### M3. A symlinked scan root (/home -> /data/homes) is not walked, and the reason leaks ENOTREG outside the closed vocabulary
- `walk.go:146-160` Lstat + IsDir() on the root; `secrets.go:281-286` never consults res.Errno, so the check passes and the engine downgrades to unknown with reason "ENOTREG" (fixture R3-G; not in `check.go:89-115`; the schema allows any string so this is a contract leak, not a schema break). The 0644 key under the real directory is missed. Patch: in Walk, when Lstat shows a symlink, Stat the target; if it is a directory and not escapesToUserTree, walk the resolved path and record ResolvedPath; map ENOTREG/ENOTDIR to a vocabulary reason (EINVAL) or treat it as a boundary. Regression: R3-G expects fail.

### M4. /root 0550 root:root (Fedora/RHEL default): CREDENTIAL_FILE_EXPOSURE and PROVISIONING_DATA_PROTECTION unknown instead of pass
- Consequence of C1 (Readers(0550, gid 0) yields members [root], so not protected). Fixture R3-D: both unknown/EACCES. Fixed by the C1 patch; keep R3-D as regression.

### M5. Protection decisions are not observations
- `secrets.go:230-235` continues without r.Add(st) for a protected root; protectionFromDenial (`:128`) stats ancestors that never enter r.Observations. A pass "N shielded" has no observation for the shield and `completeness` cannot see it. Patch: add the deciding stat with Detail = basis. Regression: assert an observation with Source == ancestor exists whenever protected_by_ancestor > 0.

## Low
- L1. Network-FS refusal reported as BUDGET_EXHAUSTED (`secrets.go:367-369`; walk sets BudgetExhausted="network-filesystem"). Fixture R3-F. Use NOT_ATTEMPTED.
- L2. Prose gate bypass: "the search did not find any exposed key; 0 candidates, every root covered" + one irrelevant OK observation + a reasoned opt-out ships as pass with no flag (fixture R3-H; `entailment.go:52`). Defence in depth only; extend the regexp (did not find | not found | covered | 0 candidate) or rely on the structural gate alone and say so.
- L3. ADV-1: SSH_POLICY_IN_FORCE reason=EINVAL while the detail says the unit properties were UTILITY_MISSING; the reason should follow the failing observation.
- L4. Row 29 claims Env.Readers() is the one place used by bmc.go and storage.go; neither calls it (`bmc.go:308-321` own loop with len(g.Members) > 0, which shares C1 for a 0660 root:root node; `storage.go:809` openableByUs via SelfGroups, correct for "can we open it"). Fix the claim or the code.
- L5. CREDENTIAL_FILE_EXPOSURE drops ENOENT stats before r.Add (`secrets.go:524-526`), so a pass rests on /etc/passwd alone (load_bearing 1/1 in the WSL and Docker artifacts). Add the AbsenceProven stats.
- L6. Readers "group has no members, so owner-only" is applied to rules whose software checks MODE bits: libpq rejects a 0640 .pgpass regardless of membership, but the check passes it (`secrets.go:441-444`). Rule text says "not group- or world-readable"; the predicate is looser.

## Closure verdict, CLOSURE_TABLE rows 1-41 (closed = re-verified here by fixture or artifact; test-only = the regression test passes but I did not independently re-attack)

| rows | verdict | evidence |
|---|---|---|
| 1 | closed (structural gate); residual L2 (prose regexp bypass) | R2-G flagged; R3-H not flagged |
| 2, 3 | closed | R2-A, ADV-3 (now pass by design, row 39), WSL artifact boundaries |
| 4 | closed | ADV-6 fail with ENABLED=no cited |
| 5, 37 | closed | R2-I pass, no downgrade |
| 6, 8 | closed | R2-H unknown/CONTESTED, ADV-4 |
| 7, 9, 10, 11, 12, 13, 14, 15, 16, 17 | test-only (suite green Windows + WSL uid 1000) | not re-attacked in the time box |
| 18, 34 | verified green in this run: Windows lab ok, WSL lab.test PASS (my cross-compiled binary) | table still says OPEN; can move to VERIFIED |
| 19 | not re-run (Docker) | artifacts in reports/testlab predate nothing relevant; images lack sudo so C1 is invisible there |
| 20, 21, 22, 23, 24, 25, 26, 27 | closed / deferred as recorded | ADV-1, ADV-2, WSL artifact symlinks_skipped |
| 28 | partly closed | R2-A fixed; but H2 (wrong protection basis) and M1 (copy bug) sit on the same path |
| 29 | NOT closed | C1: owner counted as another reader (false FAIL), `check.go:511-558, 578-633` |
| 30 | NOT closed | R2-D2 passes only with a passwd lacking the owner account; R3-C (realistic passwd) fails the stock layout |
| 31 | closed | R2-C |
| 32 | closed (NO_EVIDENCE gate works); residual L2 | R2-G, R3-H |
| 33 | NOT closed | H1: undetermined group model yields FAIL, `check.go:601-622` + `secrets.go:318,1023` |
| 35 | closed for 0700; NOT for 0550 (M4, same cause as C1) | R2-E2 pass; R3-D unknown |
| 36 | closed | R2-F fail |
| 38 | closed | R2-E pass |
| 39 | doc; consistent with ADV-3 now passing | |
| 40 | closed (abandonment test green; refusal works) ; reason label L1 | R3-F |
| 41 | closed; new vocabulary leak ENOTREG (M3) | R3-G |

## Fixture results (`reports/review3/r3_adversarial.log`; sources in `reports/review3/sensorcopy/internal/checks/zz_r3*_test.go`, `zz_r1_adv_test.go`)

| id | fixture | expected | observed | verdict |
|---|---|---|---|---|
| ADV-1 | same-second mtime vs unit start | not fail | unknown/EINVAL (detail says UTILITY_MISSING) | ok; L3 |
| ADV-2 | default cloud-init layout | not fail | pass | ok |
| ADV-3 | /root 0000 hiding a 0644 key | (old) not pass | pass, 1 shielded | by design since row 39 |
| ADV-4 | Match flips PasswordAuthentication | not pass | unknown/CONTESTED | ok |
| ADV-5 | sysfs disk without size | unknown marker, no raw machine-id | ok | ok |
| ADV-6 | ufw active + ENABLED=no | detail not "enabled" | fail, cites ufw.conf | ok |
| R2-A | key 0040, populated group, sniff EACCES | not pass | fail | closed |
| R2-B | key 0640, primary-gid member | fail | fail | closed |
| R2-C | ~/.ssh/config 0644 | pass | pass | closed |
| R2-D | /etc/group 0000, /etc/shadow 0640 | unknown | **fail** (R3-B) | NOT closed, H1 |
| R2-D2 | /etc/sudoers.d 0755 + 0440 README, minimal passwd | not fail | pass | closed for that passwd only (see R3-C) |
| R2-E | comment mentioning ssh_pwauth | not fail | pass | closed |
| R2-E2 | /root 0700 | pass | pass | closed |
| R2-F | truncated /proc/net/tcp with telnet | fail | fail | closed |
| R2-G | unlisted absence prose, 0 load-bearing OK | violation | unknown/EACCES, viol=true | closed |
| R2-H | Include inside Match | unknown/CONTESTED | unknown/CONTESTED | closed |
| R2-I | no BMC, /dev listable | pass | pass | closed |
| R3-A | ancestor 0010 (group x, member postgres), key 0640 | not protected | evidence says protected; status unknown/BUDGET only via M1/H3 | **H2** |
| R3-B | passwd or group unreadable, 0640 secret/key | unknown | **fail/POLICY** x4 | **H1** |
| R3-C | /etc/sudoers 0440 owner-only-member; 0640 key same | pass | **fail/POLICY** x2 | **C1** |
| R3-D | /root 0050 (0550 analog) | pass | unknown/EACCES x2 | M4 |
| R3-E | mountinfo 0000 + world-readable key | fail | unknown/EACCES (downgraded from fail) | M2 |
| R3-F | /home on nfs4; / on nfs4 | unknown, honest reason | unknown/BUDGET_EXHAUSTED | refusal ok; L1 |
| R3-G | /home symlink to /data/homes, key 0644 | fail | unknown/ENOTREG | M3 |
| R3-H | prose smuggle + reasoned opt-out | flag | pass, no flag | L2 |
| R3-I | /etc/ssl/private 0000 (stock) | pass, 1 shielded | unknown/EACCES, downgraded from pass | **H3** (also on the real WSL host) |

## Attacks that did not land (verified sound)
- (c) Entailment gate: no check can return pass/fail with zero OK load-bearing observations (`finalize.go:61-68`, NO_EVIDENCE); opting out without a reason is impossible through `Result.OptOut` (`check.go:56-71`) and a direct `OptOut` assignment always carries text into `not_load_bearing_because`; the WSL and Docker A/B/C artifacts contain no NO_EVIDENCE finding and no `entailment_violation`, so (f) under-claim regression from the new gate is not observed. Residual: prose regexp (L2).
- (d) Abandonment: the only state an abandoned goroutine can reach is `Env` (sync.Once caches built once then read-only, `muUnits` mutex) and its own `Result` sent on a buffered channel nobody reads; `env.Degradations` is written only in `main.go:108` before the run; `cancel()` fires on abandonment so a child process is killed; no late mutation of the findings slice is possible (`engine.go:117-150`). A stuck `sync.Once` (Groups on hung storage) cascades later callers into their own abandonment, still bounded by the scan deadline.
- (e) Network filesystems: a bind or direct nfs4 line at any mount point is honoured by longest prefix (`walk.go:247-261`), a diskless NFS root refuses every root (R3-F); an unreadable mountinfo lets the walk proceed (abandonment is the fallback) and, through the load-bearing mounts observation, forces unknown, which is the honest direction except for M2.
- Exec bounding, read gating, O_NOFOLLOW/os.Root policy, host_id hashing, no device opens: unchanged since REVIEW_FINDINGS_2 and re-covered by the green probe/scan suites; no writes outside the output file were observed in the WSL run (output 0600).

## What I could not verify and why
- The Lava host itself (no SSH from this role). Predictions from code + HOST_SUMMARY: SYSTEM_SECRET_STORE_PROTECTION will be unknown/EACCES with a detail asserting a false exposure of /etc/sudoers (C1, H3); registry says pass. PRIVATE_KEY and PROVISIONING should pass (/root is 0700 root:root there, so C1 does not bite them on Lava; it would on RHEL).
- Docker profiles A/B/C not re-run; their images lack sudo, so C1 is structurally invisible in the lab, which is why three green gates missed it.
- Whether ssl-cert has members on the Lava host (decides whether H2 is a live lie there or only a wrong basis in evidence).
- Rows 7, 9-17, 27 were not independently re-attacked (time box); their regression tests are green on Windows and WSL.

## Verdict: DO-NOT-SHIP
Blocking before the final host run: C1 (owner-as-reader false FAIL; registry disagreement on the host), H1 (undetermined group model reported as FAIL), H2 (group-traversable ancestor recorded as protection), H3 (secret-store check permanently unknown on Ubuntu with a self-contradicting detail). All four are in one 60-line region (`scan/check.go` Readers/Groups + `checks/secrets.go` protectionFromDenial and the two opt-out sites) and share one fix: give `Readers` the owner uid and the traverse bit, subtract the owner, branch on Determined, and opt out every denial that was counted as protection. Then M1, M2, M3 (FIX-THEN-SHIP); Lows can follow.
