# PROPAGATION_AUDIT — stale-claim survivals and top-10 re-verification (2026-09-09)

Scope: for every fact corrected, weakened, contested or retracted during reconciliation (FACTS.jsonl F90-F104 and the CONTESTED set), the load-bearing artifacts were grepped for the stale version: `research/R*/REPORT.md`, `research/R4/*_PLAN.md`, `research/R1/BVB_MATRIX.md`, `research/R5/IMPL_BVB.md`, `research/R3/DESIGN_LAWS.md`, `research/R5/ARCHITECTURE_NOTES.md`, `research/R2/CUSTOM_CATEGORY_CANDIDATES.md`, `state/HOST_SUMMARY.md`, `task/derived/TASK_CONTRACT.md`, `CLAUDE.md` (+ `research/R1/STOLEN_PATTERNS.md`, `research/R4/STORAGE_ASSESSMENT.md`, `state/HOST_SNAPSHOT.json` as extras). Nothing outside `research/` top level was edited; every survival below is reported for the lead.

Already corrected by the lead before this audit (verified by grep, no action): `task/derived/TASK_CONTRACT.md:54` (C4a now says `sshd -G` works and is primary); `CLAUDE.md:8` (derived schema); `state/HOST_SUMMARY.md:6` (`sshd -G` WORKS); `state/HOST_SUMMARY.md:7`/`HOST_SNAPSHOT.json:176` (mdadm.conf EXISTS).

## A. Surviving stale occurrences (file:line -> required correction)

### A1. `sshd -G` works unprivileged (F24/F97 retract the parse-only framing)
| file:line | stale text | correction |
|---|---|---|
| `research/R3/DESIGN_LAWS.md:30` | L18 "Never depend on sshd -T; record its stderr as EXECUTION_ERROR and fall back to the walker" | walker is the FALLBACK; `sshd -G` is primary (reconciled L18 in `research/DESIGN_LAWS.md`) |
| `research/R3/DESIGN_LAWS.md:122` | "LAW: own walker is primary" | "LAW: `sshd -G` (bounded, real rc) is primary; own walker is fallback + provenance" |
| `research/R3/REPORT.md:283-288` | L18 text "MUST NOT depend on sshd -T ... (3) `sshd -T -C` is strictly worse" | add: `sshd -G` works (host probe network.sshd_g_effective); `-G -C` untested |
| `research/R4/REPORT.md:39` | "Effective policy must be derived by parsing sshd_config ..." | "obtained from `sshd -G` (works unprivileged, F24); parsing is the fallback/provenance path" |
| `research/R4/HOST_SPECIFIC_PLAN.md:67` | "UTILITY_MISSING: irrelevant; do not shell out to `sshd`" | we DO shell out to `sshd -G` via the bounded runner; UTILITY_MISSING (sshd not found) => walker fallback |
| `research/R4/GENERIC_FALLBACK_PLAN.md:95` | "derive by parsing + runtime cross-check" | "`sshd -G` primary; derive by parsing when sshd absent/-G fails" |
| `research/R1/REPORT.md:47`, `:125`; `research/R1/BVB_MATRIX.md:24` | "REUSE — pending R1-OR9" | "REUSE — host-confirmed (network.sshd_g_effective, 85 directives)" |
| `research/R5/IMPL_BVB.md` row 6 (line 13) | "BUILD, narrow scope only" for sshd_config parsing (no mention of -G) | keep BUILD but as fallback; `sshd -G` is the primary oracle (R5 never evaluated -G) |

### A2. Dependency count / x/sys (F71, F102, F96; C-05, C-06)
| file:line | stale text | correction |
|---|---|---|
| `research/R1/REPORT.md:3` | "plus exactly one third-party runtime module (`golang.org/x/sys`)" | zero runtime third-party modules; x/sys rejected (stdlib syscall) |
| `research/R1/REPORT.md:65`, `:111`, `:117`, `:125`, `:135`, `:155` | x/sys REUSE / "one runtime dependency worth taking" / Openat2 | REJECT x/sys; openat2 dropped for os.Root |
| `research/R1/BVB_MATRIX.md:46` | "`golang.org/x/sys/unix` already exposes Getxattr" | stdlib `syscall.Getxattr` (still REJECT pkg/xattr) |
| `research/R1/BVB_MATRIX.md:48` | openat2 "BUILD as optional hardening" | REJECT (os.Root; F96) |
| `research/R1/BVB_MATRIX.md:87`, `:97` | x/sys "REUSE — shipped ... The only third-party runtime dependency we take" | REJECT; zero runtime deps |
| `research/R1/STOLEN_PATTERNS.md:106` | SP-23 example "openat2 availability ... ENOSYS" | keep the capability-detection pattern, drop the openat2 example (or note unused) |
| `research/R1/STOLEN_PATTERNS.md:111` | "third-party runtime surface stays at exactly one module (`golang.org/x/sys`)" | zero modules |
| `research/R5/REPORT.md:119`, `:123`; `research/R5/IMPL_BVB.md:23` | "Net: one third-party dependency in the shipped binary" (santhosh) | zero: santhosh is a test-only import + release-gate tool (C-06) |
| `research/R5/ARCHITECTURE_NOTES.md:108` | "validate at runtime, before writing ... On failure: write nothing to --out ... exit 1" | test-time + release gate + stdlib runtime invariants; on failure WRITE the file, exit 1, print pointers (never suppress output) |

### A3. Schema now derived and present (F101; C-29)
| file:line | stale text | correction |
|---|---|---|
| `research/R5/ARCHITECTURE_NOTES.md:112` | "Blocked on input: finding.schema.json is not in the repository" | resolved: `task/derived/finding.schema.json` (2020-12, open additionalProperties) |
| `research/R5/IMPL_BVB.md:11` | "the schema is a customer artifact and is not yet in hand" | in hand (derived); codegen remains optional |
| `research/R1/BVB_MATRIX.md:98`; `research/R1/REPORT.md:156` | "whichever draft it turns out to use" | draft 2020-12 declared; enable format assertion |
| `task/derived/TASK_CONTRACT.md:43`, `:44`, `:127` | "(PENDING-SCHEMA ...)" tags on B6, B7 and the H coverage table | replace with "settled against task/derived/finding.schema.json (AM-1)" |

### A4. AppArmor profiles NOT readable (F94; C-08)
| file:line | stale text | correction |
|---|---|---|
| `research/R4/HOST_SPECIFIC_PLAN.md:174` | "read ... `/sys/kernel/security/apparmor/profiles` (0444, R4-F44)" | 0444 but EACCES by apparmorfs policy on this host (kernel.apparmor_profiles); enforcement mode UNKNOWN by construction |
| `research/R4/GENERIC_FALLBACK_PLAN.md:114` | "`/sys/kernel/security/apparmor/profiles` is **0444** (R4-F44)" | mode is not authorisation: attempt the read, expect EACCES unprivileged; enabled=Y is the only positive evidence |
| `research/R4/REPORT.md:114` | "R4-OR4 (AppArmor enforcement mode — likely one read of a 0444 file)" | answered: read denied; unknown by construction |

### A5. Storage wording (F55, F57, F59, F99)
| file:line | stale text | correction |
|---|---|---|
| `task/derived/TASK_CONTRACT.md:42` | B5a "`size_bytes` = `/sys/block/<d>/size × logical block size 512`" | "× 512 (fixed sector unit; NOT logical_block_size — wrong on 4Kn)" |
| `state/HOST_SUMMARY.md:7`; `CLAUDE.md:58` | "nvme1n1: NO partitions, NO filesystem" / "nvme1n1 unused (no partitions/fs)" | "no partition table and no filesystem signature known to udev (device not opened)" — wording only |
| `research/R4/STORAGE_ASSESSMENT.md:128` | "group disk has zero members — so no unprivileged path exists" | still true as observation; ensure no remediation text says "join group disk" (line 42 already says it would not help) — no change needed |

### A6. BMC network reachability (F93; C-12)
| file:line | stale text | correction |
|---|---|---|
| `research/R2/CUSTOM_CATEGORY_CANDIDATES.md:82` | "this host's BMC is **not** network-reachable at scan time" | "the OS cannot observe the dedicated BMC LAN port (R4-F53); out-of-band exposure is UNKNOWN by construction, not absent" |
| `research/R2/CUSTOM_CATEGORY_CANDIDATES.md:70`, `:167` | cites R2-F17 as support | cite F47/F93 instead |
| `research/R2/CUSTOM_CATEGORY_CANDIDATES.md:17` | "`mokutil --sb-state` if present, else sysfs fallback" | inverted: efivars 5-byte read is primary, mokutil optional cross-check (F48) |

### A7. Open-path rule (F95; C-23) and identity hashing (F6)
| file:line | stale text | correction |
|---|---|---|
| `research/R1/STOLEN_PATTERNS.md:85-87` | SP-18 "`lstat` first, and never rely on `O_NONBLOCK` ... This is the mechanism" | mechanism = O_NONBLOCK open + Fstat(fd) IsRegular (TOCTOU-safe); lstat is a pre-filter |
| `research/R1/REPORT.md:61` | "`lstat`-first is mandatory and `O_NONBLOCK` is not a substitute" | as above; the repro used `cat` (no O_NONBLOCK) |
| `research/R5/ARCHITECTURE_NOTES.md:118`; `research/R5/REPORT.md:73` | "`host_id` from `/etc/machine-id`" with no hashing | keyed derivation of machine-id, never raw (machine-id(5); L32) |
| `task/derived/TASK_CONTRACT.md:33` | B1a candidate chain without the confidentiality rule | add "emit a keyed hash of machine-id, never the raw value; label clone/re-image caveats" |

### A8. Host-summary / snapshot housekeeping (answered observation requests)
| file:line | stale text | correction |
|---|---|---|
| `state/HOST_SUMMARY.md:1` | "169 read-only probes" | 187 recorded / 193-probe registry (3 rounds, rebuilt 23:13Z) |
| `state/HOST_SUMMARY.md:8` | "`/dev/i2c-0..2` exist (perms not yet checked)" | 0600 root:root (bmc.i2c_dev_modes) |
| `state/HOST_SNAPSHOT.json:455-456` | unresolved "/dev/i2c-* permissions: not probed" | answered (R4-OR2) — remove from unresolved |
| `state/HOST_SNAPSHOT.json:513-518` | follow_up_observations list | all six executed (i2c modes, USB operstate, dmi 42-0 mode, sshd_config.d mtime, group membership, cloud instance dir) — clear or mark done |

### A9. Contract items that need a lead decision (not stale, but contested)
| file:line | item | see |
|---|---|---|
| `task/derived/TASK_CONTRACT.md:58`, `:108` | C6a / AM-6 permit `ipmitool mc info` when the node is openable | C-26 / DECISIONS D-07 (research: never issue IPMI commands) |
| `task/derived/TASK_CONTRACT.md:73`, `:106` | D6 / AM-4 severity-vs-status provisional | C-36 / DECISIONS D-04 (confirm) |
| `research/R5/ARCHITECTURE_NOTES.md:82` | Observation.Source example "ipmitool mc info" | cosmetic; replace with a sysfs example if D-07 adopted |

### A10. Checked and clean (no survivals)
- gitleaks relicensing myth: only appears as its own correction (`R1/REPORT.md:53`, `R1/BVB_MATRIX.md:41`). `prompts/R1/prompt.md` is lead-owned and was not audited (contains the original premise by construction).
- securityfs root-only: no survivals (only the correction in `R1/REPORT.md:97`).
- dmesg EACCES: no survivals in load-bearing files (R4 facts.jsonl carries it only as the CONTESTED/CORRECTED R4-F43).
- R4-F30 "raw only": HOST_SPECIFIC_PLAN D1 already conservative.
- `CLAUDE.md` host-facts block (lines 55-61): consistent with FACTS except the nvme1n1 wording above; "SMART needs root" is acceptable (CAP_SYS_ADMIN).

## B. Top-10 load-bearing current claims — re-verified against primary source or host evidence
| # | Claim (fact) | Re-verification performed now | Result |
|---|---|---|---|
| 1 | `sshd -G` works as uid 1000 (F24) | Read probe `network.sshd_g_effective` stdout: 95 lines, keyword/value pairs incl. `passwordauthentication no`, `permitrootlogin without-password`, `usepam yes`, three `hostkey` lines; `rc_T=1` with "no hostkeys available" | **CONFIRMED** (rc_G=141 is the probe pipe's SIGPIPE; the sensor runner captures the real rc) |
| 2 | BMC identity attributes readable and populated; read is fast on a healthy BMC (F43, F44) | `bmc.bmc_sysfs_attrs` (ipmi_version 2.0, fw 1.5, 0x002a7c, 0x1d6e, guid present); `bmc.bmc_read_timing` nanosecond stamps: 1.41 ms / 1.63 ms / 0.98 ms | **CONFIRMED** (worst-case KCS timing is from kernel source, not host-tested — by design) |
| 3 | DMI: 4 attributes 0400, rest 0444 (F3) | `identity.dmi_ls`: `-r--------` on board_serial, chassis_serial, product_serial, product_uuid; `-r--r--r--` on the other 18 | **CONFIRMED** |
| 4 | Secure Boot disabled + Setup Mode via efivars byte 4 (F48) | `kernel.secureboot`: `SecureBoot...: 6 0 0 0 0`, `SetupMode...: 6 0 0 0 1`; mokutil agrees | **CONFIRMED** |
| 5 | Taint 12288 = O+E attributable to bnxt_en (F49) | `kernel.module_taint`: `12288`, `/sys/module/bnxt_en/taint:OE`, count 1 | **CONFIRMED** |
| 6 | `/etc/mdadm/mdadm.conf` exists (F2) | `storage.mdadm_conf_content`: `-rw-r--r-- 18 mdadm.conf`, `HOMEHOST <ignore>` | **CONFIRMED** |
| 7 | apparmor/profiles 0444 yet EACCES; mode bits are not authorisation (F50, F8) | `kernel.apparmor_profiles`: `-r--r--r-- profiles` + `cat: Permission denied`; `kernel.dmesg_head`: "Operation not permitted" | **CONFIRMED** |
| 8 | Include is the first non-comment line; one drop-in (F27) | `network.sshd_config` (line `Include /etc/ssh/sshd_config.d/*.conf` before any directive), `network.sshd_effective_lines`, `network.sshd_config_d` | **CONFIRMED** |
| 9 | Capacity = size x 512 (F55) | recomputed 1875385008 x 512 = 960197124096 == snapshot size_bytes | **CONFIRMED** |
| 10 | WaitDelay bounds the two Wait delays; CommandContext's default Cancel only kills the process and leaves WaitDelay unset (F21, F22) | `go doc os/exec.Cmd.WaitDelay` and `go doc os/exec.CommandContext` on the local Go 1.26.2 toolchain: "bounds the time spent waiting on two sources of unexpected delay in Wait: a child process that fails to exit after the associated Context is canceled, and a child process that exits but leaves its I/O pipes unclosed"; "sets the command's Cancel function to invoke the Kill method on its Process, and leaves its WaitDelay unset" | **CONFIRMED** verbatim |
| 11 (bonus) | udev DB readable; lsblk populates FSTYPE while the device is unopenable (F57) | `storage.udev_data_readability` (0755, 362 entries, `E:ID_*`), `storage.lsblk_fs` (vfat/ext4), `storage.dev_ls` (root:disk 0660), `users.group_members` (disk empty) | **CONFIRMED** |
| 12 (bonus) | Only `sudo` has members (F33) | `users.group_members`, `users.priv_groups` | **CONFIRMED** |

Not re-verifiable from this workstation (left at track status): Bowtie conformance numbers (F69, VERIFIED by R5 from raw NDJSON), OpenSSH source line numbers (F24-F27, VERIFIED by R1/R3 at tag V_9_6_P1), R5 orphan-reaping repro (F23, single-source; OR-OPEN-3).

## C. Calibration note
All host confirmations are n=1 (one machine, one recon window, sampling method one-shot); they establish what THIS host does, and the generic laws rest on the cited primary sources, not on the host. Where a track's status was raised (F34, F57) the raising evidence is a new lead probe named in the fact; no status was raised on argument alone.
