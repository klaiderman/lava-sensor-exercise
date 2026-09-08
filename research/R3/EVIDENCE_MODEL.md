# R3 — EVIDENCE_MODEL.md

Recommended evidence-block fields per observation type. This is the shape the sensor's
`evidence` payload should take so that a reviewer can reproduce the observation and so that
PASS / FAIL / UNKNOWN are distinguishable from each other *and* from "the check never ran".

Design rule behind the whole table: **the evidence block must record the observation, not the
conclusion.** A reader who has only the evidence block must be able to re-run the observation
by hand and get the same bytes.

## 0. Universal fields (every finding, every observation type)

| Field | Mandatory | Meaning |
|---|---|---|
| `check_id` | yes | Stable registry id. Present even when the check errors out — this is what makes silent omission detectable. |
| `status` | yes | `pass` \| `fail` \| `unknown`. Never absent, never a 4th value. |
| `reason` | yes when `status=unknown` | Machine-readable failure class, from the closed vocabulary in §7. Free text goes in `detail`, not here. |
| `observed_at` | yes | RFC3339 UTC of the observation, not of report assembly. |
| `duration_ms` | recommended | Lets a reviewer see which probe is near its budget. |
| `observation_type` | yes | One of the types in §1–§6, so consumers know which optional fields to expect. |
| `detail` | optional | Human-readable one-liner. Never contains a secret value. |

## 1. `file_read` — reading a regular file (`/proc`, `/sys`, `/etc` config)

| Field | Mandatory | Notes |
|---|---|---|
| `path` | yes | Absolute, as opened. If a symlink was resolved, record both `path` and `resolved_path`. |
| `value` | yes on success | The parsed value, **capped**. Never the raw contents of a credential-shaped file. |
| `bytes_read` | yes on success | Because sysfs/procfs `st_size` lies (see L07), the byte count actually read is the real evidence. |
| `errno` | yes on failure | Symbolic (`EACCES`, `ENOENT`, `EINVAL`, `ENODEV`, `EOPNOTSUPP`, `EIO`), not numeric-only. |
| `truncated` | yes if cap hit | `true` means the read hit the byte cap; the value is a prefix, and any conclusion drawn from it must be `unknown` unless the cap provably exceeds the field's maximum length. |
| `mode`,`uid`,`gid` | recommended | From the `lstat` performed before opening (L06). Cheap, and it explains an `EACCES` without a second probe. |

## 2. `file_metadata` — stat/lstat only, file contents never opened

Used for the entire secrets surface: presence and permission are the finding; content is not.

| Field | Mandatory | Notes |
|---|---|---|
| `path` | yes | |
| `exists` | yes | `false` only when `lstat` returned `ENOENT`, never when it returned `EACCES`. |
| `file_type` | yes when exists | `regular`\|`dir`\|`symlink`\|`chardev`\|`blockdev`\|`fifo`\|`socket`. Drives the "never open a device node" rule. |
| `mode`,`uid`,`gid`,`size` | yes when exists | Metadata only. `size` is legitimate evidence for a secret-shaped file; contents are not. |
| `symlink_target` | when symlink | Recorded, not followed, outside `/sys`. |
| `acl_present` | optional | Boolean derived from the `system.posix_acl_access` xattr, never the ACL's decoded contents if that would reveal a principal list unnecessarily. |
| `magic_class` | optional | A *classification label* (`pem-private-key`, `openssh-private-key`, `jks`, `keytab`, `unknown`) derived from a bounded ≤64-byte header read that is discarded immediately. Never the bytes themselves. |
| `errno` | yes on failure | `EACCES` on a parent directory means the subtree is **unknown**, not empty (L13). |

## 3. `dir_walk` — bounded enumeration

| Field | Mandatory | Notes |
|---|---|---|
| `root` | yes | Where the walk started. |
| `entries_scanned` | yes | |
| `dirs_pruned` | yes | List (or count + sample) of pruned paths, including `/proc`, `/sys`, `/dev`, `/run` and any non-native fstype. |
| `budget_exhausted` | yes | `entries`\|`depth`\|`time`\|`none`. If not `none`, **absence of a match is not evidence of absence** and the finding must be `unknown`. |
| `crossed_mounts` | yes | Should be `false` (`-xdev` equivalent). |
| `unreadable_dirs` | yes | Count + sample of `EACCES` directories. This is the honest boundary of the enumeration and must appear in the finding, not only in a log. |

## 4. `command_exec` — subprocess fallback (never the primary probe)

| Field | Mandatory | Notes |
|---|---|---|
| `command` | yes | argv as an array, never a shell string. No shell is spawned. |
| `binary_resolved_path` | yes when found | Distinguishes `UTILITY_MISSING` from `EACCES` on the binary. |
| `exit_code` | yes when the process ran | |
| `signal` | yes when killed | E.g. `SIGKILL` after the deadline. Distinguishes TIMEOUT from a clean non-zero exit. |
| `timed_out` | yes | Boolean. A `true` here forces `status=unknown`, never `fail` (L20). |
| `stdout_bytes`,`stderr_bytes` | yes | Byte counts even when the content is dropped. |
| `stdout_truncated` | yes if cap hit | If the cap was hit, any parse of the output is partial and must not produce a `pass`. |
| `stderr_excerpt` | recommended | Capped, e.g. 256 bytes. This is where `sshd: no hostkeys available -- exiting.` lands, and it is the *actual* evidence for the UNKNOWN. |
| `wait_delay_expired` | recommended | True when the child exited but pipes stayed open past `Cmd.WaitDelay` — a distinct failure mode from a plain timeout. |

## 5. `config_resolution` — an effective value assembled from several files

Needed because "the value in this file" and "the effective value" are different facts (sshd).

| Field | Mandatory | Notes |
|---|---|---|
| `directive` | yes | |
| `effective_value` | yes when resolvable | |
| `winning_source` | yes when resolvable | `{path, line}` of the occurrence that actually won under the program's precedence rule. |
| `shadowed_occurrences` | yes | Every other `{path, line, value}` seen. This is what makes a false FAIL from "the main file says X" detectable. |
| `resolution_rule` | yes | E.g. `first-obtained-value-wins`, with a citation id. |
| `defaulted` | yes | `true` if no file set it and a documented compiled-in default was applied. |
| `default_source` | yes when `defaulted` | Citation for the default (man page + version). A `pass` from an assumed default with no `default_source` is a bug (L21). |
| `conditional_blocks` | yes when present | Count and criteria of `Match` blocks; their presence downgrades a global verdict to evidence-only. |

## 6. `device_probe` — hardware / kernel-object observation

| Field | Mandatory | Notes |
|---|---|---|
| `sysfs_path` | yes | The attribute or device directory actually read. |
| `device_node` | when relevant | E.g. `/dev/ipmi0`; recorded with `mode`,`uid`,`gid` and **never opened**. |
| `driver` / `module` | recommended | From `/sys/.../driver` symlink basename or `/proc/modules`. |
| `capability_present` | yes | Whether the kernel-side capability exists (interface discovered). |
| `access_permitted` | yes | Whether *this* uid could use it. These are two different findings and collapsing them is the classic BMC mistake (L30). |

## 7. Closed `reason` vocabulary for `status=unknown`

Never collapse these. Each maps to a different remediation and a different re-probe.

| `reason` | Means | Must NOT be reported as |
|---|---|---|
| `EACCES` | The object exists; this uid may not read it. | absent / pass |
| `ENOENT` | The path does not exist (proven by a successful parent listing). | unknown-forever; if a documented default exists, resolve against it |
| `EPERM` | Operation not permitted (capability, not file mode) — e.g. `dmesg` under `dmesg_restrict=1`. | EACCES (different remediation: capability vs mode) |
| `EINVAL` / `ENODEV` / `EOPNOTSUPP` | The kernel attribute exists but the operation/feature is not supported here. | absent / fail |
| `TIMEOUT` | The probe was attempted and did not finish inside its budget. | fail / unsupported |
| `UTILITY_MISSING` | The helper binary is not installed. | capability missing |
| `BUDGET_EXHAUSTED` | A walk/scan hit its entry, depth or time cap before completing. | "nothing found" |
| `PARSE_ERROR` | Output was obtained but did not match the expected shape (tool version drift). | fail |
| `EXECUTION_ERROR` | The tool ran and failed for its own reasons (non-zero exit, diagnostic on stderr). | fail |
| `CONTESTED` | Two probes gave contradicting answers; both recorded. | first-observation-wins |

## 8. Fields that must NEVER appear

- The contents of any file classified `magic_class != unknown`, or any prefix/suffix of it.
- Any hash of a secret value (a hash is still a value-derived artifact and invites offline attack).
- `/etc/machine-id` verbatim — `machine-id(5)` states the ID "should be considered 'confidential'".
  Emit an application-keyed derivation, and record the derivation method, not the raw ID.
- Environment variables of any process, including our own.
- Private-key file *contents*; the `path`, `mode`, `uid`, `gid`, `size` and `magic_class` are the finding.
