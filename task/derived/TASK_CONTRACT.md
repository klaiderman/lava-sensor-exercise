# TASK_CONTRACT — Lava Sensor Exercise

Authoritative inputs: `task/original/Lava-Sensor-Exercise.html` (primary), `task/original/Lava-Sensor-Exercise.pdf` (8 pp; same document, printed from the HTML — word-level diff shows only CSS tokens/punctuation differences). Schema: no separate `finding.schema.json` was supplied; per the user's decision (2026-09-09) the contract embedded in both files was cross-checked and transcribed into **`task/derived/finding.schema.json`** (derived artifact; provenance and transcription rules in `task/derived/SCHEMA_PROVENANCE.md`), which is the validation source from that point on — see AM-1.

Tags: **[EXPLICIT]** Lava requirement, quoted or closely paraphrased from the brief · **[ASSUMPTION]** ours, could be wrong · **[INTERPRETATION]** our engineering reading of an explicit requirement · **[AMBIGUITY]** unresolved or settled-by-us question.

Rule: interpretations and assumptions never get promoted to Lava requirements. When in doubt, the brief wins; when the brief is silent, the schema wins; when both are silent, we choose, record it here and in NOTES_INPUTS, and keep the choice visible in the output.

---

## A. Deliverable and interface

| ID | Tag | Requirement | Source | Acceptance |
|---|---|---|---|---|
| A1 | EXPLICIT | Command-line tool; canonical invocation `sensor scan --out findings.json`; "inspects the server and writes what it found to a file". | The task | Binary `sensor`, subcommand `scan`, flag `--out <path>`; exit 0 on completed scan even if findings fail/unknown. |
| A2 | EXPLICIT | Deliver the source plus "the one command that runs it. If we cannot run it, we cannot give you credit for it." | What to send us §01 | One documented command works from a clean unpack (clean-room gate). Build step, if any, is part of documented workflow. |
| A3 | EXPLICIT | `findings.json` "from a real run against the server we gave you, not a hand-written example". | §02 | Final findings.json produced by the exact submitted artifact on the Lava host; hash + timestamp recorded. |
| A4 | EXPLICIT | `NOTES.md`, one page at most: what we assumed; what was ambiguous and how we settled it; the category we added and why; what we'd do with another day; one thing Claude got wrong that we rejected, with the reason. | §03 + "at least one category of your own" | All five items present; ≤ 1 page (we cap at ~60 lines / ~600 words). |
| A5 | EXPLICIT | Our Claude session, "the transcript, as exported"; "a messy real one is far better received than a tidied one". | §04 | Native export included unchanged. Any HTML viewer is additional, never a replacement. |
| A6 | EXPLICIT | One tarball by email. "No repository to create and no accounts to link." | What to send us | Tarball contains only deliverables; no GitHub links required or relied upon. |
| A7 | EXPLICIT | Any language; Go preferred; language does not affect score. | Chips + "What we are not testing" | — |
| A7a | ASSUMPTION | We implement in Go (stdlib-first). | ours | — |
| A8 | EXPLICIT | "Use Claude, and send us the session." | Rules → Required | Session export in tarball. |
| A9 | EXPLICIT | Both workflows allowed and unscored: code locally + run over SSH, or work on the server with Claude installed there. | "Work wherever you prefer" | We chose local orchestration + controlled SSH (`state/SSH_PLAN.md`). |

## B. Part one — describe the machine

"Report at least these, and add whatever else you think belongs." "If you cannot determine one of these, say so in the output. An empty string or a plausible guess is worse than a field that admits it does not know." "A finding with no machine attached to it is not worth much once you have more than one server."

| ID | Tag | Requirement | Acceptance / notes |
|---|---|---|---|
| B1 | EXPLICIT | **Identity**: a host identifier "that stays the same across runs", and the hostname. | `machine.host_id`, `machine.hostname` present. Two consecutive runs on the Lava host yield identical `host_id`. |
| B1a | INTERPRETATION | Stable = identical across runs and reboots on the same machine, independent of time, network state and our own process; derived from machine-resident identity with explicit provenance (`host_id_source`). Candidate chain (to be fixed by R3/R5 research): DMI product UUID (root-only on most kernels) → `/etc/machine-id` → hashed stable hardware identifiers (board serial / primary disk WWN / primary NIC MAC) → explicit unknown. Never a random or time-based value. | Provenance field present; test: run twice, compare. |
| B2 | EXPLICIT | **Owner**: "Who this machine belongs to, as far as the machine itself can tell." Schema example: `"owner": "<or an explicit unknown>"`. | Owner string or explicit unknown, plus provenance. |
| B2a | AMBIGUITY→INTERPRETATION | No canonical Linux "owner" exists. We define owner evidence sources resident on the machine, in precedence order (to be validated by research): DMI chassis/board asset tags and product SKU/family; `/etc/machine-info` (DEPLOYMENT/LOCATION); provisioning/cloud-init metadata visible to us (`/run/cloud-init/instance-data.json`, `/var/lib/cloud/...`); login banners (`/etc/motd`, `/etc/issue`); hostname domain / naming scheme; organization fields in host TLS certs. Report `owner` as the best-supported value with `owner_source`; otherwise the explicit unknown marker plus `owner_candidates` for weaker hints. | Unknown is a legal, expected answer. |
| B3 | EXPLICIT | **Hardware**: vendor and model; CPU model and core count; memory. | `machine.vendor`, `machine.model`, `machine.cpu.model`, `machine.cpu.cores`, `machine.memory_bytes`. |
| B3a | INTERPRETATION | Vendor/model from `/sys/class/dmi/id/{sys_vendor,product_name}` (world-readable), with `board_*` as fallback; `dmidecode` is root-only and not relied upon. | Each unreadable source recorded, not guessed. |
| B3b | AMBIGUITY | "core count": physical cores vs logical CPUs. Example shows `"cores": 0` only. **Settled (provisional):** `cpu.cores` = physical cores when derivable from `/proc/cpuinfo` (`physical id`/`core id`) or `/sys/devices/system/cpu/*/topology`; else online logical CPUs with `cores_basis` stating which. Extra fields: `logical_cpus`, `sockets`, `threads_per_core`. | Both numbers visible; basis explicit. |
| B3c | INTERPRETATION | `memory_bytes` = kernel-visible `MemTotal` from `/proc/meminfo` in bytes, with `memory_source: "/proc/meminfo:MemTotal"`. DMI-installed capacity needs root → reported as unknown/extra only if readable. | — |
| B4 | EXPLICIT | **Operating system**: distribution, version, kernel release. | `os.name`, `os.version` from `/etc/os-release` (`NAME`/`VERSION_ID` or `VERSION`), `os.kernel` from `uname -r` / `/proc/sys/kernel/osrelease`. |
| B5 | EXPLICIT | **Storage**: "The block devices attached, their models and sizes." | `machine.storage[]` with `device`, `model`, `size_bytes`. |
| B5a | INTERPRETATION | "Block devices attached" = whole physical/virtual disks (`/sys/block/*` excluding loop/ram/zram/dm/md unless nothing else exists), `size_bytes` = `/sys/block/<d>/size × logical block size 512`, `model` from `/sys/block/<d>/device/model` or NVMe `/sys/class/nvme/*/model`; extra fields welcome: `transport`, `rotational`, `serial` (if readable), `wwn`, partitions, dm/md/LVM/multipath layering, filesystems/mounts. Storage stack depth is a project priority (interviewer context), not a brief requirement. | Unreadable model → explicit unknown for that device, device still listed. |
| B6 | EXPLICIT | Unknown must be explicit: no empty strings, no plausible guesses. | No `""` anywhere in `machine`; unknown marker + reason. Exact marker representation depends on the real schema (PENDING-SCHEMA, see AM-1). |
| B7 | EXPLICIT | "Add whatever else you think belongs." Extra fields welcome anywhere. | Additional machine fields allowed if the schema permits additionalProperties (PENDING-SCHEMA). |

## C. Part two — posture checks and categories

| ID | Tag | Requirement | Acceptance |
|---|---|---|---|
| C1 | EXPLICIT | Organize checks within categories; each category "should contain at least two relevant checks (or as many as needed), with each check yielding its own distinct result". "A category with four checks produces four findings, each with its own status and severity." | Every category ≥ 2 findings; one finding per check per run. |
| C2 | EXPLICIT | Required categories (UPPER_SNAKE_CASE): `REMOTE_ACCESS`, `SECRETS_ON_DISK`, `BMC_INBAND_ACCESS`. | Exactly these strings present. |
| C3 | EXPLICIT | At least one category of our own, for "a server sitting in someone's data center"; one line in NOTES.md on why; more than one welcome. Kernel Flags is their benchmark ("hardware security features active, unsigned code permitted, boot chain verified — each its own check"). "What impresses us most is discovering a category we did not anticipate, supported by clear engineering intent." | ≥ 1 custom category with ≥ 2 checks; NOTES line. |
| C4 | EXPLICIT | `REMOTE_ACCESS` answers: how this machine can be logged into from elsewhere and what that permits; who may connect, by what means of authentication, and as whom; "what is actually in force on the running system, which is not always what any single configuration file says". | Checks cover listeners/services, effective sshd policy (Include/drop-ins/Match, defaults), auth methods, who (users with shells, authorized keys, sudo/wheel), plus non-SSH remote paths. |
| C4a | INTERPRETATION | "Actually in force" without root: `sshd -T` is root-only → we derive effective config by parsing the running daemon's config path (from process args/systemd unit), applying Include/drop-in/first-match-wins semantics and OpenSSH defaults for the detected version, and cross-checking runtime evidence (listening sockets, process presence, PAM, our own session's auth method). Where derivation is not possible we say unknown, not "default". | Evidence names the files read, directives found, and defaults applied. |
| C5 | EXPLICIT | `SECRETS_ON_DISK` answers: what credential material is sitting on the machine and who can read it — "keys, tokens, passwords, certificates, provisioning data, anything someone could pick up and reuse somewhere else. Both what is there and how well it is protected." | Checks cover presence + protection (mode/owner/group/world-readability) of key material, credentials files, provisioning data, and our own user's exposure. |
| C5a | INTERPRETATION + SAFETY | Evidence contains metadata only (path, type detected from headers/names, mode, owner, size, mtime) — never secret content, never partial key bytes. Unreadable directories are reported as observation boundaries (EACCES), not as "no secrets". | Secret scan of findings.json passes. |
| C6 | EXPLICIT | `BMC_INBAND_ACCESS` answers: whether this machine can talk to its own BMC from inside the OS, through which interface (KCS / `ipmi_si`, `ipmi_devintf`, device node, `ipmitool`), and who is permitted to do it. "That path is not always present and not always permitted." | Checks: driver/module presence; device node presence; device node permissions/ACLs (who may open it); client tooling presence; actual in-band reachability if permitted (bounded); ACPI/DMI evidence of the interface. |
| C6a | INTERPRETATION | "Who is permitted" = device-node mode/owner/group + POSIX ACLs + udev rules + group membership of login users + presence of privilege paths (sudo group). Running `ipmitool mc info` is a read-only BMC query and acceptable only with a hard timeout and only when the device is openable by us; failure/EACCES/timeout is evidence, never "absent". | — |
| C7 | EXPLICIT | Severity `info` "is a real answer, not a cop out. Plenty of things are worth reporting because an operator should know them, not because they are broken." | Observational checks use `info`. |
| C8 | EXPLICIT | "Working out what that means on this particular machine, and how to establish it rather than assume it, is the exercise." | Every status is evidence-backed; no status from assumptions/defaults without saying so. |
| C9 | EXPLICIT | Volume is not tested: "A handful of checks done thoughtfully beats twenty done thinly." | Prefer depth: ~3–6 checks per category. |

## D. Finding and document semantics

| ID | Tag | Requirement | Acceptance |
|---|---|---|---|
| D1 | EXPLICIT | Finding fields: `category` (UPPER_SNAKE_CASE), `check_id` (unique per check), `status` ∈ {pass, fail, unknown}, `severity` ∈ {critical, high, medium, low, info}, `title` (one readable line), `reason` (required when status is fail or unknown), `evidence` (object: "what someone needs to act on it"), `collected_at` (RFC 3339). | Schema validation (PENDING-SCHEMA) + our own tests. |
| D1a | INTERPRETATION | `check_id` is stable across runs and machines (a check identity, e.g. `ROOT_LOGIN_PERMITTED`), UPPER_SNAKE_CASE like the example; unique within the document. | Uniqueness test. |
| D2 | EXPLICIT | Evidence must be real: "the path you read, the value you found, the command you ran, the errno you got back" — "rather than a restatement of the title". "A good evidence block means the reader does not have to run your tool again to believe you." | Evidence objects carry sources (paths/commands), observed values, and errors (errno/exit codes/timeouts) as applicable. |
| D3 | EXPLICIT | "When a check is unexecutable or out of reach, state that explicitly. A report that silently omits unreached checks ... destroys trust. Returning no issues is a valid outcome; claiming to have checked when you could not is a critical failure." | Every registered check emits exactly one finding per run; `unknown` carries `reason` + evidence of why (errno, missing utility, timeout, budget). Test: injected EACCES/timeout/missing-tool ⇒ unknown, never pass/fail, never omitted. |
| D4 | EXPLICIT | Top-level shape: `schema_version: "1"`, `collected_at` RFC 3339, `sensor_version` optional, `machine {...}`, `findings [...]`. "Extra fields are welcome anywhere." | Validation. |
| D5 | EXPLICIT | Output "has to validate against" `finding.schema.json`; "We fix the shape because a stable one is what makes a finding usable by anything other than a person reading a terminal, and because it lets us compare submissions fairly." | Validate in tests and on the final output against `task/derived/finding.schema.json` (transcribed from the brief; AM-1). If Lava's own schema file ever arrives, re-validate against it and record any difference. |
| D6 | AMBIGUITY | Severity vs status: is severity the check's impact (static) or the reported finding's urgency (varies with status)? **Provisional settlement:** each check declares an `impact` severity; reported `severity` = impact when status is `fail` or `unknown` (an unverifiable control is an assurance gap of the same weight); `info` when status is `pass` unless the check is observational (always `info`). To be confirmed at architecture freeze; documented in NOTES. | Consistent rule applied by the engine, not per check by hand. |
| D7 | INTERPRETATION | `collected_at` per finding = time the check completed, UTC RFC 3339 with fractional seconds allowed; document `collected_at` = scan start or end (schema may not care) — choose scan end. | — |
| D8 | ASSUMPTION | Output is a single UTF-8 JSON document, deterministic key order and finding order (by category, then check_id) so diffs across runs are meaningful. | Two runs differ only in timestamps/volatile values. |

## E. Rules — required safety properties

| ID | Tag | Requirement | Acceptance |
|---|---|---|---|
| E1 | EXPLICIT | **Read only.** "The sensor observes the machine, it never changes it." | No writes except the `--out` file (and nothing else, not even temp files unless in `$TMPDIR` and removed); no config/state changes; no module loads; no network connections. Verified by strace-style review of code paths + Lich witness. |
| E1a | ASSUMPTION | No outbound network calls at all (no DNS, no metadata endpoints) — keeps "read only" and "bounded" trivially true and avoids leaking that a scan happened. | Code review + test. |
| E2 | EXPLICIT | **Bounded.** "Every subprocess gets a timeout, output stays a sane size, and nothing hangs forever on a device that does not answer." | Per-subprocess timeout + process-group kill; output caps; file reads capped and restricted to regular files (never block on device/FIFO nodes); per-check and whole-scan deadlines. Tests inject hang/flood. |
| E3 | EXPLICIT | **Does not crash.** "One check hitting something unexpected should not take the other checks down with it." | Per-check panic recovery → `unknown` with reason; malformed/huge/missing inputs tested. |
| E4 | EXPLICIT | **Unprivileged.** "It runs as the user we give you, with no escalation." | No sudo/su/setuid/capabilities; never invokes `sudo`. Host fact: our user is in group `sudo` — irrelevant, unused, reported as evidence. Must also remain safe if someone runs it as root. |
| E5 | EXPLICIT | Out of scope, ungraded, "the most common way a four hour exercise becomes a ten hour one": daemon/scheduler, database, UI, API server, packaging, CI. | None built. Tarball creation is the requested deliverable, not "packaging". |
| E6 | EXPLICIT | "Safe on someone's machine. This kind of tool runs on hardware other people depend on." | Same as E1–E4; also: no heavy I/O (bounded `find` depth/time, no full-disk hashing), no SMART/self-tests, no BMC commands beyond read-only identification. |

## F. Evaluation signals and process

| ID | Tag | Signal | How we honour it |
|---|---|---|---|
| F1 | EXPLICIT | Judgment: "how gracefully your sensor handles unanswerable checks while maintaining a clean, generic architecture." | Explicit UNKNOWN semantics; capability detection + fallbacks; no hostname/device hardcoding. |
| F2 | EXPLICIT | How we work with Claude: "what you specified before generating, what you rejected, and what you verified before believing." | Wixie-engineered prompts, approval gates, author≠reviewer, NOTES "one thing Claude got wrong". |
| F3 | EXPLICIT | Not testing prior BMC/IPMI/firmware knowledge or Go fluency or volume. | Research fills domain gaps; no gold-plating. |
| F4 | EXPLICIT | "The four hours: a guide, not a stopwatch." Questions welcome; "needing no clarification at all is not a score". If the server breaks, tell them. | Ask Lava when materially blocked (AM-1 candidate). |
| F5 | EXPLICIT | Follow-up conversation topics (outbound-only sensors, customer identity on first hello, volume/deltas, cross-customer isolation) — "nothing to prepare and nothing extra to submit". | Discussion material only; NOT implementation scope. |

## G. Ambiguities register

| ID | Ambiguity | Status / settlement |
|---|---|---|
| AM-1 | `finding.schema.json` is described as supplied ("This brief, plus finding.schema.json, which your output has to validate against") but is not on this machine. | **SETTLED by the user (2026-09-09).** No separate file exists in the supplied material; the output contract is embedded in the brief. Both files were cross-checked (they agree) and the contract was transcribed without invented constraints into `task/derived/finding.schema.json` (draft 2020-12), with provenance in `SCHEMA_PROVENANCE.md`. It is the project's validation source; NOTES.md discloses that validation was against a schema derived from the brief. Former PENDING-SCHEMA items (B6, B7, D1, D5, AM-5, AM-7) are settled against it. |
| AM-2 | Owner semantics (B2). | Settled provisionally (B2a); explicit unknown allowed. |
| AM-3 | Core count semantics (B3b). | Settled provisionally: physical cores + logical extras + basis. |
| AM-4 | Severity vs status (D6). | Settled provisionally; confirm at architecture freeze. |
| AM-5 | Representation of "explicit unknown" for typed fields (`memory_bytes: 0`? `cores: 0`? `size_bytes`?) — depends on schema types. | **Settled (provisional) against the derived schema:** `cores`, `memory_bytes`, `size_bytes` are integers (the brief's literals), string fields carry the literal `unknown`, and every unknown value is accompanied by an explicit marker — a machine-level `unknowns` object (field → reason + sources tried) and, for numerics, the value 0 only together with that marker. Extra fields are allowed anywhere, so the marker is schema-valid. |
| AM-6 | Is attempting an in-band BMC query (`ipmitool mc info` / Get Device ID) "read only"? | Settled: yes, it is a read; allowed only when the device node is openable by us, with a short timeout, never write/set/chassis-control subcommands. |
| AM-7 | "Extra fields welcome anywhere" vs schema strictness. | **Settled:** the derived schema leaves `additionalProperties` open everywhere (faithful to "Extra fields are welcome anywhere"), so provenance/basis/unknown-marker fields may sit next to the required ones. |
| AM-8 | Does `--out` need parent directories created? | Settled: no; write only the named file, fail loudly (non-zero exit) if it cannot be written. |

## H. Coverage checklist (contract self-verification)

| Kickoff checklist item | Covered by |
|---|---|
| required machine-description fields | B1–B7 |
| stable host identity requirements | B1, B1a |
| owner semantics incl. explicit unknown | B2, B2a, AM-2 |
| hardware/OS/CPU/memory/storage requirements | B3–B5 (+a/b/c) |
| REMOTE_ACCESS | C4, C4a |
| SECRETS_ON_DISK | C5, C5a |
| BMC_INBAND_ACCESS | C6, C6a, AM-6 |
| at least one custom category | C3 |
| minimum relevant checks per category | C1, C9 |
| status/severity/reason/evidence semantics | D1, D2, D6, D7, C7 |
| no silent omission of unexecutable checks | D3 |
| actual findings.json schema requirements | D4, D5, AM-1, AM-5, AM-7 (PENDING-SCHEMA) |
| required source + one-command execution | A1, A2 |
| real-host findings.json | A3 |
| NOTES requirements | A4, C3 |
| native Claude session/export requirement | A5, A8 |
| safety invariants (read-only, bounded, no crash, unprivileged) | E1–E6 |
| out-of-scope guard | E5, F5 |

## I. Cross-check record
- PDF vs HTML: identical content (8 pages; produced by HeadlessChrome from the HTML). Only rendering differences (`--out` extracted as `/-out` by the PDF text layer).
- HTML vs schema: schema file absent → cannot cross-check yet. The HTML's JSON example is illustrative (comments, `|` alternations) and is not a schema.
- Kickoff prompt vs brief: kickoff items that the brief does NOT require (storage-category emphasis, Tiny Custom Investigator, Fixed Registry, tool stack, HTML transcript viewer) are project process choices, tagged as such, not Lava requirements.
