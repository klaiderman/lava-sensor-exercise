# R4 — PROVENANCE

- **Track / role:** R4 `r4-host-investigation`, model `claude-opus-5`.
- **Deep-research plugin version:** `a0d67e9` (v1.8.0), at `~/.lava-workbench/deep-research`.
- **Wall clock:** 2026-09-08 22:36Z → 23:35Z, ≈ 59 minutes (budget was ~40 min of active work; the
  overrun came from four background research streams finishing between 22:52Z and 23:26Z and from the
  corrections their results forced into artifacts that were already written).
- **Prompt executed:** `prompts/R4/prompt.md` (read in full before any other action).
- **Write scope:** `research/R4/` only. No other path was created or modified.

## Passes executed

| Phase | What ran | When (UTC) | Notes |
|---|---|---|---|
| 0 — mandatory inputs | `state/HOST_SNAPSHOT.json`, `state/HOST_SNAPSHOT.evidence.json` (169 probes), `task/derived/TASK_OVERVIEW.md`, `task/derived/TASK_CONTRACT.md`, `prompts/raw/EXECUTION_CONTRACT.md`; `tooling/tci/probes.json` as the read-only probe-command reference | 22:36–22:41 | Built a probe-id → status → command → stdout-length table for all 169 probes, then dumped full stdout for the storage, BMC, kernel, identity, network, users and secrets groups |
| 0 — decomposition | 5 streams, storage weighted heaviest | 22:41 | S1 storage (priority), S2 BMC/IPMI, S3 Ubuntu 24.04, S4 provider + kernel flags, S5 cross-distro/VM/container |
| 1 — parallel broad search | **Sub-agent spawning WAS available** and was used: S1, S2, S3, S5 ran as concurrent background sub-agents | 22:42–23:26 | **S4 FAILED TO LAUNCH** — the harness returned "Concurrent subagent limit reached" for that one call. See "Failures" below |
| 1.5 — signal map | Built implicitly per stream (each stream returned per-question confidence) | — | Recorded as `status` + `confidence` in `facts.jsonl` rather than as a separate document |
| 2 — adaptive deep dives | Storage: kernel source at tag v6.8 for `drivers/nvme/host/sysfs.c`, `ioctl.c`, `block/sed-opal.c`, `drivers/md/md.c`. BMC: `ipmi_msghandler.c`, `ipmi_devintf.c`, `dmi-sysfs.c` at v6.8, DSP0134, DSP0270. Ubuntu: `sshd.c`, `apparmorfs.c`, cloud-init source, noble man pages | 22:50–23:26 | Every load-bearing storage and BMC claim resolved to source at the host's exact kernel tag rather than to `master` |
| 3 — SIFT synthesis / conflict resolution | Four explicit conflicts resolved, all recorded as `CONTESTED` facts | 23:10–23:30 | See "Conflicts resolved" |
| 4 — opinionated recommendation | Storage custom-category verdict with both sides argued, decision left to the lead | 23:12 | `STORAGE_ASSESSMENT.md` §4 |
| 5 — modular output | 10 artifacts under `research/R4/` | 22:58–23:35 | Written incrementally: `TECHNOLOGY_INVENTORY.md` and `facts.jsonl` first, then `STORAGE_ASSESSMENT.md`, then plans, then contract deliverables |

## Acquisition tooling (aggregate across this context and the four sub-agent streams)

| Tool | Count | Notes |
|---|---|---|
| WebSearch | ~35 queries | across S1/S2/S3/S5 |
| WebFetch | ~12 | used where trafilatura returned <500 chars or was blocked |
| Trafilatura (`venv/Scripts/python.exe -m trafilatura -u`) | ~14 | default extractor; man pages, discourse, freedesktop docs |
| `curl` raw fetch | ~15 | kernel and cloud-init source from `raw.githubusercontent.com` at pinned tags; IANA PEN registry |
| Crawl4AI | **0** | not needed: no JS-heavy page was load-bearing. PDF escalation went through `curl` with a browser User-Agent plus `pypdf` (DMTF) and WebFetch's binary cache plus `pypdf` (Supermicro) — recorded here as a substitute for the specified Crawl4AI PDF path |
| Crawlee | 0 | correctly not used (R4 is not assigned Crawlee) |
| LOCAL_REPRO (`wsl -e bash -lc`) | ~20 read-only commands | WSL2 Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2, unprivileged uid 1000, never `sudo`, nothing destructive |
| Sources recorded | **39** (35 primary, 4 secondary, 0 tertiary) | `sources.jsonl` |
| Facts recorded | **60** (43 VERIFIED, 13 LIKELY, 4 CONTESTED) | `facts.jsonl` |
| Observation requests | **10** (R4-OR1 … R4-OR10), none blocking | `OBSERVATION_REQUESTS.md` |
| Snapshot probes cited | 169 available; ~95 cited across the artifacts | probe ids, never paraphrase |

## Conflicts resolved (SIFT)

1. **Snapshot prose vs. evidence file on `mdadm.conf`** — the prose lists it as proven absent; the evidence
   shows `/etc/mdadm/mdadm.conf` was read successfully (`HOMEHOST <ignore>`). Evidence file wins per the
   prompt's edge-case rule. Recorded as R4-F02 (CONTESTED) and flagged to the lead.
2. **S3 vs. host evidence on ssh.socket** — S3 concluded from Ubuntu discourse that Noble derives the
   listen address from `sshd_config` via a generator; the host's `systemctl cat ssh.socket` shows a literal
   `ListenStream=0.0.0.0:22`. Host evidence wins for the host; both are recorded (R4-F31, CONTESTED) and
   the design recommendation is to read the effective value at runtime rather than assume either form.
3. **S3 vs. host evidence on the dmesg denial errno** — S3 said EACCES; the host observed
   `Operation not permitted` (EPERM). Host evidence wins (R4-F43, CONTESTED); the design rule is to quote
   the observed errno rather than a documented one.
4. **My own R4-F30 vs. S1/S2 kernel-source finding on DMI entry permissions** — I inferred from the host
   evidence that only `raw` is root-only; the v6.8 source shows every attribute in a DMI entry directory is
   admin-read-only. My inference was under-constrained. Recorded as R4-F49 (CONTESTED, correcting F30) and
   turned into R4-OR7.

Two further corrections came from S1 **against claims I had already written**, and the affected artifacts
were edited rather than left standing:
- The remediation for the SMART EACCES is **CAP_SYS_ADMIN**, not group `disk` (`/dev/nvme0` is 0600
  root:root, and `nvme_cmd_allowed()` gates Get Log Page on CAP_SYS_ADMIN). R4-F54; `STORAGE_ASSESSMENT.md`
  §1 and trap T-S4 updated.
- SED capability cannot be inferred from the Micron model string, because the base part number is shared
  between SED and non-SED SKUs. R4-F58; new trap T-S12.

## Contradiction-hunting against my own conclusions (doubt-engine pass)

- Re-read every "absent" claim in the snapshot and reclassified it as ENOENT-proven / EACCES / UTILITY_MISSING
  / unobserved. This produced §0 of `TECHNOLOGY_INVENTORY.md`, which shows the TCI **probe status is a coarse
  aggregate that disagrees with its own stdout in at least seven probes** (R4-F01). That finding was not
  in the brief; it emerged from distrusting the status column.
- Challenged the storage custom-category thesis by constructing the strongest competing case
  (boot chain / firmware trust) and grading both on evidence density and severity. The verdict was weakened
  from "storage is the strongest category" to "storage is materially strong but narrow, and boot chain is
  denser" — and the call was left to the lead.
- Challenged my own "no filesystem on nvme1n1" claim: it rests on the udev database, not on a device read,
  so it was downgraded to a scoped statement (trap T-S3, R4-F08, R4-OR8).
- Challenged the bounded-`find` negatives: `world_writable_find` returning empty is a bounded negative, not
  proof, because unreadable directories and other filesystems are silently skipped (R4-F27).

## Failures, gaps and timeouts (a TIMEOUT is not "unsupported")

- **Stream S4 never launched.** The harness rejected the Agent call with "Concurrent subagent limit reached".
  Its topic (provider fingerprinting from evidence classes; UEFI/taint/TPM semantics; host-id stability) was
  **covered in part** by my own analysis of the snapshot evidence and by overlap with S3 and S5, but the
  following remain **OPEN**: (a) no official Latitude.sh documentation was fetched by me on their bare-metal
  metadata service or customer BMC policy (S2 reached their IPMI docs only via a search snippet, credibility 1);
  (b) the `module_blacklist=af_alg,algif_*,sctp*` cmdline was not traced to a distro or provider default, so
  whether it is a Latitude.sh hardening choice or an Ubuntu image default is **unresolved**; (c) the
  stability-across-re-image comparison of host-id candidates (NVMe `wwid`/`eui64` vs machine-id vs NIC
  permanent MAC) was not researched to primary sources.
- **Micron 7450 PRO datasheet not retrieved.** Repeated attempts (S1) were WAF-blocked or timed out —
  `curl` returned `http_code:000 size:0`, i.e. **a timeout with no data, not a 404 and not "unsupported"**.
  The dependent claim (SED SKU ambiguity, R4-F58) is therefore LIKELY at confidence 0.6, not VERIFIED.
- **`systemd.socket(5)` at freedesktop.org returned HTTP 403** to WebFetch (S3); the Ubuntu openssh packaging
  git returned a cgit HTML wrapper rather than plain text. Both are recorded as failed acquisitions, and the
  dependent ssh.socket claim rests on the host's own `systemctl cat` output instead.
- **`sysfs-class-nvme` does not exist** in Documentation/ABI at v6.8 (neither stable nor testing). This is a
  genuine absence in the kernel docs, not a fetch failure; ground truth came from the driver source (R4-F55).
- **nvme-cli exit code / exact stderr not confirmed** from upstream source (GitHub rate-limited during S1).
  Filed as R4-OR10.
- **Supermicro AS-3015MR-H10TNR datasheet** fetched but had no extractable text layer (image-rendered PDF);
  the H13SRE-F product page carried the needed facts instead.

## Encountered injection attempts

**None.** All four streams were instructed to quote verbatim any text in fetched content that read as an
instruction to an AI, and all four reported none. Nothing in the snapshot files, the probe registry or the
task documents attempted to redirect scope. No fetched page asked for credentials, for `.env`, for `~/.ssh`,
for `state/raw_host/`, or for an ssh/scp/rsync invocation. No such command was run and none of those paths
was read at any point.

## Artifacts produced

`TECHNOLOGY_INVENTORY.md`, `STORAGE_ASSESSMENT.md`, `HOST_SPECIFIC_PLAN.md`, `GENERIC_FALLBACK_PLAN.md`,
`REPORT.md`, `facts.jsonl` (60), `sources.jsonl` (39), `OBSERVATION_REQUESTS.md` (10), `PROPAGATION_NOTES.md`,
`PROVENANCE.md`, plus the four raw stream files under `raw/` (`S1_storage.md`, `S2_bmc.md`, `S3_ubuntu.md`,
`S5_crossmachine.md`) retained as the streams' unedited working notes.

**Convention used in `facts.jsonl`:** the `sources` array mixes web source ids (`R4-S<k>`, defined in
`sources.jsonl`) with snapshot probe ids prefixed `PROBE:`. Two *independent* snapshot probes observing the
same fact count as two independent observations for status purposes; a single probe plus a single web source
is LIKELY, never VERIFIED, per the prompt's status discipline.

---

## VIS_CONTRIBUTION

What each conduct module actually changed, not that it was applied.

- **`orchestration/conduct/task-decomposition.md`** — forced the split into five streams with an explicit
  weighting rather than one broad sweep, and forced each stream to be answerable independently. Concrete
  effect: S1 was given the kernel-source questions (not just "research NVMe"), which is why the
  group-`disk`-vs-CAP_SYS_ADMIN correction surfaced at all. A single undifferentiated pass would have
  accepted my original, plausible, wrong remediation.
- **`web/conduct/research-pipeline.md`** — mandated the parallel cast and the 15-minute wall-clock floor.
  Concrete effect: I did **not** conclude at ~25 minutes when the host-evidence analysis was done and the
  artifacts looked complete; waiting for S1 and S2 produced five corrections to already-written files
  (R4-F49, R4-F54, R4-F56, R4-F57, R4-F58). The floor was the difference between a plausible deliverable and
  a correct one.
- **`web/conduct/source-discipline.md`** + **`citation-verification.md`** — required pinned-commit citations.
  Concrete effect: S1 and S2 were re-pointed from `master` to the **v6.8 tag** matching the host's running
  kernel for `dmi-sysfs.c` and the NVMe driver, which is exactly where the DMI-permission claim changed
  (master and v6.8 could have differed, and the load-bearing citation had to be the host's version).
  It also downgraded the Latitude.sh IPMI-policy claim to credibility 1, since only a search snippet was obtained.
- **`core/conduct/doubt-engine.md`** — applied to my own emerging conclusions, not just to sources. Concrete
  effects: the discovery that TCI probe status contradicts its own stdout (R4-F01); the downgrade of the
  storage-category verdict from "strongest" to "materially strong but narrow"; the reclassification of
  "no filesystem on nvme1n1" as a udev-database statement.
- **`core/conduct/verification.md`** — "verify before you believe" is why R4-F08, R4-F18, R4-F29, R4-F33,
  R4-F58 are LIKELY rather than VERIFIED, and why four facts are CONTESTED rather than silently resolved in
  favour of whichever source I read first.
- **`core/conduct/prior-art-discovery.md`** — checked `research/` for existing Lava work before deriving
  anything: `research/R2/` and `research/R3/` existed as empty directories at 22:36Z, so there was no prior
  art to reuse and no duplication to avoid. Concrete effect: none beyond confirming the gap — recorded so
  the lead knows the check was made rather than skipped.
- **`core/conduct/capability-fidelity.md`** — the reason Q2, Q7 and Q14 in `STORAGE_ASSESSMENT.md` are
  labelled "UNKNOWN BY CONSTRUCTION" and separated from "unknown, merely unobserved". Concrete effect: I did
  not substitute the weaker answerable question ("is dm-crypt present?") for the one actually asked ("is the
  data at rest encrypted?"); the plan requires the check to name its own blind spot in the finding's reason.
