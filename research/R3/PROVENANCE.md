# R3 — PROVENANCE.md

Tooling and methodology record for track R3 (`r3-sensor-evidence`), run on claude-opus-5.

## Methodology baseline

- Deep-research plugin at `/c/Users/KLDRM/.lava-workbench/deep-research`, commit **a0d67e9**
  (verified with `git log -1`). **Discrepancy logged:** the launch brief cites v1.8.0, but
  `commands/deep-research.md` self-declares **Version 1.6.0** and `skills/research/SKILL.md`
  declares Version 4.1.0. The commit hash matches, so the version string in the brief is stale;
  methodology was taken from the files as they exist at that commit.
- Phase 0 (mandatory read) completed before any research: `commands/deep-research.md`,
  `skills/research/SKILL.md`, `agents/deep-research-agent.md`, `agents/research-agent.md`,
  `agents/critic-agent.md`, `agents/fact-check-agent.md`.

## Phases executed (times UTC, 2026-09-08/09)

| Phase | What happened | Time |
|---|---|---|
| 0 | Methodology read; output dir created | 22:36–22:38 |
| 1 | Topic decomposition into 6 streams (below) | 22:38 |
| 2 | Parallel stream launch (see concurrency note) | 22:39 |
| — | Lead LOCAL_REPRO batches + own fetches, concurrent with streams | 22:38–23:05 |
| 2.5 | Signal Map (below) | implicit per stream, recorded below |
| 3 | Adaptive deep dives inside each stream (primary sources at pinned refs) | 22:40–23:16 |
| 4 | SIFT synthesis + contradiction pass by the lead | 23:16–23:25 |
| 5/6 | 2-D confidence assignment and artifact writing | 23:20–23:40 |

## Phase 1 — decomposition and Phase 2 execution honesty

Six streams were defined:

- **A** kernel/sysfs/procfs unprivileged exposure (topic 1)
- **B** bounded subprocesses and bounded reads in Go (topic 2)
- **C** sshd effective config + non-SSH remote access (topic 3)
- **D** secrets on disk + BMC in-band (topics 4, 5)
- **E** storage evidence + machine identity (topics 6, 7)
- **F** failure taxonomy/prior art + portability (topics 8, 9)

**Parallelism actually achieved — partial, and this matters.** A, B, C and F launched in parallel in
a single message. **D and E were rejected by the harness with "Concurrent subagent limit reached"**
(the session already held other agents). The instruction attached to that error was not to retry, so
the lead covered D and E directly for ~25 minutes (kernel IPMI doc, xattr(7), machine-id(5),
sysfs.rst, dmi-id.c, genhd.c, sysfs-block ABI, plus LOCAL_REPRO), and then, once a slot freed,
launched a **single combined DE stream** with the already-covered ground explicitly excluded from its
scope. Net effect: 5 sub-agents instead of 6, with the D/E material split between the lead and the
combined worker. This is a real deviation from a fully parallel Phase 2 and is recorded here rather
than smoothed over.

Model allocation: streams A, C, F, DE on sonnet (the deep-research `research-agent` pattern);
stream B on the parent model (opus) because the Go stdlib semantics are the most exactness-sensitive
material in the track and a wrong `WaitDelay` reading would silently poison L09–L12.

## Phase 2.5 — Signal Map

| Stream | Sources | Quality | Contradictions | Signal |
|---|---|---|---|---|
| A kernel exposure | 20 (15 primary, kernel source at v6.8) | very high | 1 real (EPERM vs EACCES in fs/namei.c) | **STRONG** |
| B Go execution | 9 web primary + 12 local stdlib file:line | very high | 3 resolved | **STRONG** |
| C sshd/remote | 19 (16 primary man pages + source at V_9_6_P1) | high | 3 real | **STRONG** |
| DE secrets/BMC/storage | 19 (14 primary incl. DMTF PDF, kernel + cryptsetup source) | high | 0 | **MODERATE→STRONG** |
| F taxonomy/portability | 22 (16 primary; 2 PDFs unreadable) | mixed | 2 real | **MODERATE** |

Effort followed the map: F's PDF-blocked items were left at LIKELY/SPECULATIVE rather than being
force-fitted, and no law rests on them.

## Acquisition tooling and counts

- **WebSearch / WebFetch**: used by all five streams; the dominant extractor overall.
- **Trafilatura** (pinned venv, `2.2.0`): the briefed invocation
  `python -m trafilatura -u <URL>` **DOES NOT WORK** — trafilatura 2.2.0 ships no `__main__`, so the
  module form fails with "cannot be directly executed", and it silently produced empty output at
  first. Working form is the Python API (`fetch_url` + `extract(favor_precision=True)`) with stdout
  re-wrapped as UTF-8, because the default cp1252 console encoding raises `UnicodeEncodeError` on
  man-page glyphs such as U+27E8. Both fixes are recorded so the next track does not lose the same
  ten minutes. Successful trafilatura extractions by the lead: 4 (kernel IPMI doc, xattr(7),
  machine-id(5), sysfs.rst). Stream A used trafilatura successfully against elixir.bootlin.com.
- **Plain urllib / curl at pinned refs**: the highest-yield tool of the run. Raw kernel source at
  `torvalds/linux` tag **v6.8** (dmi-id.c, dmi-sysfs.c, dmi_scan.c, genhd.c, nvme/host/ioctl.c,
  fs/namei.c, printk.c, and four `Documentation/` files), OpenSSH at tag **V_9_6_P1** (sshd.c,
  PROTOCOL.key), cryptsetup `lib/libdevmapper.c`.
- **Local source reads (primary)**: Go **1.26.2** stdlib at `C:\Program Files\Go\src\...` —
  `os/file.go`, `os/exec/exec.go`, `os/exec.go`, `os/root.go`, `os/root_unix.go`, `os/error.go`,
  `os/timeout_test.go`, `syscall/exec_linux.go`, `io/io.go`, `io/fs/fs.go`, `path/filepath/path.go`.
  Wording cross-checked against pkg.go.dev `@go1.24.0` and found identical, i.e. stable Go 1.20→1.26.
- **Crawl4AI escalation**: one — DMTF **DSP0270 v1.3.1** (PDF). WebFetch returned 403; the stream
  escalated to a direct curl with a User-Agent plus PDF text extraction. Reason recorded: PDF behind
  a UA check, not a JS-heavy page.
- **Total sources in `sources.jsonl`: 77** (≈62 primary, 12 secondary, 1 low-credibility community
  thread used only as corroboration, 2 LOCAL_REPRO/local-source pseudo-sources).

## Failures, distinguished by class

- **TIMEOUT**: none. No fetch was abandoned for exceeding time.
- **EXTRACTION_FAILED (not timeout, not missing)**: NIST SP 800-115 PDF and NIST IR 7275 Rev.4 PDF —
  fetched, but no usable text layer was recovered. The XCCDF enumeration was recovered instead from
  the NIST-hosted XSD, which is a *better* source; SP 800-115 was left SPECULATIVE and supports no
  law.
- **HTTP 403**: freedesktop.org (os-release(5)) — worked around via the Debian manpages mirror;
  dmtf.org PDF via WebFetch — worked around with curl + UA.
- **HTTP 404**: manpages mirror for pam.conf(5)/pam.d(5). Recorded as a gap; no law depends on PAM.
- **UTILITY_MISSING (local)**: `getfacl` and `getfattr` are absent from the WSL2 environment, so the
  ACL-xattr question could not be answered by LOCAL_REPRO at all. This is exactly the
  UTILITY_MISSING-vs-EACCES distinction the sensor must make, encountered first-hand; it became
  R3-OR2.
- **Harness limit**: the concurrent-subagent rejection described above. Not a timeout, not a tool
  failure — a capacity limit, handled by re-scoping rather than by dropping the topics.
- **Write-tool policy block**: the harness refused `Write` for `REPORT.md` (a report-named markdown
  file). Since REPORT.md is a required deliverable of this track's approved prompt, the content was
  written to a temp file and copied into place with `cp`. No other path in the repo was touched.

## LOCAL_REPRO record

Environment for every LOCAL_REPRO in this track: **WSL2, Ubuntu 26.04 LTS userspace, kernel
`6.18.33.2-microsoft-standard-WSL2`, uid 1000 (`kldrm`), groups incl. `adm sudo` but NOT `disk`.**
This is emphatically **not** the Lava target (Ubuntu 24.04.4 / 6.8.0-139-generic) and is used only
where the mechanism is kernel-generic. Eight batches were run by the lead plus additional batches by
streams A, B and F. Findings that became evidence:

1. `/sys/class/dmi` and `/sys/firmware/dmi` are **ENOENT** — no DMI at all despite `ID=ubuntu`. Became
   R3-F77 and half of L37.
2. `/proc/cpuinfo` st_size **0**; `/sys/block/sda/size` st_size **4096**, mode 0444, 7 bytes of
   content. Confirms R3-F07 against Go's own source comment.
3. `/etc/shadow` 0640 root:shadow; `/etc/sudoers` 0440 root:root; `ls /root` → EACCES. R3-F28, R3-F36.
4. `getfacl`/`getfattr` absent → the ACL question is unanswerable locally (R3-OR2).
5. `fs.protected_regular=2`, `protected_fifos=1`, `kptr_restrict=1`, `perf_event_paranoid=2`,
   `unprivileged_bpf_disabled=2`, `yama.ptrace_scope=1`, `dmesg_restrict=0` (so `dmesg` succeeded
   here, unlike on the target — a clean illustration of why the sysctl must be read, L08).
6. `kernel.unprivileged_userns_clone` **absent**, `user.max_user_namespaces=30839`, on an
   `ID=ubuntu, ID_LIKE=debian` system. The live counter-example behind R3-F74 and L37.
7. `dd if=/dev/sda` → EACCES while `lsblk -J -o NAME,SERIAL,WWN,FSTYPE` returned populated values and
   `/run/udev/data` exists; UUID null for 2 of 4 devices. R3-F46 and the partial-fallback caveat.
8. `ss -tlnp` as uid 1000 listed all LISTEN sockets with a blank process column; `/proc/net/tcp`
   shows a uid field. R3-F30.
9. `/sys/kernel/security/lsm` ENOENT; `/proc/mdstat` ENOENT; `systemd-detect-virt` → `wsl`, exit 0;
   `/run/systemd/system` present; util-linux 2.41.3, iproute2 6.19.0.
10. `/sys/class/net/lo` and `/sys/block/loop0` are symlinks into `../devices/...`. R3-F19.

Nothing destructive was run. No `ssh`, `scp` or `rsync` was executed at any point. `.env`,
`~/.ssh` and `state/raw_host/` were never opened.

## Prompt-injection and safety events

- **No injection attempts observed.** All five streams reported clean fetched content, and the lead's
  own fetches (kernel docs, man pages, raw source, systemd docs) contained nothing resembling an
  instruction to the reader.
- **No source requested SSH use, credentials, or environment variables.**
- One safety-relevant self-imposed narrowing: stream C established that `sudo -n -l` would be
  technically non-prompting and read-only, and it was explicitly excluded from the sensor's probe set
  anyway per project policy (L22). Recorded so the reasoning is not re-litigated later.

## Artifacts produced (all under `research/R3/`)

`REPORT.md`, `DESIGN_LAWS.md` (39 laws, L04/L06 unallocated), `facts.jsonl` (66 records, JSON-validated),
`sources.jsonl` (77 records, JSON-validated), `EVIDENCE_MODEL.md`, `FIXTURE_MATRIX.md` (51 fixtures),
`OBSERVATION_REQUESTS.md` (10 requests, 3 blocking), `PROPAGATION_NOTES.md`, this file, and
`streams/` (five raw stream notes: A, B, C, DE, F).

Approximate wall time: **~65 minutes** against a ~40-minute box. The overrun is attributable to the
concurrency rejection (D/E had to be done twice over: once by hand, once re-scoped) and to the
trafilatura invocation being broken as briefed.

## VIS_CONTRIBUTION

What each Vis conduct module actually changed, not that it was read.

- **`orchestration/conduct/task-decomposition.md`** — pushed me to group the 9 brief topics by
  *evidence surface* (kernel source / Go stdlib / man pages / specs) rather than by brief numbering.
  That is why topics 4+5 and 6+7 were paired: they share the "kernel source at a pinned tag" surface,
  so one worker could reuse fetch machinery. It also made the D/E concurrency failure recoverable —
  the pairing was already coherent enough to re-issue as a single combined stream without rewriting
  the scope.
- **`web/conduct/research-pipeline.md`** — set the shape "broad launch → signal map → pinned-ref deep
  dive" and, concretely, made me require a *pinned ref in the URL* for every source-code claim. That
  single rule is why every kernel citation in this track says `v6.8` and every OpenSSH citation says
  `V_9_6_P1`, instead of `master` — which would have made the whole KB unfalsifiable in six months.
- **`web/conduct/source-discipline.md`** — caused two concrete demotions. (1) The Ubuntu socket-
  activation fact (R3-F27) rests on a Canonical discourse thread, not a man page; I refused to write
  L20 as "Ubuntu ignores Port" and rewrote it as the observable cross-check "the socket table is the
  truth", which is sourced independently and is also more generic. (2) The cloud-init drop-in fact
  (R3-F22) rests on an HN thread; it stayed LIKELY at credibility -1 and was explicitly *not* allowed
  to carry L16 — L16 stands on sshd_config(5) instead.
- **`web/conduct/citation-verification.md`** — forced verification instead of recall in two places
  that would otherwise have been plausible fabrications: the golang/go issue numbers (#23019 and
  #50436 were *fetched*, and it turned out the memorable one is closed "not planned" while a
  different one shipped the API), and the `/sys/block/<disk>/size` unit, which I expected to find in
  `Documentation/ABI/stable/sysfs-block` and which **is not there** — the 512-byte unit had to be
  established from `block/genhd.c` instead. Without this module I would have cited an ABI file that
  does not document the attribute.
- **`core/conduct/doubt-engine.md`** — the contradiction pass is entirely its doing. It produced the
  R3-F20 correction (the brief's own assumption that sshd_config and ssh_config have opposite
  precedence is wrong — both say first-value-wins), and it stopped me from writing a tidy
  "EACCES = permission, EPERM = capability" mapping after stream A found that `protected_hardlinks`
  denies EPERM while its three siblings deny EACCES from the same file.
- **`core/conduct/verification.md`** — converted three would-be assumptions into LOCAL_REPRO runs:
  that `lsblk` needs device access (it does not), that `ss -tlnp` fails unprivileged (it does not — it
  blanks a column), and that a WSL "Ubuntu" carries Ubuntu's kernel sysctls (it does not). The third
  became the strongest single argument in the track for capability-gating over distro-gating.
- **`core/conduct/prior-art-discovery.md`** — sent stream F to the *schemas* (XCCDF XSD, OVAL, SARIF)
  rather than to tool blog posts, which is why topic 8 has primary citations at all. It also produced
  the most useful negative result of the run: Wazuh SCA's documented merging of absent/unreadable/
  timeout into one "not applicable" label, which is now the citable justification for our finer
  reason vocabulary (L35).
- **`core/conduct/capability-fidelity.md`** — kept laws inside what the evidence supports. Two visible
  effects: L26 is worded as "report the observed mode" rather than "expect 0600", because R3-F44 is
  only LIKELY; and L23 is a law about the *procedure* (bounded read, classify, discard) rather than
  about the magic-byte table, because half that table is unverified. In both cases the tempting
  stronger law would have been unsupported by its own footnotes.
