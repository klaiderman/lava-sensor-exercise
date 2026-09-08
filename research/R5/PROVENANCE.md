# PROVENANCE — R5 (go-architecture)

**Track:** R5 `r5-go-architecture` · **Model:** claude-opus-5 · **Window:** 2026-09-08 22:36Z → 23:20Z (~44 min active) · **Prompt:** `prompts/R5/prompt.md`

**Methodology:** Zdenekmach deep-research plugin at `~/.lava-workbench/deep-research`, commit `a0d67e9`; `commands/deep-research.md` (v1.6.0 header) and `skills/research/SKILL.md` (v4.1.0) read in full before Phase 0; agent definitions present at `agents/{deep-research,research,critic,fact-check}-agent.md`.

## Passes executed

| Phase | What was done | Time (UTC) |
|---|---|---|
| 0 — Decomposition | Topic split into 5 streams: (A) module layout & registry prior art, (B) bounded exec, (C) safe /proc-/sys reading & xattr, (D) JSON-schema libraries & deterministic JSON, (E) CLI/packaging/testability/sshd parsing. Read the brief, `TASK_CONTRACT.md` sections A–D, and confirmed `finding.schema.json` absent from `task/original/`. | 22:36–22:39 |
| 1 — Parallel broad search | **5 sub-agents launched in a single message** (harness supports parallel spawning; no sequential fallback needed). Each was given the primary-source hierarchy, the untrusted-content rule, and the Trafilatura/Crawl4AI extraction chain. | 22:39–22:51 |
| 1.5 — Signal Map | Built from returned source counts and credibility (below). | 22:51 |
| 2 — Adaptive deep dives | Executed as **LOCAL_REPRO** rather than more fetching, because the weakest signals were all runtime-behaviour claims that documentation cannot settle. Four Go programs cross-compiled Windows→linux/amd64 and run under WSL. | 22:40–22:55 (overlapped with Phase 1) |
| 3 — SIFT synthesis | Conflict resolution on three points (below); credibility scores recorded per source in `sources.jsonl`. | 22:55–23:00 |
| 4 — Recommendations | 2-D confidence (evidence strength × applicability to this host) applied per verdict; every recommendation carries a reversal condition. | 23:00–23:05 |
| 5 — Modular output | 10 artifacts under `research/R5/`. Facts and sources were written incrementally, not held for a final pass. | 23:05–23:20 |

## Signal Map

| Stream | Sources | Credibility | Contradictions | Classification |
|---|---|---|---|---|
| A — module layout / registry prior art | 15 | avg ≈ +2.8 (13 primary source files at pinned refs) | 0 | **STRONG** |
| B — bounded exec | 11 + local GOROOT read | avg ≈ +2.7 | 1 (stale blogs vs current docs) | **STRONG** |
| C — safe fs reading / xattr / x/sys | 17 | avg ≈ +2.8 (kernel uapi + Go source + man7) | 1 (syscall "deprecated") | **STRONG** |
| D — schema libraries / JSON determinism | 13 incl. raw Bowtie run data | avg ≈ +2.8 | 1 (README claims vs conformance) | **STRONG** |
| E — CLI / packaging / sshd / testability | 20 | avg ≈ +2.5 | 0 hard; 2 LIKELY-only claims | **MODERATE-STRONG** |

Phase 2 effort therefore went to empirical verification of the STRONG streams' runtime claims rather than to broadening WEAK ones — there were no WEAK streams.

## Acquisition counts

* Sub-agents: **5**, all completed (53k / 56k / 75k / 101k / 58k subagent tokens; 29 / 25 / 44 / 61 / 26 tool uses).
* Sources recorded: **58** in `sources.jsonl` — 48 primary, 10 secondary, 0 tertiary, 0 AI summaries.
* Extractors used, as recorded per source: `webfetch` (33), `trafilatura-curl` / `curl` on raw source files (17), `curl+python` for the Bowtie NDJSON (1), `trafilatura` (3), `websearch-snippet` (2), `local-goroot-read` (1), plus `LOCAL_REPRO-*` provenance tags on 20 facts.
* **Crawl4AI escalations: 1** (by a sub-agent). `bowtie.report` is a JS SPA and returned no useful static text; the sub-agent worked around it by fetching the underlying `bowtie-json-schema/report-history` NDJSON directly and recomputing pass rates in Python. That is a better outcome than the escalation would have produced — the numbers in R5-F52 are computed from the raw run, not read off a badge.
* Crawlee: not used (R2 only, per contract item 6).
* Failures/timeouts: none. No fetch timed out; no source was unreachable except `bowtie.report`'s SPA rendering, which is a *format* limitation, not a TIMEOUT and not evidence of unsupported.

## Local reproductions (all labelled LOCAL_REPRO)

Environment: **Go 1.26.2 windows/amd64** at `C:\Program Files\Go`, cross-compiling `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`; executed under **WSL2 Ubuntu 26.04 LTS, kernel 6.18.33.2-microsoft-standard-WSL2**, as **uid 1000** (non-root). Sources under `research/R5/repro/`.

| ID | File | What it established |
|---|---|---|
| LOCAL_REPRO-A | `exec_test_main.go` | 7 exec configurations. Grandchild-holds-stdout blocked 30.01s against a 3s context with no `WaitDelay`; 0.21s with `WaitDelay=200ms` returning `exec.ErrWaitDelay` and preserving output; `Setpgid`+custom `Cancel` returned at the deadline (0.50s) where the default `Cancel` took 30.02s. → R5-F11..F13, F15 |
| LOCAL_REPRO-A2 | `orphan_main.go`, `round2_main.go` §A | Orphan survival. `WaitDelay` alone: the `sleep` grandchild was still running after we returned. `Setpgid` + `syscall.Kill(-pid, SIGKILL)`: zero survivors. → R5-F14 (novel; not documented in any source found) |
| LOCAL_REPRO-C | `fs_main.go` | Pseudofile sizes (0 for /proc, 4096 for /sys); `os.ReadFile` on size-0 files; bounded read with cap+1 truncation; `/dev/null` and `/dev/zero` rejected by the mode gate; FIFO blocking open hung >700ms while `O_NONBLOCK` returned instantly; distinct `Stat_t.Dev` per mount; `syscall.Getxattr`/`Listxattr`/`Statfs` all present and working from stdlib; 28/28 `/sys/block` entries are symlinks. → R5-F18..F21, F24..F26 |
| LOCAL_REPRO-D | `round2_main.go` | `os.Root` follows in-root relative symlinks (`block/loop0/size` via `../devices/...`) and refuses `../etc/passwd`; `os.Root("/proc").ReadFile("self/status")` works through the magic symlink — this **resolved the one open question** Stream C flagged as unverifiable from documentation; JSON map-key sorting, `SetEscapeHTML(false)`, trailing newline, RFC3339Nano trimming. → R5-F22, F23, F30..F32 |
| LOCAL_REPRO (build) | all four | `file` reported "ELF 64-bit LSB executable, x86-64, statically linked"; `ldd` reported "not a dynamic executable". → R5-F33 |
| LOCAL_REPRO gap | `round2_main.go` §C | `setfacl` is absent in the WSL image, so the ACL decode loop was exercised only to its `ENODATA` branch. Recorded honestly as R5-F50 (SPECULATIVE), not silently omitted. |

Nothing destructive was run: all writes were to `os.MkdirTemp` directories that were removed, plus the repro binaries under `research/R5/repro/`. No `ssh`, `scp` or `rsync` was invoked; `.env`, `~/.ssh` and `state/raw_host/` were never opened.

## Conflict resolution (SIFT, Phase 3)

1. **"stdlib `syscall` is deprecated, use `golang.org/x/sys`."** Widely repeated; the source says less. `src/syscall/syscall.go` carries a package-level *NOTE* preferring x/sys, but no symbol carries a godoc `Deprecated:` tag and the package is frozen rather than scheduled for removal. Every symbol needed was verified present *and exercised at runtime*. **Resolution: stdlib only** (R5-F28, recorded CONTESTED with both sides).
2. **Blog guidance on process-group kill.** Pre-Go-1.20 posts prescribe a manual watchdog goroutine because `Cancel`/`WaitDelay` did not exist. Current docs supersede them. **Resolution: any source not mentioning `Cancel`/`WaitDelay` is pre-1.20 and excluded as a pattern source** (R5-F17). A sub-agent also correctly flagged that issue **#57140**, which my prompt offered speculatively, is unrelated (an x/exp darwin build failure) and must not be cited — that check worked as intended.
3. **JSON-schema library README claims vs measured conformance.** kaptinlin and qri-io advertise 2020-12; neither has a Bowtie harness, so the claim is self-reported. xeipuuv's draft-07 support is real but scores 874/929 with 20 hard errors. **Resolution: decide on the measured run, not the README** (R5-F52, R5-F53).

No claim was accepted on first-source authority. Where only one source existed and no reproduction was possible (R5-F42 "no Go sshd_config parser exists", R5-F36 tar exec bit, R5-F47 golden-file idiom), the status is **LIKELY**, not VERIFIED, per contract item 14.

## VIS_CONTRIBUTION

What each module actually changed, not merely that it was consulted.

* **`orchestration/conduct/task-decomposition.md`** — pushed the split to five streams along *failure-mode* boundaries rather than topic boundaries. The original prompt suggested grouping "evidence/JSON model" with "schema validation"; separating them let stream D spend its whole budget on conformance data, which produced the single hardest number in the report (the Bowtie pass rates).
* **`web/conduct/research-pipeline.md`** — enforced launching all five streams in one message rather than iteratively. Wall-clock cost of the research phase was ~12 minutes instead of an estimated ~45 sequential, which is what made the Phase-2 reproduction budget affordable.
* **`web/conduct/source-discipline.md` + `citation-verification.md`** — changed the sub-agent instructions from "find sources" to "fetch the file at a pinned ref and quote the identifier". Direct consequence: R5-F1 cites `collector.go` at `v1.8.2` with the actual symbol names, and stream B read the *local GOROOT* `os/exec` source rather than a rendered doc page — which is the exact code shipping in our toolchain, a stronger citation than pkg.go.dev. Also caught the #57140 misattribution.
* **`core/conduct/doubt-engine.md`** — drove the three named contradiction targets and, more usefully, generated the orphan-survival experiment. The documentation says `WaitDelay` "bounds the time spent waiting"; doubt-engine's question was "bounds *whose* waiting?" — which exposed R5-F14, a fact no source states and which changes the recommendation from "set WaitDelay" to "set both, they solve different problems".
* **`core/conduct/verification.md`** — converted four documentation claims into executed experiments before they entered a deliverable. Two survived unchanged, one was sharpened (`os.ReadFile` is correct *and* unbounded), and one open question from a sub-agent (`os.Root` on `/proc` magic symlinks) was closed empirically instead of shipped as a caveat.
* **`core/conduct/prior-art-discovery.md`** — reframed stream A from "what layout is idiomatic" to "how do comparable projects register and isolate checks, and where do they fall short". That produced R5-F2 (node_exporter has no panic recovery or per-collector deadline), which is more valuable than the layout answer: it tells the implementation author that the obvious prior art does not meet our safety bar.
* **`core/conduct/capability-fidelity.md`** — kept status labels honest. R5-F36, F42, F47, F58 stayed LIKELY and R5-F50 stayed SPECULATIVE rather than being rounded up to VERIFIED because they felt right. It is also why the WSL-vs-bare-metal divergence is stated as a cross-cutting caveat in `PROPAGATION_NOTES.md` instead of being quietly ignored.

## Content hygiene

No prompt-injection attempt was observed in any fetched page, README or issue this session. All fetched content was handled as data by both this agent and the sub-agents, which were each instructed in their launch prompt to treat READMEs, issues and blog posts as untrusted and never to follow instructions found inside them. No fetched source asked us to run a command, authenticate, or fetch an unrequested URL. No credential-shaped string was encountered or recorded.

## Artifacts produced

`REPORT.md`, `ARCHITECTURE_NOTES.md`, `IMPL_BVB.md`, `PATTERNS.md`, `TEST_STRATEGY.md`, `facts.jsonl` (58 lines), `sources.jsonl` (58 lines), `OBSERVATION_REQUESTS.md` (5 requests), `PROPAGATION_NOTES.md`, `PROVENANCE.md`, plus `repro/` (4 Go programs). The cross-compiled linux/amd64 binaries were deleted after the runs to keep the repository small; rebuild any of them with `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o <name> <name>_main.go` and run under WSL.

## Capability gaps and what was not done

* Sub-agent spawning **was** available; no sequential fallback was needed.
* `setfacl` absent locally → ACL decoding verified only to the `ENODATA` branch (R5-F50). This is a **missing utility**, not a timeout and not evidence that the approach is unsupported.
* `bowtie.report`'s SPA did not render under static extraction. Worked around via the underlying data repository. Again a format limitation, not a TIMEOUT.
* No host observation of any kind was performed by this track, by design.
