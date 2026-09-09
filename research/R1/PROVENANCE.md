# R1 — PROVENANCE

Track: `r1-build-vs-buy`. Model: `claude-opus-5`. Repo: `C:\lava-sensor-exercise`.
Window: **2026-09-08 22:35Z → 22:58Z** wall clock for the lead context; parallel stream workers ran concurrently inside that window (longest stream ≈ 14 min). Approximate total active work across lead + workers: **~75 agent-minutes** compressed into ~23 minutes of wall clock by parallelism.

## Methodology executed

**deep-research plugin**, `~/.lava-workbench/deep-research`, commit **`a0d67e9`** (v1.8.0). Read before starting: `commands/deep-research.md`. The agent definitions in `agents/` and `skills/research/SKILL.md` were **not** read in full — the command file carries the phase contract, credibility scale and anti-patterns, and budget was spent on the research itself. **Disclosed shortcut, not a silent one.**

### Passes executed

| Phase | What happened | Time (UTC) |
|---|---|---|
| **0 — Decomposition** | Topic split into 6 streams, one per capability area in the brief: S1 inventory/DMI, S2 remote-access/SSH, S3 secrets-on-disk, S4 BMC/IPMI, S5 kernel-hardening/boot, S6 Go framework + schema validation. Each stream got an explicit contradiction to hunt and a mandated local-reproduction list. | 22:36–22:39 |
| **1 — Parallel broad search** | Six stream briefs written. **Four launched as concurrent sub-workers (S1, S2, S3, S4).** **S5 and S6 failed to launch: "Concurrent subagent limit reached" (20-agent session cap, shared with the other R-tracks).** They were therefore **run sequentially by the lead itself** — see *Degradations* below. | 22:39–22:53 |
| **1.5 — Signal Map** | Built after the first three streams returned; see below. | 22:53 |
| **2 — Adaptive deep dives** | Folded into Phase 1 by design: each stream brief pre-loaded its own deep-dive targets (the named contradiction, the named source files, the named local reproductions), so workers deep-dived within their single pass rather than in a separate round. **This is a deviation from the plugin's two-round shape**, taken deliberately for the time box. Consequence: no cross-stream re-query round happened. | — |
| **3 — SIFT synthesis** | Conflict resolution performed per stream (each has a `CONTRADICTIONS` section with both sides recorded) and again at the lead level in `PROPAGATION_NOTES.md`. Credibility scored −2..+3 in every `sources.jsonl` row. | 22:54–22:58 |
| **4 — Opinionated recommendations** | 2-D model applied as *confidence in the claim × confidence in its design impact* per the R1 brief (not the plugin's signal×convergence, which is tuned for market research). Recorded in `BVB_MATRIX.md` and `REPORT.md`. | 22:56–22:58 |
| **5 — Final output** | Artifacts below. | 22:58 |

### Signal Map (Phase 1.5)

| Stream | Sources | Source-level code reads | Local repro | Rating |
|---|---|---|---|---|
| S1 inventory/DMI | ~30 | kernel `dmi-id.c`, `dmi_scan.c`, ghw, gopsutil, procfs, osquery | yes (uid 1000) | **STRONG** |
| S2 remote-access/SSH | 32 | OpenSSH `sshd.c`/`servconf.c` @V_9_6_P1, Wazuh SCA policy, Lynis `include/functions`, `proc_pid_fd(5)` | yes (uid 1000, `ss`/`/proc/net/tcp` degradation) | **STRONG** — and it produced the track's only verdict reversal (`sshd -G`) |
| S3 secrets-on-disk | 26 | gitleaks, trufflehog, kernel UAPI `posix_acl_xattr.h`, OpenSSH `PROTOCOL.key`, osquery | yes, incl. byte-level ACL decode and a FIFO hang test | **STRONG** |
| S4 BMC/IPMI | ~25 | kernel `ipmi_devintf.c`/`ipmi_msghandler.c`/`devtmpfs.c`/`dmi-sysfs.c`/`ipmi_kcs_sm.c` @v6.8, ipmitool `open.c` | yes (absence-evidence paths) | **STRONG** |
| S5 kernel-hardening | 6 | osquery `secureboot.cpp` @5.15.0, kernel Documentation ×2 | yes (uid 1000) | **MODERATE** — lead-run, time-boxed; Lynis and kernel LSM source unread (G5-1, G5-5) |
| S6 Go framework/schema | 10 | jsonschema `draft.go` @v6.0.3, os/exec docs, 4 LICENSE files | yes — measured dependency graphs with the real Go 1.26.2 toolchain | **STRONG** on dependencies, **WEAK** on evidence-model standards (XCCDF/SARIF unfetched, G6-1/G6-2) |

## Acquisition tools and counts (lead context only; per-stream tooling is in each stream file)

- **WebFetch** — 4 calls (kernel efivarfs docs, kernel tainted-kernels docs, pkg.go.dev/os/exec, NIST IR 7275 landing page). 3 succeeded, 1 returned a metadata-only landing page.
- **curl (raw source at pinned tags)** — 11 fetches: jsonschema v6.0.3 `LICENSE`/`README.md`/`draft.go`, gojsonschema v1.2.0 `README.md`/`LICENSE-APACHE-2.0.txt`, kaptinlin `LICENSE`, golang/sys `LICENSE`, osquery 5.15.0 `LICENSE` and `secureboot.cpp`, plus two GitHub API commit-date queries.
- **Go toolchain (Go 1.26.2)** — 5 temp modules created **outside the repo** (`mktemp -d`) to measure real dependency graphs via `go get` / `go mod tidy` / `go list -deps` / `go list -m all`. No sensor code was built. This produced the strongest evidence in S6: measured module and package counts rather than README claims.
- **WSL2 local reproduction** — 1 combined probe run as **uid 1000 on Ubuntu 26.04 LTS, kernel `6.18.33.2-microsoft-standard-WSL2`**, covering efi/securityfs/tainted/cpu-vulnerabilities/sysctls/kallsyms/tpm/dmi paths. Labelled `LOCAL_REPRO` throughout. **WSL2 is not the target host and is not UEFI bare metal** — every fact that depends on that difference says so.
- **Trafilatura** — **available and configured but not used by the lead context.** For the sources that mattered here (raw source files at pinned commits, kernel HTML docs, LICENSE files) `curl` and WebFetch were more precise: trafilatura's boilerplate-stripping is designed for articles and would risk dropping the exact lines being cited. Disclosed rather than silently skipped.
- **Crawl4AI** — **not used.** The only fetch that would have justified escalation was the NIST IR 7275 PDF; the time box expired first. Recorded as gap G6-1, not as an unsupported capability.
- **Crawlee** — **not invoked**, correctly: it is scoped to R2's bounded same-domain crawl, and the R1 brief says so explicitly.

## Degradations (disclosed, not silent)

1. **Phase 1 was only partially parallel.** Streams S5 and S6 could not be launched as sub-workers — the harness returned "Concurrent subagent limit reached. You can run 20 subagents at once." (the cap is shared across all concurrently running R-tracks). Both were run **sequentially by the lead**, with a correspondingly smaller source count and explicit GAPS sections. S5 is rated MODERATE and S6 WEAK-on-standards for exactly this reason.
2. **Phase 2 was merged into Phase 1** rather than run as a separate adaptive round (see the table). No cross-stream follow-up queries were issued.
3. **Streams S2 and S4 returned after the first draft of this file was written**, so the Signal Map above and the S2 row of `BVB_MATRIX.md` were revised rather than composed in one pass. Both are now fully folded in; the provisional REMOTE_ACCESS verdicts were **replaced**, not appended to — `sshd -G` moved from an assumed REJECT to a REUSE, which is the track's only verdict reversal.
4. The deep-research agent definitions and `skills/research/SKILL.md` were not read (see above).

## Failures and blocked fetches — **a blocked fetch is NOT evidence of absence**

- **NIST IR 7275 Rev 4 (XCCDF spec)** — csrc.nist.gov returned a publication landing page only; the normative result-enumeration text is in a PDF that was not extracted. **BLOCKED EXTRACTION.** The XCCDF result vocabulary is therefore cited as LIKELY, not VERIFIED (G6-1).
- **GitHub unauthenticated API rate limit hit 0** during stream S1, which blocked commit-date lookups and one `osquery/utils/linux/block_device_enumeration.*` path (404 at the tried path). **RATE LIMIT / WRONG PATH, not "the code does not exist."**
- **GitHub commit-date queries from the lead context returned empty** for both jsonschema repos (same rate limiting). Maintenance recency for santhosh-tekuri is therefore argued from the v6.0.3 tag and its dependency pins, not from a commit date.
- **SARIF 2.1.0 result model** — not fetched (budget). Unfetched, not disproven.
- **Lynis test sources** (`include/tests_kernel`, `tests_boot_services`, `tests_hardening`) — not read in the lead-run S5 stream. Its GPLv3 licence and its "not run vs passed" behaviour remain **asserted, not verified** (G5-1).
- No timeouts were hit on any tool call in the lead context. Where a fact is missing it is because of a rate limit, a landing page, or the time box — each labelled individually above.

## Artifacts produced

Under `research/R1/` only:
`REPORT.md`, `facts.jsonl`, `sources.jsonl`, `PROVENANCE.md`, `OBSERVATION_REQUESTS.md`, `PROPAGATION_NOTES.md`, `BVB_MATRIX.md`, `STOLEN_PATTERNS.md`, and the per-stream evidence files `streams/S1.md`, `streams/S2.md`, `streams/S3.md`, `streams/S4.md`, `streams/S5.md`, `streams/S6.md`. Nothing was written outside `research/R1/`. No `ssh`/`scp`/`rsync` was run by the lead or by any stream worker; `.env`, `~/.ssh` and `state/raw_host/` were never opened.

## VIS_CONTRIBUTION

What each Vis conduct module actually **changed**, not merely that it was consulted.

- **`orchestration/conduct/task-decomposition.md`** — Changed the decomposition axis. The obvious split was by *tool* (osquery / Lynis / Go libraries). Decomposing by **capability area** instead — matching the six areas in the brief — meant every stream terminated in a verdict the lead could use directly, and made the S5/S6 fallback to sequential execution cheap because no stream depended on another's output. It also drove the choice to hand each worker its contradiction *up front* rather than hoping it would find one.
- **`web/conduct/research-pipeline.md`** — Shaped the four-worker cast and the "write incrementally to disk" instruction in every brief. That instruction is why S4's partial file existed and was readable while its worker was still running, and why a stream dying mid-flight would still have left evidence.
- **`web/conduct/source-discipline.md`** — Changed the *evidence bar itself*. Every brief was rewritten to demand a pinned tag plus `file:line`, which is why the strongest findings are quotes from `dmi-id.c:41-62`, `secureboot.cpp`, `draft.go:124` and `posix_acl_xattr.h:24,29-37` rather than README summaries. It also produced the explicit rule that a README claim about a library's own capability outranks community consensus (C6-1), and that a README claim about *unprivileged* behaviour must be checked against the code (which is how the ghw contradiction was confirmed).
- **`web/conduct/citation-verification.md`** — Caused the Go-toolchain measurement pass. Rather than citing dependency counts from documentation, S6 built five throwaway modules and ran `go list -deps`. This directly overturned a plausible assumption: kaptinlin's real cost is not just its dependency tree but that `go get` **silently bumped the toolchain requirement to Go 1.27**, which no README states.
- **`core/conduct/doubt-engine.md`** — Produced the three mandated contradiction hunts and, more usefully, made the workers hunt disconfirmation of *our own brief*. The payoff was S3 refuting the R1 prompt's own premise that gitleaks had been relicensed away from MIT: the `LICENSE` file has three commits, newest 2019-12-04. **The brief was wrong and the research says so.** It also produced the discovery that `kptr_restrict=1` yields a *successful read of false data* — a third failure mode neither the brief nor any prior art we read anticipates.
- **`core/conduct/verification.md`** — Enforced the two-independent-sources-or-primary-plus-local-repro bar. Concretely, it is why F11 (TPM sysfs modes) is LIKELY rather than VERIFIED: WSL2 has no TPM, so the local reproduction could not corroborate the host snapshot and the kernel source was not read. Under a weaker rule that would have been asserted.
- **`core/conduct/prior-art-discovery.md`** — Drove the "read the source, not the docs" instruction that found the three highest-value results in the whole track: osquery choosing `efivars` over `vars` *specifically* because it works without root; osquery's Secure Boot table silently emitting no row on read failure; and ghw converting EACCES into the untyped string `"unknown"`.
- **`core/conduct/capability-fidelity.md`** — Prevented the most likely overclaim. It forced the distinction between "the library compiles and runs unprivileged" and "the library returns the *answer* unprivileged", which is the entire ghw / u-root-smbios / go-smbios verdict: correct code pointed at data that uid 1000 cannot reach. It also forced the S6 conclusion that a schema validator is a **test-only** capability, not a runtime one — a reframing that removed the dependency question from the shipped artifact entirely.


## Final counts (close of track)

- **Facts:** 57 total — 53 VERIFIED, 2 CONTESTED (R1-F4 ghw's self-contradiction, R1-F51 sshd man page vs code), 2 LIKELY (R1-F54 socket activation, R1-F57 XCCDF enumeration). No SPECULATIVE facts survived to the final write: the one placeholder (the original R1-F47) was replaced by real S2 evidence.
- **Sources:** 22 rows in `sources.jsonl`, all typed primary — six stream aggregates (each carrying its own full per-source list with credibility scores) plus sixteen directly-fetched primaries, including one recorded **failure** row (NIST IR 7275, blocked). Underlying unique sources across the six streams: roughly 100.
- **Artifacts:** 8 contract deliverables plus 6 stream evidence files, 3,069 lines of stream evidence.
- **SUSPECTED_INJECTION:** none found, independently reported by all six streams.
- **Observation requests:** 10 (R1-OR1 through R1-OR10), exactly one marked blocking (R1-OR9).

**Two of this track's findings contradicted our own inputs.** The R1 brief's claim that gitleaks had been relicensed away from MIT is false (S3), and the S5 briefing assumption that securityfs is root-only is false (LOCAL_REPRO). Both were resolved in favour of the evidence and are recorded in `PROPAGATION_NOTES.md` as CR-1 and CR-2 rather than quietly corrected.
