# TOOL_USAGE — selected workbench tools (real task-relevant use ledger)

Rule: installation or smoke-testing does NOT count as use. Status becomes USED only when a phase entry below records a real task-relevant invocation with an artifact.

| Tool | Version / SHA | Kind | Invocation path | Bootstrap status | Use status |
|---|---|---|---|---|---|
| Wixie | cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9 | Claude Code plugin marketplace + stdlib Python scripts | `/create`, `/refine`, `/converge`, `/test-prompt`, `/harden`, `/translate-prompt --to <model>`, `/deep-research <topic>` | WORKING | NOT_YET_USED |
| Vis | 1579ebca9c5fe0a7a8ac891a7b7ef74657f815d6 | Claude Code plugin marketplace + prose conduct framework + hooks | @import via CLAUDE.md or `/plugin install enchanter-hooks@vis` | WORKING | NOT_YET_USED |
| Emu | 3b2c4eb8ffa726330f677107890cae754c65554b | Claude Code plugin marketplace (token-saver, context-guard, state-keeper) | `/plugin install full@emu` or direct hook invocation via CLAUDE_PLUGIN_ROOT env | WORKING | NOT_YET_USED |
| Pech | eb4c8be08c512e4157977af557160312f1a6fe0b | Claude Code plugin (7 sub-plugins + meta-plugin) | `/plugin install full@pech` then `/pech-cost`, `/pech-forecast`, `/pech-attribute`, `/pech-report` | WORKING | NOT_YET_USED |
| Ponytail | 356918eba965ee1eac64bd3a7f0dd02108350de5 | Claude Code/Codex/Copilot plugin + skill pack (node-based hooks) | `/plugin install ponytail@ponytail` then `/ponytail lite\|full\|ultra\|off` | WORKING | NOT_YET_USED |
| Hydra | e56edc52d9aacba59a11652566ebddc59969547d (pinned) | Claude Code plugin marketplace (15 security plugins + meta-installer) | `/plugin install full@hydra` or `python3 shared/scripts/vuln-scanner.py <file.go>` | WORKING | NOT_YET_USED |
| Lich | df30343dcaf63377d19f3cf7c057a2248ce54e41 (pinned) | Claude Code plugin marketplace (7 sub-plugins: core/preference/python/rubric/sandbox/typescript/verdict) | `python plugins/lich-core/scripts/__main__.py <target>` then `python plugins/lich-sandbox/scripts/sandbox.py` then `python plugins/lich-verdict/scripts/compose.py --file <target>` | PARTIAL (M5 WSL bridge kwarg-mismatch bug; M1/M7 working) | NOT_YET_USED |
| Zdenekmach deep-research | a0d67e9f7a5aeadb79b6e988a4fe0b209baa0c63 (v1.8.0, Claude Code plugin) | Markdown agents/commands/skills (Claude Code plugin, no standalone CLI) | `claude --plugin-dir <repo>` then `/deep-research:research "<topic>"` or `/deep-research:deep-research "<topic>"` with optional `--sources N`, `--format market-report` | PARTIAL (static scan complete; live nested-Claude smoke run blocked by sandbox permission classifier) | NOT_YET_USED |
| Trafilatura | 2e1d38b2dff26f1598500c7a7702755cd01e7a6e (pip 2.2.0) | Python package (pure-Python HTML extractor) | Python API: `trafilatura.fetch_url(url)` then `trafilatura.extract(html, output_format="markdown"\|"json"\|"xml"\|"csv")`; or CLI `trafilatura -u <url> -o out.md --markdown` | WORKING | NOT_YET_USED |
| Crawl4AI | 862f6bccb9c063f49b9d42701baa0eea17a4993f (pip 0.9.3) | Python package (async web crawler + PDF extractor with browser support) | Python API: `async with AsyncWebCrawler() as crawler: result = await crawler.arun(url=...)` or `PDFCrawlerStrategy()` for PDFs | WORKING (HTML crawl + PDF extraction verified; Playwright/Patchright browsers installed) | NOT_YET_USED |
| Crawlee Python | 705a0c1a258df7999b965824dd7159dce6eeebcb (pip 1.10.0) | Python package (BeautifulSoup-based crawler, HTTP-only) | `crawler = BeautifulSoupCrawler(max_requests_per_crawl=N); @crawler.router.default_handler async def handler(context): ...; await crawler.run([start_urls])` | WORKING | NOT_YET_USED |
| Staticcheck | v0.7.0 (2026.1, go1.26.2) | Go binary (static-analysis CLI for Go code) | `staticcheck ./...` from any Go module directory | WORKING | NOT_YET_USED |

## Per-tool detail

### Wixie
- version/sha: `cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9` (pinned: no, latest default branch)
- license: MIT
- runtime / how to invoke: Live: `/plugin marketplace add enchanter-ai/wixie` then `/plugin install full@wixie`, then slash commands `/create`, `/refine`, `/converge`, `/test-prompt`, `/harden`, `/translate-prompt --to <model>`, `/deep-research <topic>`. Headless: run `python shared/scripts/output-eval.py <prompt-folder>`, `output-test.py --dry-run`, `convergence.py` directly (stdlib only).
- bootstrap: WORKING, core registry/heuristic-scoring/convergence machinery executed correctly; failures are a cosmetic repo-side bug (13/18 tests passed, 5 failures pre-existing).
- caveats: Full pipeline needs a live interactive Claude Code session; only headless portions smoke-tested; most scores are offline regex heuristics, not model-verified.
- assigned job: engineer every load-bearing research/architecture/implementation prompt via full lifecycle
- uses: (none yet)

### Vis
- version/sha: `1579ebca9c5fe0a7a8ac891a7b7ef74657f815d6` (pinned: no)
- license: MIT
- runtime / how to invoke: Reference conduct modules from a project CLAUDE.md via `@shared/vis/packages/core/conduct/<module>.md`; for hook enforcement, copy the shell skeletons in packages/core/conduct/hooks.md into your own settings, or (native, not exercised) `/plugin marketplace add enchanter-ai/vis` plus `/plugin install enchanter-hooks@vis`.
- bootstrap: WORKING, both hooks fired precisely on injected real secret/destructive command, silent on benign input.
- caveats: Documentation/prompt framework, not independently-executable software beyond the 11 hooks; research pipeline requires an actual orchestrator (e.g. Wixie) to run.
- assigned job: research methodology overlay (decomposition, parallel casts, triangulation, contradiction hunting, gap filling, research→engineering translation) during R1–R5 and synthesis
- uses: (none yet)

### Emu
- version/sha: `3b2c4eb8ffa726330f677107890cae754c65554b` (pinned: no)
- license: MIT
- runtime / how to invoke: Live: `/plugin marketplace add enchanter-ai/emu` then `/plugin install full@emu` (NOTE: this will write to settings.json, see caveat). Absent that, hooks can be exercised directly by setting CLAUDE_PLUGIN_ROOT and piping hook JSON into plugins/<name>/hooks/<phase>/*.sh. Context-hygiene checkpoint = `/emu:checkpoint [text]` (appends timestamped text to checkpoint.md).
- bootstrap: WORKING, A3 compression rule fired exactly as documented; full@emu never actually installed/enabled; smoke test exercised the hook script directly.
- caveats: Full@emu never actually installed/enabled; smoke test exercised the hook script directly, not via a live plugin-loaded session. Documented install writes to ~/.claude/settings.json, which this exercise forbids.
- assigned job: context-hygiene checkpoints after R1–R5, before synthesis/architecture, before final implementation/review
- uses: (none yet)

### Pech
- version/sha: `eb4c8be08c512e4157977af557160312f1a6fe0b` (pinned: no)
- license: MIT
- runtime / how to invoke: `/plugin marketplace add enchanter-ai/pech` then `/plugin install full@pech` (or cherry-pick e.g. cost-tracker@pech); runs via SessionStart/PostToolUse/PreCompact/Stop hooks, queryable via `/pech-cost`, `/pech-forecast`, `/pech-attribute`, `/pech-report`. Outside Claude Code, shared/scripts/*.py run standalone (stdlib only).
- bootstrap: WORKING, full $-metering path (transcript parse → rate lookup → cache-modifier math → ledger append → rollup) runs correctly end-to-end. Manual end-to-end test verified 11 pytest tests passed, hand-computed ledger row matched exactly.
- caveats: Attribution/event-bus/cross-session-learning are pre-release stubs (every ledger row lands orphan:true today); bootstrap.sh not run so CLAUDE.md's @../vis/... imports would silently miss if actually installed.
- assigned job: measurement of real AI usage/cost/tokens
- uses: (none yet)

### Ponytail
- version/sha: `356918eba965ee1eac64bd3a7f0dd02108350de5` (pinned: no)
- license: MIT (third-party author, not enchanter-ai)
- runtime / how to invoke: `/plugin marketplace add DietrichGebert/ponytail` then `/plugin install ponytail@ponytail`; wires SessionStart/SubagentStart/UserPromptSubmit hooks so the ruleset auto-injects every turn. Switch intensity with `/ponytail lite|full|ultra`, one-off review with `/ponytail-review`, disable with "stop ponytail"/"normal mode". Requires node on PATH.
- bootstrap: WORKING, hooks correctly parse the Claude Code hook stdin/stdout protocol, persist mode state, emit mode-appropriate ruleset text exactly as documented; 84/84 unit tests passed.
- caveats: Full live install would modify the real ~/.claude plugin registry (deliberately not done); statusline nudge can prompt an agent to offer editing settings.json, must be declined.
- assigned job: YAGNI/accidental-complexity attack after architecture candidates and after implementation works
- uses: (none yet)

### Hydra
- version/sha: `e56edc52d9aacba59a11652566ebddc59969547d` (pinned: yes, matches e56edc52 prefix exactly)
- license: MIT
- runtime / how to invoke: Live: `/plugin marketplace add enchanter-ai/hydra` then `/plugin install full@hydra` (or individual plugins), auto-scans every Write/Edit. Batch/one-off against a Go tree: `python3 shared/scripts/vuln-scanner.py <file.go>` per file (single-file mode, not recursive), or in-session `/hydra:vulns`.
- bootstrap: WORKING, both live-hook path and standalone batch CLI correctly detected planted secrets/vulnerabilities in a real Go file with honest coverage metadata (25 Go-tagged patterns in shared/patterns/vulns.json).
- caveats: Regex/grep-based, single-line, capped at 2000 lines / 10 findings per file, not a taint/dataflow analyzer; batch scanner takes one file per invocation, not a directory; action-guard's actual blocking behavior and `/plugin install` flow not exercised live.
- assigned job: mechanical/security/coverage prefilter on the real Go implementation
- uses: (none yet)

### Lich
- version/sha: `df30343dcaf63377d19f3cf7c057a2248ce54e41` (pinned: yes, matches df30343d prefix exactly; was tip of main)
- license: MIT
- runtime / how to invoke: From the clone: `python plugins/lich-core/scripts/__main__.py <target>` (M1 flags) then `python plugins/lich-sandbox/scripts/sandbox.py` (witness confirmation, currently broken via WSL bridge at this commit) then `python plugins/lich-verdict/scripts/compose.py --file <target>` (DEPLOY/HOLD/FAIL verdict). Live: `/plugin marketplace add enchanter-ai/lich` then `/plugin install full@lich`.
- bootstrap: PARTIAL, M1 static engine plus verdict composer WORKING correctly; M5 dynamic "witness" confirmation is BROKEN at this pinned commit on the WSL backend: sandbox.py calls with different parameter names than wsl.py expects, causing a TypeError (genuine integration bug at df30343d's Windows/WSL path).
- caveats: M5/WSL bridge kwarg-mismatch bug found live (fix = align parameter names between sandbox.py and wsl.py); real `/plugin install` and bootstrap.sh intentionally not exercised.
- assigned job: at least one bounded runtime witness selected from real implementation risk
- uses: (none yet)

### Zdenekmach deep-research
- version/sha: `a0d67e9f7a5aeadb79b6e988a4fe0b209baa0c63` (tag-equivalent version in plugin.json: 1.8.0)
- license: MIT
- runtime / how to invoke: `claude --plugin-dir <repo>` then `/deep-research:research "<topic>"` (quick, 3-7 sources, 2-5 min) or `/deep-research:deep-research "<topic>"` (25-90 sources, 5 phases, 10-18 min). Optional flags: `--sources N`, `--format market-report`. Output = Markdown files under the active project's `outputs/research/` (summary file + per-stream detail files for STRONG-signal streams).
- bootstrap: PARTIAL, static scan complete and conclusive (source is 100% inspectable Markdown/config); live end-to-end `/research` or `/deep-research` run could not be executed inside the sandboxed workbench session (blocked by sandbox's own auto-mode permission classifier on nested Claude Code invocation).
- caveats: Needs a live Claude Code session (cannot run "headless" as a standalone binary); no telemetry of its own; the two helper Python scripts are the only network-calling code outside WebSearch/WebFetch and are all keyless except the optional `EBIRD_API_KEY`.
- assigned job: execution engine for all five research tracks (decomposition, parallel casts, triangulation, gap-fill, synthesis)
- uses: (none yet)

### Trafilatura
- version/sha: `2e1d38b2dff26f1598500c7a7702755cd01e7a6e` (2026-08-28); pip-installed version 2.2.0 (matches)
- license: Apache-2.0
- runtime / how to invoke: Python API — `trafilatura.fetch_url(url)` then `trafilatura.extract(html, output_format="markdown"|"json"|"xml"|"csv")`; or CLI `trafilatura -u <url> -o out.md --markdown`. Input: URL or raw HTML string. Output: plain text/Markdown/XML/JSON string with optional metadata (title, author, date).
- bootstrap: WORKING, smoke test fetched and extracted https://lavahq.io → exit 0; CHAR_COUNT: 483, first 300 chars correctly extracted.
- caveats: No telemetry; no keys needed; purely local HTTP fetch + parse.
- assigned job: default static-page extraction during research
- uses: (none yet)

### Crawl4AI
- version/sha: `862f6bccb9c063f49b9d42701baa0eea17a4993f` (2026-08-31); pip-installed version 0.9.3 (`crawl4ai[pdf]`)
- license: Apache-2.0
- runtime / how to invoke: `async with AsyncWebCrawler() as crawler: result = await crawler.arun(url=...)` → `result.markdown.raw_markdown`. For PDFs: pass `crawler_strategy=PDFCrawlerStrategy()` and `CrawlerRunConfig(scraping_strategy=PDFContentScrapingStrategy())`. Set `CRAWL4AI_MODE=api` before install to skip browser downloads entirely if only HTTP/PDF mode is needed.
- bootstrap: WORKING (both HTML crawl and PDF extraction confirmed; Playwright/Patchright browser install also completed). Real AsyncWebCrawler().arun("https://lavahq.io") → exit 0; SUCCESS: True, MARKDOWN_LEN: 5684. PDF test on W3C dummy.pdf → exit 0; SUCCESS: True, extracted text.
- caveats: No telemetry to disable (none found); to avoid the ~/.crawl4ai home-directory writes, set CRAWL4_AI_BASE_DIRECTORY to a workbench-local path before running crawl4ai-setup/first use. Install-time ~/.crawl4ai folder creation/cache-wipe and large Playwright/Patchright browser downloads are notable side effects.
- assigned job: complex/JS/PDF extraction during research
- uses: (none yet)

### Crawlee Python
- version/sha: `705a0c1a258df7999b965824dd7159dce6eeebcb` (2026-09-08, pyproject.toml declares 1.10.1); pip-installed version 1.10.0 (one patch behind repo HEAD)
- license: Apache-2.0
- runtime / how to invoke: `crawler = BeautifulSoupCrawler(max_requests_per_crawl=N); @crawler.router.default_handler async def handler(context): ...; await crawler.run([start_urls])`. Input: list of start URLs. Output: whatever the handler extracts/stores (e.g., via `context.push_data(...)` to local JSON dataset under `./storage/`).
- bootstrap: WORKING, minimal BeautifulSoupCrawler(max_requests_per_crawl=3) crawling https://lavahq.io → exit 0; VISITED: ['https://lavahq.io'], stats show requests_finished: 1, requests_failed: 0.
- caveats: Fully local by default — no Apify account/API key required; OpenTelemetry export is opt-in only.
- assigned job: R2 bounded crawl of Lava's public surface
- uses: (none yet)

### Staticcheck
- version/sha: `staticcheck.exe 2026.1 (v0.7.0)`; `go version go1.26.2 windows/amd64`
- license: n/a (pre-installed, not re-scanned/re-installed)
- runtime / how to invoke: `staticcheck ./...` from within any Go module directory.
- bootstrap: WORKING, created trivial Go module and ran staticcheck → exit 0 (no findings).
- caveats: None.
- assigned job: run directly against the real Go implementation
- uses: (none yet)

## Use log (append-only; one entry per real use)
<!-- format: - YYYY-MM-DDTHH:MMZ | <tool> | phase | invocation | artifact | changed_anything: yes/no | caveats -->
- 2026-09-08T22:34Z | Lich | pre-review tooling | patched bridge/wsl.py kwarg mismatch at pinned df30343d (tooling/lich_wsl_bridge_fix.patch); re-ran sandbox.py + compose.py on its fixture | before: sandbox_error=11 confirmed=0; after: sandbox_error=0 confirmed=1; verdict FAIL with concrete witness | changed_anything: yes (tool now functional) | caveats: fence is Python-function only (importlib) with RLIMIT_NPROC=0, so a Go witness needs the adapter in tooling/LICH_WITNESS_PLAN.md; this entry is enablement, the real witness on the sensor is still pending
- 2026-09-08T22:40Z | Pech | measurement (mid-run) | session_init.py + observe.py + finalize_session.py run against the real main-session transcript (isolated CLAUDE_PLUGIN_ROOT); load_rate_card.py imported to validate the rate card; tooling/measure_usage.py reads message.usage directly for full-session batch totals | state/usage.jsonl, state/USAGE_REPORT.md: 90 messages, 285k output / 1.45M cache-write / 9.1M cache-read tokens at snapshot; served models verified from transcripts (fable-5-1 main, sonnet-5 subagents) | changed_anything: yes (served_model UNVERIFIED -> verified for 3 agents; cost stays null because rate-card.json lacks claude-5 ids) | caveats: observe.py only tail-scans 200 lines so it cannot replay a full session; re-run at the end
- 2026-09-08T23:08Z | Wixie | phase 10 prompt engineering | 5 parallel wixie-prompt-engineer agents executed the full lifecycle from the clone (craft -> refine -> convergence.py/self-eval.py/output-eval.py -> test-runner SAT -> output-test.py real bounded call -> 12-attack harden -> translate to target model -> contract check) on prompts/raw/R1..R5.intent.md | prompts/R1..R5/{prompt.md,metadata.json,tests.json,audit.json,CONTRACT_CHECK.md,LIFECYCLE_LOG.md,learnings.md}; verdicts R1 DEPLOY 9.2/0.68, R2 HOLD 9.0/1.18, R3 HOLD 8.98/1.175, R4 DEPLOY 9.4/0.71, R5 DEPLOY 9.6/0.72 (dynamic sigma floor 0.75 used by its scripts; flat 0.45 in its CLAUDE.md would make all HOLD) | changed_anything: yes (hardening added encoded-injection, no-fabricated-tool-call, verbatim-reproduction and fictional-framing defenses; 3 agents reverted convergence.py rewrites of the verbatim host block) | caveats: efficacy-replay.py corpus not run (no domain corpus); output-test.py MODEL_MAP lacks claude-5 ids; 2 of 5 live calls returned 0 visible words (thinking/refusal), recorded as harness findings
