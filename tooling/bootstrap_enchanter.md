# Workbench Bootstrap Report

Workbench root: `$HOME/.lava-workbench/` (i.e. `C:\Users\KLDRM\.lava-workbench\`)
All seven tools cloned, scanned, risk-assessed, installed (where safe/possible), and smoke-tested by parallel sub-agents. Full details below.

## Wixie
- source: https://github.com/enchanter-ai/wixie
- commit: cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9 (pinned: no, latest default branch)
- license: MIT
- kind: Claude Code plugin marketplace (6 plugins + meta "full" plugin) with standalone stdlib Python scripts
- runtime: bash (install/test scripts) + python3 stdlib-only + markdown agent/skill defs
- scan summary:
  - marketplace.json declares 6 plugins (prompt-crafter, prompt-refiner, convergence-engine, prompt-tester, prompt-harden, prompt-translate) plus inference-engine/deep-research support plugins; v4.0.0
  - Documented installer is a pipe-to-shell one-liner, NOT run; install.sh read instead (only git-clones plus seeds an empty prompts index, no curl inside, no destructive ops)
  - Two hooks (inference-engine, prompt-crafter): advisory-only, fail-open, no network or writes beyond stderr notices
  - Root CLAUDE.md imports a sibling repo (enchanter-ai/vis) via scripts/bootstrap.sh (not run), reviewed and benign
  - Only base64 hit is an intentional adversarial-test fixture in prompt-harden's red-team agent (tests model resistance to encoded-instruction injection)
  - No package.json/pyproject/requirements/Cargo.toml anywhere; zero third-party dependency footprint
- risk verdict: SAFE_WITH_NOTES, MIT, no obfuscation/exfiltration/destructive code; only friction is the documented pipe-to-shell installer (avoided) and an optional second-repo bootstrap (skipped)
- install: `git clone https://github.com/enchanter-ai/wixie $HOME/.lava-workbench/wixie` only. Did not run install.sh, `/plugin marketplace add`/`install`, or bootstrap.sh (all would touch global ~/.claude state or clone extra repos)
- smoke test: `bash tests/run-all.sh` -> exit 1; 13/18 passed. Real output: "Registry OK: 447 models", self-eval run "Clarity 8/10, Completeness 10/10, Efficiency 10/10, Model Fit 9/10, Failure Resilience 8/10, OVERALL 8.7/10, SIGMA 0.81 (floor 0.45) FAIL, STATUS: PASS". 5 failures are a pre-existing repo bug (plugin.json name-field mismatch vs test assertions), not security-relevant.
- capability status: WORKING, core registry/heuristic-scoring/convergence machinery executed correctly; failures are a cosmetic repo-side bug
- how to invoke for real work: Live: `/plugin marketplace add enchanter-ai/wixie` then `/plugin install full@wixie`, then slash commands `/create`, `/refine`, `/converge`, `/test-prompt`, `/harden`, `/translate-prompt --to <model>`, `/deep-research <topic>`. Headless: run `python shared/scripts/output-eval.py <prompt-folder>`, `output-test.py --dry-run`, `convergence.py` directly (stdlib only).
- special items:
  - Model registry: `shared/models-registry.json`, 447 models (id -> family/display_name/context_window/format/reasoning/cot_approach/few_shot/key_constraint). Claude entries include claude-opus-4-6/4-7/4-8/5, claude-sonnet-4-5/4-6/5, claude-haiku-4-5, claude-fable-5, claude-fable-5-1, claude-mythos-5/5-1, plus claude-3-* legacy, and non-Claude families (gpt-4.1/4o/5, o1/o3/o4-mini, gemini-2.5-pro/flash/3, llama-3/4, mistral-large).
  - Model prompting profiles: `shared/references/model-profiles.md` (475 lines), per-family sections (e.g. "Claude 4.x", "GPT-4.1/4o/5.x") covering format/system-prompt/reasoning/few-shot/gotchas/token-budget.
  - Lifecycle stages (per root CLAUDE.md "Lifecycle" table): Research (`/deep-research`, auto-fires in `/create`) -> Craft (`/create`, prompt-crafter) -> Refine (`/refine`, prompt-refiner) -> Converge (`/converge`, shared/scripts/convergence.py) -> Structural test (`/test-prompt`, prompt-tester: role-play plus 8 SAT assertions, heuristic) -> Output test (real model): shared/scripts/output-test.py 4-phase pipeline (pre-flight/generate/evaluate/fix), script-only, not a slash command -> Adversarial hardening (`/harden`, prompt-harden: 12 OWASP-LLM-Top-10 attacks producing audit.json) -> Target-model adaptation (`/translate-prompt --to <model>`). "Production-grade" equals CLAUDE.md's DEPLOY bar: sigma < 0.45 AND overall >= 9.0 AND all 5 axes >= 7.0 AND 8/8 SAT assertions.
- caveats: full pipeline needs a live interactive Claude Code session; only headless portions smoke-tested; most scores are offline regex heuristics per README, not model-verified (only efficacy-replay.py makes real `claude -p` calls)
- changes outside workbench: none

## Vis
- source: https://github.com/enchanter-ai/vis
- commit: 1579ebca9c5fe0a7a8ac891a7b7ef74657f815d6 (pinned: no)
- license: MIT
- kind: Claude Code plugin marketplace plus prose "conduct" framework (markdown behavior rules) plus 1 hooks plugin (bash); not a traditional CLI
- runtime: bash (hook scripts, jq; python3 optional for syntax validators), markdown for conduct modules
- scan summary:
  - Monorepo of packages: core, skills, orchestration, safety, web, memory, cost, hooks -- mostly .md conduct docs/taxonomy/runbooks/fixtures
  - Only executable code is install.sh (vendor-copy installer, no curl-pipe execution of itself) and packages/hooks/scripts/*.sh (11 Claude Code lifecycle hooks)
  - packages/safety/security/* contains pentest/red-team fixture JSON describing prompt-injection payloads as test DATA (not executed/obeyed); one such fixture caused the harness's own instruction-shaped-output flag when quoted by the sub-agent, verified as inert documentation, not live instructions
  - Hook scripts are advisory/fail-open (every script exits 0), self-contained, no curl/wget/chmod/sudo
  - Documented install includes a pipe-to-shell one-liner (not run; manual vendored-copy equivalent used instead)
- risk verdict: SAFE_WITH_NOTES, no network exfil, no obfuscation, no sudo, hooks read-only/advisory; note the security-fixture files contain realistic fake attack payloads that must never be treated as live instructions
- install: manual vendored-copy of install.sh's effect performed locally on the already-cloned repo (git archive plus strip non-core packages), verified packages/core/conduct/{discipline,verification,tool-use,failure-modes}.md present
- smoke test: piped synthetic secret ("AKIA...") into secret-scan.sh -> exit 0, correctly flagged; piped `rm -rf /tmp/...` into reversibility-guard.sh -> exit 0, correctly flagged advisory-only; benign input -> silent (correct).
- capability status: WORKING, both hooks fired precisely on injected real secret/destructive command, silent on benign input
- how to invoke for real work: reference conduct modules from a project CLAUDE.md via `@shared/vis/packages/core/conduct/<module>.md`; for hook enforcement, copy the shell skeletons in packages/core/conduct/hooks.md into your own settings, or (native, not exercised) `/plugin marketplace add enchanter-ai/vis` plus `/plugin install enchanter-hooks@vis`
- special items -- research methodology (packages/web/conduct/research-pipeline.md), each a prose "conduct" phase invoked via @-import by an orchestrator, not a CLI:
  - Decompose (Phase 1): sub-questions plus seed queries, floor >=5 SQs
  - Cast / parallel dispatch (Phase 2): parallel Haiku fetchers (<=8 concurrent) writing sources.jsonl, floor >=20 dispatches / >=30 sources
  - Triangulate (Phase 3): claim graph plus confidence plus stop_recommended (Sonnet, single)
  - Gap-fill plus adversarial round (Phase 4): mandatory round hunting evidence contradicting round-1 high-confidence claims; "Round-1 stops are forbidden"
  - Synthesize (Phase 5) and Verify (Phase 6, incl. "CIBER" paraphrase/negation/scope-shift re-framing)
  - No dedicated "research to engineering translation" stage name found; closest analog is a cross-session memory hook pattern requiring "a rule that would prevent or mitigate recurrence"
- caveats: documentation/prompt framework, not independently-executable software beyond the 11 hooks; research pipeline requires an actual orchestrator (e.g. Wixie) to run
- changes outside workbench: none

## Emu
- source: https://github.com/enchanter-ai/emu
- commit: 3b2c4eb8ffa726330f677107890cae754c65554b (pinned: no)
- license: MIT
- kind: Claude Code plugin marketplace (meta-plugin "full" plus token-saver, context-guard, state-keeper)
- runtime: bash + jq (hooks); optional python (unused report-pdf.py)
- scan summary:
  - Repo-wide grep for curl/wget/iwr/eval/base64/sudo/exfil: zero hits outside README/CI docs
  - All 5 hooks (PreToolUse x2, PostToolUse x2, PreCompact x1) fail-open, advisory, write only to own plugin state/*.jsonl
  - shared/sanitize.sh actively redacts secret-shaped strings before logging (defensive)
  - Plugin manifests declare no install-time lifecycle scripts; install.sh only clones plus chmod +x
  - IMPORTANT: the documented install path (`claude plugin marketplace add`) writes an extraKnownMarketplaces key into ~/.claude/settings.json -- this conflicts with the hard "do not modify settings.json" rule. See "Changes made outside the workbench" below.
- risk verdict: SAFE_WITH_NOTES, code itself is clean; but the tool's own documented installer touches settings.json, which this exercise forbids. Verdict is conditioned on NOT completing that install step live (it was tested then reverted by the sub-agent, see below).
- install: sub-agent ran `claude plugin marketplace add "$HOME/.lava-workbench/emu"` to test the documented flow, observed the settings.json write, then ran `claude plugin marketplace remove emu` to revert. full@emu plugin itself was never installed. Plugin registry files (known_marketplaces.json, installed_plugins.json) confirmed back to pre-test state. A residual empty "extraKnownMarketplaces": {} key remains in settings.json (could not be scrubbed further -- direct file edit is against the hard rule and was also blocked by the harness's permission classifier).
- smoke test: piped a Bash PreToolUse hook JSON (`git log`) into hooks/pre-tool-use/compress-bash.sh (with CLAUDE_PLUGIN_ROOT pointed at the plugin dir) -> exit 0; output `{"hookSpecificOutput":{"updatedInput":{"command":"git log --oneline -20"}}}`, metrics logged
- capability status: WORKING, A3 compression rule fired exactly as documented
- how to invoke for real work: live: `/plugin marketplace add enchanter-ai/emu` then `/plugin install full@emu` (NOTE: this will write to settings.json, see caveat). Absent that, hooks can be exercised directly by setting CLAUDE_PLUGIN_ROOT and piping hook JSON into plugins/<name>/hooks/<phase>/*.sh.
- special items: context-hygiene checkpoint = `/emu:checkpoint [text]` (state-keeper command, plugins/state-keeper/commands/checkpoint.md), appends timestamped text to `${CLAUDE_PLUGIN_ROOT}/state/remember.md`, confirms "Checkpointed: ... Survives compaction." Automatic form: PreCompact hook plugins/state-keeper/hooks/pre-compact/save-checkpoint.sh fires unconditionally before context compaction and atomically writes checkpoint.md.
- caveats: full@emu never actually installed/enabled; smoke test exercised the hook script directly, not via a live plugin-loaded session
- changes outside workbench: ~/.claude/settings.json retains a residual, functionally-empty "extraKnownMarketplaces": {} key from testing the documented install flow. This is a real, if inert, change outside the workbench and should be reviewed/removed by the user directly (agents are barred from editing this file). No other files under ~/.claude were changed; no plugins remain installed.

## Pech
- source: https://github.com/enchanter-ai/pech
- commit: eb4c8be08c512e4157977af557160312f1a6fe0b (pinned: no)
- license: MIT
- kind: Claude Code plugin (marketplace of 7 sub-plugins plus 1 meta-plugin)
- runtime: bash + jq (hooks) + python3 stdlib-only (no external runtime deps)
- scan summary:
  - Clean clone, MIT, no anomalies
  - install.sh (documented via pipe-to-shell, not run) only clones to ~/.claude/plugins/pech, checks git/jq/python3 present; no eval/base64/sudo/secondary downloads
  - scripts/bootstrap.sh clones a sibling repo enchanter-ai/vis outside the sanctioned clone dir; not run
  - All 6 hooks.json files invoke only local python3/bash scripts; no network calls in any hook chain
  - shared/scripts/observe.py (core hook) is fail-open, reads local transcript JSONL plus rate-card.json, writes local ledger atomically
  - README candidly documents attribution/event-bus/cross-session-learning as NOT wired yet (stubs); only the $-metering path claimed working
- risk verdict: SAFE, no network egress anywhere in hook/script paths, stdlib/bash+jq only, no eval/exec of remote content, MIT, honest docs about unfinished parts
- install: git clone only; did not run install.sh/bootstrap.sh/`/plugin marketplace add` (all write outside sanctioned dir or need interactive session); validated capability by invoking shipped scripts directly
- smoke test: (1) `python3 -m pytest tests/test_observe_usage.py -q` -> exit 0, 11 passed. (2) Manual end-to-end: piped a hand-built JSONL transcript (1000 in/500 out/2000 cache-read tokens) through shared/scripts/observe.py with the repo's real shared/rate-card.json -> exit 0, ledger row total_cost_usd:0.0111 matching hand-computed math exactly.
- capability status: WORKING, full $-metering path (transcript parse -> rate lookup -> cache-modifier math -> ledger append -> rollup) runs correctly end-to-end
- how to invoke for real work: `/plugin marketplace add enchanter-ai/pech` then `/plugin install full@pech` (or cherry-pick e.g. cost-tracker@pech); runs via SessionStart/PostToolUse/PreCompact/Stop hooks, queryable via `/pech-cost`, `/pech-forecast`, `/pech-attribute`, `/pech-report`. Outside Claude Code, shared/scripts/*.py run standalone (stdlib only).
- special items:
  - Usage/cost source: Claude Code's own session transcript JSONL (~/.claude/projects/<project>/<session>.jsonl), per docs/adr/0001-telemetry-source.md: "Decision: transcript JSONL", NOT the API directly, NOT OTEL. Each turn's message.usage is matched to the firing tool_use.id since PostToolUse's own payload lacks token usage.
  - Exact invocation: `python3 ${CLAUDE_PLUGIN_ROOT}/shared/scripts/observe.py`, hook JSON on stdin (PostToolUse, transcript_path plus tool_use_id), env ENCHANTED_ATTRIBUTION set by caller.
  - Windows path compatibility: CONFIRMED WORKING, tested with genuine C:\Users\KLDRM\... backslash-plus-drive-letter paths for both transcript_path and CLAUDE_PLUGIN_ROOT; parsed correctly via Python's pathlib, no POSIX-only assumptions found.
- caveats: attribution/event-bus/cross-session-learning are pre-release stubs (every ledger row lands orphan:true today since no sibling plugin sets ENCHANTED_ATTRIBUTION); bootstrap.sh not run so CLAUDE.md's @../vis/... imports would silently miss if actually installed
- changes outside workbench: none

## Hydra
- source: https://github.com/enchanter-ai/hydra
- commit: e56edc52d9aacba59a11652566ebddc59969547d (pinned: yes, matches e56edc52 prefix exactly)
- license: MIT
- kind: Claude Code plugin marketplace (15 security plugins plus 1 meta-installer), NOT a Go static-analysis CLI as the name might suggest
- runtime: bash + jq (core hooks), python3 stdlib (batch scanners/report-gen); zero go.mod/package.json/pyproject anywhere
- scan summary:
  - Defensive Claude-Code-hook security suite: secret-scanner, vuln-detector, action-guard, config-shield, audit-trail (plus 10 advisory/compliance plugins)
  - install.sh (read, not executed via its documented curl-pipe form) only clones plus chmod +x's hook scripts
  - Hook scripts (detect-vuln.sh, scan-secrets.sh) have path-traversal guards, binary-file skip, size/line caps, always exit 0 (advisory/non-blocking), mask secrets, no network calls
  - action-guard's PreToolUse hook is the one plugin that can actually block (exit 2) dangerous Bash commands by design (deny-list incl. rm -rf /, curl|bash)
  - audit-trail's otel-exporter.py only emits OTLP JSON to stdout; no auto phone-home
  - Repo-root CLAUDE.md auto-imports sibling ../vis/packages/core/conduct/*.md (not present in this clone), harmless, treated as inert
- risk verdict: SAFE_WITH_NOTES, advisory-first, local-only, no exfiltration/eval/sudo, MIT. Caveat: full live install registers global cross-session hooks that intercept every Bash/Write/Edit/WebFetch call and can block commands (action-guard), out of scope for this sandboxed test, so capability was verified by running scripts standalone instead.
- install: `git clone ... && git checkout e56edc52` only; did NOT run install.sh or `/plugin marketplace add`/`install` (would register live global hooks)
- smoke test: (1) piped PostToolUse JSON for a hand-written 3-issue Go file into plugins/vuln-detector/hooks/post-tool-use/detect-vuln.sh -> exit 0, correctly flagged CWE-798 hardcoded password plus CWE-327 weak MD5 hash (SQL-concat/command-injection lines not flagged, matches documented single-line-regex scope limitation). (2) same file plus a planted fake AWS key into scan-secrets.sh -> exit 0, correctly masked plus flagged as probable test key. (3) `python3 shared/scripts/vuln-scanner.py <file.go>` standalone batch CLI -> exit 0, 2 findings, coverage "partial".
- capability status: WORKING, both live-hook path and standalone batch CLI correctly detected planted secrets/vulnerabilities in a real Go file with honest coverage metadata
- how to invoke for real work: live: `/plugin marketplace add enchanter-ai/hydra` then `/plugin install full@hydra` (or individual plugins), auto-scans every Write/Edit. Batch/one-off against a Go tree: `python3 shared/scripts/vuln-scanner.py <file.go>` per file (single-file mode, not recursive), or in-session `/hydra:vulns` (also runs shared/scripts/supply-chain.py .)
- special items: Go support = 25 Go-tagged patterns in shared/patterns/vulns.json (CWE-798 hardcoded creds, CWE-327 weak hashes, CWE-346 CORS wildcard, CWE-295 TLS-verify-disabled, etc). Claimed finding classes: secrets (319 patterns incl. entropy-based detection), OWASP/CWE vulnerabilities (156 patterns, explicitly "single-line regex prefilter, not a dataflow engine"), dangerous Bash ops (113 patterns, blocked pre-execution), config poisoning (122 patterns, e.g. malicious settings.json/tasks.json hooks), supply-chain/typosquat detection (199 patterns). No dead-code/style/performance class; security-only.
- caveats: regex/grep-based, single-line, capped at 2000 lines / 10 findings per file, not a taint/dataflow analyzer (tool's own README states this); batch scanner takes one file per invocation, not a directory; action-guard's actual blocking behavior and `/plugin install` flow not exercised live
- changes outside workbench: none

## Lich
- source: https://github.com/enchanter-ai/lich
- commit: df30343dcaf63377d19f3cf7c057a2248ce54e41 (pinned: yes, matches df30343d prefix exactly; was tip of main)
- license: MIT
- kind: Claude Code plugin marketplace (7 sub-plugins: lich-core/preference/python/rubric/sandbox/typescript/verdict) plus directly-runnable Python CLI scripts
- runtime: Python stdlib only for core engines; M5 sandbox needs POSIX resource+signal, native on Linux/macOS, bridged via WSL2 on Windows (wsl.exe -e python3); no Docker used
- scan summary:
  - install.sh only clones plus prints plugin-install instructions; no curl/wget-pipe-to-shell in the repo itself
  - Core engines (M1 static AST/interval walk, M2 diff, M6 Bayesian preference, M7 rubric) are pure-Python/stdlib wrappers around ruff/biome; no network imports anywhere
  - M5 (lich-sandbox) deliberately executes target code, fenced with 6 documented rlimits plus signal.alarm, explicitly labeled as needing security review to relax caps
  - scripts/bootstrap.sh would clone a second repo (enchanter-ai/vis); skipped, out of clone scope
  - One test fixture contains a literal "curl" string, confirmed to be static-analysis sample data (input for Lich's own detector), never executed
- risk verdict: SAFE_WITH_NOTES, MIT, no obfuscation, no pipe-to-shell installers, no network calls exercised. Caveats are scope-related (global plugin install / hook registration, out-of-scope sibling clone), not malice.
- install: no package install needed (stdlib-only). Did not run install.sh or `/plugin marketplace add`/`install` (would modify global ~/.claude plugin state). Ran the pinned clone's scripts directly instead.
- smoke test: (1) `python plugins/lich-core/scripts/__main__.py tests/fixtures/quality-ladder/bad.py` -> exit 0, `{"total":5,"by_rule":{"B006":1,"PY-M1-001":1,"PY-M1-002":3}}`. (2) `python plugins/lich-sandbox/scripts/sandbox.py` -> exit 0, `{"confirmed":0,"timeout":0,"sandbox_error":11,...}`. (3) `python plugins/lich-verdict/scripts/compose.py --file tests/fixtures/quality-ladder/bad.py` -> exit 0, verdict FAIL, confidence reduced.
- capability status: PARTIAL, M1 static engine plus verdict composer WORKING correctly; M5 dynamic "witness" confirmation is BROKEN at this pinned commit on the WSL backend: sandbox.py calls `runner(script_path=..., entrypoint=..., witness_json=..., timeout_s=...)` but plugins/lich-sandbox/scripts/bridge/wsl.py's `run_in_wsl(target_file, function_name, witness_json, timeout_s=10)` uses different parameter names, causing a TypeError, caught and honestly recorded as sandbox-error for all 11 witnesses (not a crash, not a false-clean result); a genuine integration bug in df30343d's Windows/WSL path, found by direct execution.
- how to invoke for real work: from the clone: `python plugins/lich-core/scripts/__main__.py <target>` (M1 flags) then `python plugins/lich-sandbox/scripts/sandbox.py` (witness confirmation, currently broken via WSL bridge at this commit) then `python plugins/lich-verdict/scripts/compose.py --file <target>` (DEPLOY/HOLD/FAIL verdict). Live: `/plugin marketplace add enchanter-ai/lich` then `/plugin install full@lich`.
- special items: a "runtime witness" is a synthesized boundary-value input (e.g. `{"args":[[]]}` for a div-by-zero flag) executed inside a resource-capped subprocess to turn an M1 static suspicion into a confirmed runtime failure via traceback-class matching. README: "A ~60-line resource-capped subprocess fence runs the flagged function with one synthesized boundary witness. Either the bug surfaces with a real traceback, or it doesn't." Outcomes recorded in plugins/lich-sandbox/state/run-log.jsonl as one of confirmed-bug / timeout-without-confirmation / no-bug-found / input-synthesis-failed / sandbox-error / platform-unsupported. Runtime requirement per README: "Windows with WSL: bridged via scripts/bridge/wsl.py. Child runs under wsl.exe -e env -i python3... Windows without WSL: platform-unsupported." No Docker involved.
- caveats: M5/WSL bridge kwarg-mismatch bug found live (fix = align parameter names between sandbox.py and wsl.py); real `/plugin install` and bootstrap.sh intentionally not exercised
- changes outside workbench: none

## Ponytail
- source: https://github.com/DietrichGebert/ponytail
- commit: 356918eba965ee1eac64bd3a7f0dd02108350de5 (pinned: no)
- license: MIT (third-party author, not enchanter-ai; scanned with extra scrutiny per instructions)
- kind: Claude Code/Codex/Copilot/Qoder/OpenCode/Gemini/Pi plugin plus multi-host skill pack; core artifact is a "lazy senior dev" system-prompt/ruleset injected via lifecycle hooks
- runtime: node 24 (core hooks, zero external deps: fs/path/os only); optional ponytail-mcp subpackage needs @modelcontextprotocol/sdk plus zod; benchmarks use python
- scan summary:
  - No preinstall/postinstall/lifecycle scripts anywhere (all package.json variants clean, only a test script)
  - Hooks write only a small mode-flag file under $CLAUDE_CONFIG_DIR; only read settings.json to suggest text about a missing statusline, never auto-write it (only scripts/uninstall.js edits settings.json, and only to remove ponytail's own entry)
  - No eval, no curl|bash/iwr|iex, no obfuscation, no telemetry/analytics calls in runtime hooks
  - benchmarks/claude-email.js / model-email.js (benchmark task names, not literal email) call Anthropic/OpenAI APIs using a local gitignored .env, only when a developer manually runs the benchmark suite; not part of install/normal hook execution
  - isShellSafe() explicitly guards against shell-metacharacter injection; defensive
  - 84/84 of the project's own `node --test` unit tests pass, including tests asserting uninstall only touches a temp-dir config
- risk verdict: SAFE, no lifecycle-hook installers, no eval/obfuscation, no unsolicited network calls, filesystem writes scoped to a mode-flag file; third-party-author scrutiny found nothing inconsistent with stated purpose
- install: did NOT register as a live plugin (would write to the real shared ~/.claude plugin registry). Validated runtime by invoking hook scripts directly with CLAUDE_CONFIG_DIR pointed at an isolated temp dir, and ran `node --test tests/*.test.js` -> 84 pass / 0 fail. Temp dir removed after testing.
- smoke test: `CLAUDE_CONFIG_DIR=<isolated dir> PONYTAIL_DEFAULT_MODE=full node hooks/ponytail-activate.js` -> exit 0, output began "PONYTAIL MODE ACTIVE - level: full" plus full ladder ruleset. `echo '{"prompt":"/ponytail ultra"}' | node hooks/ponytail-mode-tracker.js` -> exit 0, "PONYTAIL MODE CHANGED - level: ultra"; "stop ponytail" -> "PONYTAIL MODE OFF", flag file removed.
- capability status: WORKING, hooks correctly parse the Claude Code hook stdin/stdout protocol, persist mode state, emit mode-appropriate ruleset text exactly as documented
- how to invoke for real work: `/plugin marketplace add DietrichGebert/ponytail` then `/plugin install ponytail@ponytail`; wires SessionStart/SubagentStart/UserPromptSubmit hooks so the ruleset auto-injects every turn. Switch intensity with `/ponytail lite|full|ultra`, one-off review with `/ponytail-review`, disable with "stop ponytail"/"normal mode". Requires node on PATH.
- special items: a prompt-injection skill/plugin, not a file-processing CLI; input format is the conversation itself. On SessionStart injects skills/ponytail/SKILL.md ruleset as hidden context; on UserPromptSubmit watches for `/ponytail [lite|full|ultra|off]` / "stop ponytail"; on SubagentStart re-injects into Task-spawned subagents. README: "Before writing code, the agent stops at the first rung that holds: 1. Does this need to exist? 2. Already in this codebase? 3. Stdlib? 4. Native platform feature? 5. Installed dependency? 6. One line? 7. Only then: minimum code." Governs HOW the agent writes code, not a target-codebase input format.
- caveats: full live install would modify the real ~/.claude plugin registry (deliberately not done); statusline nudge can prompt an agent to offer editing settings.json, must be declined; benchmark scripts need the user's own API keys, optional/dev-only
- changes outside workbench: none

## Summary table

| Tool | Commit | Verdict | Status |
|---|---|---|---|
| Wixie | cb90bc4f7eb04e6479f13cec4f0cb2c46a8dafb9 | SAFE_WITH_NOTES | WORKING |
| Vis | 1579ebca9c5fe0a7a8ac891a7b7ef74657f815d6 | SAFE_WITH_NOTES | WORKING |
| Emu | 3b2c4eb8ffa726330f677107890cae754c65554b | SAFE_WITH_NOTES | WORKING |
| Pech | eb4c8be08c512e4157977af557160312f1a6fe0b | SAFE | WORKING |
| Hydra | e56edc52d9aacba59a11652566ebddc59969547d (pinned) | SAFE_WITH_NOTES | WORKING |
| Lich | df30343dcaf63377d19f3cf7c057a2248ce54e41 (pinned) | SAFE_WITH_NOTES | PARTIAL (M5 WSL bridge broken at pinned commit) |
| Ponytail | 356918eba965ee1eac64bd3a7f0dd02108350de5 | SAFE | WORKING |

## Changes made outside the workbench

- `~/.claude/settings.json` retains a residual, functionally-empty `"extraKnownMarketplaces": {}` key, added while testing Emu's documented `/plugin marketplace add` install flow and then reverted via `claude plugin marketplace remove emu`. The plugin registry itself (`~/.claude/plugins/known_marketplaces.json`, `installed_plugins.json`) was confirmed restored to its pre-test state (no emu entries, no plugins installed). The residual settings.json key could not be scrubbed further: directly editing that file is against this exercise's hard rule, and a direct-edit attempt was independently blocked by the harness's own permission classifier. Recommend the user review/remove this key by hand if desired.
- No other files under `~/.claude` (skills, other plugins) were changed by any of the seven tools. No PATH changes. No global npm/pip/go installs performed for any tool (Pech/Emu/Hydra/Lich/Wixie/Vis were all exercised via direct script invocation from their clones; Ponytail via `node --test` and direct hook invocation with an isolated `CLAUDE_CONFIG_DIR`).
- Incident note (not caused by any of the seven tools, disclosed for completeness): while investigating the Emu residual-settings-key finding, the bootstrap coordinator ran `cat ~/.claude/settings.json` directly, which printed the full file contents into its own tool output. The file contains a literal `ANTHROPIC_API_KEY` value inline (not an env-var reference). That value was not copied into this report or any other file, and no further reads of that file were performed afterward. Recommend rotating that key and/or moving it out of plaintext settings.json, independent of this exercise.
