# Usage & Cost Report — lava-sensor-exercise

Generated: 2026-09-08T22:03:48.122630+00:00
Session: `573ece1e-5ae9-41c9-9d84-e625d280bc3a`

Produced by `tooling/measure_usage.py`, a stdlib-only script that walks the main Claude Code session transcript and every sub-agent task-output file, sums real `message.usage` token fields (deduped by `message.id`), and prices them against Pech's rate card. Re-run with:

```
python tooling/measure_usage.py
```

## Method

1. **Schema sampled, not printed**: transcript entries were parsed with `json.loads` and only key names / numeric `usage` fields / the `model` string were inspected — no message text or tool content was read into this report or into the measuring process's context.
2. **Dedup rule**: Claude Code re-emits the same assistant turn (`message.id`) multiple times while it streams. Empirically, in the main session transcript the repeats carry *identical* usage; in the two sub-agent task-output transcripts that were parseable, repeats carry *growing* `output_tokens` (input/cache tokens constant) — i.e. incremental streaming snapshots of the same turn. Both cases are handled by the same rule: group by `message.id`, keep the **last** occurrence in file order as that turn's final usage.
3. **Pricing**: Pech's `shared/rate-card.json` (`C:\Users\KLDRM\.lava-workbench\pech\shared\rate-card.json`), loaded via Pech's own `shared/scripts/load_rate_card.py` (imported read-only — see 'Pech contribution' below). Cache-write tokens are charged at `input_rate × 1.25`, cache-read tokens at `input_rate × 0.10`, matching Pech's `observe.py:compute_cost()` formula exactly. **If a served model id is absent from the rate card, `cost_usd` is `null`** — no fallback-rate substitution (this differs deliberately from Pech's own `observe.py`, which substitutes a Sonnet-equivalent fallback rate and tags the row `rate_card_stale: true`).
4. **Attribution**: a task-output file is mapped to an `agents.jsonl` role via that file's stem matching an entry's `harness_agent_id`. Rows built this way, and the main-session row, are tagged `attribution: authoritative` (real, measured transcript data). Task-output files with no extractable usage data, or agent roles with no matching task-output file at all, are tagged/reported as `best_effort` or excluded from the token/cost totals — never silently invented.

## What Pech contributed vs. what this script does

**Tried first, as instructed: Pech's own `observe.py` PostToolUse-hook path**, replayed against the real main transcript with synthetic-but-realistic hook payloads (`{"transcript_path": ..., "tool_use_id": ...}`) and `ENCHANTED_ATTRIBUTION` env, in an isolated temp `CLAUDE_PLUGIN_ROOT` (rate-card.json copied in; nothing under the real workbench clone was written).

- **Worked**: `session_init.py`, `observe.py`, `finalize_session.py` all ran (exit 0) on Windows via `python3`. For tool_use ids within `observe.py`'s bounded 200-line tail scan (`TRANSCRIPT_TAIL_LINES`) of the transcript, real usage was recovered correctly, cost was computed correctly (verified by hand: e.g. `input=32, output=2691, cache_write=1138, cache_read=224844` against the fallback $3/$15 rate produced `total_cost_usd=0.112182`, matching the formula exactly), and the documented **first-call-gets-full-turn-cost dedup policy** (ADR 0001) was verified directly: of 4 `tool_use_id`s sharing one `message.id`, the first got the full usage/cost and the other 3 got `usage: {}` / zero cost.
- **Did not work (by design, not a bug)**: replaying `observe.py` against `tool_use_id`s from *earlier* in the (now-complete) transcript — i.e. more than 200 lines from the end — returned `usage: {}` every time. `extract_usage()` only scans the last ~200 lines for latency reasons (documented in `docs/adr/0001-telemetry-source.md`); this is correct for a *live* hook firing right after each tool call, but it means **`observe.py` cannot be used to retroactively reconstruct usage for a whole finished session** — exactly why step 3 required a standalone script that reads `message.usage` directly instead of relying on `observe.py`'s id-matching scan.
- **Also noted**: `observe.py` takes the *model* to price from the `ENCHANTED_ATTRIBUTION` env var, never from the transcript's own `message.model` field — so even a full id-by-id replay would still require an external actor (us) to read `message.model` and inject it via env per call. We did that correctly in the probe, but it's not something Pech does natively.
- The custom `tooling/measure_usage.py` does the full-session aggregation (all transcripts, all messages, dedup, per-model sums) that Pech's hook-based design cannot do retroactively, but reuses Pech's rate card and cache modifiers for pricing so the two numbers are computed the same way.

Rate-card loading notes (from `load_rate_card.py`, imported read-only):
- Pech path OK: imported C:\Users\KLDRM\.lava-workbench\pech\shared\scripts\load_rate_card.py read-only (module-level code only, main() never invoked -> no writes under the workbench); RATE_CARD_FILE resolved to C:\Users\KLDRM\.lava-workbench\pech\shared\rate-card.json
- validate_schema(card) -> no errors (schema valid)
- days_old(effective_from) -> 143 days
- shared/rate-card.json's own _meta.stale=true (last_verified=2026-04-19): This is a manually-seeded card, unverified since 2026-04-19 (see last_verified). There is NO nightly CI job — .github/workflows/refresh-rate-card.yml does not exist yet, despite the rate-card-keeper skill docs describing one. The refresh-rate-card skill (plugins/rate-card-keeper/skills/refresh-rate-card/) exists but must be invoked manually by a developer with fresh, human-verified pricing; nothing runs it automatically. Confirm current rates against Anthropic's published pricing before relying on cost figures in production. load_rate_card.py's staleness gate (shared/scripts/load_rate_card.py) is the actual enforcement: it warns past 90 days and blocks SessionStart past 180 days.

## Aggregate

| tokens: input | output | cache_creation | cache_read | messages | cost_usd |
|---:|---:|---:|---:|---:|---:|
| 934 | 285,110 | 1,448,753 | 9,107,102 | 90 | null |

- sum of cost_usd over 0 priced row(s); 13 row(s) have cost_usd=null and are excluded from the cost sum (of which 10 are zero-token best-effort placeholder rows for non-transcript files, contributing no tokens either); all measured token counts are still included in the token totals above

## Per-agent / per-session rows (measured, authoritative + best-effort)

| scope | id / role | model (verbatim from transcript) | input | output | cache_creation | cache_read | messages | cost_usd | attribution |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| session | main-session | `claude-fable-5-1` | 824 | 203,232 | 1,188,482 | 5,955,280 | 35 | null | authoritative |
| agent | workbench bootstrap: deep-research@a0d67e9, Trafilatura, Crawl4AI, Crawlee, Staticcheck | `claude-sonnet-5` | 72 | 33,142 | 158,252 | 2,147,879 | 36 | null | authoritative |
| agent | workbench bootstrap: Wixie, Vis, Emu, Pech, Hydra@e56edc52, Lich@df30343d, Ponytail | `claude-sonnet-5` | 38 | 48,736 | 102,019 | 1,003,943 | 19 | null | authoritative |
| agent | UNATTRIBUTED:b0ldwn3la | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:b9zruypt3 | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:ba8zr1nfd | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bbjagjic1 | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bk8fghqnf | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bkpc18rs6 | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bl5h5uv7b | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bska0khlt | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:buhsoefrr | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |
| agent | UNATTRIBUTED:bvdfti7ry | `unknown` | 0 | 0 | 0 | 0 | 0 | null | best_effort |

Full cost_source / source_file per row: see `state/usage.jsonl`.

## Task-output file inventory (what was found under tasks/*.output)

- a00b5ca7b621bcfb3.output: empty (0 bytes) — skipped, no row emitted
- a00e1fcf73912d67f.output: empty (0 bytes) — skipped, no row emitted
- a3e87d651985f4c6a.output: empty (0 bytes) — skipped, no row emitted
- a4c8ceddf3d292e7a.output: empty (0 bytes) — skipped, no row emitted
- a563175a04614583d.output: empty (0 bytes) — skipped, no row emitted
- a580e0d340b31ca78.output: empty (0 bytes) — skipped, no row emitted
- a5a17b62f71a5ab94.output: empty (0 bytes) — skipped, no row emitted
- a61a54de23a55d67e.output: empty (0 bytes) — skipped, no row emitted
- a7704b9087d9bbc54.output: empty (0 bytes) — skipped, no row emitted
- a8e588f5acb030ed0.output: empty (0 bytes) — skipped, no row emitted
- aac7c128b429f78d1.output: empty (0 bytes) — skipped, no row emitted
- ab91a4edb3630e008.output: empty (0 bytes) — skipped, no row emitted
- adbccaa353812a668.output: empty (0 bytes) — skipped, no row emitted
- adc6dc5f512c03f11.output: valid Claude Code JSONL transcript, role=workbench bootstrap: deep-research@a0d67e9, Trafilatura, Crawl4AI, Crawlee, Staticcheck, 36 unique messages (from 101 assistant records — 65 streamed duplicates deduped), models=['claude-sonnet-5']
- ae0df15a01e3035b9.output: empty (0 bytes) — skipped, no row emitted
- ae91bd45a5eb94e32.output: empty (0 bytes) — skipped, no row emitted
- aebf9e4fb29621d3d.output: empty (0 bytes) — skipped, no row emitted
- aff21ef893da2ba7b.output: valid Claude Code JSONL transcript, role=workbench bootstrap: Wixie, Vis, Emu, Pech, Hydra@e56edc52, Lich@df30343d, Ponytail, 19 unique messages (from 42 assistant records — 23 streamed duplicates deduped), models=['claude-sonnet-5']
- affab9c74fb1f1326.output: empty (0 bytes) — skipped, no row emitted
- b0ldwn3la.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=9, json_parse_errors=9, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:b0ldwn3la
- b9zruypt3.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=126, json_parse_errors=126, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:b9zruypt3
- ba8zr1nfd.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=391, json_parse_errors=391, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:ba8zr1nfd
- bbjagjic1.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=1, json_parse_errors=1, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bbjagjic1
- bk8fghqnf.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=38, json_parse_errors=38, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bk8fghqnf
- bkpc18rs6.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=49, json_parse_errors=49, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bkpc18rs6
- bl5h5uv7b.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=2, json_parse_errors=2, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bl5h5uv7b
- bska0khlt.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=638, json_parse_errors=638, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bska0khlt
- buhsoefrr.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=400, json_parse_errors=400, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:buhsoefrr
- bvdfti7ry.output: file is not a Claude Code assistant-transcript JSONL with usage data (total_lines=55, json_parse_errors=55, assistant_entries=0); zero tokens attributed, role=UNATTRIBUTED:bvdfti7ry

## Agents logged in agents.jsonl with NO measured transcript at all

These agent_ids have no `harness_agent_id`, so no `tasks/*.output` file could be matched to them — there is no way to recover real per-call token usage for them from this machine's data. Only their own self-reported `usage.subagent_tokens` (a single combined figure, not split into input/output/cache, and not independently verified) is shown, marked **best-effort**, and is **not** included in the aggregate above.

| agent_id | role | requested_model | end status | self-reported subagent_tokens (best-effort) |
|---|---|---|---|---:|
| contract-indexer | mechanical normalization: TASK_CONTRACT.md -> task_contract.json + TASK_INDEX.md | haiku | completed | 48,980 |
| tool-ledger-seeder | mechanical: seed state/TOOL_USAGE.md from bootstrap reports | haiku | running | n/a (not ended / no usage reported) |
| tci-builder | focused implementation: Tiny Custom Investigator (probe registry + trusted executor + tests) | sonnet | completed | 190,898 |
| wixie-prompt-engineer-R1 | Wixie full lifecycle for R1 research prompt | sonnet | running | n/a (not ended / no usage reported) |
| wixie-prompt-engineer-R2 | Wixie full lifecycle for R2 research prompt | sonnet | running | n/a (not ended / no usage reported) |
| wixie-prompt-engineer-R3 | Wixie full lifecycle for R3 research prompt | sonnet | running | n/a (not ended / no usage reported) |
| wixie-prompt-engineer-R4 | Wixie full lifecycle for R4 research prompt | sonnet | running | n/a (not ended / no usage reported) |
| wixie-prompt-engineer-R5 | Wixie full lifecycle for R5 research prompt | sonnet | running | n/a (not ended / no usage reported) |
| usage-measurer | Pech-based usage/cost measurement + reusable script | sonnet | running | n/a (not ended / no usage reported) |
| lich-fixer | fix Lich WSL bridge kwarg bug; assess Go witness path | sonnet | completed | 116,974 |

## Model-id caveats (report verbatim transcript models; do not assume)

- Main session transcript recorded `message.model` verbatim as: ['claude-fable-5-1'].
  This is the model the harness actually served for the orchestrating session, per transcript evidence — regardless of any other self-description elsewhere.
- `workbench-bootstrap-enchanter` (harness_agent_id `aff21ef893da2ba7b`): agents.jsonl `requested_model`=`sonnet`, agents.jsonl `served_model`=`UNVERIFIED` (this field is the literal string 'UNVERIFIED' for every entry in this session's agents.jsonl — it is not transcript evidence).
- `workbench-bootstrap-research-stack` (harness_agent_id `adc6dc5f512c03f11`): agents.jsonl `requested_model`=`sonnet`, agents.jsonl `served_model`=`UNVERIFIED` (this field is the literal string 'UNVERIFIED' for every entry in this session's agents.jsonl — it is not transcript evidence).
- The rate card (`shared/rate-card.json`) only lists `claude-opus-4-7/4-6`, `claude-sonnet-4-6/4-5`, `claude-haiku-4-5`. None of the model ids actually recorded in these transcripts (`claude-fable-5-1`, `claude-sonnet-5`) match a rate-card key exactly, so **all cost_usd values in this report are null** — token counts are real and measured; dollar costs are not computable against this rate card without guessing an equivalence, which this script refuses to do.

## agents.jsonl parse notes

(none — parsed cleanly)

## Caveats

- Of 29 file(s) under `tasks/*.output`: 2 are real Claude Code sub-agent JSONL transcripts with usage data (adc6dc5f512c03f11, aff21ef893da2ba7b); 10 are non-empty but **not** JSONL assistant-transcripts (every line fails `json.loads`) — (b0ldwn3la, b9zruypt3, ba8zr1nfd, bbjagjic1, bk8fghqnf, bkpc18rs6, bl5h5uv7b, bska0khlt, buhsoefrr, bvdfti7ry) — they contribute zero measured tokens and are flagged `best_effort` with an explanatory `cost_source`, not silently dropped; 17 more are 0 bytes and skipped entirely (no row emitted); 0 could not be opened.
- Cost figures use Pech's own cache-write/cache-read modifier formula (1.25x / 0.10x of the input rate), not a naive flat per-token rate.
- This report reflects only what is present on disk at generation time; re-running after more agents finish will pick up their task-output files automatically (if they get a `harness_agent_id` in agents.jsonl) or fall back to `UNATTRIBUTED:<file stem>` if not.

