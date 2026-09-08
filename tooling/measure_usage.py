#!/usr/bin/env python3
"""
measure_usage.py — measured AI token/cost usage for the lava-sensor-exercise session.

Walks the main Claude Code session transcript plus every sub-agent task-output
file, accumulates real `message.usage` token counts per (source file, model),
prices them against Pech's rate card, and writes:

    state/usage.jsonl        one JSON line per (session|agent|aggregate) row
    state/USAGE_REPORT.md    human-readable report

Design notes / honesty rules
-----------------------------
- Stdlib only. No network access, no writes outside the two output files above.
- Never touches anything under the Pech workbench clone. Pech's
  shared/scripts/load_rate_card.py is imported *read-only* (its module-level
  code has no I/O; its main() is never invoked, so no logs are written under
  the workbench) purely to reuse its RATE_CARD_FILE resolution and
  validate_schema()/days_old() functions. If that import fails for any reason,
  we fall back to reading shared/rate-card.json directly and say so.
- Streamed/duplicate assistant records: Claude Code re-emits the same
  `message.id` multiple times while a turn streams (see PECH_INTEGRATION.md
  notes below / final report). Empirically:
    * in the main session transcript, duplicate records for one message.id
      carry IDENTICAL usage;
    * in sub-agent task-output transcripts, duplicate records carry GROWING
      usage (output_tokens increases monotonically across duplicates as the
      turn streams; input/cache tokens stay constant).
  Both are handled correctly by the same rule: dedupe by message.id, keep the
  LAST occurrence encountered in file order (the final, complete snapshot for
  that turn). This is verified safe for the identical case (last == first)
  and correct for the growing case.
- If a served model id is not present in the rate card, cost_usd is emitted as
  null with cost_source explaining why — no fallback-rate substitution. (Pech's
  own observe.py silently substitutes a Sonnet-equivalent fallback rate and
  tags the row rate_card_stale=true instead; we deliberately do NOT do that
  here, because "claude-fable-5-1" — the model actually recorded in this
  session's transcript — is not verified to be Sonnet-priced.)
- Attribution of a task-output file to an agent role uses agents.jsonl's
  `harness_agent_id` when present. Most agent rows in agents.jsonl in this
  session were never given a harness_agent_id, so most task-output files (and
  most logged agents) cannot be matched to each other at all — this is
  reported explicitly, not papered over.

Re-run any time with:  python tooling/measure_usage.py
"""

import argparse
import importlib.util
import json
import os
import sys
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

SESSION_ID = "573ece1e-5ae9-41c9-9d84-e625d280bc3a"

DEFAULT_MAIN_TRANSCRIPT = Path(
    r"C:\Users\KLDRM\.claude\projects\C--lava-sensor-exercise"
) / f"{SESSION_ID}.jsonl"
DEFAULT_TASKS_DIR = (
    Path(r"C:\Users\KLDRM\AppData\Local\Temp\claude\C--lava-sensor-exercise")
    / SESSION_ID
    / "tasks"
)
DEFAULT_AGENTS_FILE = REPO_ROOT / "agents.jsonl"
DEFAULT_PECH_ROOT = Path(os.path.expanduser("~")) / ".lava-workbench" / "pech"
DEFAULT_OUT_JSONL = REPO_ROOT / "state" / "usage.jsonl"
DEFAULT_OUT_REPORT = REPO_ROOT / "state" / "USAGE_REPORT.md"

FALLBACK_CACHE_WRITE_MOD = 1.25
FALLBACK_CACHE_READ_MOD = 0.10

USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


# --------------------------------------------------------------------------
# Rate card (Pech integration)
# --------------------------------------------------------------------------

def load_rate_card(pech_root: Path):
    """Load the rate card, preferring Pech's own load_rate_card.py module.

    Returns (card: dict|None, rate_card_path: Path|None, notes: list[str]).
    Never executes load_rate_card.py's main() (no workbench writes) — only its
    module-level constants and pure functions (validate_schema, days_old) are
    used, purely as read-only validation of the card we load ourselves.
    """
    notes = []
    lrc_path = pech_root / "shared" / "scripts" / "load_rate_card.py"
    card = None
    rate_card_path = None

    try:
        spec = importlib.util.spec_from_file_location("pech_load_rate_card", lrc_path)
        mod = importlib.util.module_from_spec(spec)
        saved_env = os.environ.pop("CLAUDE_PLUGIN_ROOT", None)
        try:
            spec.loader.exec_module(mod)  # module name != "__main__" -> main() guard never fires
        finally:
            if saved_env is not None:
                os.environ["CLAUDE_PLUGIN_ROOT"] = saved_env

        rate_card_path = mod.RATE_CARD_FILE
        with open(rate_card_path, encoding="utf-8") as f:
            card = json.load(f)

        errors = mod.validate_schema(card)
        age = mod.days_old(card.get("effective_from", ""))
        notes.append(
            f"Pech path OK: imported {lrc_path} read-only (module-level code only, "
            f"main() never invoked -> no writes under the workbench); "
            f"RATE_CARD_FILE resolved to {rate_card_path}"
        )
        notes.append(
            "validate_schema(card) -> "
            + ("no errors (schema valid)" if not errors else f"errors: {errors}")
        )
        notes.append(f"days_old(effective_from) -> {age} days")
        stale_meta = card.get("_meta", {})
        if stale_meta.get("stale"):
            notes.append(
                "shared/rate-card.json's own _meta.stale=true "
                f"(last_verified={stale_meta.get('last_verified')}): "
                f"{stale_meta.get('note', '')}"
            )
    except Exception as e:
        notes.append(
            f"Pech load_rate_card.py import path failed ({type(e).__name__}: {e}); "
            "falling back to a direct JSON read of shared/rate-card.json"
        )
        rate_card_path = pech_root / "shared" / "rate-card.json"
        try:
            with open(rate_card_path, encoding="utf-8") as f:
                card = json.load(f)
            notes.append(f"direct read of {rate_card_path} succeeded")
        except Exception as e2:
            notes.append(f"direct read also failed ({type(e2).__name__}: {e2}); no rate card available")
            card = None
            rate_card_path = None

    return card, rate_card_path, notes


def compute_cost(acc: dict, model: str, rate_card: dict | None, rate_card_path):
    """Price one (model, accumulated-usage) bucket. Returns (cost_usd|None, cost_source: str)."""
    if not rate_card:
        return None, "no rate card available"

    models = rate_card.get("models", {})
    modifiers = rate_card.get("modifiers", {})
    rate = models.get(model)

    if rate is None:
        return None, (
            f"model '{model}' is absent from rate-card.json's models{{}} ({rate_card_path}); "
            "cost intentionally left null — no fallback-rate substitution "
            "(Pech's own observe.py would silently use its Sonnet-equivalent "
            "fallback_model_rate and tag rate_card_stale=true instead; we do not, "
            "per this measurement's honesty requirement)"
        )

    input_rate = rate.get("input_rate_per_mtok", 0.0)
    output_rate = rate.get("output_rate_per_mtok", 0.0)
    cache_write_mod = modifiers.get("cache_write_modifier", FALLBACK_CACHE_WRITE_MOD)
    cache_read_mod = modifiers.get("cache_read_modifier", FALLBACK_CACHE_READ_MOD)

    input_cost = acc["input_tokens"] * input_rate / 1_000_000
    output_cost = acc["output_tokens"] * output_rate / 1_000_000
    cache_write_cost = acc["cache_creation_input_tokens"] * input_rate * cache_write_mod / 1_000_000
    cache_read_cost = acc["cache_read_input_tokens"] * input_rate * cache_read_mod / 1_000_000
    total = input_cost + output_cost + cache_write_cost + cache_read_cost

    source = (
        f"rate-card.json models['{model}'] @ {rate_card_path} "
        f"(in=${input_rate}/Mtok, out=${output_rate}/Mtok); "
        f"cache_write x{cache_write_mod}, cache_read x{cache_read_mod} "
        "(same formula as Pech shared/scripts/observe.py:compute_cost)"
    )
    return round(total, 6), source


# --------------------------------------------------------------------------
# Transcript scanning
# --------------------------------------------------------------------------

def scan_transcript(path: Path) -> dict:
    """Stream one JSONL file, dedupe assistant usage records by message.id
    (keeping the LAST occurrence per id — see module docstring), and
    accumulate token usage per model. Never loads the whole file into memory
    at once for large files; never surfaces message text/content.
    """
    total_lines = 0
    parse_errors = 0
    assistant_entries = 0
    usage_entries = 0
    last_seen = OrderedDict()  # message_id (or synthetic) -> (model, usage_dict)
    anon_counter = 0

    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except Exception as e:
        return {
            "path": str(path), "open_error": f"{type(e).__name__}: {e}",
            "total_lines": 0, "json_parse_errors": 0, "assistant_entries": 0,
            "usage_entries": 0, "unique_message_ids": 0, "per_model": {},
            "looks_like_transcript": False,
        }

    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total_lines += 1
            try:
                entry = json.loads(line)
            except Exception:
                parse_errors += 1
                continue
            if not isinstance(entry, dict) or entry.get("type") != "assistant":
                continue
            assistant_entries += 1
            message = entry.get("message")
            if not isinstance(message, dict):
                continue
            usage = message.get("usage")
            if not isinstance(usage, dict) or not usage:
                continue
            usage_entries += 1
            model = message.get("model") or "unknown"
            mid = message.get("id")
            if not mid:
                anon_counter += 1
                mid = f"__no_message_id_{anon_counter}"
            last_seen[mid] = (model, usage)  # overwrite -> last occurrence wins

    per_model = {}
    for _mid, (model, usage) in last_seen.items():
        acc = per_model.setdefault(model, {f: 0 for f in USAGE_FIELDS} | {"messages": 0})
        for f in USAGE_FIELDS:
            try:
                acc[f] += int(usage.get(f) or 0)
            except (TypeError, ValueError):
                pass
        acc["messages"] += 1

    return {
        "path": str(path),
        "total_lines": total_lines,
        "json_parse_errors": parse_errors,
        "assistant_entries": assistant_entries,
        "usage_entries": usage_entries,
        "unique_message_ids": len(last_seen),
        "per_model": per_model,
        "looks_like_transcript": usage_entries > 0,
    }


# --------------------------------------------------------------------------
# agents.jsonl
# --------------------------------------------------------------------------

def load_agents(path: Path):
    """Merge agents.jsonl's start/end event pairs by agent_id. Returns
    (records: dict[agent_id -> dict], harness_index: dict[harness_agent_id -> agent_id], notes: list[str])."""
    records = {}
    notes = []
    if not path.exists():
        notes.append(f"agents.jsonl not found at {path}")
        return records, {}, notes

    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception as ex:
                notes.append(f"agents.jsonl line {lineno}: parse error ({ex})")
                continue
            aid = e.get("agent_id")
            if not aid:
                continue
            rec = records.setdefault(aid, {"agent_id": aid})
            if e.get("event") == "end":
                rec["ended"] = True
                rec["end_status"] = e.get("status")
                rec["end_served_model"] = e.get("served_model")
                rec["end_usage"] = e.get("usage")
                rec["result_summary"] = e.get("result_summary")
            else:
                for k, v in e.items():
                    rec.setdefault(k, v)

    harness_index = {
        rec["harness_agent_id"]: aid
        for aid, rec in records.items()
        if rec.get("harness_agent_id")
    }
    return records, harness_index, notes


# --------------------------------------------------------------------------
# Row construction
# --------------------------------------------------------------------------

def make_row(ts, scope, row_id, role, model, acc, cost_usd, cost_source, attribution, source_file):
    return {
        "ts": ts,
        "scope": scope,
        "id": row_id,
        "role": role,
        "model": model,
        "input_tokens": acc.get("input_tokens", 0),
        "output_tokens": acc.get("output_tokens", 0),
        "cache_creation_tokens": acc.get("cache_creation_input_tokens", 0),
        "cache_read_tokens": acc.get("cache_read_input_tokens", 0),
        "messages": acc.get("messages", 0),
        "cost_usd": cost_usd,
        "cost_source": cost_source,
        "attribution": attribution,
        "source_file": source_file,
    }


def accumulate(agg, acc, cost_usd):
    agg["input_tokens"] += acc.get("input_tokens", 0)
    agg["output_tokens"] += acc.get("output_tokens", 0)
    agg["cache_creation_tokens"] += acc.get("cache_creation_input_tokens", 0)
    agg["cache_read_tokens"] += acc.get("cache_read_input_tokens", 0)
    agg["messages"] += acc.get("messages", 0)
    if cost_usd is not None:
        agg["cost_usd"] += cost_usd
        agg["priced_rows"] += 1
    else:
        agg["unpriced_rows"] += 1


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--main-transcript", type=Path, default=DEFAULT_MAIN_TRANSCRIPT)
    p.add_argument("--tasks-dir", type=Path, default=DEFAULT_TASKS_DIR)
    p.add_argument("--agents-file", type=Path, default=DEFAULT_AGENTS_FILE)
    p.add_argument("--pech-root", type=Path, default=DEFAULT_PECH_ROOT)
    p.add_argument("--out-jsonl", type=Path, default=DEFAULT_OUT_JSONL)
    p.add_argument("--out-report", type=Path, default=DEFAULT_OUT_REPORT)
    return p.parse_args()


def main():
    args = parse_args()
    ts_now = datetime.now(timezone.utc).isoformat()

    rate_card, rate_card_path, rate_card_notes = load_rate_card(args.pech_root)
    agents_records, harness_index, agents_notes = load_agents(args.agents_file)

    rows = []
    agg = {
        "input_tokens": 0, "output_tokens": 0, "cache_creation_tokens": 0,
        "cache_read_tokens": 0, "messages": 0, "cost_usd": 0.0,
        "priced_rows": 0, "unpriced_rows": 0, "zero_data_rows": 0,
    }

    # -- main session transcript --------------------------------------
    main_scan = scan_transcript(args.main_transcript)
    for model, acc in main_scan["per_model"].items():
        cost, source = compute_cost(acc, model, rate_card, rate_card_path)
        row = make_row(ts_now, "session", SESSION_ID, "main-session", model, acc,
                        cost, source, "authoritative", str(args.main_transcript))
        rows.append(row)
        accumulate(agg, acc, cost)

    # -- every task-output file ----------------------------------------
    task_file_notes = []
    file_counts = {"empty": 0, "valid_transcript": 0, "non_jsonl": 0, "open_error": 0, "total": 0}
    non_jsonl_names = []
    valid_transcript_names = []
    if args.tasks_dir.exists():
        task_files = sorted(args.tasks_dir.glob("*.output"))
    else:
        task_files = []
        task_file_notes.append(f"tasks dir not found: {args.tasks_dir}")

    for f in task_files:
        file_counts["total"] += 1
        stem = f.stem
        size = f.stat().st_size
        agent_id = harness_index.get(stem)
        role = agents_records.get(agent_id, {}).get("role") if agent_id else None
        role = role or f"UNATTRIBUTED:{stem}"

        if size == 0:
            file_counts["empty"] += 1
            task_file_notes.append(f"{f.name}: empty (0 bytes) — skipped, no row emitted")
            continue

        scan = scan_transcript(f)
        if scan.get("open_error"):
            file_counts["open_error"] += 1
            task_file_notes.append(f"{f.name}: open error ({scan['open_error']}) — skipped")
            continue

        if scan["looks_like_transcript"]:
            file_counts["valid_transcript"] += 1
            valid_transcript_names.append(f.stem)
            for model, acc in scan["per_model"].items():
                cost, source = compute_cost(acc, model, rate_card, rate_card_path)
                row = make_row(ts_now, "agent", agent_id or stem, role, model, acc,
                                cost, source, "authoritative", str(f))
                rows.append(row)
                accumulate(agg, acc, cost)
            task_file_notes.append(
                f"{f.name}: valid Claude Code JSONL transcript, role={role}, "
                f"{scan['unique_message_ids']} unique messages "
                f"(from {scan['assistant_entries']} assistant records — "
                f"{scan['assistant_entries'] - scan['unique_message_ids']} streamed duplicates deduped), "
                f"models={sorted(scan['per_model'].keys())}"
            )
        else:
            file_counts["non_jsonl"] += 1
            non_jsonl_names.append(f.stem)
            zero_acc = {f_: 0 for f_ in USAGE_FIELDS} | {"messages": 0}
            note = (
                f"file is not a Claude Code assistant-transcript JSONL with usage data "
                f"(total_lines={scan['total_lines']}, json_parse_errors={scan['json_parse_errors']}, "
                f"assistant_entries={scan['assistant_entries']}); zero tokens attributed"
            )
            row = make_row(ts_now, "agent", agent_id or stem, role, "unknown", zero_acc,
                            None, note, "best_effort", str(f))
            rows.append(row)
            accumulate(agg, zero_acc, None)  # all-zero -> only affects unpriced_rows bookkeeping
            agg["zero_data_rows"] = agg.get("zero_data_rows", 0) + 1
            task_file_notes.append(f"{f.name}: {note}, role={role}")

    # -- aggregate row ---------------------------------------------------
    agg_row = {
        "ts": ts_now,
        "scope": "aggregate",
        "id": "ALL",
        "role": "ALL",
        "model": "ALL",
        "input_tokens": agg["input_tokens"],
        "output_tokens": agg["output_tokens"],
        "cache_creation_tokens": agg["cache_creation_tokens"],
        "cache_read_tokens": agg["cache_read_tokens"],
        "messages": agg["messages"],
        "cost_usd": round(agg["cost_usd"], 6) if agg["priced_rows"] > 0 else None,
        "cost_source": (
            f"sum of cost_usd over {agg['priced_rows']} priced row(s); "
            f"{agg['unpriced_rows']} row(s) have cost_usd=null and are excluded from the "
            f"cost sum (of which {agg['zero_data_rows']} are zero-token best-effort "
            "placeholder rows for non-transcript files, contributing no tokens either); "
            "all measured token counts are still included in the token totals above"
        ),
        "attribution": "authoritative" if agg["unpriced_rows"] == 0 else "mixed(see per-row attribution)",
        "source_file": "ALL",
    }
    rows.append(agg_row)

    # -- write state/usage.jsonl (full regeneration each run) -----------
    args.out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out_jsonl, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    # -- agents.jsonl entries with NO harness_agent_id (best-effort only) --
    unattributable_agents = []
    for aid, rec in agents_records.items():
        if rec.get("harness_agent_id"):
            continue  # already covered by a task-output row above
        unattributable_agents.append(rec)

    write_report(
        args.out_report, ts_now, rows, agg_row, main_scan, task_file_notes,
        rate_card, rate_card_path, rate_card_notes, agents_notes,
        agents_records, harness_index, unattributable_agents, args,
        file_counts, non_jsonl_names, valid_transcript_names,
    )

    print(f"wrote {len(rows)} rows to {args.out_jsonl}")
    print(f"wrote report to {args.out_report}")
    print(
        f"aggregate: input={agg_row['input_tokens']} output={agg_row['output_tokens']} "
        f"cache_creation={agg_row['cache_creation_tokens']} cache_read={agg_row['cache_read_tokens']} "
        f"cost_usd={agg_row['cost_usd']}"
    )
    return 0


def write_report(out_path, ts_now, rows, agg_row, main_scan, task_file_notes,
                  rate_card, rate_card_path, rate_card_notes, agents_notes,
                  agents_records, harness_index, unattributable_agents, args,
                  file_counts, non_jsonl_names, valid_transcript_names):
    lines = []
    w = lines.append

    w("# Usage & Cost Report — lava-sensor-exercise")
    w("")
    w(f"Generated: {ts_now}")
    w(f"Session: `{SESSION_ID}`")
    w("")
    w(
        "Produced by `tooling/measure_usage.py`, a stdlib-only script that walks the "
        "main Claude Code session transcript and every sub-agent task-output file, "
        "sums real `message.usage` token fields (deduped by `message.id`), and prices "
        "them against Pech's rate card. Re-run with:"
    )
    w("")
    w("```")
    w("python tooling/measure_usage.py")
    w("```")
    w("")

    w("## Method")
    w("")
    w(
        "1. **Schema sampled, not printed**: transcript entries were parsed with "
        "`json.loads` and only key names / numeric `usage` fields / the `model` string "
        "were inspected — no message text or tool content was read into this report or "
        "into the measuring process's context."
    )
    w(
        "2. **Dedup rule**: Claude Code re-emits the same assistant turn "
        "(`message.id`) multiple times while it streams. Empirically, in the main "
        "session transcript the repeats carry *identical* usage; in the two sub-agent "
        "task-output transcripts that were parseable, repeats carry *growing* "
        "`output_tokens` (input/cache tokens constant) — i.e. incremental streaming "
        "snapshots of the same turn. Both cases are handled by the same rule: group by "
        "`message.id`, keep the **last** occurrence in file order as that turn's final "
        "usage."
    )
    w(
        "3. **Pricing**: Pech's `shared/rate-card.json` "
        f"(`{rate_card_path}`), loaded via Pech's own "
        "`shared/scripts/load_rate_card.py` (imported read-only — see 'Pech contribution' "
        "below). Cache-write tokens are charged at `input_rate × 1.25`, cache-read tokens "
        "at `input_rate × 0.10`, matching Pech's `observe.py:compute_cost()` formula "
        "exactly. **If a served model id is absent from the rate card, `cost_usd` is "
        "`null`** — no fallback-rate substitution (this differs deliberately from Pech's "
        "own `observe.py`, which substitutes a Sonnet-equivalent fallback rate and tags "
        "the row `rate_card_stale: true`)."
    )
    w(
        "4. **Attribution**: a task-output file is mapped to an `agents.jsonl` role via "
        "that file's stem matching an entry's `harness_agent_id`. Rows built this way, "
        "and the main-session row, are tagged `attribution: authoritative` (real, "
        "measured transcript data). Task-output files with no extractable usage data, or "
        "agent roles with no matching task-output file at all, are tagged/reported as "
        "`best_effort` or excluded from the token/cost totals — never silently invented."
    )
    w("")

    w("## What Pech contributed vs. what this script does")
    w("")
    w("**Tried first, as instructed: Pech's own `observe.py` PostToolUse-hook path**, "
      "replayed against the real main transcript with synthetic-but-realistic hook "
      "payloads (`{\"transcript_path\": ..., \"tool_use_id\": ...}`) and "
      "`ENCHANTED_ATTRIBUTION` env, in an isolated temp `CLAUDE_PLUGIN_ROOT` "
      "(rate-card.json copied in; nothing under the real workbench clone was written).")
    w("")
    w("- **Worked**: `session_init.py`, `observe.py`, `finalize_session.py` all ran "
      "(exit 0) on Windows via `python3`. For tool_use ids within `observe.py`'s "
      "bounded 200-line tail scan (`TRANSCRIPT_TAIL_LINES`) of the transcript, real "
      "usage was recovered correctly, cost was computed correctly (verified by hand: "
      "e.g. `input=32, output=2691, cache_write=1138, cache_read=224844` against the "
      "fallback $3/$15 rate produced `total_cost_usd=0.112182`, matching the formula "
      "exactly), and the documented **first-call-gets-full-turn-cost dedup policy** "
      "(ADR 0001) was verified directly: of 4 `tool_use_id`s sharing one `message.id`, "
      "the first got the full usage/cost and the other 3 got `usage: {}` / zero cost.")
    w("- **Did not work (by design, not a bug)**: replaying `observe.py` against "
      "`tool_use_id`s from *earlier* in the (now-complete) transcript — i.e. more than "
      "200 lines from the end — returned `usage: {}` every time. `extract_usage()` "
      "only scans the last ~200 lines for latency reasons (documented in "
      "`docs/adr/0001-telemetry-source.md`); this is correct for a *live* hook firing "
      "right after each tool call, but it means **`observe.py` cannot be used to "
      "retroactively reconstruct usage for a whole finished session** — exactly why "
      "step 3 required a standalone script that reads `message.usage` directly instead "
      "of relying on `observe.py`'s id-matching scan.")
    w("- **Also noted**: `observe.py` takes the *model* to price from the "
      "`ENCHANTED_ATTRIBUTION` env var, never from the transcript's own "
      "`message.model` field — so even a full id-by-id replay would still require an "
      "external actor (us) to read `message.model` and inject it via env per call. We "
      "did that correctly in the probe, but it's not something Pech does natively.")
    w("- The custom `tooling/measure_usage.py` does the full-session aggregation (all "
      "transcripts, all messages, dedup, per-model sums) that Pech's hook-based design "
      "cannot do retroactively, but reuses Pech's rate card and cache modifiers for "
      "pricing so the two numbers are computed the same way.")
    w("")
    w("Rate-card loading notes (from `load_rate_card.py`, imported read-only):")
    for n in rate_card_notes:
        w(f"- {n}")
    w("")

    w("## Aggregate")
    w("")
    w("| tokens: input | output | cache_creation | cache_read | messages | cost_usd |")
    w("|---:|---:|---:|---:|---:|---:|")
    agg_cost_str = "null" if agg_row["cost_usd"] is None else f"${agg_row['cost_usd']:.4f}"
    w(
        f"| {agg_row['input_tokens']:,} | {agg_row['output_tokens']:,} | "
        f"{agg_row['cache_creation_tokens']:,} | {agg_row['cache_read_tokens']:,} | "
        f"{agg_row['messages']:,} | {agg_cost_str} |"
    )
    w("")
    w(f"- {agg_row['cost_source']}")
    w("")

    w("## Per-agent / per-session rows (measured, authoritative + best-effort)")
    w("")
    w("| scope | id / role | model (verbatim from transcript) | input | output | cache_creation | cache_read | messages | cost_usd | attribution |")
    w("|---|---|---|---:|---:|---:|---:|---:|---:|---|")
    for row in rows:
        if row["scope"] == "aggregate":
            continue
        cost_str = "null" if row["cost_usd"] is None else f"${row['cost_usd']:.4f}"
        w(
            f"| {row['scope']} | {row['role']} | `{row['model']}` | "
            f"{row['input_tokens']:,} | {row['output_tokens']:,} | "
            f"{row['cache_creation_tokens']:,} | {row['cache_read_tokens']:,} | "
            f"{row['messages']:,} | {cost_str} | {row['attribution']} |"
        )
    w("")
    w("Full cost_source / source_file per row: see `state/usage.jsonl`.")
    w("")

    w("## Task-output file inventory (what was found under tasks/*.output)")
    w("")
    for note in task_file_notes:
        w(f"- {note}")
    w("")

    w("## Agents logged in agents.jsonl with NO measured transcript at all")
    w("")
    w(
        "These agent_ids have no `harness_agent_id`, so no `tasks/*.output` file could "
        "be matched to them — there is no way to recover real per-call token usage for "
        "them from this machine's data. Only their own self-reported `usage.subagent_tokens` "
        "(a single combined figure, not split into input/output/cache, and not "
        "independently verified) is shown, marked **best-effort**, and is **not** "
        "included in the aggregate above."
    )
    w("")
    if not unattributable_agents:
        w("(none — every agent_id had a harness_agent_id)")
    else:
        w("| agent_id | role | requested_model | end status | self-reported subagent_tokens (best-effort) |")
        w("|---|---|---|---|---:|")
        for rec in unattributable_agents:
            usage = rec.get("end_usage") or {}
            tok = usage.get("subagent_tokens")
            tok_str = f"{tok:,}" if isinstance(tok, (int, float)) else "n/a (not ended / no usage reported)"
            w(
                f"| {rec['agent_id']} | {rec.get('role', 'n/a')} | "
                f"{rec.get('requested_model', 'n/a')} | {rec.get('end_status', rec.get('status', 'n/a'))} | "
                f"{tok_str} |"
            )
    w("")

    w("## Model-id caveats (report verbatim transcript models; do not assume)")
    w("")
    session_models = sorted(main_scan["per_model"].keys())
    w(f"- Main session transcript recorded `message.model` verbatim as: {session_models}.")
    w(
        "  This is the model the harness actually served for the orchestrating session, "
        "per transcript evidence — regardless of any other self-description elsewhere."
    )
    for aid, rec in agents_records.items():
        hid = rec.get("harness_agent_id")
        if not hid:
            continue
        requested = rec.get("requested_model")
        end_served = rec.get("end_served_model")
        w(
            f"- `{aid}` (harness_agent_id `{hid}`): agents.jsonl `requested_model`="
            f"`{requested}`, agents.jsonl `served_model`=`{end_served}` "
            "(this field is the literal string 'UNVERIFIED' for every entry in this "
            "session's agents.jsonl — it is not transcript evidence)."
        )
    w(
        "- The rate card (`shared/rate-card.json`) only lists `claude-opus-4-7/4-6`, "
        "`claude-sonnet-4-6/4-5`, `claude-haiku-4-5`. None of the model ids actually "
        "recorded in these transcripts (`claude-fable-5-1`, `claude-sonnet-5`) match a "
        "rate-card key exactly, so **all cost_usd values in this report are null** — "
        "token counts are real and measured; dollar costs are not computable against "
        "this rate card without guessing an equivalence, which this script refuses to do."
    )
    w("")

    w("## agents.jsonl parse notes")
    w("")
    if not agents_notes:
        w("(none — parsed cleanly)")
    else:
        for n in agents_notes:
            w(f"- {n}")
    w("")

    w("## Caveats")
    w("")
    w(
        f"- Of {file_counts['total']} file(s) under `tasks/*.output`: "
        f"{file_counts['valid_transcript']} are real Claude Code sub-agent JSONL "
        f"transcripts with usage data ({', '.join(sorted(valid_transcript_names)) or 'none'}); "
        f"{file_counts['non_jsonl']} are non-empty but **not** JSONL assistant-transcripts "
        f"(every line fails `json.loads`) — ({', '.join(sorted(non_jsonl_names)) or 'none'}) "
        "— they contribute zero measured tokens and are flagged `best_effort` with an "
        f"explanatory `cost_source`, not silently dropped; {file_counts['empty']} more are "
        f"0 bytes and skipped entirely (no row emitted); {file_counts['open_error']} could "
        "not be opened."
    )
    w(
        "- Cost figures use Pech's own cache-write/cache-read modifier formula "
        "(1.25x / 0.10x of the input rate), not a naive flat per-token rate."
    )
    w(
        "- This report reflects only what is present on disk at generation time; "
        "re-running after more agents finish will pick up their task-output files "
        "automatically (if they get a `harness_agent_id` in agents.jsonl) or fall back "
        "to `UNATTRIBUTED:<file stem>` if not."
    )
    w("")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    sys.exit(main())
