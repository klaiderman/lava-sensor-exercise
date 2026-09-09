#!/usr/bin/env python3
"""tooling/transcript/render.py

Deterministic renderer for the Lava-sensor-exercise reviewer transcript.

Reads (read-only):
  - the two native Claude Code session JSONL files (main + fork)
  - sub-agent task-output JSONL files under the harness TEMP tasks/ dirs
  - agents.jsonl (append-only agent ledger)
  - state/time_events.jsonl, state/usage.jsonl, state/USAGE_REPORT.md,
    state/BTW_INDEX.md, research/DECISIONS.md

Writes (only these):
  - ai/transcripts/normalized/events.jsonl   (one JSON object per line)
  - reports/claude-transcript.html           (self-contained viewer)
  - reports/claude-transcript-data.json      (sidecar for oversized text, if any)
  - reports/TRANSCRIPT_README.md             (short description; separate doc)

Determinism: every ordering decision in this file is a function of the input
files' *content* (uuid dedup, sha256-derived ids) plus a fixed processing
order, never wall-clock time or random ids. Re-running against unchanged
inputs reproduces byte-identical output. The only *label* in the output that
looks like a timestamp is the footer's "rendered_from" line, which is a hash
of the input files, not `datetime.now()`.

Redaction: exactly one pattern, `sk-ant-[A-Za-z0-9_-]{8,}`, is replaced with
`[REDACTED-API-KEY]` everywhere text is emitted (recursively through JSON
structures). Nothing else is redacted -- a messy real session is wanted.

Run: python tooling/transcript/render.py
"""

import hashlib
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Fixed paths for this exercise. Override via env vars if ever re-run
# elsewhere; defaults match this machine's layout (documented in the README).
# ---------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[2]
HOME = Path(os.environ.get("USERPROFILE") or os.path.expanduser("~"))

MAIN_SESSION_ID = "573ece1e-5ae9-41c9-9d84-e625d280bc3a"
FORK_SESSION_ID = "b64b46f1-8baf-4e2c-9e1a-4730b6251260"

PROJECTS_DIR = Path(os.environ.get(
    "TRANSCRIPT_PROJECTS_DIR",
    str(HOME / ".claude" / "projects" / "C--lava-sensor-exercise"),
))
TASKS_ROOT = Path(os.environ.get(
    "TRANSCRIPT_TASKS_ROOT",
    str(Path(os.environ.get("TEMP", str(HOME / "AppData" / "Local" / "Temp"))) / "claude" / "C--lava-sensor-exercise"),
))

MAIN_SESSION_PATH = PROJECTS_DIR / f"{MAIN_SESSION_ID}.jsonl"
FORK_SESSION_PATH = PROJECTS_DIR / f"{FORK_SESSION_ID}.jsonl"
TASKS_DIRS = OrderedDict([
    (MAIN_SESSION_ID, TASKS_ROOT / MAIN_SESSION_ID / "tasks"),
    (FORK_SESSION_ID, TASKS_ROOT / FORK_SESSION_ID / "tasks"),
])

AGENTS_JSONL = REPO / "agents.jsonl"
TIME_EVENTS_JSONL = REPO / "state" / "time_events.jsonl"
USAGE_JSONL = REPO / "state" / "usage.jsonl"
USAGE_REPORT_MD = REPO / "state" / "USAGE_REPORT.md"
BTW_INDEX_MD = REPO / "state" / "BTW_INDEX.md"
DECISIONS_MD = REPO / "research" / "DECISIONS.md"

OUT_EVENTS = REPO / "ai" / "transcripts" / "normalized" / "events.jsonl"
OUT_HTML = REPO / "reports" / "claude-transcript.html"
OUT_DATA = REPO / "reports" / "claude-transcript-data.json"
OUT_README = REPO / "reports" / "TRANSCRIPT_README.md"

BLOB_INLINE_MAX = 6000  # chars; larger text bodies are offloaded to the sidecar JSON

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

REDACT_PATTERN = re.compile(r"sk-ant-[A-Za-z0-9_-]{8,}")
_redaction_count = [0]


def redact_text(s):
    if not isinstance(s, str):
        return s

    def _sub(m):
        _redaction_count[0] += 1
        return "[REDACTED-API-KEY]"

    return REDACT_PATTERN.sub(_sub, s)


def redact_deep(o):
    if isinstance(o, str):
        return redact_text(o)
    if isinstance(o, list):
        return [redact_deep(x) for x in o]
    if isinstance(o, dict):
        return {k: redact_deep(v) for k, v in o.items()}
    return o


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Generic JSONL loading
# ---------------------------------------------------------------------------

def load_jsonl(path):
    records = []
    if not path.exists():
        return records
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            line = line.rstrip("\n\r")
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                obj["_line_no"] = i
            records.append(obj)
    return records


def load_main_and_fork():
    main_recs = load_jsonl(MAIN_SESSION_PATH)
    fork_recs = load_jsonl(FORK_SESSION_PATH)
    seen = set()
    combined = []
    for rec in main_recs:
        u = rec.get("uuid") if isinstance(rec, dict) else None
        if u:
            seen.add(u)
        if isinstance(rec, dict):
            rec["_origin_session"] = MAIN_SESSION_ID
        combined.append(rec)
    skipped_dupes = 0
    for rec in fork_recs:
        u = rec.get("uuid") if isinstance(rec, dict) else None
        if u and u in seen:
            skipped_dupes += 1
            continue
        if u:
            seen.add(u)
        if isinstance(rec, dict):
            rec["_origin_session"] = FORK_SESSION_ID
        combined.append(rec)
    return combined, len(main_recs), len(fork_recs), skipped_dupes


# ---------------------------------------------------------------------------
# Content-block helpers
# ---------------------------------------------------------------------------

def content_blocks(message):
    if not isinstance(message, dict):
        return []
    content = message.get("content")
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [b for b in content if isinstance(b, dict)]
    return []


TASK_NOTIFICATION_RE = re.compile(
    r"<task-notification>\s*"
    r"<task-id>(?P<task_id>.*?)</task-id>\s*"
    r"(?:<tool-use-id>(?P<tool_use_id>.*?)</tool-use-id>\s*)?"
    r"<output-file>(?P<output_file>.*?)</output-file>\s*"
    r"<status>(?P<status>.*?)</status>\s*"
    r"<summary>(?P<summary>.*?)</summary>\s*"
    r"(?:<note>.*?</note>\s*)?"
    r"(?:<result>(?P<result>.*?)</result>)?",
    re.DOTALL,
)
SUMMARY_DESC_RE = re.compile(r'Agent\s+"(?P<desc>.*?)"\s+\S+', re.DOTALL)

# Renderer alias table: Agent tool_use `description` -> agents.jsonl agent_id.
# Built by hand from the actual descriptions found in the two session files
# and cross-checked against agents.jsonl roles/artifacts (see TRANSCRIPT_README
# for the verification note). Anything not in this table falls back to
# "UNATTRIBUTED:<harness task id>" rather than being guessed.
DESCRIPTION_ALIAS = {
    "Bootstrap enchanter workbench tools": "workbench-bootstrap-enchanter",
    "Bootstrap research-stack tools": "workbench-bootstrap-research-stack",
    "Build Tiny Custom Investigator": "tci-builder",
    "Index task contract to JSON": "contract-indexer",
    "Seed TOOL_USAGE ledger": "tool-ledger-seeder",
    "Wixie lifecycle for R1 prompt": "wixie-prompt-engineer-R1",
    "Wixie lifecycle for R2 prompt": "wixie-prompt-engineer-R2",
    "Wixie lifecycle for R3 prompt": "wixie-prompt-engineer-R3",
    "Wixie lifecycle for R4 prompt": "wixie-prompt-engineer-R4",
    "Wixie lifecycle for R5 prompt": "wixie-prompt-engineer-R5",
    "Measure AI usage with Pech": "usage-measurer",
    "Fix Lich WSL bridge, assess Go witness": "lich-fixer",
    "R1 build-vs-buy research worker": "r1-build-vs-buy",
    "R2 Lava context research worker": "r2-lava-context",
    "R3 sensor epistemology research worker": "r3-sensor-evidence",
    "R4 host-specific research worker": "r4-host-investigation",
    "R5 Go architecture research worker": "r5-go-architecture",
    "Wixie lifecycle for Grill-Me prompt": "wixie-prompt-engineer-GRILL",
    "Synthesize R1-R5 into research KB": "research-synthesizer",
    "Grill-Me architecture challenger": "architecture-challenger",
    "Draft concrete check registry": "check-registry-drafter",
    "Ponytail pass 1 on architecture options": "ponytail-reviewer-pass1",
    "Wixie lifecycle for implementation prompt": "wixie-prompt-engineer-IMPL",
    "Implementation author: vertical slice first": "implementation-author",
    "Test lab author: profiles and fault injection": "test-lab-author",
    "Crawl4AI gap-fill: Micron datasheet, Latitude docs": "gap-filler-crawl4ai",
    "Ponytail pass 2 on implementation": "ponytail-reviewer-pass2",
    "Lich runtime witness on sensor": "lich-witness-runner",
    "Fresh Fable independent code review": "code-reviewer",
    "Build transcript HTML viewer": "transcript-html-author",
}


# ---------------------------------------------------------------------------
# Main pass over the deduped main+fork transcript
# ---------------------------------------------------------------------------

class Emitter:
    def __init__(self):
        self.events = []
        self.seq = 0

    def emit(self, **kw):
        self.seq += 1
        kw["seq"] = self.seq
        kw.setdefault("agent_id", None)
        kw.setdefault("role", None)
        kw.setdefault("parent", None)
        kw.setdefault("model", None)
        kw.setdefault("text", None)
        kw.setdefault("refs", {})
        kw.setdefault("synthesized", False)
        kw.setdefault("synthesized_note", None)
        self.events.append(kw)


def process_main_fork(combined, em):
    agent_calls = {}  # tool_use_id -> dict
    pending_by_desc = defaultdict(list)  # (session, description) -> [tool_use_id,...]
    invocations = OrderedDict()  # task_id -> dict

    for rec in combined:
        if not isinstance(rec, dict):
            continue
        ts = rec.get("timestamp")
        session = rec.get("_origin_session")
        typ = rec.get("type")
        is_meta = bool(rec.get("isMeta"))

        if typ == "assistant":
            msg = rec.get("message", {})
            model = msg.get("model", "UNVERIFIED")
            blocks = content_blocks(msg)
            text_parts = []
            for b in blocks:
                bt = b.get("type")
                if bt == "text":
                    txt = redact_text(b.get("text", ""))
                    if txt:
                        text_parts.append({"kind": "text", "text": txt})
                elif bt == "thinking":
                    th = redact_text(b.get("thinking", ""))
                    if th:
                        text_parts.append({"kind": "thinking", "text": th})
                elif bt == "tool_use":
                    tool_id = b.get("id")
                    tool_name = b.get("name")
                    tool_input = redact_deep(b.get("input", {}))
                    if tool_name == "Agent":
                        desc = tool_input.get("description")
                        entry = {
                            "tool_use_id": tool_id,
                            "description": desc,
                            "subagent_type": tool_input.get("subagent_type"),
                            "requested_model": tool_input.get("model"),
                            "prompt": tool_input.get("prompt", ""),
                            "session": session,
                            "ts": ts,
                        }
                        agent_calls[tool_id] = entry
                        pending_by_desc[(session, desc)].append(tool_id)
                    em.emit(ts=ts, session=session, kind="TOOL_CALL", role="main-agent",
                            model=model, text=tool_name,
                            refs={"tool_use_id": tool_id, "tool_name": tool_name, "input": tool_input})
            if text_parts:
                em.emit(ts=ts, session=session, kind="MAIN_AGENT", role="main-agent",
                         model=model, refs={"blocks": text_parts})

        elif typ == "user":
            msg = rec.get("message", {})
            blocks = content_blocks(msg)
            tool_result_blocks = [b for b in blocks if b.get("type") == "tool_result"]
            other_blocks = [b for b in blocks if b.get("type") != "tool_result"]
            for b in tool_result_blocks:
                content = b.get("content")
                if isinstance(content, str):
                    text = content
                else:
                    text = json.dumps(redact_deep(content), ensure_ascii=False)
                em.emit(ts=ts, session=session, kind="TOOL_RESULT", role="tool-system",
                        text=redact_text(text),
                        refs={"tool_use_id": b.get("tool_use_id"), "is_error": bool(b.get("is_error", False))})
            if other_blocks:
                texts = []
                for b in other_blocks:
                    if b.get("type") == "text":
                        texts.append(redact_text(b.get("text", "")))
                joined = "\n".join(t for t in texts if t and t.strip())
                if joined.strip() and "<local-command-caveat>" not in joined:
                    kind = "SYSTEM" if is_meta else "USER"
                    em.emit(ts=ts, session=session, kind=kind,
                            role="meta-caveat" if is_meta else "user",
                            text=joined, refs={"isMeta": is_meta})

        elif typ == "system":
            content = rec.get("content", "")
            text = content if isinstance(content, str) else json.dumps(content, ensure_ascii=False)
            em.emit(ts=ts, session=session, kind="SYSTEM", role="system",
                    text=redact_text(text), refs={"subtype": rec.get("subtype")})

        elif typ == "attachment":
            att = rec.get("attachment", {})
            if not isinstance(att, dict):
                continue
            atype = att.get("type")
            if atype == "queued_command":
                prompt = att.get("prompt", "") or ""
                m = TASK_NOTIFICATION_RE.search(prompt)
                if m:
                    task_id = m.group("task_id").strip()
                    tool_use_id = (m.group("tool_use_id") or "").strip() or None
                    output_file = m.group("output_file").strip()
                    status = m.group("status").strip()
                    summary = m.group("summary").strip()
                    result = (m.group("result") or "").strip()
                    call = None
                    if tool_use_id and tool_use_id in agent_calls:
                        call = agent_calls[tool_use_id]
                    else:
                        sm = SUMMARY_DESC_RE.search(summary)
                        desc = sm.group("desc") if sm else None
                        if desc is not None:
                            for key in ((session, desc), (MAIN_SESSION_ID, desc), (FORK_SESSION_ID, desc)):
                                q = pending_by_desc.get(key)
                                if q:
                                    call = agent_calls.get(q.pop(0))
                                    break
                    if task_id not in invocations:
                        invocations[task_id] = {
                            "task_id": task_id,
                            "description": call.get("description") if call else None,
                            "subagent_type": call.get("subagent_type") if call else None,
                            "requested_model": call.get("requested_model") if call else None,
                            "prompt": call.get("prompt") if call else None,
                            "tool_use_id": call.get("tool_use_id") if call else tool_use_id,
                            "call_session": call.get("session") if call else session,
                            "call_ts": call.get("ts") if call else None,
                            "output_file": output_file,
                            "notifications": [],
                        }
                        if call:
                            em.emit(ts=call.get("ts"), session=call.get("session"),
                                    kind="SUBAGENT_PROMPT", agent_id=task_id, role=call.get("description"),
                                    parent="main", model=call.get("requested_model"),
                                    text=redact_text(call.get("prompt", "") or ""),
                                    refs={"subagent_type": call.get("subagent_type"),
                                          "tool_use_id": call.get("tool_use_id")})
                    invocations[task_id]["notifications"].append({
                        "ts": ts, "status": status, "summary": redact_text(summary),
                        "result": redact_text(result),
                    })
                else:
                    em.emit(ts=ts, session=session, kind="USER_MIDTURN", role="user (mid-turn /btw)",
                            text=redact_text(prompt),
                            refs={}, synthesized=True,
                            synthesized_note="Classified by the renderer as a genuine mid-turn user message "
                                             "because this queued_command attachment is NOT a <task-notification> "
                                             "wrapper (see state/BTW_INDEX.md).")
            elif atype == "hook_success":
                hook_name = att.get("hookName")
                em.emit(ts=ts, session=session, kind="SYSTEM", role="hook",
                        text=redact_text(f"hook {hook_name} exit={att.get('exitCode')}"),
                        refs={"attachment_type": atype, "full": redact_deep(att)})
            # other attachment subtypes (file-history, etc.) are not conversation
            # content and are intentionally not rendered as events.

    return invocations


# ---------------------------------------------------------------------------
# agents.jsonl ledger
# ---------------------------------------------------------------------------

def build_agent_ledger():
    lines = load_jsonl(AGENTS_JSONL)
    starts = OrderedDict()
    lifecycle = defaultdict(list)
    harness_id_map = {}
    global_events = []
    for rec in lines:
        if not isinstance(rec, dict):
            continue
        ev = rec.get("event")
        aid = rec.get("agent_id")
        if ev == "harness_id_map":
            harness_id_map.update(rec.get("map", {}))
            continue
        if aid is None:
            global_events.append(rec)
            continue
        if ev is None and "start" in rec:
            starts[aid] = rec
        else:
            lifecycle[aid].append(rec)
    return starts, lifecycle, harness_id_map, global_events


def resolve_friendly_id(task_id, inv, harness_id_map):
    for friendly, harness in harness_id_map.items():
        if harness == task_id:
            return friendly, True, "resolved via agents.jsonl harness_id_map event"
    desc = inv.get("description")
    if desc and desc in DESCRIPTION_ALIAS:
        return (DESCRIPTION_ALIAS[desc], True,
                "resolved via renderer's description->agent_id alias table "
                "(hand-verified against agents.jsonl roles and prompt content)")
    return f"UNATTRIBUTED:{task_id}", True, "no mapping found; labeled by harness task id (consistent with USAGE_REPORT.md convention)"


# ---------------------------------------------------------------------------
# Sub-agent task-output files
# ---------------------------------------------------------------------------

TRANSCRIPT_TYPES = {"user", "assistant", "system"}


def find_task_output(task_id):
    for _, d in TASKS_DIRS.items():
        p = d / f"{task_id}.output"
        if p.exists():
            return p
    return None


def scan_task_output(path):
    total_lines = 0
    json_ok = 0
    transcript_records = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            json_ok += 1
            if isinstance(obj, dict) and obj.get("type") in TRANSCRIPT_TYPES and isinstance(obj.get("message"), dict):
                transcript_records.append(obj)
    return total_lines, json_ok, transcript_records


def emit_subagent_transcript(em, friendly_id, parent_id, records):
    for rec in records:
        typ = rec.get("type")
        msg = rec.get("message", {})
        if typ == "assistant":
            model = msg.get("model", "UNVERIFIED")
            blocks = content_blocks(msg)
            text_parts = []
            for b in blocks:
                bt = b.get("type")
                if bt == "text":
                    txt = redact_text(b.get("text", ""))
                    if txt:
                        text_parts.append({"kind": "text", "text": txt})
                elif bt == "thinking":
                    th = redact_text(b.get("thinking", ""))
                    if th:
                        text_parts.append({"kind": "thinking", "text": th})
                elif bt == "tool_use":
                    tool_input = redact_deep(b.get("input", {}))
                    em.emit(ts=rec.get("timestamp"), session=f"agent:{friendly_id}", kind="TOOL_CALL",
                            agent_id=friendly_id, role=friendly_id, parent=parent_id, model=model,
                            text=b.get("name"),
                            refs={"tool_use_id": b.get("id"), "tool_name": b.get("name"), "input": tool_input})
            if text_parts:
                em.emit(ts=rec.get("timestamp"), session=f"agent:{friendly_id}", kind="SUBAGENT_REPLY",
                        agent_id=friendly_id, role=friendly_id, parent=parent_id, model=model,
                        refs={"blocks": text_parts})
        elif typ == "user":
            blocks = content_blocks(msg)
            for b in blocks:
                if b.get("type") == "tool_result":
                    content = b.get("content")
                    text = content if isinstance(content, str) else json.dumps(redact_deep(content), ensure_ascii=False)
                    em.emit(ts=rec.get("timestamp"), session=f"agent:{friendly_id}", kind="TOOL_RESULT",
                            agent_id=friendly_id, role=friendly_id, parent=parent_id,
                            text=redact_text(text),
                            refs={"tool_use_id": b.get("tool_use_id"), "is_error": bool(b.get("is_error", False))})
            # plain user-role text inside a sub-agent transcript is either the
            # replayed initial prompt (already captured verbatim as
            # SUBAGENT_PROMPT from the parent's Agent tool_use) or an injected
            # system-reminder; not re-rendered here (see README "known gaps").
        # 'system' records inside sub-agent transcripts: rare, not rendered.


def process_invocations(invocations, starts, harness_id_map, em):
    """Resolve each Agent-tool invocation to a friendly agent_id, then emit its
    reply content either from a parseable task-output file or, failing that,
    from the queued_command <result> text."""
    artifact_events = []
    for task_id, inv in invocations.items():
        friendly_id, synth, note = resolve_friendly_id(task_id, inv, harness_id_map)
        start_rec = starts.get(friendly_id, {})
        parent_id = start_rec.get("parent_id", "main")
        path = find_task_output(task_id)
        used_file = False
        if path is not None:
            total_lines, json_ok, records = scan_task_output(path)
            if records:
                emit_subagent_transcript(em, friendly_id, parent_id, records)
                used_file = True
            em.emit(ts=inv.get("call_ts"), session=f"agent:{friendly_id}", kind="ARTIFACT",
                    agent_id=friendly_id, role=friendly_id, parent=parent_id,
                    text=str(path),
                    refs={"kind": "task-output-file", "bytes": path.stat().st_size,
                          "total_lines": total_lines, "json_ok_lines": json_ok,
                          "transcript_records": len(records), "opaque": not records},
                    synthesized=synth, synthesized_note=note)
        if not used_file and inv.get("notifications"):
            last = inv["notifications"][-1]
            if last.get("result"):
                em.emit(ts=last.get("ts"), session=f"agent:{friendly_id}", kind="SUBAGENT_REPLY",
                        agent_id=friendly_id, role=friendly_id, parent=parent_id,
                        text=last.get("result"),
                        refs={"source": "queued_command <result> (no parseable task-output transcript file)"},
                        synthesized=synth, synthesized_note=note)


# ---------------------------------------------------------------------------
# state/time_events.jsonl -> PHASE / APPROVAL / DECISION / SYSTEM
# ---------------------------------------------------------------------------

def process_time_events(em):
    for rec in load_jsonl(TIME_EVENTS_JSONL):
        if not isinstance(rec, dict):
            continue
        ev = rec.get("event")
        ts = rec.get("ts")
        if ev in ("START", "PHASE", "PHASE_END", "MILESTONE"):
            label = rec.get("phase") or rec.get("milestone") or ev
            text = rec.get("note") or ""
            em.emit(ts=ts, session="ledger", kind="PHASE", role=ev,
                    text=f"{ev}: {label}" + (f" -- {text}" if text else ""),
                    refs={k: v for k, v in rec.items() if k not in ("event", "ts")})
        elif ev == "APPROVAL":
            em.emit(ts=ts, session="ledger", kind="APPROVAL", role="APPROVAL",
                    text=f"{rec.get('item')}: {rec.get('decision')}",
                    refs={k: v for k, v in rec.items() if k not in ("event", "ts")})
        elif ev == "DECISION":
            em.emit(ts=ts, session="ledger", kind="DECISION", role="DECISION",
                    text="; ".join(rec.get("ids", [])),
                    refs={"file": rec.get("file")})
        else:
            em.emit(ts=ts, session="ledger", kind="SYSTEM", role=ev or "time_event",
                    text=json.dumps({k: v for k, v in rec.items() if k != "_line_no"}, ensure_ascii=False),
                    refs={})


LD_ROW_RE = re.compile(r"^\|\s*(LD-\d+)\s*\|(.*)\|\s*$")


def process_decisions_md(em):
    if not DECISIONS_MD.exists():
        return
    text = DECISIONS_MD.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = LD_ROW_RE.match(line.strip())
        if m:
            ld_id = m.group(1)
            em.emit(ts=None, session="research", kind="DECISION", role="research/DECISIONS.md",
                    text=redact_text(line.strip()),
                    refs={"ld_id": ld_id, "file": "research/DECISIONS.md"},
                    synthesized=True,
                    synthesized_note="Row extracted from research/DECISIONS.md's LEAD DECISIONS table by a "
                                      "fixed-pattern line match (`^\\| LD-\\d+ \\|...`), not a raw captured event.")


# ---------------------------------------------------------------------------
# ARTIFACT events from agents.jsonl "artifacts" arrays
# ---------------------------------------------------------------------------

def process_ledger_artifacts(starts, em):
    seen = set()
    for aid, rec in starts.items():
        for path in rec.get("artifacts", []) or []:
            key = (aid, path)
            if key in seen:
                continue
            seen.add(key)
            em.emit(ts=rec.get("start"), session="ledger", kind="ARTIFACT", agent_id=aid, role=aid,
                    parent=rec.get("parent_id"), text=path,
                    refs={"kind": "declared-artifact", "source": "agents.jsonl"},
                    synthesized=True, synthesized_note="Path taken verbatim from agents.jsonl's artifacts[] field.")


# ---------------------------------------------------------------------------
# Sorting
# ---------------------------------------------------------------------------

def sort_key(ev):
    ts = ev.get("ts") or ""
    return (ts, ev.get("session") or "", ev.get("seq", 0))


# ---------------------------------------------------------------------------
# Blob extraction (keeps the main HTML small; big text goes to the sidecar)
# ---------------------------------------------------------------------------

def extract_blobs(events):
    blobs = OrderedDict()
    counter = [0]

    def maybe_offload(text):
        if not isinstance(text, str) or len(text) <= BLOB_INLINE_MAX:
            return text, None
        counter[0] += 1
        blob_id = f"blob-{counter[0]:05d}"
        blobs[blob_id] = text
        return None, {"_blob_ref": blob_id, "preview": text[:1500], "bytes": len(text.encode("utf-8"))}

    for ev in events:
        t = ev.get("text")
        if isinstance(t, str) and len(t) > BLOB_INLINE_MAX:
            _, ph = maybe_offload(t)
            ev["text"] = None
            ev["text_blob"] = ph
        refs = ev.get("refs")
        if isinstance(refs, dict):
            blocks = refs.get("blocks")
            if isinstance(blocks, list):
                for b in blocks:
                    if isinstance(b, dict) and isinstance(b.get("text"), str) and len(b["text"]) > BLOB_INLINE_MAX:
                        _, ph = maybe_offload(b["text"])
                        b["text"] = None
                        b["text_blob"] = ph
            # large tool_result/tool input dumped as JSON string inside refs.input
            inp = refs.get("input")
            if isinstance(inp, dict):
                dumped = json.dumps(inp, ensure_ascii=False)
                if len(dumped) > BLOB_INLINE_MAX:
                    _, ph = maybe_offload(dumped)
                    refs["input"] = None
                    refs["input_blob"] = ph
    return blobs


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>Lava Sensor Exercise -- Claude Transcript</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@500&display=swap">
<style>
:root {
  --bg:#F9FAFB; --surface:#FFFFFF; --muted:#F5F6F8; --text:#2F3438; --text-2:#6B7280; --text-3:#9CA3AF;
  --line:#E5E7EB; --brand:#FF5C00; --brand-tint:rgba(255,92,0,0.07);
  --chip-risk-t:#C23E49; --chip-risk-b:rgba(194,62,73,0.20);
  --chip-info-t:#3C7FE7; --chip-info-b:rgba(60,127,231,0.20);
  --chip-pos-t:#3C9567;  --chip-pos-b:rgba(60,149,103,0.20);
  --chip-gray-t:#646464; --chip-gray-b:rgba(100,100,100,0.20);
  --sans:"Inter",-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
  --mono:"JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --measure: 1180px;
}
* { box-sizing: border-box; }
html { color-scheme: light; }
body { margin:0; background:var(--bg); color:var(--text); font-family:var(--sans); font-size:14px; line-height:1.55; -webkit-font-smoothing:antialiased; }
.chrome { background:var(--surface); padding:0 32px; display:flex; align-items:center; justify-content:space-between; gap:16px; min-height:60px; border-bottom:1px solid var(--line); position:sticky; top:0; z-index:20; }
.wordmark { font-family:var(--mono); font-size:15px; color:var(--text); }
.meta { font-family:var(--mono); font-size:12px; color:var(--text-3); }
main { max-width: var(--measure); margin:0 auto; padding:24px 32px 64px; }
.eyebrow { font-family:var(--mono); font-size:12px; color:var(--brand); margin:0 0 4px; }
h1 { font-size:28px; font-weight:600; letter-spacing:-0.01em; margin:0 0 6px; }
.lead { font-size:14px; color:var(--text-2); max-width:78ch; margin:0 0 18px; }
.tabs { display:flex; gap:4px; border-bottom:1px solid var(--line); margin-bottom:18px; flex-wrap:wrap; }
.tab-btn { font-family:var(--mono); font-size:12.5px; color:var(--text-2); background:none; border:none; padding:10px 14px; cursor:pointer; border-bottom:2px solid transparent; }
.tab-btn.active { color:var(--brand); border-bottom-color:var(--brand); }
.tab-btn:hover { color:var(--text); }
.view { display:none; }
.view.active { display:block; }
.toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:14px; align-items:center; }
.toolbar select, .toolbar input[type=search] { font-family:var(--mono); font-size:12px; padding:6px 8px; border:1px solid var(--line); border-radius:6px; background:var(--surface); color:var(--text); }
.toolbar input[type=search] { flex:1; min-width:180px; }
.count-pill { font-family:var(--mono); font-size:11.5px; color:var(--text-3); }
.chip { display:inline-block; border-radius:4px; padding:1px 7px; font-family:var(--mono); font-size:11px; line-height:1.5; white-space:nowrap; }
.chip--value{ color:var(--brand); background:var(--brand-tint); }
.chip--risk { color:var(--chip-risk-t); background:var(--chip-risk-b); }
.chip--info { color:var(--chip-info-t); background:var(--chip-info-b); }
.chip--pos  { color:var(--chip-pos-t);  background:var(--chip-pos-b); }
.chip--gray { color:var(--chip-gray-t); background:var(--chip-gray-b); }
.chip--meta { color:#8B5CF6; background:rgba(139,92,246,0.12); }
code { font-family:var(--mono); font-size:11.5px; color:var(--brand); background:var(--brand-tint); border-radius:4px; padding:1px 5px; }
.ev { background:var(--surface); border:1px solid var(--line); border-left:4px solid var(--text-3); border-radius:8px; padding:10px 14px; margin-bottom:8px; }
.ev[data-kind="USER"], .ev[data-kind="USER_MIDTURN"] { border-left-color:#3C7FE7; }
.ev[data-kind="MAIN_AGENT"] { border-left-color:var(--brand); }
.ev[data-kind="SUBAGENT_PROMPT"], .ev[data-kind="SUBAGENT_REPLY"] { border-left-color:#9556CE; }
.ev[data-kind="TOOL_CALL"], .ev[data-kind="TOOL_RESULT"] { border-left-color:var(--text-3); }
.ev[data-kind="SYSTEM"] { border-left-color:#B8BCC2; }
.ev[data-kind="DECISION"] { border-left-color:#3C9567; }
.ev[data-kind="APPROVAL"] { border-left-color:#3C9567; }
.ev[data-kind="ARTIFACT"] { border-left-color:#C29B3C; }
.ev[data-kind="PHASE"] { border-left-color:#646464; }
.ev-head { display:flex; align-items:center; gap:8px; flex-wrap:wrap; font-family:var(--mono); font-size:11px; color:var(--text-3); margin-bottom:6px; }
.ev-ts { white-space:nowrap; font-variant-numeric:tabular-nums; }
.ev-body { font-size:13px; white-space:pre-wrap; word-break:break-word; }
.ev-body.thinking { color:var(--text-2); font-style:italic; }
.ev-preview { cursor:pointer; }
.ev-full { display:none; margin-top:6px; border-top:1px dashed var(--line); padding-top:6px; }
.ev-full.open { display:block; }
.expand-btn { font-family:var(--mono); font-size:11px; color:var(--brand); background:none; border:none; cursor:pointer; padding:2px 0; }
.block + .block { margin-top:8px; }
.section-title { font-family:var(--mono); font-size:11px; color:var(--text-3); margin:20px 0 8px; text-transform:uppercase; letter-spacing:.04em; }
.tree { display:flex; flex-direction:column; gap:4px; }
.tree-node { background:var(--surface); border:1px solid var(--line); border-radius:8px; padding:9px 13px; }
.tree-node .row1 { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
.tree-node .agent-id { font-family:var(--mono); font-size:12.5px; font-weight:600; }
.tree-node .role { font-size:12.5px; color:var(--text-2); }
.tree-children { margin-left:22px; border-left:1px solid var(--line); padding-left:12px; margin-top:4px; display:flex; flex-direction:column; gap:4px; }
.tablewrap { overflow-x:auto; border:1px solid var(--line); border-radius:8px; background:var(--surface); margin-bottom:14px; }
table { border-collapse:collapse; width:100%; font-size:12.5px; }
th, td { text-align:left; padding:8px 12px; vertical-align:top; border-bottom:1px solid var(--line); }
tr:last-child td { border-bottom:0; }
th { font-size:10.5px; font-family:var(--mono); font-weight:500; color:var(--text-3); background:var(--muted); white-space:nowrap; }
td.mono { font-family:var(--mono); font-size:12px; white-space:nowrap; }
pre.raw { margin:0; background:var(--muted); border:1px solid var(--line); border-radius:8px; padding:14px 16px; overflow-x:auto; font-family:var(--mono); font-size:11.5px; line-height:1.55; max-height:520px; overflow-y:auto; white-space:pre-wrap; }
footer.foot { font-family:var(--mono); font-size:11px; color:var(--text-3); border-top:1px solid var(--line); margin-top:32px; padding-top:14px; }
a { color: var(--brand); }
:focus-visible { outline:2px solid var(--brand); outline-offset:2px; border-radius:3px; }
.hidden { display:none !important; }
</style>
</head>
<body>
<header class="chrome">
  <span class="wordmark">LAVA</span>
  <span class="meta">Engineering exercise / Claude transcript viewer (rendered, not the source of truth)</span>
</header>
<main>
  <p class="eyebrow">Reviewer artifact</p>
  <h1>Claude session transcript</h1>
  <p class="lead">This is a deterministically rendered presentation layer over the native exported Claude Code
    session files, sub-agent task transcripts, and the project's own run ledgers. The native session JSONL
    exports remain the source-of-truth deliverable and were not modified to build this page. Anything labeled
    <span class="chip chip--meta">metadata</span> below was inferred or restructured by the renderer
    (<code>tooling/transcript/render.py</code>) rather than captured verbatim.</p>

  <div class="tabs" id="tabs"></div>
  <div id="views"></div>

  <footer class="foot" id="footer"></footer>
</main>
<script id="events-json" type="application/json">__EVENTS_JSON__</script>
<script id="blobs-json" type="application/json">__BLOBS_INLINE_JSON__</script>
<script id="agents-json" type="application/json">__AGENTS_JSON__</script>
<script id="usage-json" type="application/json">__USAGE_JSON__</script>
<script id="meta-json" type="application/json">__META_JSON__</script>
<script>
(function(){
"use strict";
var EVENTS = JSON.parse(document.getElementById('events-json').textContent);
var BLOBS = JSON.parse(document.getElementById('blobs-json').textContent);
var AGENTS = JSON.parse(document.getElementById('agents-json').textContent);
var USAGE = JSON.parse(document.getElementById('usage-json').textContent);
var META = JSON.parse(document.getElementById('meta-json').textContent);
var remoteBlobCache = null;

function esc(s){ return (s==null?'':String(s)); }

function fetchRemoteBlob(id, cb){
  if (remoteBlobCache){ cb(remoteBlobCache[id]); return; }
  fetch('claude-transcript-data.json').then(function(r){return r.json();}).then(function(j){
    remoteBlobCache = j; cb(j[id]);
  }).catch(function(e){ cb('[could not lazy-load claude-transcript-data.json: ' + e + ' -- if you opened this file directly (file://), try a local static server or Firefox; see reports/TRANSCRIPT_README.md]'); });
}

function resolveBlobRef(ref, cb){
  if (!ref) { cb(''); return; }
  if (Object.prototype.hasOwnProperty.call(BLOBS, ref._blob_ref)) { cb(BLOBS[ref._blob_ref]); return; }
  fetchRemoteBlob(ref._blob_ref, cb);
}

function chipForKind(kind){
  var map = {USER:'info', USER_MIDTURN:'info', MAIN_AGENT:'value', SUBAGENT_PROMPT:'pos', SUBAGENT_REPLY:'pos',
             TOOL_CALL:'gray', TOOL_RESULT:'gray', SYSTEM:'gray', DECISION:'pos', APPROVAL:'pos', ARTIFACT:'value', PHASE:'gray'};
  return map[kind] || 'gray';
}

function makeExpandable(container, fullText, previewText){
  var pre = document.createElement('div');
  pre.className = 'ev-body ev-preview';
  pre.textContent = previewText;
  var btn = document.createElement('button');
  btn.className = 'expand-btn';
  btn.textContent = 'expand full text ▾';
  var full = document.createElement('div');
  full.className = 'ev-full';
  var opened = false;
  function toggle(){
    if (!opened){
      opened = true;
      if (typeof fullText === 'function'){
        full.textContent = 'loading…';
        fullText(function(t){ full.textContent = t; });
      } else {
        full.textContent = fullText;
      }
    }
    full.classList.toggle('open');
    btn.textContent = full.classList.contains('open') ? 'collapse ▴' : 'expand full text ▾';
  }
  btn.addEventListener('click', toggle);
  pre.addEventListener('click', toggle);
  container.appendChild(pre);
  container.appendChild(btn);
  container.appendChild(full);
}

function renderTextField(container, ev, textKey, blobKey){
  var t = ev[textKey];
  var blobRef = ev[blobKey];
  if (t != null){
    var div = document.createElement('div');
    div.className = 'ev-body';
    div.textContent = t;
    container.appendChild(div);
    return;
  }
  if (blobRef){
    makeExpandable(container, function(cb){ resolveBlobRef(blobRef, cb); }, blobRef.preview + '… [' + blobRef.bytes + ' bytes total, click to load full text]');
  }
}

function renderBlocks(container, blocks){
  blocks.forEach(function(b){
    var wrap = document.createElement('div');
    wrap.className = 'block';
    if (b.text != null){
      var div = document.createElement('div');
      div.className = 'ev-body' + (b.kind==='thinking' ? ' thinking' : '');
      div.textContent = (b.kind==='thinking' ? '[thinking] ' : '') + b.text;
      wrap.appendChild(div);
    } else if (b.text_blob){
      var label = (b.kind==='thinking' ? '[thinking, collapsed] ' : '');
      makeExpandable(wrap, function(cb){ resolveBlobRef(b.text_blob, cb); }, label + b.text_blob.preview + '… [' + b.text_blob.bytes + ' bytes total]');
    }
    container.appendChild(wrap);
  });
}

function fmtTs(ts){ return ts ? ts.replace('T',' ').replace('Z',' UTC') : '(no timestamp)'; }

function renderEvent(ev){
  var d = document.createElement('div');
  d.className = 'ev';
  d.setAttribute('data-kind', ev.kind);
  d.setAttribute('data-agent', ev.agent_id || '');
  var head = document.createElement('div');
  head.className = 'ev-head';
  var kindChip = document.createElement('span');
  kindChip.className = 'chip chip--' + chipForKind(ev.kind);
  kindChip.textContent = ev.kind;
  head.appendChild(kindChip);
  var ts = document.createElement('span'); ts.className='ev-ts'; ts.textContent = fmtTs(ev.ts);
  head.appendChild(ts);
  if (ev.role){ var r = document.createElement('span'); r.textContent = ev.role; head.appendChild(r); }
  if (ev.agent_id){ var a = document.createElement('span'); a.className='chip chip--gray'; a.textContent = 'agent: '+ev.agent_id; head.appendChild(a); }
  if (ev.model){ var mo = document.createElement('span'); mo.className='chip chip--gray'; mo.textContent = 'model: '+ev.model; head.appendChild(mo); }
  if (ev.synthesized){ var s = document.createElement('span'); s.className='chip chip--meta'; s.textContent='metadata'; s.title = ev.synthesized_note||''; head.appendChild(s); }
  d.appendChild(head);

  if (ev.refs && ev.refs.blocks){
    renderBlocks(d, ev.refs.blocks);
  } else {
    renderTextField(d, ev, 'text', 'text_blob');
  }
  if (ev.refs && (ev.refs.tool_name || ev.refs.input || ev.refs.input_blob)){
    var ti = document.createElement('div'); ti.className='ev-body';
    if (ev.refs.input){
      ti.textContent = JSON.stringify(ev.refs.input, null, 2);
    } else if (ev.refs.input_blob){
      makeExpandable(d, function(cb){ resolveBlobRef(ev.refs.input_blob, cb); }, '(input) ' + ev.refs.input_blob.preview + '…');
    }
    if (ev.refs.input) d.appendChild(ti);
  }
  if (ev.refs && ev.refs.is_error){
    var err = document.createElement('span'); err.className='chip chip--risk'; err.textContent='tool error'; d.appendChild(err);
  }
  return d;
}

// ---- Tabs ----
var TABS = [
  {id:'timeline', label:'Timeline'},
  {id:'conversations', label:'Conversations'},
  {id:'agents', label:'Agents'},
  {id:'decisions', label:'Decisions'},
  {id:'artifacts', label:'Artifacts'},
  {id:'usage', label:'Usage & Timing'}
];
var tabsEl = document.getElementById('tabs');
var viewsEl = document.getElementById('views');
TABS.forEach(function(t, i){
  var btn = document.createElement('button');
  btn.className = 'tab-btn' + (i===0?' active':'');
  btn.textContent = t.label;
  btn.addEventListener('click', function(){
    document.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
    document.querySelectorAll('.view').forEach(function(v){v.classList.remove('active');});
    btn.classList.add('active');
    document.getElementById('view-'+t.id).classList.add('active');
  });
  tabsEl.appendChild(btn);
  var view = document.createElement('div');
  view.className = 'view' + (i===0?' active':'');
  view.id = 'view-' + t.id;
  viewsEl.appendChild(view);
});

// ---- Timeline ----
(function(){
  var view = document.getElementById('view-timeline');
  var toolbar = document.createElement('div'); toolbar.className='toolbar';
  var kinds = Array.from(new Set(EVENTS.map(function(e){return e.kind;}))).sort();
  var kindSel = document.createElement('select'); kindSel.multiple = false;
  var optAll = document.createElement('option'); optAll.value=''; optAll.textContent='all kinds'; kindSel.appendChild(optAll);
  kinds.forEach(function(k){ var o=document.createElement('option'); o.value=k; o.textContent=k; kindSel.appendChild(o); });
  var agents = Array.from(new Set(EVENTS.map(function(e){return e.agent_id;}).filter(Boolean))).sort();
  var agentSel = document.createElement('select');
  var optAllA = document.createElement('option'); optAllA.value=''; optAllA.textContent='all agents'; agentSel.appendChild(optAllA);
  agents.forEach(function(a){ var o=document.createElement('option'); o.value=a; o.textContent=a; agentSel.appendChild(o); });
  var search = document.createElement('input'); search.type='search'; search.placeholder='search text…';
  var count = document.createElement('span'); count.className='count-pill';
  toolbar.appendChild(kindSel); toolbar.appendChild(agentSel); toolbar.appendChild(search); toolbar.appendChild(count);
  view.appendChild(toolbar);
  var list = document.createElement('div'); view.appendChild(list);

  function matches(ev, k, a, q){
    if (k && ev.kind !== k) return false;
    if (a && ev.agent_id !== a) return false;
    if (q){
      var hay = (ev.text||'') + ' ' + (ev.role||'') + JSON.stringify(ev.refs && ev.refs.blocks || '');
      if (hay.toLowerCase().indexOf(q.toLowerCase()) === -1) return false;
    }
    return true;
  }
  function redraw(){
    var k = kindSel.value, a = agentSel.value, q = search.value;
    list.innerHTML = '';
    var shown = 0;
    var frag = document.createDocumentFragment();
    for (var i=0;i<EVENTS.length;i++){
      if (matches(EVENTS[i], k, a, q)){ frag.appendChild(renderEvent(EVENTS[i])); shown++; }
    }
    list.appendChild(frag);
    count.textContent = shown + ' / ' + EVENTS.length + ' events';
  }
  kindSel.addEventListener('change', redraw);
  agentSel.addEventListener('change', redraw);
  search.addEventListener('input', redraw);
  redraw();
})();

// ---- Conversations ----
(function(){
  var view = document.getElementById('view-conversations');
  var groups = {};
  var order = [];
  EVENTS.forEach(function(ev){
    var key = ev.agent_id || 'main';
    if (!groups[key]){ groups[key]=[]; order.push(key); }
    if (['USER','USER_MIDTURN','MAIN_AGENT','TOOL_CALL','TOOL_RESULT','SUBAGENT_PROMPT','SUBAGENT_REPLY'].indexOf(ev.kind)>=0){
      groups[key].push(ev);
    }
  });
  order.sort(function(x,y){ return x==='main' ? -1 : (y==='main'?1:x.localeCompare(y)); });
  var nav = document.createElement('div'); nav.className='toolbar';
  var sel = document.createElement('select');
  order.forEach(function(k){ var o=document.createElement('option'); o.value=k; o.textContent = k + ' (' + groups[k].length + ' events)'; sel.appendChild(o); });
  nav.appendChild(sel);
  view.appendChild(nav);
  var body = document.createElement('div'); view.appendChild(body);
  function redraw(){
    body.innerHTML = '';
    var frag = document.createDocumentFragment();
    (groups[sel.value]||[]).forEach(function(ev){ frag.appendChild(renderEvent(ev)); });
    body.appendChild(frag);
  }
  sel.addEventListener('change', redraw);
  redraw();
})();

// ---- Agents tree ----
(function(){
  var view = document.getElementById('view-agents');
  var byId = {}; AGENTS.forEach(function(a){ byId[a.agent_id]=a; a._children=[]; });
  var roots = [];
  AGENTS.forEach(function(a){
    var p = a.parent_id;
    if (p && byId[p] && p!==a.agent_id){ byId[p]._children.push(a); } else { roots.push(a); }
  });
  function usageRowFor(id){
    return USAGE.rows.find(function(r){ return r.id===id || r.role===id; });
  }
  function nodeEl(a){
    var el = document.createElement('div'); el.className='tree-node';
    var row1 = document.createElement('div'); row1.className='row1';
    var aid = document.createElement('span'); aid.className='agent-id'; aid.textContent=a.agent_id; row1.appendChild(aid);
    var status = document.createElement('span'); status.className='chip chip--' + (a.status==='completed'?'pos':(a.status==='running'?'info':'gray')); status.textContent = a.status||'unknown'; row1.appendChild(status);
    var rm = document.createElement('span'); rm.className='chip chip--gray'; rm.textContent='requested: '+(a.requested_model||'?'); row1.appendChild(rm);
    var sm = document.createElement('span'); sm.className='chip chip--gray'; sm.textContent='served: '+(a.served_model||'UNVERIFIED'); row1.appendChild(sm);
    el.appendChild(row1);
    if (a.role){ var role=document.createElement('div'); role.className='role'; role.textContent=a.role; el.appendChild(role); }
    var times = document.createElement('div'); times.className='role'; times.textContent = 'start '+(a.start||'?')+'  →  end '+(a.end||'(not ended)');
    el.appendChild(times);
    if (a.result_summary){ var rs=document.createElement('div'); rs.className='ev-body'; rs.textContent=a.result_summary; el.appendChild(rs); }
    var u = usageRowFor(a.agent_id);
    var tok = document.createElement('div'); tok.className='role';
    if (u){ tok.textContent = 'measured tokens (authoritative='+(u.attribution==='authoritative')+'): in '+u.input+' out '+u.output+' cache_w '+u.cache_creation+' cache_r '+u.cache_read; }
    else if (a.self_reported_tokens != null){ tok.textContent = 'self-reported subagent_tokens (best-effort, not independently measured): '+a.self_reported_tokens; }
    el.appendChild(tok);
    if (a.artifacts && a.artifacts.length){
      var arts = document.createElement('div'); arts.className='role';
      arts.textContent = 'artifacts: ' + a.artifacts.join(', ');
      el.appendChild(arts);
    }
    if (a._children.length){
      var kids = document.createElement('div'); kids.className='tree-children';
      a._children.forEach(function(c){ kids.appendChild(nodeEl(c)); });
      el.appendChild(kids);
    }
    return el;
  }
  var tree = document.createElement('div'); tree.className='tree';
  roots.forEach(function(r){ tree.appendChild(nodeEl(r)); });
  view.appendChild(tree);
})();

// ---- Decisions ----
(function(){
  var view = document.getElementById('view-decisions');
  var list = document.createElement('div');
  EVENTS.filter(function(e){ return e.kind==='DECISION' || e.kind==='APPROVAL'; }).forEach(function(ev){
    list.appendChild(renderEvent(ev));
  });
  view.appendChild(list);
})();

// ---- Artifacts ----
(function(){
  var view = document.getElementById('view-artifacts');
  var seen = {};
  var rows = [];
  EVENTS.filter(function(e){ return e.kind==='ARTIFACT'; }).forEach(function(ev){
    var key = ev.text;
    if (!seen[key]) { seen[key] = {path: key, agents: []}; rows.push(seen[key]); }
    if (ev.agent_id && seen[key].agents.indexOf(ev.agent_id)===-1) seen[key].agents.push(ev.agent_id);
  });
  var wrap = document.createElement('div'); wrap.className='tablewrap';
  var table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>path</th><th>referenced by</th></tr></thead>';
  var tbody = document.createElement('tbody');
  rows.sort(function(a,b){ return a.path.localeCompare(b.path); }).forEach(function(r){
    var tr = document.createElement('tr');
    var td1 = document.createElement('td'); td1.className='mono';
    var relPath = r.path.replace(/\\/g,'/');
    var isRepoRel = !/^[A-Za-z]:|^\//.test(relPath);
    if (isRepoRel){
      var a = document.createElement('a'); a.href = '../' + relPath; a.textContent = relPath; a.target='_blank';
      td1.appendChild(a);
    } else { td1.textContent = relPath; }
    var td2 = document.createElement('td'); td2.textContent = r.agents.join(', ');
    tr.appendChild(td1); tr.appendChild(td2); tbody.appendChild(tr);
  });
  table.appendChild(tbody); wrap.appendChild(table); view.appendChild(wrap);
})();

// ---- Usage & Timing ----
(function(){
  var view = document.getElementById('view-usage');
  var phaseTitle = document.createElement('div'); phaseTitle.className='section-title'; phaseTitle.textContent='Phases (state/time_events.jsonl)';
  view.appendChild(phaseTitle);
  var phaseList = document.createElement('div');
  EVENTS.filter(function(e){return e.kind==='PHASE';}).forEach(function(ev){ phaseList.appendChild(renderEvent(ev)); });
  view.appendChild(phaseList);

  var costTitle = document.createElement('div'); costTitle.className='section-title'; costTitle.textContent='Authoritative cost snapshot (state/USAGE_REPORT.md, verbatim)';
  view.appendChild(costTitle);
  var pre = document.createElement('pre'); pre.className='raw'; pre.textContent = USAGE.report_md || '(not found)';
  view.appendChild(pre);

  var tblTitle = document.createElement('div'); tblTitle.className='section-title'; tblTitle.textContent='Per-agent token table (state/usage.jsonl) -- secondary evidence';
  view.appendChild(tblTitle);
  var wrap = document.createElement('div'); wrap.className='tablewrap';
  var table = document.createElement('table');
  table.innerHTML = '<thead><tr><th>scope</th><th>id/role</th><th>model</th><th>input</th><th>output</th><th>cache_w</th><th>cache_r</th><th>msgs</th><th>attribution</th></tr></thead>';
  var tbody = document.createElement('tbody');
  (USAGE.rows||[]).forEach(function(r){
    var tr = document.createElement('tr');
    ['scope','role','model','input','output','cache_creation','cache_read','messages','attribution'].forEach(function(k){
      var td = document.createElement('td'); if (k==='model'||k==='scope') td.className='mono';
      td.textContent = r[k]; tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody); wrap.appendChild(table); view.appendChild(wrap);
})();

// ---- Footer ----
(function(){
  var f = document.getElementById('footer');
  var lines = [
    'rendered_from (sha256 of input files, see reports/TRANSCRIPT_README.md): ' + META.rendered_from,
    'redaction: ' + META.redaction_count + ' occurrence(s) of sk-ant-* replaced with [REDACTED-API-KEY]',
    'events: ' + EVENTS.length + '  |  inline blobs: ' + Object.keys(BLOBS).length + '  |  sidecar blobs: ' + META.sidecar_blob_count,
    'sessions covered: ' + META.sessions.join(', ')
  ];
  f.innerHTML = lines.map(esc).join('<br>');
})();

})();
</script>
</body>
</html>
"""


def build_html(events, blobs_inline, blobs_remote, agents_json, usage_json, meta_json):
    events_json = json.dumps(events, ensure_ascii=False, separators=(",", ":"))
    blobs_inline_json = json.dumps(blobs_inline, ensure_ascii=False, separators=(",", ":"))
    agents_json_s = json.dumps(agents_json, ensure_ascii=False, separators=(",", ":"))
    usage_json_s = json.dumps(usage_json, ensure_ascii=False, separators=(",", ":"))
    meta_json_s = json.dumps(meta_json, ensure_ascii=False, separators=(",", ":"))
    html = HTML_TEMPLATE
    html = html.replace("__EVENTS_JSON__", events_json.replace("</script>", "<\\/script>"))
    html = html.replace("__BLOBS_INLINE_JSON__", blobs_inline_json.replace("</script>", "<\\/script>"))
    html = html.replace("__AGENTS_JSON__", agents_json_s.replace("</script>", "<\\/script>"))
    html = html.replace("__USAGE_JSON__", usage_json_s.replace("</script>", "<\\/script>"))
    html = html.replace("__META_JSON__", meta_json_s.replace("</script>", "<\\/script>"))
    return html


# ---------------------------------------------------------------------------
# Agents-tree / usage-table assembly
# ---------------------------------------------------------------------------

def build_agents_json(starts, lifecycle):
    out = []
    for aid, rec in starts.items():
        node = {
            "agent_id": aid,
            "parent_id": rec.get("parent_id"),
            "role": rec.get("role"),
            "requested_model": rec.get("requested_model"),
            "served_model": rec.get("served_model"),
            "start": rec.get("start"),
            "end": rec.get("end"),
            "status": rec.get("status"),
            "artifacts": rec.get("artifacts", []),
            "self_reported_tokens": None,
            "result_summary": None,
        }
        events = lifecycle.get(aid, [])
        # last event wins for status/end/summary/tokens
        for ev in events:
            if ev.get("event") in ("end", "milestone", "progress", "resume"):
                if ev.get("status"):
                    node["status"] = ev["status"]
                if ev.get("end"):
                    node["end"] = ev["end"]
                if ev.get("served_model"):
                    node["served_model"] = ev["served_model"]
                if ev.get("usage", {}).get("subagent_tokens") is not None:
                    node["self_reported_tokens"] = ev["usage"]["subagent_tokens"]
                if ev.get("result_summary"):
                    node["result_summary"] = ev["result_summary"]
        out.append(node)
    # agents with lifecycle events but no start record (e.g. research-synthesizer, test-lab-author)
    for aid, events in lifecycle.items():
        if aid in starts:
            continue
        node = {"agent_id": aid, "parent_id": "main", "role": None, "requested_model": None,
                "served_model": None, "start": None, "end": None, "status": None,
                "artifacts": [], "self_reported_tokens": None, "result_summary": None}
        for ev in events:
            if ev.get("status"):
                node["status"] = ev["status"]
            if ev.get("end"):
                node["end"] = ev["end"]
            if ev.get("served_model"):
                node["served_model"] = ev["served_model"]
            if ev.get("usage", {}).get("subagent_tokens") is not None:
                node["self_reported_tokens"] = ev["usage"]["subagent_tokens"]
            if ev.get("result_summary"):
                node["result_summary"] = ev["result_summary"]
        out.append(node)
    if not any(a["agent_id"] == "main" for a in out):
        out.insert(0, {"agent_id": "main", "parent_id": None, "role": "lead orchestrator (this session)",
                       "requested_model": None, "served_model": "claude-fable-5-1 (verified, see USAGE_REPORT.md)",
                       "start": None, "end": None, "status": "running", "artifacts": [],
                       "self_reported_tokens": None, "result_summary": None})
    return out


def build_usage_json():
    rows = []
    for rec in load_jsonl(USAGE_JSONL):
        if not isinstance(rec, dict):
            continue
        rows.append({
            "scope": rec.get("scope"), "id": rec.get("id"), "role": rec.get("role"),
            "model": rec.get("model"), "input": rec.get("input_tokens"), "output": rec.get("output_tokens"),
            "cache_creation": rec.get("cache_creation_tokens"), "cache_read": rec.get("cache_read_tokens"),
            "messages": rec.get("messages"), "attribution": rec.get("attribution"),
        })
    report_md = ""
    if USAGE_REPORT_MD.exists():
        report_md = USAGE_REPORT_MD.read_text(encoding="utf-8", errors="replace")
    return {"rows": rows, "report_md": report_md}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    em = Emitter()

    combined, n_main, n_fork, skipped_dupes = load_main_and_fork()
    invocations = process_main_fork(combined, em)

    starts, lifecycle, harness_id_map, global_events = build_agent_ledger()
    process_invocations(invocations, starts, harness_id_map, em)
    process_ledger_artifacts(starts, em)

    for rec in global_events:
        ev = rec.get("event")
        text = json.dumps({k: v for k, v in rec.items() if k not in ("event", "_line_no")}, ensure_ascii=False)
        em.emit(ts=rec.get("ts"), session="ledger", kind="SYSTEM", role=ev or "ledger-global",
                text=redact_text(text), refs={},
                synthesized=True, synthesized_note="Global (non-per-agent) event from agents.jsonl.")

    process_time_events(em)
    process_decisions_md(em)

    events = em.events
    events.sort(key=sort_key)
    for i, ev in enumerate(events):
        ev["seq"] = i + 1  # renumber post-sort for a clean, deterministic final sequence

    # Write normalized events.jsonl BEFORE blob extraction (full fidelity artifact)
    OUT_EVENTS.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_EVENTS, "w", encoding="utf-8", newline="\n") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            f.write("\n")

    # Extract oversized text into blobs for the HTML (operates on a deep copy
    # so events.jsonl above keeps full inline text)
    html_events = json.loads(json.dumps(events, ensure_ascii=False))
    blobs = extract_blobs(html_events)

    # Decide inline vs sidecar: keep the main HTML small by always sending
    # offloaded blobs to the sidecar file (see README for the threshold).
    blobs_inline = {}
    blobs_remote = blobs
    if blobs_remote:
        OUT_DATA.write_text(json.dumps(blobs_remote, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                             encoding="utf-8")
    elif OUT_DATA.exists():
        OUT_DATA.unlink()

    agents_json = build_agents_json(starts, lifecycle)
    usage_json = build_usage_json()

    input_files = [MAIN_SESSION_PATH, FORK_SESSION_PATH, AGENTS_JSONL, TIME_EVENTS_JSONL,
                   USAGE_JSONL, USAGE_REPORT_MD, BTW_INDEX_MD, DECISIONS_MD]
    hashes = OrderedDict((str(p), sha256_file(p)) for p in input_files)
    combined_hash = hashlib.sha256("".join(h or "" for h in hashes.values()).encode()).hexdigest()

    sessions_covered = sorted(set(e.get("session") for e in events if e.get("session") in (MAIN_SESSION_ID, FORK_SESSION_ID)))
    meta_json = {
        "rendered_from": combined_hash[:16],
        "input_hashes": hashes,
        "redaction_count": _redaction_count[0],
        "sidecar_blob_count": len(blobs_remote),
        "sessions": sessions_covered,
        "main_session_records": n_main,
        "fork_session_records": n_fork,
        "fork_replay_records_skipped": skipped_dupes,
    }

    html = build_html(html_events, blobs_inline, blobs_remote, agents_json, usage_json, meta_json)
    OUT_HTML.parent.mkdir(parents=True, exist_ok=True)
    OUT_HTML.write_text(html, encoding="utf-8", newline="\n")

    # ---- Console summary ----
    from collections import Counter
    kind_counts = Counter(e["kind"] for e in events)
    print("Event counts by kind:")
    for k, v in sorted(kind_counts.items()):
        print(f"  {k}: {v}")
    print(f"Total events: {len(events)}")
    print(f"Sessions covered: {sessions_covered}")
    print(f"Redactions: {_redaction_count[0]}")
    print(f"HTML size: {OUT_HTML.stat().st_size} bytes")
    if OUT_DATA.exists():
        print(f"Sidecar data.json size: {OUT_DATA.stat().st_size} bytes ({len(blobs_remote)} blobs)")
    print(f"rendered_from: {combined_hash[:16]}")


if __name__ == "__main__":
    main()
