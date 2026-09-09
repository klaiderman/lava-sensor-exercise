#!/usr/bin/env python3
"""Stage submission-safe copies of the two native Claude Code session transcripts.

- Copies BOTH native JSONL files (the session forked) into submission/transcripts/ as-is EXCEPT one redaction:
  every occurrence of an Anthropic API-key-shaped value (sk-ant-...) is replaced by [REDACTED-API-KEY].
- Records: source path hashes (of the untouched originals, kept local), staged-copy hashes, redaction counts,
  line counts, and the fact that the staged copies are NOT byte-identical to the originals.
- Also stages the sub-agent transcripts (tasks/*.output) that belong to the two sessions, with the same redaction,
  because the supervision trail (what each sub-agent was told and replied) lives there.
- Never modifies the originals. Never prints the key value.
Usage: python tooling/stage_transcripts.py
"""
import glob
import hashlib
import json
import os
import re

HOME = os.path.expanduser("~")
PROJ = os.path.join(HOME, ".claude", "projects", "C--lava-sensor-exercise")
SESSIONS = ["573ece1e-5ae9-41c9-9d84-e625d280bc3a", "b64b46f1-8baf-4e2c-9e1a-4730b6251260"]
TASKS_BASE = os.path.join(os.environ.get("LOCALAPPDATA", os.path.join(HOME, "AppData", "Local")), "Temp", "claude", "C--lava-sensor-exercise")
OUT = os.path.join("submission", "transcripts")
# Real Anthropic keys are long; the brief's own public placeholder "sk-ant-REPLACE_ME" is excluded so the disclosed count is exact.
KEY_RX = re.compile(r"sk-ant-(?!REPLACE_ME\b)[A-Za-z0-9_-]{20,}")

os.makedirs(os.path.join(OUT, "subagents"), exist_ok=True)


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stage(src, dst):
    data = open(src, "rb").read()
    text = data.decode("utf-8", errors="surrogateescape")
    redacted, n = KEY_RX.subn("[REDACTED-API-KEY]", text)
    with open(dst, "wb") as f:
        f.write(redacted.encode("utf-8", errors="surrogateescape"))
    return {"source_sha256": sha(src), "staged_sha256": sha(dst), "redactions": n,
            "lines": text.count("\n"), "byte_identical": n == 0, "staged": os.path.relpath(dst).replace("\\", "/")}


manifest = {"note": "Native Claude Code session transcripts (JSONL). Two sessions because the run forked at 2026-09-08T22:30Z. "
                    "Staged copies differ from the originals ONLY by replacing Anthropic API-key-shaped values with [REDACTED-API-KEY]; "
                    "the redaction count is disclosed per file. Hashes below refer to the staged copies (and to the untouched local originals). "
                    "Mid-turn user messages are stored by Claude Code as queued_command attachment records, not user turns; they are preserved here as-is.",
            "sessions": [], "subagents": []}

for sid in SESSIONS:
    src = os.path.join(PROJ, sid + ".jsonl")
    if not os.path.exists(src):
        manifest["sessions"].append({"session": sid, "status": "MISSING_NATIVE"})
        continue
    rec = stage(src, os.path.join(OUT, sid + ".jsonl"))
    rec["session"] = sid
    manifest["sessions"].append(rec)
    for t in sorted(glob.glob(os.path.join(TASKS_BASE, sid, "tasks", "*.output"))):
        r = stage(t, os.path.join(OUT, "subagents", sid[:8] + "-" + os.path.basename(t)))
        r["session"] = sid
        r["task_id"] = os.path.basename(t).replace(".output", "")
        manifest["subagents"].append(r)

manifest["total_redactions"] = sum(r.get("redactions", 0) for r in manifest["sessions"] + manifest["subagents"])
json.dump(manifest, open(os.path.join(OUT, "TRANSCRIPT_MANIFEST.json"), "w", encoding="utf-8"), indent=1)
print(json.dumps({"sessions": [(r.get("session", "")[:8], r.get("redactions"), r.get("lines")) for r in manifest["sessions"]],
                  "subagent_files": len(manifest["subagents"]), "total_redactions": manifest["total_redactions"]}))
