#!/usr/bin/env bash
# Emu context-hygiene checkpoint (real Emu machinery, run from the repo root):
#   . tooling/emu_checkpoint.sh "<checkpoint text>"   or   bash tooling/emu_checkpoint.sh "<text>"
# 1) runs Emu state-keeper's PreCompact hook (save-checkpoint.sh) with a hook JSON for the CURRENT session
#    transcript -> Emu writes its checkpoint.md under the plugin state dir;
# 2) appends the lead's checkpoint text to Emu's remember.md exactly as /emu:checkpoint would;
# 3) mirrors both into state/emu/ so the checkpoint survives inside the repo (workbench stays outside).
# Never prints secrets. Requires jq (present) and the Emu clone at $HOME/.lava-workbench/emu.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EMU="${EMU_ROOT:-$HOME/.lava-workbench/emu}"
PLUGIN="$EMU/plugins/state-keeper"
STATE="$PLUGIN/state"
MIRROR="$ROOT/state/emu"
TEXT="${1:-}"
SESSION="${CLAUDE_SESSION_ID:-b64b46f1-8baf-4e2c-9e1a-4730b6251260}"
TRANSCRIPT="${CLAUDE_TRANSCRIPT_PATH:-$HOME/.claude/projects/C--lava-sensor-exercise/$SESSION.jsonl}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
mkdir -p "$STATE" "$MIRROR"

if [ -z "$TEXT" ]; then
  echo "usage: emu_checkpoint.sh <checkpoint text>"; exit 1
fi

# 1) real PreCompact hook with hook-style JSON on stdin (the hook must always exit 0 by spec)
HOOK="$PLUGIN/hooks/pre-compact/save-checkpoint.sh"
if [ -x "$HOOK" ] || [ -f "$HOOK" ]; then
  printf '{"session_id":"%s","transcript_path":"%s","cwd":"%s","hook_event_name":"PreCompact","trigger":"manual"}' \
    "$SESSION" "$(cygpath -w "$TRANSCRIPT" 2>/dev/null || printf '%s' "$TRANSCRIPT")" "$(cygpath -w "$ROOT" 2>/dev/null || printf '%s' "$ROOT")" \
    | CLAUDE_PLUGIN_ROOT="$PLUGIN" bash "$HOOK" >"$MIRROR/hook_stdout.txt" 2>"$MIRROR/hook_stderr.txt"
  echo "hook rc=$? (spec: always 0); stdout $(wc -c < "$MIRROR/hook_stdout.txt") bytes, stderr $(wc -c < "$MIRROR/hook_stderr.txt") bytes"
else
  echo "hook not found at $HOOK"
fi

# 2) manual checkpoint exactly like /emu:checkpoint <text>
printf '%s %s\n' "$TS" "$TEXT" >> "$STATE/remember.md"
printf '{"event":"manual_checkpoint","ts":"%s"}\n' "$TS" >> "$STATE/metrics.jsonl"
echo "Checkpointed: ${TEXT:0:80}. Survives compaction."

# 3) mirror into the repo (no secrets: remember.md holds only the lead's text; checkpoint.md is Emu's transcript digest)
for f in remember.md metrics.jsonl checkpoint.md; do
  [ -f "$STATE/$f" ] && cp "$STATE/$f" "$MIRROR/$f"
done
ls -la "$MIRROR" | awk 'NR>1{print $5, $9}'
