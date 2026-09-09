#!/usr/bin/env bash
# Build the MINIMAL official Lava tarball from submission/ staging. Run from the repo root after the final host run.
#   bash tooling/package_submission.sh
# Contents (what the brief asks for, easy to find):
#   README.md                      one-command build + run, layout, verification
#   sensor/                        Go source + tests + testdata (no bin/), go.mod/go.sum
#   sensor/bin/sensor              the exact cross-compiled linux/amd64 binary that produced findings.json (+ sha256)
#   findings.json                  from the final real run on the Lava host
#   NOTES.md                       <= 1 page
#   finding.schema.json + SCHEMA_PROVENANCE.md   the transcribed contract used for validation
#   transcripts/                   both native session JSONL (redacted copies) + sub-agent transcripts + manifest
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$ROOT"
STAGE="submission/stage"; TS="$(date -u +%Y%m%dT%H%M%SZ)"
rm -rf "$STAGE"; mkdir -p "$STAGE/sensor" "$STAGE/transcripts"
[ -f reports/real_host/findings.json ] || { echo "no final findings (reports/real_host/findings.json)"; exit 2; }
[ -f sensor/bin/sensor ] || { echo "no built binary sensor/bin/sensor"; exit 2; }
[ -f submission/NOTES.md ] || { echo "no NOTES.md"; exit 2; }
# source (exclude build outputs, reviewer scratch, caches)
rsync -a --exclude 'bin/' --exclude '.gitignore' sensor/ "$STAGE/sensor/" 2>/dev/null || cp -r sensor/. "$STAGE/sensor/"
rm -rf "$STAGE/sensor/bin"; mkdir -p "$STAGE/sensor/bin"; cp sensor/bin/sensor "$STAGE/sensor/bin/sensor"
sha256sum sensor/bin/sensor | awk '{print $1}' > "$STAGE/sensor/bin/sensor.sha256"
cp reports/real_host/findings.json "$STAGE/findings.json"
cp submission/NOTES.md "$STAGE/NOTES.md"
cp task/derived/finding.schema.json "$STAGE/finding.schema.json"; cp task/derived/SCHEMA_PROVENANCE.md "$STAGE/SCHEMA_PROVENANCE.md"
cp -r submission/transcripts/. "$STAGE/transcripts/"
cp submission/README.md "$STAGE/README.md"
# hygiene gates
echo "== secret / local-path scan of the stage (transcripts excluded from the path rule) =="
if { grep -rIlE "sk-ant-[A-Za-z0-9_-]{8,}|TARGET_HOST=|SSH_KEY_PATH=" "$STAGE"; grep -rIlE "BEGIN (RSA|OPENSSH|EC) PRIVATE KEY" "$STAGE" --exclude="*.go"; } | grep -v '/transcripts/' ; then echo "SECRET-SHAPED CONTENT IN STAGE - ABORT"; exit 3; fi
if grep -rIohE "sk-ant-[A-Za-z0-9_-]{8,}" "$STAGE/transcripts" | grep -vx "sk-ant-REPLACE_ME" | grep -q .; then echo "UNREDACTED KEY IN TRANSCRIPTS - ABORT"; exit 3; fi
if grep -rIlE 'C:\\\\Users\\\\|/c/Users/|~/\.claude/|C:/Users/' "$STAGE" --include='*.md' --include='*.go' --include='*.json' | grep -v '/transcripts/' | grep -v 'findings.json'; then echo "LOCAL ABSOLUTE PATHS IN AUTHORED FILES - fix before packaging"; exit 3; fi
wc -w "$STAGE/NOTES.md" | awk '{ if ($1 > 760) { print "NOTES.md too long: " $1 " words"; exit 1 } else print "NOTES words: " $1 }'
# validate the shipped findings against the shipped schema
"$HOME/.lava-workbench/venv/Scripts/python.exe" tooling/validate_findings.py "$STAGE/findings.json" --schema "$STAGE/finding.schema.json" | tail -1
# manifest + tarball
( cd "$STAGE" && find . -type f | sort | xargs sha256sum > MANIFEST.sha256 )
OUTTAR="submission/lava-sensor-exercise-${TS}.tar.gz"
tar -czf "$OUTTAR" -C "$STAGE" .
echo "tarball: $OUTTAR ($(stat -c %s "$OUTTAR") bytes) sha256=$(sha256sum "$OUTTAR" | awk '{print $1}')"
tar -tzf "$OUTTAR" | grep -vE '^\./sensor/(internal|cmd)/|^\./transcripts/subagents/' | sort | head -40
