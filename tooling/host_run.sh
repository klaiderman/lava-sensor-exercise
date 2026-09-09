#!/usr/bin/env bash
# Final real-host run, exactly per state/SSH_PLAN.md: build -> hash -> upload (scp, Lava-approved) -> run the ONE documented
# command as the supplied unprivileged user -> fetch findings + stderr -> hash-verify -> validate against the derived schema.
#   bash tooling/host_run.sh                 # full run; artifacts under reports/real_host/
#   bash tooling/host_run.sh --no-build      # reuse sensor/bin/sensor
# Never uses sudo. StrictHostKeyChecking=yes against ~/.ssh/known_hosts.lava (recorded at first contact). Never prints credentials.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
. tooling/loadenv.sh
OUT="$ROOT/reports/real_host"; mkdir -p "$OUT"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VP="$HOME/.lava-workbench/venv/Scripts/python.exe"
SSH_OPTS=(-i "$SSH_KEY_PATH_UNIX" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$HOME/.ssh/known_hosts.lava" -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no)
DEST="$TARGET_USER@$TARGET_HOST"
REMOTE_DIR='~/sensor'

if [ "${1:-}" != "--no-build" ]; then
  echo "== build (static linux/amd64) =="
  ( cd sensor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o bin/sensor ./cmd/sensor )
fi
[ -f sensor/bin/sensor ] || { echo "missing sensor/bin/sensor"; exit 2; }
LOCAL_SHA="$(sha256sum sensor/bin/sensor | awk '{print $1}')"
echo "local sha256: $LOCAL_SHA ($(stat -c %s sensor/bin/sensor) bytes)"

echo "== upload (scp, per Lava cheatsheet) =="
ssh "${SSH_OPTS[@]}" "$DEST" "mkdir -p $REMOTE_DIR"
scp "${SSH_OPTS[@]}" -q sensor/bin/sensor "$DEST:$REMOTE_DIR/sensor"
REMOTE_SHA="$(ssh "${SSH_OPTS[@]}" "$DEST" "chmod u+x $REMOTE_DIR/sensor && sha256sum $REMOTE_DIR/sensor | cut -d' ' -f1")"
echo "remote sha256: $REMOTE_SHA"
[ "$LOCAL_SHA" = "$REMOTE_SHA" ] || { echo "HASH MISMATCH after upload - aborting"; exit 3; }

echo "== run the documented command as the unprivileged user =="
# The exact one command Lava will run (from sensor/README.md): ./sensor scan --out findings.json
ssh "${SSH_OPTS[@]}" "$DEST" "cd $REMOTE_DIR && id -un && rm -f findings.json && s=\$(date +%s%N); ./sensor scan --out findings.json 2> sensor.stderr; rc=\$?; e=\$(date +%s%N); echo exit=\$rc >> sensor.stderr; echo wall_ms=\$(( (e - s) / 1000000 )) >> sensor.stderr; tail -5 sensor.stderr; sha256sum findings.json | cut -d' ' -f1" | tee "$OUT/run.log.$TS"
REMOTE_FSHA="$(tail -1 "$OUT/run.log.$TS")"

echo "== fetch results =="
scp "${SSH_OPTS[@]}" -q "$DEST:$REMOTE_DIR/findings.json" "$OUT/findings.json"
scp "${SSH_OPTS[@]}" -q "$DEST:$REMOTE_DIR/sensor.stderr" "$OUT/sensor.stderr"
LOCAL_FSHA="$(sha256sum "$OUT/findings.json" | awk '{print $1}')"
echo "findings sha256 remote=$REMOTE_FSHA local=$LOCAL_FSHA"
[ "$REMOTE_FSHA" = "$LOCAL_FSHA" ] || { echo "findings.json hash mismatch"; exit 4; }

echo "== validate =="
"$VP" tooling/validate_findings.py "$OUT/findings.json" | tee "$OUT/validation.txt"
printf '{"ts":"%s","binary_sha256":"%s","findings_sha256":"%s","remote_dir":"%s","command":"./sensor scan --out findings.json","user":"%s"}\n' "$TS" "$LOCAL_SHA" "$LOCAL_FSHA" "$REMOTE_DIR" "(target user, not printed)" >> "$OUT/runs.jsonl"
echo "done: $OUT/findings.json"
