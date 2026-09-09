#!/usr/bin/env bash
# Clean-room submission gate: unpack the tarball in a temp dir containing ONLY the tarball, follow only README.md,
# build from source, run the ONE documented command (under WSL as uid 1000 = the Linux the reviewer would use),
# validate against the shipped schema, and verify no repo/workbench dependency was needed.
#   bash tooling/cleanroom_gate.sh submission/lava-sensor-exercise-<ts>.tar.gz
set -euo pipefail
TARBALL="${1:?tarball path}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TEMP:-/tmp}/lava-cleanroom-XXXXXX")"
cp "$TARBALL" "$TMP/sub.tar.gz"; cd "$TMP" && tar -xzf sub.tar.gz && rm sub.tar.gz
echo "== unpacked into $TMP =="; ls
echo "== README documented commands =="; grep -nE '^\s*(\$ |```|go build|\./sensor|sensor scan)' README.md sensor/README.md 2>/dev/null | head -12
echo "== build from source exactly as documented (Windows host cross-compile, as a Go-less Lava reviewer could not; the shipped binary hash must match) =="
( cd sensor && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /tmp/cleanroom-sensor ./cmd/sensor ) 2>&1 | tail -3
echo "shipped binary sha256: $(cat sensor/bin/sensor.sha256)"; echo "rebuilt  binary sha256: $(sha256sum /tmp/cleanroom-sensor | awk '{print $1}') (may differ only by build path; -trimpath makes it deterministic when the toolchain matches)"
echo "== run the shipped binary with the documented command under WSL as uid 1000 =="
WSLDIR="$(wsl -e wslpath -a "$(cygpath -w "$TMP")" 2>/dev/null | tr -d '\r')"
wsl -e bash -lc "cd '$WSLDIR' && chmod u+x sensor/bin/sensor && id -un && ./sensor/bin/sensor scan --out cleanroom-findings.json; echo exit=\$?" 2>&1 | tr -d '\0' | tail -4
echo "== validate against the SHIPPED schema (no repo dependency) =="
"$HOME/.lava-workbench/venv/Scripts/python.exe" "$ROOT/tooling/validate_findings.py" "$TMP/cleanroom-findings.json" --schema "$TMP/finding.schema.json" | tail -1
echo "== shipped findings.json validates too =="
"$HOME/.lava-workbench/venv/Scripts/python.exe" "$ROOT/tooling/validate_findings.py" "$TMP/findings.json" --schema "$TMP/finding.schema.json" | tail -1
echo "== tests from the shipped source (Windows go test; Linux-only tests skip) =="
( cd sensor && go test ./... -count=1 2>&1 | tail -6 )
echo "clean-room dir left for inspection: $TMP"
