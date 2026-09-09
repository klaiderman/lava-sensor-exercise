#!/usr/bin/env bash
# Mechanical prefilter before the independent review: Staticcheck (direct) + Hydra (pinned e56edc52) vuln/secret/supply-chain scans.
#   bash tooling/review/prefilter.sh            -> writes reports/PREFILTER.md (+ raw outputs under reports/prefilter/)
# Hydra is a regex/grep-based single-line prefilter (per its README) — it is not the primary Go reviewer.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SENSOR="$ROOT/sensor"
HYDRA="${HYDRA_ROOT:-$HOME/.lava-workbench/hydra}"
OUT="$ROOT/reports/prefilter"; mkdir -p "$OUT"
REPORT="$ROOT/reports/PREFILTER.md"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ -d "$SENSOR" ] || { echo "no sensor/ module"; exit 2; }

echo "== staticcheck =="
( cd "$SENSOR" && GOOS=linux GOARCH=amd64 staticcheck ./... ) > "$OUT/staticcheck.txt" 2>&1; SC_RC=$?
echo "staticcheck rc=$SC_RC ($(wc -l < "$OUT/staticcheck.txt") lines)"
echo "== go vet =="
( cd "$SENSOR" && GOOS=linux GOARCH=amd64 go vet ./... ) > "$OUT/govet.txt" 2>&1; VET_RC=$?
echo "go vet rc=$VET_RC ($(wc -l < "$OUT/govet.txt") lines)"

echo "== hydra vuln-scanner (per file) =="
: > "$OUT/hydra_vulns.txt"
HY_FILES=0; HY_ERR=0
while IFS= read -r f; do
  HY_FILES=$((HY_FILES+1))
  { echo "### $f"; python "$HYDRA/shared/scripts/vuln-scanner.py" "$f" 2>&1 || HY_ERR=$((HY_ERR+1)); echo; } >> "$OUT/hydra_vulns.txt"
done < <(find "$SENSOR" -name '*.go' -not -path '*/testdata/*' | sort)
echo "hydra scanned $HY_FILES files (errors: $HY_ERR)"
echo "== hydra supply-chain =="
( cd "$SENSOR" && python "$HYDRA/shared/scripts/supply-chain.py" . ) > "$OUT/hydra_supply_chain.txt" 2>&1; SUP_RC=$?
echo "supply-chain rc=$SUP_RC"
echo "== hydra entropy/secret scan on testdata + source =="
( cd "$SENSOR" && python "$HYDRA/shared/scripts/entropy-analyzer.py" . ) > "$OUT/hydra_entropy.txt" 2>&1; ENT_RC=$?
echo "entropy rc=$ENT_RC"

FINDINGS=$(grep -cE '^\s*(\[|- |\* |[A-Z]{2,}-[0-9]+|CWE-|HIGH|MEDIUM|LOW|CRITICAL)' "$OUT/hydra_vulns.txt" 2>/dev/null || echo 0)
{
  echo "# PREFILTER — Staticcheck + Hydra (mechanical, not the primary review)"
  echo
  echo "Run: $TS · module: sensor/ · Hydra pinned e56edc52 (regex single-line prefilter per its README; capped at 2000 lines / 10 findings per file) · Staticcheck $(staticcheck -version 2>/dev/null | head -1)"
  echo
  echo "| tool | rc | output lines | notes |"
  echo "|---|---|---|---|"
  echo "| staticcheck ./... (GOOS=linux) | $SC_RC | $(wc -l < "$OUT/staticcheck.txt") | rc 0 = no findings |"
  echo "| go vet ./... (GOOS=linux) | $VET_RC | $(wc -l < "$OUT/govet.txt") | |"
  echo "| hydra vuln-scanner.py per file | files=$HY_FILES errors=$HY_ERR | $(wc -l < "$OUT/hydra_vulns.txt") | finding-shaped lines: $FINDINGS |"
  echo "| hydra supply-chain.py . | $SUP_RC | $(wc -l < "$OUT/hydra_supply_chain.txt") | go.mod/go.sum surface |"
  echo "| hydra entropy-analyzer.py . | $ENT_RC | $(wc -l < "$OUT/hydra_entropy.txt") | secret-shaped strings incl. testdata |"
  echo
  echo "## staticcheck"; echo '```'; head -80 "$OUT/staticcheck.txt"; echo '```'
  echo "## go vet"; echo '```'; head -40 "$OUT/govet.txt"; echo '```'
  echo "## hydra vuln-scanner (first 120 lines)"; echo '```'; head -120 "$OUT/hydra_vulns.txt"; echo '```'
  echo "## hydra supply-chain"; echo '```'; head -40 "$OUT/hydra_supply_chain.txt"; echo '```'
  echo "## hydra entropy (first 60 lines)"; echo '```'; head -60 "$OUT/hydra_entropy.txt"; echo '```'
  echo
  echo "Findings ≠ coverage: a clean result above does not prove the behaviours the independent review must check (false PASS/FAIL/UNKNOWN, EACCES≠absent, bounded exec, secret leakage in evidence)."
} > "$REPORT"
echo "wrote $REPORT"
