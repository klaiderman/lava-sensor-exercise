#!/usr/bin/env bash
# Run the cross-compiled sensor inside the host-shaped container (PROFILE A) or a minimal generic image (PROFILE B).
#   bash tooling/testlab/run_in_docker.sh A            # host-shaped Ubuntu 24.04 userspace
#   bash tooling/testlab/run_in_docker.sh B            # generic minimal (alpine:3.20, busybox coreutils, no systemd, no sshd)
#   bash tooling/testlab/run_in_docker.sh C            # restricted: profile A image but with the utility set removed from PATH
# Requires: docker daemon running; the linux/amd64 binary at sensor/bin/sensor (built by sensor/README.md instructions).
# The container is NOT the target: no DMI, no NVMe, no BMC, no efivars; it exercises userspace/parsing/permission behaviour.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="${1:-A}"
BIN="$ROOT/sensor/bin/sensor"
OUT="$ROOT/reports/testlab"
mkdir -p "$OUT"
[ -f "$BIN" ] || { echo "missing $BIN — build first (GOOS=linux GOARCH=amd64 CGO_ENABLED=0)"; exit 2; }
BIN_WIN="$(cygpath -w "$BIN" 2>/dev/null || printf '%s' "$BIN")"
OUT_WIN="$(cygpath -w "$OUT" 2>/dev/null || printf '%s' "$OUT")"
case "$PROFILE" in
  A)
    docker build -q -t lava-sensor-testlab:profileA -f "$ROOT/tooling/testlab/Dockerfile.profileA" "$ROOT/tooling/testlab" >/dev/null
    IMG=lava-sensor-testlab:profileA; USERSPEC="1000:1000"; CMD="./sensor scan --out /out/findings.profileA.json" ;;
  B)
    IMG=alpine:3.20; USERSPEC="1000:1000"; CMD="./sensor scan --out /out/findings.profileB.json" ;;
  C)
    docker build -q -t lava-sensor-testlab:profileA -f "$ROOT/tooling/testlab/Dockerfile.profileA" "$ROOT/tooling/testlab" >/dev/null
    IMG=lava-sensor-testlab:profileA; USERSPEC="1000:1000"
    CMD="env PATH=/nonexistent ./sensor scan --out /out/findings.profileC.json" ;;
  *) echo "unknown profile $PROFILE"; exit 2 ;;
esac
echo "profile $PROFILE image $IMG"
# read-only root fs, no network, no new privileges, binary mounted read-only, output dir writable.
docker run --rm --network none --read-only --security-opt no-new-privileges --cap-drop ALL \
  --tmpfs /tmp --user "$USERSPEC" \
  -v "${BIN_WIN}:/home/ubuntu/sensor/sensor:ro" -v "${OUT_WIN}:/out" -w /home/ubuntu/sensor \
  "$IMG" sh -c "time $CMD; echo exit=\$?"
ls -la "$OUT"
