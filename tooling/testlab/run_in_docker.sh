#!/usr/bin/env bash
# Run the cross-compiled sensor inside the host-shaped container (PROFILE A), a
# minimal generic image (PROFILE B), or the restricted/hostile image (PROFILE C).
#   bash tooling/testlab/run_in_docker.sh A            # host-shaped Ubuntu 24.04 userspace
#   bash tooling/testlab/run_in_docker.sh B            # generic minimal (alpine:3.20, busybox coreutils, no systemd, no sshd)
#   bash tooling/testlab/run_in_docker.sh C            # restricted/hostile: see Dockerfile.profileC's header for exactly
#                                                       # what is denied and why (real removed binaries + real chmod 0000,
#                                                       # not a PATH trick — that was the external review's Docker Gate finding)
# Requires: docker daemon running; the linux/amd64 binary at sensor/bin/sensor (built by sensor/README.md instructions);
# a python with jsonschema installed for tooling/testlab/assert_profile.py (the same venv as tooling/validate_findings.py).
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
TESTLAB_WIN="$(cygpath -w "$ROOT/tooling/testlab" 2>/dev/null || printf '%s' "$ROOT/tooling/testlab")"

# Git Bash / MSYS on Windows silently rewrites standalone unix-looking arguments
# (e.g. "-w /home/ubuntu/sensor", "--tmpfs /proc/net:...") into Windows paths
# before exec-ing docker.exe, which breaks `docker run -w ...` and container-
# internal tmpfs targets with "invalid working directory" / mount errors. This
# is scoped to just the `docker run` invocation below (via a command-local env
# var, not `export`) so it never touches the `docker build` calls above, whose
# path arguments (host paths, already converted with cygpath -w) need normal
# MSYS handling. On native Linux bash / WSL, MSYS2_ARG_CONV_EXCL is simply
# unused, so this line is a no-op there.
DOCKER_RUN_ENV=()
case "$(uname -s 2>/dev/null || true)" in
  MINGW*|MSYS*|CYGWIN*) DOCKER_RUN_ENV=(env MSYS2_ARG_CONV_EXCL='*') ;;
esac

EXTRA_RUN_ARGS=()
case "$PROFILE" in
  A)
    docker build -q -t lava-sensor-testlab:profileA -f "$ROOT/tooling/testlab/Dockerfile.profileA" "$TESTLAB_WIN" >/dev/null
    IMG=lava-sensor-testlab:profileA; USERSPEC="1000:1000"
    OUT_NAME="findings.profileA.json"; CMD="./sensor scan --out /out/$OUT_NAME" ;;
  B)
    IMG=alpine:3.20; USERSPEC="1000:1000"
    OUT_NAME="findings.profileB.json"; CMD="./sensor scan --out /out/$OUT_NAME" ;;
  C)
    # C is built FROM the already-built A image, so build A first.
    docker build -q -t lava-sensor-testlab:profileA -f "$ROOT/tooling/testlab/Dockerfile.profileA" "$TESTLAB_WIN" >/dev/null
    docker build -q -t lava-sensor-testlab:profileC -f "$ROOT/tooling/testlab/Dockerfile.profileC" "$TESTLAB_WIN" >/dev/null
    IMG=lava-sensor-testlab:profileC
    # uid:gid 4242:4242 has no /etc/passwd entry and no home directory in this
    # image — a real "who am I" unknown, not a simulated one.
    #
    # Masking /proc/net and /sys/class/dmi with an empty tmpfs (as originally
    # asked for) was tried and is NOT available under runc without extra
    # capabilities we deliberately do not grant:
    #   - tmpfs onto /proc/net: runc refuses any mount nested under /proc
    #     ("check proc-safety of /proc/net mount") — a container-escape
    #     hardening rule in the runtime itself, not a docker flag to work
    #     around, and CAP_SYS_ADMIN would be needed to bypass it, which would
    #     contradict --cap-drop ALL.
    #   - tmpfs onto /sys/class/dmi: docker mounts /sys read-only by default,
    #     so runc cannot even create the mountpoint directory
    #     ("read-only file system") without write access to /sys, again only
    #     obtainable by adding back a capability this profile exists to deny.
    # What still holds without those: --network none means the container's own
    # netns has no non-loopback interface at all, so /proc/net/tcp{,6} is
    # genuinely empty of listeners (a real restriction, just not a "masked
    # path" one); and /sys/class/dmi here is Docker Desktop's own backend VM's
    # DMI table, never the Lava host's, whether or not it is hidden — the
    # sensor is told to say so via execution_context, not have the path
    # disappear. See CLAUDE.md: never claim a container equals the bare-metal
    # host, in either direction.
    USERSPEC="4242:4242"
    OUT_NAME="findings.profileC.json"; CMD="./sensor scan --out /out/$OUT_NAME" ;;
  *) echo "unknown profile $PROFILE"; exit 2 ;;
esac
echo "profile $PROFILE image $IMG"
# read-only root fs, no network, no new privileges, binary mounted read-only, output dir writable.
if [ "$PROFILE" = "C" ]; then
  # uid 4242 owns nothing on the host, and Docker Desktop's Windows bind-mount
  # layer does not honour chmod 0777 on the host side reliably enough for an
  # arbitrary unmapped uid to write into a bind-mounted directory (tried:
  # permission denied). A tmpfs target at /out was tried next and rejected too
  # (tmpfs content does not survive past `docker cp` on a stopped container).
  # What works: a real docker volume, world-writable by a throwaway root prep
  # step, mounted at /out for the restricted run, then copied to the host bind
  # mount by a final throwaway step. Three tiny container runs, none of them
  # the sensor run itself gains any capability from this plumbing.
  VOL="lava-sensor-testlab-c-out-$$"
  docker volume create "$VOL" >/dev/null
  "${DOCKER_RUN_ENV[@]}" docker run --rm -v "$VOL:/out" alpine:3.20 chmod 0777 /out >/dev/null
  "${DOCKER_RUN_ENV[@]}" docker run --rm --network none --read-only --security-opt no-new-privileges --cap-drop ALL \
    --tmpfs /tmp --user "$USERSPEC" "${EXTRA_RUN_ARGS[@]}" \
    -v "${BIN_WIN}:/home/ubuntu/sensor/sensor:ro" -v "$VOL:/out" -w /home/ubuntu/sensor \
    "$IMG" sh -c "$CMD; echo exit=\$?"
  "${DOCKER_RUN_ENV[@]}" docker run --rm -v "$VOL:/out" -v "${OUT_WIN}:/hostout" alpine:3.20 cp "/out/$OUT_NAME" "/hostout/$OUT_NAME"
  docker volume rm "$VOL" >/dev/null
else
  "${DOCKER_RUN_ENV[@]}" docker run --rm --network none --read-only --security-opt no-new-privileges --cap-drop ALL \
    --tmpfs /tmp --user "$USERSPEC" "${EXTRA_RUN_ARGS[@]}" \
    -v "${BIN_WIN}:/home/ubuntu/sensor/sensor:ro" -v "${OUT_WIN}:/out" -w /home/ubuntu/sensor \
    "$IMG" sh -c "$CMD; echo exit=\$?"
fi
ls -la "$OUT"

# Mechanical assertion gate: schema, 26/26 check_ids exactly once, per-profile
# expected statuses, and the "verdict text never over-claims past a denied
# observation" property. Non-zero exit here fails this script.
PY="$HOME/.lava-workbench/venv/Scripts/python.exe"
[ -x "$PY" ] || PY="python3"
"$PY" "$ROOT/tooling/testlab/assert_profile.py" "$OUT/$OUT_NAME" "$PROFILE"
