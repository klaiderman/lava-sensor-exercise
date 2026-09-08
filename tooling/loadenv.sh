#!/usr/bin/env bash
# Source this: `. tooling/loadenv.sh` — loads .env without word-splitting or backslash mangling.
# Exports TARGET_HOST, TARGET_USER, SSH_KEY_PATH (raw) and SSH_KEY_PATH_UNIX (cygpath-converted).
# Never prints values.
_envfile="${LAVA_ENV_FILE:-/c/lava-sensor-exercise/.env}"
while IFS= read -r _line || [ -n "$_line" ]; do
  _line="${_line%$'\r'}"
  case "$_line" in ''|'#'*) continue;; esac
  _key="${_line%%=*}"; _val="${_line#*=}"
  _val="${_val%\"}"; _val="${_val#\"}"
  export "$_key=$_val"
done < "$_envfile"
if [ -n "${SSH_KEY_PATH:-}" ]; then
  export SSH_KEY_PATH_UNIX="$(cygpath -u "$SSH_KEY_PATH" 2>/dev/null || printf '%s' "$SSH_KEY_PATH")"
fi
unset _envfile _line _key _val
