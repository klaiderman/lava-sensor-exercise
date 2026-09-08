# SSH_PLAN

## source
- Lava's SSH guidance is the "Cheatsheet" section of `task/original/Lava-Sensor-Exercise.html` (identical in the PDF, page 2-3). Verbatim commands Lava gives:
  - Connect: `ssh -i KEY USER@HOST`
  - Copy code up: `rsync -avz -e "ssh -i KEY" ./sensor/ USER@HOST:~/sensor/` or `scp -i KEY ./sensor.py USER@HOST:~/`
  - Copy results down: `scp -i KEY USER@HOST:~/findings.json .` or rsync of `~/sensor/`
  - One command without logging in: `ssh -i KEY USER@HOST 'cat /proc/cmdline'`
  - Optional: install Claude Code on the server (we do NOT do this; we orchestrate locally).
- Constraints Lava gave: KEY/USER/HOST come from their email; 10-hour access window; "Real bare metal"; both local-over-SSH and on-server work are allowed and unscored. Rules for the sensor also bound our recon: read-only, bounded, unprivileged (no escalation), does not crash things.
- Lava provides NO host-key fingerprint -> controlled trust-on-first-use (see connection).

## local
- repo root: `C:\lava-sensor-exercise` (Git Bash: `/c/lava-sensor-exercise`)
- SSH client: MSYS OpenSSH 10.2p1 at `/usr/bin/ssh` (Git for Windows); `scp`, `rsync` availability checked at transfer time (fallback: scp/tar-over-ssh)
- credentials: `.env` (gitignored) -> `TARGET_HOST`, `TARGET_USER`, `SSH_KEY_PATH`; load ONLY via `. tooling/loadenv.sh` (raw-line loader; bash `source` mangles Windows backslashes). Never print values.
- key: outside the repo, under `~/.ssh/lava/`; ED25519; must be mode 600 for the MSYS client
- host-key store: `~/.ssh/known_hosts.lava` (dedicated file; recorded fingerprint below)
- local build output: `sensor/bin/` (gitignored) -> linux/amd64 (or host arch) static binary + source tarball staging in `submission/`
- final findings destination: `submission/findings.json` (copied from the real run), validated locally against `task/original/finding.schema.json`

## target
- host: `$TARGET_HOST` (from .env, Lava email). user: `$TARGET_USER` (from .env, Lava email). Expected: an unprivileged account with a home directory.
- expected/allowed working directory: the user's `$HOME` (Lava's own cheatsheet uploads to `~/sensor/` and reads `~/findings.json`)
- upload location: `~/sensor/` (per Lava cheatsheet)
- final execution location: `~/sensor/` — run exactly the documented command, e.g. `./sensor scan --out ~/findings.json` (final form frozen after implementation)
- output location: `~/findings.json` or `~/sensor/findings.json`; retrieved with scp
- NEVER: sudo/su/doas, writes outside `$HOME`, service changes, module loads, package installs, editing any config

## connection
- host-key policy: first connection `StrictHostKeyChecking=accept-new` into `UserKnownHostsFile=~/.ssh/known_hosts.lava`; every later connection `StrictHostKeyChecking=yes` against that file, so a changed key fails loudly. Never `StrictHostKeyChecking=no`.
- identity: `-i $SSH_KEY_PATH` + `IdentitiesOnly=yes` (do not offer the machine's other keys)
- auth: `BatchMode=yes`, `PasswordAuthentication=no`, `KbdInteractiveAuthentication=no` (no interactive fallback)
- timeouts: `ConnectTimeout=15`; every remote command additionally wrapped in coreutils `timeout` on the remote side and a local subprocess timeout
- keepalive: `ServerAliveInterval=10`, `ServerAliveCountMax=3`
- first harmless read-only command: `id; hostname; uname -srm` -> confirms user, machine, no escalation
- recorded host key fingerprint: ED25519 SHA256:qvIugmbBODixC8kKuWELSAvL/6f6dkh6eJj/T6b1xrA (TOFU 2026-09-08T21:11Z into ~/.ssh/known_hosts.lava; no fingerprint was supplied by Lava). First connection: user uid 1000, unprivileged shell, groups include `sudo` — never used.

## transfer
- needed: yes — local Go build (cross-compiled or built on host) must reach the host for the final real run; results come back
- approved mechanism (from Lava): rsync over ssh or scp. Local rsync may be missing on Git Bash -> use `scp -i KEY` (also Lava-approved) or `tar | ssh` as fallback; record which.
- local -> remote: `sensor/bin/sensor-linux-<arch>` (+ source tree only if building on host), sha256 recorded before and verified after (`sha256sum` remote)
- remote -> local: `~/findings.json` (and stderr log) via scp; sha256 verified

## cleanup
- files we create remotely: `~/sensor/` (binary + optional source), `~/findings.json`, nothing else; no crontab, no services, no dotfile edits
- to clean at the end: optionally leave `~/sensor/` + `~/findings.json` in place (Lava may inspect), delete any scratch dirs we created (`~/sensor/tmp*`); record in EXECUTION_STATE what remains
- must never be modified: anything outside `$HOME`; sshd/PAM/sudoers/udev/modprobe config; kernel state; device nodes; other users' files

## observation executor discipline (recon)
- Only the lead-controlled executor (`tooling/tci/`) runs remote commands; probes are symbolic ProbeIDs mapped to exact, allowlisted read-only commands with per-probe `timeout` + output cap.
- Research agents never get SSH; they submit `OBSERVATION_REQUEST`s.
- Raw probe output is stored under `state/raw_host/` (gitignored); the sanitized `state/HOST_SNAPSHOT.json` is what agents see.
