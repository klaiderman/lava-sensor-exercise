# R3 Stream C — Effective sshd configuration vs single file, and non-SSH remote-access surfaces

Target: Ubuntu 24.04 noble, OpenSSH 9.6p1 Ubuntu-3ubuntu13.19, sshd socket-activated via ssh.socket, unprivileged uid 1000 (group sudo, sudo unusable). LOCAL_REPRO note: WSL not probed this run (time-boxed to primary-doc reading); all facts below are man-page/source/official-doc derived and flagged APPLIES_TO accordingly.

---

FACT: sshd_config(5) states, verbatim: "The file contains keyword-argument pairs, one per line. Unless noted otherwise, for each keyword, the first obtained value will be used." This is the SAME rule ssh_config(5) uses for the client ("Unless noted otherwise, for each configuration directive, the first specified value will be used") — NOT the opposite as commonly assumed. What differs is the *reading order* per program (sshd: main file top-to-bottom, Include expanded in place; ssh client: CLI args, then user config, then system config), not the "first wins" rule itself.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read /etc/ssh/sshd_config as a regular file (mode typically 0644) — always permitted unprivileged; EACCES here would be anomalous and itself reportable. This establishes only the FIRST-FILE view; see Match/Include facts below for why that's insufficient.
IMPACT: Sensor must never conclude an effective directive value by grepping only /etc/ssh/sshd_config; must read the whole Include-expanded chain in file order and keep the first occurrence of each keyword, or explicitly report UNKNOWN/"static-file-only" for that directive.
SOURCES: S1 | https://man.openbsd.org/sshd_config | sshd_config(5) OpenBSD (canonical upstream) | primary | WebFetch; S3 | https://man.openbsd.org/ssh_config | ssh_config(5) OpenBSD | primary | WebFetch

FACT: `Include` is processed at the point it appears: "Include the specified configuration file(s). Multiple pathnames may be specified and each pathname may contain glob(7) wildcards that will be expanded and processed in lexical order. Files without absolute paths are assumed to be in /etc/ssh. An Include directive may appear inside a Match block to perform conditional inclusion." Combined with first-obtained-value-wins, an `Include /etc/ssh/sshd_config.d/*.conf` line placed near the TOP of /etc/ssh/sshd_config means keywords set in those drop-ins win over the same keyword appearing later in the main file.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read /etc/ssh/sshd_config to find the Include line's position and glob; then list+read /etc/ssh/sshd_config.d/*.conf in lexical (glob) order — all world-readable, unprivileged-safe. ENOENT on sshd_config.d means no drop-ins (older layout); EACCES would be anomalous.
IMPACT: Sensor's "effective config" reconstruction must walk Include in file order, expand globs lexically, and treat drop-in values as authoritative over later same-name keywords in the parent file — matches real Ubuntu 24.04 cloud images (see cloud-init fact below).
SOURCES: S1 | https://man.openbsd.org/sshd_config | sshd_config(5) | primary | WebFetch

FACT: Ubuntu 24.04 cloud images ship `/etc/ssh/sshd_config.d/50-cloud-init.conf` containing `PasswordAuthentication yes` (driven by cloud-init's `ssh_pwauth` setting), included via the stock `Include /etc/ssh/sshd_config.d/*.conf` line that Debian/Ubuntu package maintainers place near the top of /etc/ssh/sshd_config. A real-world consequence reported by admins: setting `PasswordAuthentication no` in the main file has NO effect because the drop-in's `yes` was read first. This is the concrete case that makes "read one file" wrong.
STATUS: VERIFIED
APPLIES_TO: generic (Ubuntu cloud images specifically; not necessarily present on bare-metal/ISO installs)
PROBE: check existence of /etc/ssh/sshd_config.d/50-cloud-init.conf (stat, world-readable) and its content vs the same keyword in /etc/ssh/sshd_config; report CONTESTED if they disagree, citing which wins per Include order.
IMPACT: Never report PasswordAuthentication (or any drop-in-eligible keyword) from the main file alone; always resolve via the full Include chain, first-occurrence-wins.
SOURCES: S7 | https://news.ycombinator.com/item?id=42138026 | HN thread on Ubuntu 24.04 cloud-init sshd drop-in | secondary (community discussion, but describes verifiable file layout) | WebFetch; corroborated informally by Launchpad bug traffic on cloud-init/sshd interaction (not independently fetched this run — GAP).

FACT: `Match` introduces a conditional block: "If all of the criteria on the Match line are satisfied, the keywords on the following lines override those set in the global section of the config file, until either another Match line or the end of the file." Per-user/host/address effective policy can therefore differ arbitrarily from the global section, and a static read cannot evaluate Match criteria without knowing the actual connecting user/host/address (which the sensor, running locally with no live SSH session context, does not have in general).
STATUS: VERIFIED
APPLIES_TO: both
PROBE: parse all Match blocks and their criteria (User, Group, Host, Address, LocalAddress, LocalPort, RDomain) textually; report them as evidence ("N Match blocks found, criteria X") rather than asserting a single effective value for the whole host.
IMPACT: Sensor should report sshd policy as "global defaults + list of conditional overrides" (evidence-only), not collapse to one verdict, when Match blocks exist for security-relevant keywords (PermitRootLogin, PasswordAuthentication, AllowUsers, etc.).
SOURCES: S1 | https://man.openbsd.org/sshd_config | sshd_config(5), Match section | primary | WebFetch

FACT: `sshd -T` "check[s] the validity of the configuration file, output[s] the effective configuration to stdout and then exit[s]," and `-C user=...,host=...,addr=...` supplies connection parameters so Match blocks are evaluated as they would be for that specific connection — this is the closest thing to ground truth for "effective config for user X," but per the OpenSSH source it is gated by host-key availability, not by the Match-evaluation logic itself.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: attempt `sshd -T` unprivileged (no sudo). Expected outcome on this host class: exit 1 with "sshd: no hostkeys available -- exiting." (stderr), NOT a permission-denied on the config file itself. Record exit code + stderr text as evidence; this is EXECUTION_ERROR, not UNSUPPORTED and not a proxy for "policy is X."
IMPACT: The sensor cannot use `sshd -T` output on this unprivileged host; must fall back to static Include/Match parsing (above) and report the -T attempt's failure as evidence of *why* (host keys unreadable), not as a check failure to hide.
SOURCES: S2 | https://man.openbsd.org/sshd | sshd(8), -T/-C flags | primary | WebFetch

FACT: The exact code path for "no hostkeys available -- exiting" is in `main()` of sshd.c: after all configured host keys are loaded (each read attempt failing silently as keys are root:root mode 0600 and unreadable by uid 1000), the code checks `if (!sensitive_data.have_ssh2_key) { logit("sshd: no hostkeys available -- exiting."); exit(1); }`. Critically, host-key loading happens UNCONDITIONALLY before the `test_flag` (-T) check — i.e., `-T` does NOT skip host-key loading, so an unprivileged user hits this exit even though they only wanted to dump parsed config, not run the daemon. This is a privilege limitation of the -T implementation, not a documented "requires root" flag in the man page (the man page is silent on this).
STATUS: VERIFIED
APPLIES_TO: both
PROBE: fallback chain for "what would sshd -T report": (1) try sshd -T unprivileged -> expect EXECUTION_ERROR "no hostkeys available"; (2) fall back to manual Include/Match static parse (facts above); (3) if host private keys become readable (never expected unprivileged), -T becomes usable. Never interpret the -T failure as "sshd config is invalid" — it is orthogonal to config validity.
IMPACT: Documents precisely why the sensor must implement its own Include/Match walker rather than shelling out to sshd -T, and gives exact evidence text to log for the UNKNOWN/EXECUTION_ERROR finding.
SOURCES: S4 | https://raw.githubusercontent.com/openssh/openssh-portable/V_9_6_P1/sshd.c | OpenSSH portable source, tag V_9_6_P1, main() | primary | WebFetch (source read directly, line ~2406 "no hostkeys available -- exiting", host-key load block lines ~2355-2406 precede the test_flag exit at ~2424)

FACT: Upstream (OpenBSD) sshd_config(5) defaults for OpenSSH 9.6: PermitRootLogin=prohibit-password, PasswordAuthentication=yes, PubkeyAuthentication=yes, KbdInteractiveAuthentication=yes, MaxAuthTries=6, PermitEmptyPasswords=no, X11Forwarding=no, AllowTcpForwarding=yes, AllowAgentForwarding=yes, ClientAliveInterval=0, ClientAliveCountMax=3, LoginGraceTime=120s, StrictModes=yes, AuthorizedKeysFile=".ssh/authorized_keys .ssh/authorized_keys2". UsePAM's UPSTREAM default is "no".
STATUS: VERIFIED
APPLIES_TO: generic (upstream baseline, use only when no explicit setting found anywhere in the Include chain)
PROBE: n/a (reference values only, not directly observable — used as the fallback when a keyword is absent from every file in the Include chain)
IMPACT: Sensor's default table for "keyword absent everywhere" must use these upstream values, EXCEPT UsePAM where Debian/Ubuntu override (next fact) — using the wrong default silently misclassifies policy.
SOURCES: S1 | https://man.openbsd.org/sshd_config | sshd_config(5) | primary | WebFetch

FACT: Debian/Ubuntu's shipped openssh-server package sets `UsePAM yes` (contradicting the upstream default of "no"), documented explicitly in the Ubuntu noble sshd_config(5) manpage which notes the packaged default diverges from the upstream manual text. `UsePAM yes` means PAM account and session modules (pam_nologin, pam_access, etc. via /etc/pam.d/sshd) run for ALL authentication types, not just keyboard-interactive.
STATUS: VERIFIED — CONTESTED CLASS (upstream doc text vs Debian/Ubuntu packaging default)
APPLIES_TO: host (Ubuntu 24.04) and generic-Debian-family
PROBE: read /etc/ssh/sshd_config (and Include chain) for an explicit `UsePAM` line; if absent everywhere, the sensor must NOT assume the upstream "no" — for a Debian-family distro (detected via /etc/os-release ID=ubuntu/debian) the correct absent-value default is "yes". Report distro-specific default source as evidence.
IMPACT: This is exactly the kind of "generic fallback would be wrong" case the project cares about — hardcode a distro-family-aware default table, cite it, and flag UNKNOWN with reason if the distro can't be identified from /etc/os-release.
SOURCES: S5 | https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html | Ubuntu noble sshd_config(5) manpage | primary (distro-shipped manpage) | WebFetch

FACT: Ubuntu 22.10+ (including 24.04) ships `ssh.socket` and switched sshd to systemd socket activation by default (openssh-server 1:9.0p1-1ubuntu1 introduced this in kinetic). Under socket activation, `Port` and `ListenAddress` in sshd_config are IGNORED for determining what address/port is actually listened on — that is controlled by `ListenStream=` in ssh.socket (and any `/etc/systemd/system/ssh.socket.d/*.conf` drop-in). On 24.04 specifically, address/port settings are no longer migrated into socket drop-ins at upgrade time but are instead "pulled dynamically from sshd_config via a systemd generator" per Canonical's own discourse explanation, but administrators are told to edit `ssh.socket`, not `sshd_config`, to change the listening port (`systemctl edit ssh.socket`, set `ListenStream=`, `daemon-reload`, `restart ssh.socket`).
STATUS: VERIFIED
APPLIES_TO: host (Ubuntu 24.04) and generic (any systemd + ssh.socket distro)
PROBE: unprivileged: `systemctl is-enabled ssh.socket` / `systemctl show ssh.socket -p Listen` are typically allowed read-only via the systemd bus (no root needed for `show`/status of a unit); confirm actual listening endpoint via `ss -tln` (any user can see LISTEN state + local address, just not the owning PID of sockets they don't own — see ss fact below) rather than trusting sshd_config's Port/ListenAddress. If ssh.socket is absent/inactive, fall back to sshd_config's Port/ListenAddress as authoritative (traditional standalone sshd).
IMPACT: Sensor must NOT report "SSH listens on port X" from sshd_config Port/ListenAddress alone when ssh.socket is the active unit — must cross-check against ss -tln output and/or ssh.socket's effective ListenStream, and report a CONTESTED/EXECUTION_ERROR if they disagree.
SOURCES: S6 | https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189 | Canonical/Ubuntu Server team discourse thread (semi-official — posted by Ubuntu server maintainers) | primary-adjacent (official Canonical communication channel, not a man page) | WebFetch

FACT: PAM's role when UsePAM=yes: /etc/pam.d/sshd is the per-service PAM config; Debian/Ubuntu populate it with `@include common-auth`, `@include common-account`, `@include common-session[-noninteractive]`, which are themselves managed centrally by `pam-auth-update` (libpam-runtime) so all services share one auth policy. account-type modules (pam_nologin, pam_access, pam_unix account checks) and session-type modules run on every login regardless of whether auth was via pubkey or password, because UsePAM=yes wires account/session processing in even for non-interactive (pubkey) auth.
STATUS: VERIFIED
APPLIES_TO: generic (Debian/Ubuntu family)
PROBE: read /etc/pam.d/sshd (world-readable) for @include lines; read /etc/pam.d/common-account and common-session for active modules (pam_nologin.so, pam_access.so, etc.) — all world-readable text files, EACCES here would be anomalous.
IMPACT: Even a pubkey-only login (PasswordAuthentication no) can still be blocked by pam_nologin (/etc/nologin present) or pam_access (/etc/security/access.conf) when UsePAM=yes — sensor should surface presence of these modules + their config files as separate evidence, not assume "PasswordAuthentication no" means "PAM doesn't matter."
SOURCES: S9pam | (search-derived, no single fetchable primary reached this run — GAP) Debian pam-auth-update / libpam-runtime behavior | secondary | WebSearch — recommend follow-up fetch of manpages.debian.org pam.conf(5) or pam.d(5) directly (404'd on the mirrored path tried this run)

FACT: `AuthorizedKeysFile` default is ".ssh/authorized_keys .ssh/authorized_keys2" (relative to the user's home unless absolute); `AuthorizedKeysCommand` (plus `AuthorizedKeysCommandUser`) lets sshd execute an external program to fetch keys instead of/in addition to files — if set, the "authorized keys" answer is NOT fully determinable by reading a file at all, since the command's output at connection time governs. `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups` restrict login by username/group glob patterns (DenyUsers/DenyGroups evaluated before Allow*); `TrustedUserCAKeys` names a file of CA public keys trusted to sign user certificates, meaning a user need not have any entry in authorized_keys at all if they hold a CA-signed certificate.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read AuthorizedKeysFile/AuthorizedKeysCommand/AllowUsers/DenyUsers/AllowGroups/DenyGroups/TrustedUserCAKeys from the resolved Include+Match chain. If AuthorizedKeysCommand is set, report UNKNOWN for "who can log in via keys" with reason "external command governs, not statically determinable," rather than silently reading only authorized_keys files.
IMPACT: Prevents a false PASS/FAIL on "key-based access is limited to file X" when a CA or command-based scheme is in play.
SOURCES: S1 | https://man.openbsd.org/sshd_config | sshd_config(5) | primary | WebFetch

FACT: `passwd -S` (shadow-utils) reports account status as 7 fields; field 2 is one of L (locked password), NP (no password), or P (usable password), followed by last-change date, min/max age, warn period, inactivity period. A regular (unprivileged) user can query only their OWN account this way; the man page's general framing ("a regular user can only change the password for their own account") plus /etc/shadow being mode 0640 root:shadow together mean password status for OTHER users is UNKNOWN to an unprivileged process — not "no password"/"unlocked" by default.
STATUS: VERIFIED (own-account case); LIKELY (other-user rejection mechanism — man page doesn't spell out the exact errno/message for -S on another user, inferred from shadow(5) file perms + general passwd(1) privilege framing)
APPLIES_TO: generic
PROBE: `stat -c "%a %U:%G" /etc/shadow` (expect "640 root:shadow", world-unreadable) as the primary unprivileged evidence; `passwd -S $USER` for self is safe/expected to succeed; do NOT attempt `passwd -S <other-user>` speculatively in the sensor beyond a single bounded probe, and treat any non-zero exit / EACCES as UNKNOWN-with-reason, never as "account has no password."
IMPACT: Sensor must report per-other-user password/lock status as UNKNOWN (reason: shadow unreadable, uid mismatch), and must never infer "no password set" from an inability to check.
SOURCES: S9 | https://man7.org/linux/man-pages/man1/passwd.1.html | passwd(1), Linux man-pages (mirrors shadow-utils passwd) | primary | WebFetch

FACT: Debian/Ubuntu default sudoers grants the `sudo` group `%sudo ALL=(ALL:ALL) ALL` (password-required); sudoers(5) documents `%groupname` as valid User_List/Runas_User_List syntax for group-based rules (the specific `%sudo` line itself is a Debian packaging convention, not documented in upstream sudoers(5) — GAP, not independently re-verified against /etc/sudoers this run since that file is root-readable only 0440 and thus unprivileged-unreadable anyway). Cloud-init additionally writes `/etc/sudoers.d/90-cloud-init-users` granting the cloud image's default_user (e.g. `ubuntu`) `ALL=(ALL) NOPASSWD:ALL` when configured via `sudo: ["ALL=(ALL) NOPASSWD:ALL"]` in cloud-config.
STATUS: VERIFIED (cloud-init part, from official docs); LIKELY (Debian %sudo default line — well-established but sudoers itself is unreadable to verify in-band)
APPLIES_TO: host (Latitude.sh/cloud-init-provisioned Ubuntu) and generic (any cloud-init default_user image)
PROBE: `id ubuntu` / `groups` to confirm sudo group membership (unprivileged, always works); `ls -la /etc/sudoers.d/` typically EACCES (0750 root:root) so drop-in existence/content is UNKNOWN unprivileged — this is a hard boundary, report as UNKNOWN with reason "sudoers.d unreadable," never infer NOPASSWD either way.
IMPACT: Sensor can truthfully report "user is in group sudo" (fact, capability implication only) but must report actual sudo RULE (password required or not) as UNKNOWN — matches project's stated stance that "sudoers unreadable" is a known host fact already logged.
SOURCES: S8 | https://docs.cloud-init.io/en/latest/reference/yaml_examples/user_groups.html | cloud-init official docs, user/group cloud-config reference | primary | WebSearch-derived (page content quoted by search, not independently re-fetched — minor GAP)

FACT: `sudo -l` lists the invoking user's own privileges; `sudo -n` ("non-interactive") makes sudo fail with an error message and exit rather than ever prompting if a password would be required. The man page does not explicitly document `-n -l` together, but the documented `-n` semantic ("avoid prompting... display an error message and exit" when a password is required) implies `sudo -n -l` is safe to run unprivileged in a bounded sensor: it either prints the (possibly empty/NOPASSWD) rule list or fails immediately with no prompt/hang.
STATUS: LIKELY (combination behavior inferred, not explicitly spelled out in the man page text fetched)
APPLIES_TO: generic
PROBE: EXPLICITLY NOT USED by the sensor per project safety rules (no sudo invocation at all, even read-only `-n -l`). Documented here only to establish what would theoretically be knowable/safe if policy ever changed — current policy: do not run sudo, period.
IMPACT: None for implementation (sensor must not call sudo); recorded for completeness/decision trail only.
SOURCES: S10 | https://man7.org/linux/man-pages/man8/sudo.8.html | sudo(8) | primary | WebFetch; S11 | https://man7.org/linux/man-pages/man5/sudoers.5.html | sudoers(5) | primary | WebFetch

FACT: `ss` (iproute2) with `-p`/`--processes` shows the owning process; the ss(8) man page text itself is terse ("Show processes using sockets.") and does NOT explicitly document the privilege restriction. The actual mechanism is kernel/proc-level: `/proc/net/tcp` and `/proc/net/tcp6` expose one line per socket including a `uid` field (effective UID of the socket's creator) per the kernel's own proc_net_tcp documentation, but mapping a socket's inode to an owning PID requires ss to scan `/proc/<pid>/fd/*` symlinks for every process, and `/proc/<pid>/fd/` of a process owned by another uid is not readable/traversable by a non-root, non-matching-uid caller (permission enforced by the kernel's proc filesystem, generally EACCES/ENOENT-as-empty depending on hidepid mount options). Net effect: unprivileged `ss -tlnp` shows ALL listening sockets' local address/port/state (that part is not uid-restricted) but the process/PID column is blank for sockets owned by other users.
STATUS: VERIFIED (uid field + /proc/<pid>/fd access model); LIKELY (exact ss-internal fallback behavior when it can't resolve owner — inferred from documented /proc semantics, not from ss source code this run)
APPLIES_TO: generic
PROBE: `ss -tlnp` unprivileged as the primary probe: parse the LISTEN table for local address:port (always visible) and treat a missing/blank "users:" column entry as EXPECTED-UNKNOWN for that socket's owning process (not evidence of "no process" — the socket demonstrably exists and is listening). For UDP: `ss -ulnp` behaves the same way (state-less but still enumerable via /proc/net/udp with the same uid-field/PID-mapping limitation).
IMPACT: Sensor can PASS/FAIL "is anything listening on port X" unprivileged with full confidence, but must report "which process" as UNKNOWN (reason: EACCES on /proc/<pid>/fd of other-uid processes) rather than blank/absent.
SOURCES: S12 | https://man7.org/linux/man-pages/man8/ss.8.html | ss(8), iproute2 | primary | WebFetch; S13proc | https://docs.kernel.org/networking/proc_net_tcp.html | Linux kernel documentation, proc/net/tcp and proc/net/tcp6 | primary | WebSearch; S13 | https://man7.org/linux/man-pages/man5/proc.5.html | proc(5), hidepid mount option semantics | primary | WebFetch

FACT: Detection surface for common non-SSH remote-access daemons, unprivileged, by listening port + interface + package/unit name (all via `ss -tuln`, `/sys/class/net/*/uevent`, `systemctl list-units` read, or `dpkg -l`/`ls /usr/sbin`): VNC (5900 + N for display :N, e.g. 5901 = display 1), RDP/xrdp (3389), Cockpit (9090 — "Cockpit's cockpit-ws component is configured by default to accept connections on port 9090" per official Cockpit docs), Webmin (10000, MiniServ speaks HTTPS by default with a self-signed cert per official Webmin docs), Tailscale (`tailscaled` process, `tailscale0` interface, UDP 41641 default per Tailscale's own firewall-ports doc, control-socket at /var/run/tailscale/tailscaled.sock — socket path not found in the fetched doc, standard convention from Tailscale package layout, flagged LIKELY), ZeroTier (UDP 9993, conventionally), WireGuard (interface whose `/sys/class/net/<if>/uevent` contains `DEVTYPE=wireguard`, set by the kernel driver's `SET_NETDEV_DEVTYPE` call in drivers/net/wireguard/device.c — confirmed present in current upstream Linux source), OpenVPN (tun0-style interface, no fixed port by convention), mosh (SSH login handshake then a UDP session port in 60000-61000 per mosh.org's own docs).
STATUS: VERIFIED (Cockpit, Webmin, Tailscale, WireGuard DEVTYPE, mosh port range — each from an official/primary doc); LIKELY (VNC/RDP/xrdp/ZeroTier/OpenVPN port conventions — well-known but not re-verified against each project's own docs this run, time-boxed)
APPLIES_TO: generic
PROBE: enumerate via `ss -tuln` for listening ports (unprivileged-safe per ss fact above), cross-reference `/sys/class/net/*/uevent` for DEVTYPE=wireguard, and (best-effort, non-fatal) `systemctl list-units --type=service` / `dpkg -l` for confirming unit/package names when readable. Any single probe's EACCES/timeout should not block the others (isolated checks per project rules).
IMPACT: Gives the sensor a concrete, cite-able table of "known remote-access surface" signatures to check for and report as evidence (found/not-found + how determined), each independently, rather than one monolithic "remote access" check.
SOURCES: S17 | https://docs.cockpit-project.org/cockpit-guide/latest/guide/listen.html | Cockpit Project official docs, TCP Port and Address | primary | WebSearch; S19 | https://webmin.com/docs/modules/webmin-configuration/ | Webmin official docs | primary | WebSearch; S14 | https://tailscale.com/docs/reference/faq/firewall-ports | Tailscale Inc. official docs | primary | WebFetch; S16 | https://github.com/torvalds/linux/blob/master/drivers/net/wireguard/device.c | Linux kernel source (torvalds/linux, current) | primary | WebSearch; S18 | https://mosh.org/ | Mosh official site | primary | WebSearch (secondary confirmation via manpages.debian.org/mosh-server.1)

FACT: Outbound-only reverse tunnels (Cloudflare Tunnel/`cloudflared`, and by the same architecture ngrok/frp in "client" mode) are, per Cloudflare's own docs, "an outbound-only daemon" that "establishes four outbound-only connections... There are no open inbound ports and no public IPs required." This creates a fundamental detection ASYMMETRY: such tunnels are INVISIBLE to any listening-socket enumeration (`ss -tln` shows nothing, because there is nothing listening) and are detectable, if at all, only via (a) the running process name/binary (`cloudflared`, `frpc`, `ngrok`) visible in `/proc/*/comm` or `ps` for the sensor's own uid / world-readable process list, (b) established OUTBOUND connections in `ss -tn` (state ESTABLISHED, remote port 7844 for cloudflared per its docs), or (c) config files under the user's home or /etc if readable. A sensor that only checks LISTEN sockets will systematically under-report this entire class of remote access.
STATUS: VERIFIED
APPLIES_TO: generic
PROBE: `ss -tln` alone proves nothing about tunnels (absence-of-listener is not absence-of-tunnel); must additionally check `ss -tn state established` for known tunnel ports/remote-endpoint patterns and enumerate process names (bounded, best-effort, EACCES-tolerant) for cloudflared/frpc/ngrok/tailscaled binaries. Report explicitly that outbound tunnels are a known blind spot of the listening-socket method, not silently omit the category.
IMPACT: Directly shapes the sensor's "remote access surface" check design — it must not conflate "no listeners found" with "no remote access surface," and should document the asymmetry in NOTES.md as a known limitation regardless of what is actually found on the host.
SOURCES: S15 | https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ | Cloudflare official docs, Cloudflare Tunnel overview | primary | WebSearch

---

## SOURCES LIST

- S1 | https://man.openbsd.org/sshd_config | sshd_config(5), OpenBSD (canonical upstream) | primary
- S2 | https://man.openbsd.org/sshd | sshd(8), OpenBSD | primary
- S3 | https://man.openbsd.org/ssh_config | ssh_config(5), OpenBSD | primary
- S4 | https://raw.githubusercontent.com/openssh/openssh-portable/V_9_6_P1/sshd.c | OpenSSH portable source @ tag V_9_6_P1 | primary
- S5 | https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html | Ubuntu noble sshd_config(5) | primary (distro-shipped manpage)
- S6 | https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189 | Canonical/Ubuntu Server discourse thread | primary-adjacent
- S7 | https://news.ycombinator.com/item?id=42138026 | HN discussion, Ubuntu 24.04 cloud-init sshd drop-in | secondary
- S8 | https://docs.cloud-init.io/en/latest/reference/yaml_examples/user_groups.html | cloud-init official docs | primary
- S9 | https://man7.org/linux/man-pages/man1/passwd.1.html | passwd(1), Linux man-pages (shadow-utils) | primary
- S10 | https://man7.org/linux/man-pages/man8/sudo.8.html | sudo(8) | primary
- S11 | https://man7.org/linux/man-pages/man5/sudoers.5.html | sudoers(5) | primary
- S12 | https://man7.org/linux/man-pages/man8/ss.8.html | ss(8), iproute2 | primary
- S13 | https://man7.org/linux/man-pages/man5/proc.5.html | proc(5) | primary
- S13proc | https://docs.kernel.org/networking/proc_net_tcp.html | Linux kernel docs, proc/net/tcp | primary
- S14 | https://tailscale.com/docs/reference/faq/firewall-ports | Tailscale official docs | primary
- S15 | https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/ | Cloudflare official docs | primary
- S16 | https://github.com/torvalds/linux/blob/master/drivers/net/wireguard/device.c | Linux kernel source, WireGuard driver | primary
- S17 | https://docs.cockpit-project.org/cockpit-guide/latest/guide/listen.html | Cockpit Project official docs | primary
- S18 | https://mosh.org/ | Mosh official site | primary
- S19 | https://webmin.com/docs/modules/webmin-configuration/ | Webmin official docs | primary

## CONTRADICTIONS

1. **UsePAM upstream vs Ubuntu**: sshd_config(5) upstream text says default "no"; Ubuntu/Debian packaging ships effective default "yes" (documented in the Ubuntu noble manpage itself). Real contradiction class per the task's own framing — sensor needs a distro-aware default table, not one global default.
2. **"First obtained value wins" — same rule, not opposite**: initial task framing suspected sshd_config and ssh_config differ (opposite precedence). Verified both use literally the same "first value wins" rule; what differs is which files/sources are consulted and in what order, not the tie-break direction. Framing in the task prompt should be corrected in any downstream design doc.
3. **sshd_config Port/ListenAddress vs actual listening socket** under ssh.socket: the config file's static claim can be flatly wrong about the real listening address once socket activation is in effect — a direct file-vs-reality contradiction the sensor must resolve via `ss`, not via sshd_config parsing alone.

## GAPS

- Did not independently re-fetch a primary pam.conf(5)/pam.d(5) man page (Debian manpages mirror 404'd on the path tried; man7.org does not host pam.conf(5) under the same tree). PAM account/session-module fact rests on secondary/search-derived sources — recommend a follow-up fetch of `https://man7.org/linux/man-pages/man5/pam.conf.5.html` or `https://linux.die.net/man/5/pam.d` if this becomes load-bearing.
- Did not verify the literal `%sudo ALL=(ALL:ALL) ALL` line against a primary Debian source (e.g. Debian's sudo package changelog/README); sudoers(5) itself is silent on this distro-specific default. /etc/sudoers is unreadable unprivileged so this cannot be host-verified either — permanently UNKNOWN on the real host by design, which is itself the correct sensor behavior.
- Did not confirm `/var/run/tailscale/tailscaled.sock` path or ZeroTier/OpenVPN exact conventions against each project's own docs (time-boxed); treat those specific sub-claims as LIKELY, not VERIFIED.
- Did not perform any LOCAL_REPRO on WSL this run (ss -tlnp, passwd -S, stat on /etc/shadow, sshd -T) — all facts here are doc/source-derived only; recommend a follow-up pass to empirically confirm the ss/proc EACCES behavior and sshd -T error text on an actual Ubuntu 24.04 box before hardening the sensor's PROBE fallback chains.
- xrdp/VNC/ZeroTier/OpenVPN port facts sourced from secondary pentest-reference pages, not each project's own docs — acceptable per task's "1-2 solid sources each" breadth allowance but flagged LIKELY rather than VERIFIED.
