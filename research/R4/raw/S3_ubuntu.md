# S3 — Ubuntu 24.04 specific behaviours (track R4)

Scope: research only, no host access. Target host facts assumed as given in the task
brief. WSL2 Ubuntu 26.04 (kernel 6.18.33.2-microsoft-standard-WSL2) used for
LOCAL_REPRO where noted; it is NOT the target and diverges in important ways
(custom Microsoft kernel: no AppArmor LSM compiled in, no lockdown LSM, no EFI/efivars,
no sshd installed, cloud-init present but self-disabled via ds-identify). Divergences
are called out explicitly per question.

---

## Q1 — sshd socket activation on Ubuntu 24.04

**What changed, by release (primary: Canonical/Ubuntu discourse post, staff-authored):**
- Ubuntu 22.10 (`openssh-server` 1:9.0p1-1ubuntu1): OpenSSH switched to systemd socket
  activation by default. `ssh.socket` listens; `sshd` is not resident until a connection
  arrives. Stated rationale: memory savings in VMs/containers (~3MiB/instance, ~5% of an
  idle LXD container).
- Ubuntu 22.10/23.04/23.10: on **upgrade**, a pre-existing `Port`/single `ListenAddress`
  in `sshd_config` was migrated into `/etc/systemd/system/ssh.socket.d/addresses.conf`.
  If more than one `ListenAddress` was configured, migration was skipped (systemd
  `ListenStream` semantics differ: a configured-but-absent-at-boot address prevents
  `ssh.socket` from starting at all, and this can't be reliably predicted at upgrade
  time) — such hosts keep the traditional service-started-at-boot behaviour instead.
- **Ubuntu 24.04 LTS (noble)**: settings are **no longer migrated**; instead "the port
  and address settings are pulled dynamically from sshd\[_\]config via a systemd
  generator" — i.e. a generator reads `sshd_config` at boot and produces the effective
  socket listen directives, so `ListenStream=` in the socket unit's drop-ins is not the
  sole source of truth; the *config file* is (through the generator), which is a
  deliberate change from 22.10-23.10 behaviour.
- Both `ssh.socket` and `ssh.service` **being simultaneously "active" is normal, not a
  misconfiguration.** Confirmed by Canonical maintainer Nick Rosbrook on Launchpad bug
  #2020560: "It is expected that you have both ssh.socket and ssh.service on your
  system. The ssh.socket unit is enabled by default and is responsible for listening on
  the configured port. Once it receives a connection it activates ssh.service." This
  directly matches the target host's observed state (both active) — that state is
  expected under Ubuntu's model and requires no further explanation/flag in the sensor.
- Practical operational gotcha (same bug thread, repeated across many other bug/forum
  reports): after changing socket-related settings you must `systemctl restart
  ssh.socket`, not `ssh.service` — restarting `ssh.service` does not reload the listen
  configuration and is the most common cause of user confusion in the wild.
- Reverting to fully traditional (pre-22.10) behaviour requires disabling `ssh.socket`
  **and** removing the drop-in `/etc/systemd/system/ssh.service.d/00-socket.conf`
  (undocumented until Launchpad bug #2017434 was filed; the openssh-server
  README.Debian.gz was inaccurate on this point after 1:9.0p1-1ubuntu4).

**`sshd -i` vs `-D`:** `-i` is classic inetd/socket-activation mode: sshd assumes
stdin/stdout are already a connected socket (passed in by the activator — inetd or
systemd) and services exactly one connection without daemonizing or listening itself.
`-D` is "don't detach and become a daemon" — it still does its own listen()/accept()
loop in the foreground; this is the mode used when `ssh.service` runs directly (no
socket activation) via `ExecStart=/usr/sbin/sshd -D $SSHD_OPTS` in the traditional unit.
Socket-activated invocation on Ubuntu passes `-i` implicitly through
`Accept=`/`ExecStart=` wiring in `ssh.socket`/`ssh@.service`-style plumbing (per the
above discourse thread and systemd.socket semantics below); could not fetch the exact
Ubuntu `ssh.socket`/`ssh.service` unit file text this session (Launchpad cgit URLs
returned HTML wrapper only, not raw plain text, in the time available — see SOURCES).

**systemd.socket semantics (secondary — fetch of the primary freedesktop.org page was
blocked, HTTP 403; relying on Ubuntu discourse + general systemd knowledge cited
there):** `ListenStream=` in a `.socket` unit defines what systemd itself binds/listens
on; when `Accept=no` (the normal case for a forking daemon like sshd), systemd keeps a
single listening socket open, and on each connection starts the associated `.service`
unit, passing it the listening socket via `LISTEN_FDS`. This is why, on 24.04, the
*actual* bound address/port is controlled by whatever the socket unit + drop-ins
resolve to (themselves generated dynamically from `sshd_config` by a systemd generator)
rather than by `sshd_config`'s own `Port`/`ListenAddress` directives being read by a
long-running daemon — those directives in `sshd_config` are cosmetically still present
but ignored for *what to listen on* under socket activation (the discourse thread notes
Ubuntu still ships `#ListenAddress`/`#Port` commented lines with **no** warning that
they're inert under socket activation — an acknowledged documentation gap raised in the
same thread).

**Correct UNPRIVILEGED way to determine what's actually in force (synthesis, no single
source states all of this, but each element is independently confirmed above/below):**
1. `ss -ltnp` (or `-ltn` unprivileged, PID/process column blank without root) — ground
   truth for what is actually bound and listening, regardless of any config.
2. `systemctl show ssh.socket -p Listen*,SubState,ActiveState` / `systemctl cat
   ssh.socket ssh.service` (unprivileged users can read unit files and query systemd
   state) — shows the resolved `ListenStream=` values systemd computed, including
   generator/drop-in overrides. `systemctl cat` lists drop-ins in application order.
3. Parse `/etc/ssh/sshd_config` **honouring Include-at-point-of-inclusion +
   first-obtained-value-wins** (Q3) to see what the daemon *would* use if socket
   activation were bypassed — useful as a secondary/contextual signal, not the source
   of truth for the actually-bound address on 24.04.
4. None of the above requires root; `sshd -T` (config dump) is **not** part of this list
   because it cannot run unprivileged at all (Q2).

## Q2 — `sshd -T` privilege requirement (openssh-portable source, confirmed by direct read)

Fetched `sshd.c` from `github.com/openssh/openssh-portable` (master, primary source).
Line numbers below are from that fetch (2026 master; drifts release to release but the
control flow is stable across OpenSSH 9.x per the accompanying commit history and is
the same structure OpenSSH 9.6 — Ubuntu's shipped version — uses):

- `-t` sets `test_flag = 1`; `-T` sets `test_flag = 2` (`sshd.c:1420-1423`).
- Immediately after option parsing and config parsing (`parse_server_config`,
  `fill_default_server_options`), the code reaches an unconditional block: **"load host
  keys"** (`sshd.c:~1567` onward) that runs regardless of `test_flag`. There is **no
  `if (test_flag) goto skip_keys;` or similar guard** — every configured
  `HostKey` file is passed to `sshkey_load_private()` in a loop.
- For each host key file: `sshkey_load_private()` (needs read access to the private key,
  e.g. `/etc/ssh/ssh_host_rsa_key`, mode 0600 root:root) is attempted; if it fails with
  a permission-class error (`SSH_ERR_SYSTEM_ERROR`) and there's no key agent, the loop
  falls through: `sshkey_load_public()` (reads the `.pub` file, normally 0644 and
  world-readable) may still succeed, but if `key == NULL` (private not loaded) and
  `!have_agent`, the code takes the **"Unable to load host key"** branch, discards both
  `host_keys[i]` and `host_pubkeys[i]`, and `continue`s — i.e. a readable `.pub` file
  alone does **not** count.
- After the loop: `if (!sensitive_data.have_ssh2_key) { logit("sshd: no hostkeys
  available -- exiting."); exit(1); }` (`sshd.c:1672-1675`) — **this check happens
  before** the `if (test_flag > 1) print_config(...)` / `if (test_flag) exit(0);` block
  later in `main()` (`sshd.c:~1745-1755`). So an unprivileged invocation can never reach
  the point where `-T`'s actual job (print effective config) executes: it dies first on
  the hostkey-loading gate.
- **Conclusion (VERIFIED from source): there is no flag combination — `-f`, `-C`, or
  otherwise — that lets `sshd -T` succeed unprivileged with the stock Ubuntu host-key
  setup (0600 private keys, no ssh-agent holding them).** The only theoretical
  workaround is a running `ssh-agent`/`HostKeyAgent` already holding the private host
  keys — not a normal unprivileged-user scenario and irrelevant to this sensor.
- Could not find a version-specific OpenSSH changelog entry that changed this behaviour;
  the `have_ssh2_key` gate long predates privsep-per-connection refactors and is
  structurally the same across the 8.x/9.x line based on this source read. No
  version-to-version behavioural *difference* found; treat as stable across the
  OpenSSH versions in scope.
- practical implication for the sensor: never attempt `sshd -T` as evidence. If the
  target's own docs/scripts assume it works read-only, that assumption is wrong for any
  properly-permissioned Ubuntu host.

## Q3 — OpenSSH 9.6 `sshd_config` semantics (primary: manpages.ubuntu.com/noble, package
openssh-server 1:9.6p1-3ubuntu13.19 — this is the exact version string reported on the
target host)

- **Default rule:** "Unless noted otherwise, for each keyword, the first obtained value
  will be used." (verbatim from the man page).
- **Explicitly additive/multiple keywords** (each instance appends rather than
  overwrites): `AcceptEnv`, `AllowGroups`, `AllowUsers`, `DenyGroups`, `DenyUsers` are
  explicitly documented as appending. `HostKey`, `Port`, `ListenAddress`, and
  `Subsystem` are used in the singular-directive-but-multiple-occurrences sense (each
  occurrence adds a host key file / listen port / listen address / subsystem
  definition to a list) rather than "first wins" — functionally additive even though the
  man page's blanket "first obtained value" line technically applies per-keyword-slot
  logic that OpenSSH implements individually per option; the practical parser
  consequence is the same: don't assume last-line-wins for these.
- **Ubuntu-specific defaults the Debian/Ubuntu package layers on top of upstream
  defaults (documented in the same man page, distinct from upstream OpenSSH defaults):**
  `Include /etc/ssh/sshd_config.d/*.conf`, `KbdInteractiveAuthentication no`,
  `X11Forwarding yes`, `PrintMotd no`, `AcceptEnv LANG LC_*`, `Subsystem sftp
  /usr/lib/openssh/sftp-server`, `UsePAM yes`.
- **Include placement is load-bearing:** "`/etc/ssh/sshd_config.d/*.conf` files are
  included **at the start of** the configuration file, so options set there will
  override those in `/etc/ssh/sshd_config`" (verbatim). Combined with first-wins
  semantics: because the `Include` line is the very first non-comment directive in
  Ubuntu's shipped `sshd_config`, anything set in a drop-in under `sshd_config.d/`
  **wins** over a same-keyword line appearing later in the main file — this is exactly
  the target host's situation (`00-latitude-instant-deploy.conf` sets
  `PasswordAuthentication no` + `KbdInteractiveAuthentication no`, and because it's
  pulled in via the first-line `Include`, those values are authoritative even though
  the shipped `sshd_config` also carries its own defaults for the same keywords later in
  the file). **A correct sshd_config parser must process Include inline at the point of
  occurrence, not after finishing the rest of the file**, or it will get first-wins
  precedence backwards.
- **Match block scoping:** "If all of the criteria on the `Match` line are satisfied,
  the keywords on the following lines override those set in the global section" and this
  applies "until either another `Match` line or the end of the file." **First-match
  wins** across multiple satisfied `Match` blocks for the same keyword (only the first
  applicable occurrence is used) — same directional rule as the global section. Only a
  restricted keyword subset is legal inside `Match` (excludes global-only settings such
  as `Port`, `Ciphers`, etc.) — a config parser needs an allowlist, not just brace/scope
  tracking, to validate this correctly, though the sensor likely doesn't need to
  validate legality, only read effective values.

## Q4 — cloud-init on provider images

**Sudoers (primary: `canonical/cloud-init` GitHub source, direct fetch of
`cloudinit/distros/__init__.py`, main branch):**
- `ci_sudoers_fn = "/etc/sudoers.d/90-cloud-init-users"` is a literal class attribute —
  **confirmed this is the actual filename**, not folklore.
- `write_sudo_rules()` writes the file (if it doesn't already exist) via
  `util.write_file(sudo_file, ..., 0o440)` — **mode 0440**. Owner is root (cloud-init
  runs as root at this stage; `util.write_file` doesn't `chown` away from the invoking
  uid, which is root during boot-time cloud-init execution). This matches — and
  explains — the target host's observation that `/etc/sudoers.d` (0750 root:root) and
  its contents are EACCES to the unprivileged `ubuntu` user: **0440 root:root is the
  cloud-init default for this specific file, not an anomaly**, and the sensor should not
  interpret unreadability here as unusual hardening.
- Typical content is `<user> <sudo-rule-string>` lines, e.g. for the default
  `ubuntu` cloud-image user the common rule is `ubuntu ALL=(ALL) NOPASSWD:ALL` (from
  cloud-init's own reference docs' user/group examples) — could not directly confirm
  the *exact* rule string cloud-init injects for Latitude.sh's specific image without
  host access (out of scope — recon forbidden), but the `90-cloud-init-users`
  file/mode/mechanism is VERIFIED from source, and `~/.sudo_as_admin_successful`
  existing on the target is consistent with sudo access having been exercised at least
  once, indirectly corroborating a NOPASSWD-or-otherwise-functional sudo rule exists for
  `ubuntu` (cannot prove NOPASSWD specifically without reading the unreadable file).

**Instance data files (secondary — could not get a primary cloud-init doc page to load
via WebFetch/trafilatura in the time available; multiple consistent secondary sources
agree):**
- `/run/cloud-init/instance-data.json` — **world-readable**, sensitive keys redacted.
- `/run/cloud-init/instance-data-sensitive.json` — **root-only**, unredacted, contains
  everything in `instance-data.json` plus the redacted sensitive content.
- Exact filenames confirmed consistently across cloud-init's own docs (via search
  snippets referencing `docs.cloud-init.io/.../instancedata.html`) and a real disclosed
  bug (`canonical/cloud-init#4093`, "cloud-init leaks credentials") that specifically
  discusses `instance-data.json` permissions — treat filenames/modes as VERIFIED,
  treat "always exactly this and never regressed" as LIKELY only (the linked bug shows
  at least one historical permission regression incident).
- Design impact: sensor should read `instance-data.json` only (world-readable by
  design) and must never attempt `instance-data-sensitive.json` even opportunistically
  — that would violate the "no secret values" and "unprivileged" invariants even if a
  misconfigured host happened to make it readable.

## Q5 — AppArmor status semantics on 24.04

- `/sys/module/apparmor/parameters/enabled = Y` proves only that **the AppArmor LSM was
  compiled into the running kernel and the module parameter reports enabled** — a
  kernel-build-time/boot-time fact. It proves **nothing** about: whether the userspace
  `apparmor` package is installed, whether `apparmor.service` ran, whether any profile
  is loaded, or whether any process is actually confined. (Reasoning from Ubuntu's own
  `apparmor(7)` man page structure: profile loading is a distinct, separate step via
  `apparmor_parser(8)`/`apparmor.service`, not implied by the kernel flag.)
- **Which unprivileged reads give real enforcement data:**
  - `/sys/kernel/security/apparmor/profiles` — **VERIFIED file mode 0444** directly from
    upstream kernel source (`torvalds/linux`, `security/apparmor/apparmorfs.c`:
    `AA_SFS_FILE_FOPS("profiles", 0444, &aa_sfs_profiles_fops)`). This is **world-
    readable by file-mode**, contrary to the common "sudo cat" habit seen in blog
    tutorials (those are precautionary/muscle-memory, not a hard requirement per the
    kernel's own mode bits). Actual readability in practice additionally requires (a)
    securityfs mounted at `/sys/kernel/security` (normally auto-mounted at boot by
    systemd/apparmor's init integration on any 24.04 image where it's used at all) and
    (b) the parent directories being traversable (`/sys/kernel/security` is typically
    0755). **CONTESTED as a blanket claim** — treat "readable" as the kernel-source-
    verified default and let an actual EACCES on the real host override it (evidence >
    assumption, per this project's own invariants).
  - `/proc/self/attr/apparmor/current` — reports the *current process's own* profile
    confinement (e.g. "unconfined" or a profile name); a way to check what confinement
    (if any) applies to the sensor's own process, not a system-wide enforcement count.
    (Could not verify exact unprivileged-readability behaviour on a real AppArmor-
    enabled kernel this session — WSL2's kernel has no AppArmor LSM at all, so
    `/proc/self/attr/apparmor/current` returned `EINVAL` there, which is a WSL artifact,
    **not** representative of Ubuntu 24.04 bare metal; do not generalize from this
    LOCAL_REPRO result.)
  - `/sys/kernel/security/apparmor/policy/` — not independently verified this session;
    treat as SPECULATIVE (analogous introspection path suggested by apparmorfs.c
    structure, not directly confirmed).
- **Package providing `aa-status`:** Directly confirmed via `packages.ubuntu.com`
  noble filelist for the **`apparmor`** package (not `apparmor-utils`): the file list
  includes `/usr/sbin/aa-status`, `/usr/sbin/aa-teardown`, `/usr/bin/aa-enabled`,
  `/usr/bin/aa-exec`, etc. `apparmor-utils` is a separate, optional package providing
  additional profile-authoring helpers (`aa-genprof`, `aa-logprof`, etc.), per Ubuntu
  security documentation — **VERIFIED**: `aa-status` ships in base `apparmor`, not
  `apparmor-utils`.
  - This means the target host's observed state ("aa-status NOT installed") implies the
    base `apparmor` **package itself is absent**, even though the kernel LSM flag is
    `Y`. This is consistent with Ubuntu's minimized cloud/server images shipping a
    kernel with AppArmor compiled in (from the generic kernel config) while not
    installing the full userspace `apparmor` package/profiles by default on every image
    variant. Design impact: the sensor must treat "LSM enabled" and "userspace tooling
    present" as two independent booleans, and report both, rather than inferring one
    from the other.

## Q6 — Kernel lockdown and Secure Boot / UEFI Setup Mode

- `/sys/kernel/security/lockdown` format: `[none] integrity confidentiality` — the
  bracketed word is the active mode (VERIFIED against kernel_lockdown(7) semantics: the
  three symbolic modes are none/integrity/confidentiality).
- **Ubuntu auto-enables lockdown under Secure Boot** — per `manpages.ubuntu.com/noble`
  `kernel_lockdown(7)` (Ubuntu-distributed man page, treated as primary for Ubuntu's
  packaging intent): "On an EFI-enabled x86 or arm64 machine, lockdown will be
  automatically enabled if the system boots in EFI Secure Boot mode." Multiple secondary
  sources (Ubuntu security docs summaries, Gentoo wiki citing the same Ubuntu kernel
  config) corroborate this has applied since Ubuntu 20.04 via
  `CONFIG_LOCK_DOWN_IN_SECURE_BOOT=y` / `CONFIG_ALLOW_LOCKDOWN_LIFT_BY_SYSRQ=y`, i.e. the
  lockdown-on-secure-boot linkage is an Ubuntu kernel config choice layered on top of
  the generic upstream lockdown LSM (which itself only auto-enables via the same EFI
  Secure Boot signal upstream — this isn't actually an Ubuntu-only patch behaviourally,
  Ubuntu's specific contribution is just enabling the relevant Kconfig options).
  Enabling mechanism otherwise: `lsm=...,lockdown` on the kernel command line, or the
  deprecated `security=` parameter, or `CONFIG_LSM` build default.
  **Directly explains the target host: Secure Boot is DISABLED, therefore lockdown =
  `[none]` is the expected, correctly-derived state — not a hardening gap needing
  explanation, just the logical consequence of Secure Boot being off.**
- **UEFI "Setup Mode" (primary: uefi.org UEFI Specification, Chapter 32 "Secure Boot and
  Driver Signing"):** the `SetupMode` global variable is 0 once a Platform Key (PK) is
  enrolled, and becomes 1 when the PK is cleared/absent. "While no Platform Key is
  enrolled... the platform is said to be operating in setup mode." While `SetupMode ==
  0` (PK enrolled), firmware requires authenticated updates to PK/KEK/OsRecoveryOrder/
  security databases; in Setup Mode those can be modified without authentication. "A
  platform cannot operate in secure boot mode if the SetupMode variable is set to 1" —
  i.e. Setup Mode and Secure Boot enforcement are **mutually exclusive by
  specification**, confirming (independent of the Ubuntu-specific lockdown note above)
  that the target host's combination of "Secure Boot disabled + Setup Mode" is
  internally consistent per spec, not two independent facts that happen to coexist —
  Setup Mode essentially *requires* Secure Boot to be non-enforcing.
- `/sys/kernel/security/lockdown` readability: **could not verify unprivileged
  readability on a real Ubuntu kernel this session.** WSL2's kernel does not compile in
  the lockdown LSM at all (`/sys/kernel/security/lockdown` is simply absent —
  `ls`/`cat` both return "No such file or directory"), so this LOCAL_REPRO result is a
  WSL-environment artifact, not evidence about Ubuntu bare-metal readability, and must
  not be used as a stand-in for the real host. Based on how other securityfs lockdown-
  adjacent files are typically exposed (world-readable status files being the norm for
  this class of introspection file, by analogy with the AppArmor `profiles` file mode
  found in Q5), LIKELY world-readable, but this is inference, not verification —
  flagged explicitly as unconfirmed.

## Q7 — `dmesg_restrict` semantics (kernel.rst, kernel.org — primary, partially
retrieved; kernel source for the /dev/kmsg linkage)

- **`kernel.dmesg_restrict`** (from `Documentation/admin-guide/sysctl/kernel.rst`, via
  WebFetch summary of the primary doc): 0 = "no restrictions" on `dmesg(8)`; 1 = caller
  must hold **`CAP_SYSLOG`** to use `dmesg(8)`. Default value is controlled by the
  `CONFIG_SECURITY_DMESG_RESTRICT` kernel build option (compiled-in default, which the
  sysctl can then override upward or downward depending on distro policy — Ubuntu ships
  it as a runtime sysctl set to 1, per the target host facts already established).
- **Does it also cover `/dev/kmsg`?** Yes — but this was historically a **separate,
  initially-missed code path**: per an LKML thread ("kmsg: Honor dmesg_restrict sysctl
  on /dev/kmsg"), the original `dmesg_restrict` implementation covered the `syslog(2)`
  syscall path but a refactor "inadvertently dropped the checks for dmesg_restrict on
  /dev/kmsg." Once util-linux ≥2.22 made `dmesg(1)` itself default to reading directly
  from `/dev/kmsg` (bypassing the syscall) on kernels newer than 3.5, that gap became
  practically exploitable, and the fix added an explicit check in `devkmsg_open()`:
  `if (dmesg_restrict && !capable(CAP_SYSLOG)) return -EACCES;`. **Both paths
  (`syslog(2)` and `open("/dev/kmsg")`) are gated by `dmesg_restrict` + `CAP_SYSLOG` on
  any kernel with this fix** (which is old enough — the LKML thread predates 2013 — to
  be present in every kernel of relevance here, including 6.8.0-139 and 7.0.0-31).
- **Exact error observed:** `EACCES` ("Permission denied") on `/dev/kmsg` open, and the
  `dmesg(8)` utility surfaces this as its own error text when `dmesg_restrict=1` and the
  caller lacks `CAP_SYSLOG` (matches the target host's established behaviour: `dmesg` ->
  EPERM/EACCES-class failure).
- Could not confirm whether `/proc/kmsg` (the legacy, non-`/dev` interface) is also
  gated identically — not found in the sources retrieved this session; flagged as
  unconfirmed (LIKELY same gating by analogy/shared underlying `check_syslog_permission`
  helper referenced in an unretrieved LKML patch title, but not directly read).

## Q8 — Pending-reboot / kernel drift signals, unattended-upgrades defaults

- **What creates `/var/run/reboot-required`:** the **`update-notifier-common`** package
  ships an APT hook (secondary sources consistently point to
  `/etc/apt/apt.conf.d/99update-notifier` plus scripts under
  `/usr/lib/update-notifier/`) that runs after `dpkg`/`apt` operations and — when a
  newly-installed kernel/library differs from the running one — writes the marker file.
  **Confirmed via LOCAL_REPRO that the causal package can simply be absent:** in the WSL
  image, `dpkg -l update-notifier-common` shows status `un` (not installed), and
  correspondingly there is no `/var/run/reboot-required`. This directly supports the
  brief's premise: **a host can have a newer kernel installed and running-kernel drift
  without the marker existing, if `update-notifier-common` was never installed** (e.g.
  stripped from a minimal cloud/bare-metal provisioning image) — the *absence of the
  marker is not evidence of absence of drift*, only evidence the hook never ran or the
  package isn't present.
- **Other unprivileged signals for "running kernel != newest installed kernel" —
  reliability assessment:**
  - `uname -r` vs `/boot/vmlinuz-*` file listing (or the `vmlinuz`/`initrd.img` symlinks
    when present, as already established for the target: they point at 7.0.0-31) —
    **reliable and directly matches this project's own established target-host
    evidence.**
  - `/lib/modules/<version>/` directory existence for versions other than the running
    one — **reliable**, a standard side effect of kernel package installation
    (`linux-modules-*` postinst populates this directory), readable by any user
    (0755-class dirs under `/lib/modules`).
  - `dpkg -l 'linux-image-*'` — **reliable**, ordinary dpkg query, no special
    permission needed; shows every installed kernel image package and can be compared
    against `uname -r`.
  - Overall: the vmlinuz-symlink + `/lib/modules` + `dpkg -l` triad is a strictly
    stronger and more portable signal than `/var/run/reboot-required`, which depends on
    a specific optional package having been installed and having actually run its hook.
    The sensor should treat `reboot-required` presence as a (weak) positive signal and
    its absence as **inconclusive**, deferring to the kernel-version-comparison triad as
    the primary evidence.
- **`unattended-upgrades` defaults on 24.04 (LOCAL_REPRO, WSL Ubuntu 26.04 image, cross-
  checked against secondary docs for 24.04 specifically since WSL isn't the same image
  class):**
  - Package **is installed** in the WSL cloud-style image (`ii unattended-upgrades
    2.12ubuntu9`), and `/etc/apt/apt.conf.d/20auto-upgrades` contains
    `APT::Periodic::Update-Package-Lists "1";` and
    `APT::Periodic::Unattended-Upgrade "1";` — i.e. periodic security-update
    installation is **on** by default in this image class.
  - `/etc/apt/apt.conf.d/50unattended-upgrades`: `Unattended-Upgrade::Automatic-Reboot`
    line is present but **commented out** (`//Unattended-Upgrade::Automatic-Reboot
    "false";`), meaning the shipped **default, when the line is absent/commented, is
    `false`** — i.e. Ubuntu does **not** auto-reboot on unattended security updates by
    default, matching Ubuntu's own documentation summary found via search ("regular
    server images and public cloud instances" install security updates daily by
    default, but minimal images/cloud instances/containers may lack it or need manual
    enabling — LIKELY, not independently re-verified against a primary Canonical doc
    page this session beyond the search-engine summary). This is consistent with — and
    explains why — a host could have unattended security-kernel-package installs
    happening silently while never auto-rebooting into them, reinforcing the kernel-
    drift-without-marker scenario in Q8 above as a plausible, even expected, steady
    state rather than an anomaly.
  - Caveat: WSL's Ubuntu is not identical to a Latitude.sh-provisioned bare-metal image;
    treat the *installed-by-default* claim as LOCAL_REPRO-supported but not host-
    confirmed, and the *Automatic-Reboot default false* claim as a property of the
    packaged config file template shipped by the `unattended-upgrades` **package**
    itself (same package/version family across image types), which is a stronger,
    more portable claim than "installed by default" per se.

## Q9 — `/etc/machine-id` provenance (primary: `manpages.ubuntu.com/noble/man5/machine-id.5.html`, systemd 255.4-1ubuntu8.17)

- Generated by **`systemd-machine-id-setup(1)`** at install time, or by systemd itself
  during early boot if the file is empty/missing (first-boot semantics); mode **0444**
  is the documented/standard mode for the file (directly matches the target host's
  observed 0444 and the WSL LOCAL_REPRO's identical `-r--r--r--` mode — this is a
  systemd-wide constant, not Ubuntu-specific, and safely portable across the fleet).
- **Empty/missing file semantics:** "For operating system images which are created once
  and used on multiple machines, for example for containers or in the cloud,
  `/etc/machine-id` should be either missing or an empty file in the generic file system
  image... An ID will be generated during boot and saved to this file if possible." This
  is exactly the mechanism that makes machine-id **stable across reboots of the same
  instance** (once generated and written, it persists) but **not automatically unique
  across a re-image** unless the imaging process resets it to empty — a generic golden
  image that failed to clear `/etc/machine-id` before capture would produce **duplicate
  machine-ids across every instance deployed from it** (a known cloud-imaging pitfall,
  not explicitly stated in this exact framing in the fetched man page but a direct,
  necessary consequence of the documented mechanism).
- **Security caveat — direct quote from the man page:** "This ID uniquely identifies the
  host. It should be considered "confidential", and must not be exposed in untrusted
  environments, in particular on the network. If a stable unique identifier that is tied
  to the machine is needed for some application, the machine ID or any part of it must
  not be used directly. Instead the machine ID should be hashed with a cryptographic,
  keyed hash function..." **Design impact: the sensor must NOT emit the raw
  `/etc/machine-id` value into `findings.json` as an identifier/evidence value** — doing
  so would violate both this systemd-documented caveat and this project's own "no secret
  values in evidence" invariant. If a stable host identifier is needed in output, it
  must not be the raw machine-id (e.g. omit it, or note only its presence/mode/whether
  it's empty, never its content).
- Machine-id is stable across reboots (by design, once written) and explicitly **not**
  guaranteed stable/unique across a re-image unless the imaging pipeline handles it
  correctly (see above) — VERIFIED mechanism, LIKELY-not-CONFIRMED for this specific
  Latitude.sh image's imaging hygiene (out of scope to check further; the sensor should
  just report presence/mode, not assume uniqueness guarantees).

## Q10 — snapd, netplan, systemd-resolved stub on a 24.04 server image

- **snapd/default snaps:** Ubuntu 24.04 (noble) **removed** `lxd`, `snapd` (as a
  preseeded snap payload) and `core22` from the default server ISO/seed
  (`ubuntu-meta` Launchpad bug #2051572, discussing *re-adding* them, which confirms by
  omission that noble's default server seed shipped without them, with a request to
  reconsider due to slower first-use `snap install lxd` performance without pre-caching).
  **VERIFIED at the seed-policy level; not independently re-confirmed against a live
  Latitude.sh image (out of scope/no host access).** LOCAL_REPRO (WSL) is not
  representative here either — WSL images customize the snap payload for WSL-specific
  reasons and showed `snap` binary present but zero snaps installed, consistent with,
  but not proof of, the noble server-seed policy.
- **netplan file permissions on a cloud-init-provisioned image:** cloud-init's
  `NETPLAN_CONFIG_ROOT_READ_ONLY` feature flag (referenced directly in Launchpad bug
  #2048828) makes cloud-init render `/etc/netplan/50-cloud-init.yaml` as **root-read-only
  (0600)** rather than the historical world-readable 0644, specifically to stop
  netplan.io ≥0.106.1-7 from emitting "Permissions... too open" warnings and to prevent
  leaking e.g. wifi passwords from V2 passthrough configs. This flag is true for Jammy
  and later per the same bug thread (**"can be removed after Jammy is no longer
  supported,"** implying Noble ships with the fixed/0600 behaviour as the unconditional
  default, not a feature-flagged special case) — **LIKELY VERIFIED for 24.04** (the bug
  thread is explicit about the flag being needed only for Jammy backport purposes, i.e.
  Noble's baseline already does the right thing). A sensor checking netplan file modes
  should expect **0600**, not 0644, on a modern (23.1+ cloud-init) 24.04 image, and
  should not flag 0600 as unusually restrictive — it's the current shipped default.
- **`systemd-resolved` stub semantics:** `127.0.0.53:53` is the well-known systemd-
  resolved "stub listener" address — `/etc/resolv.conf` on a systemd-resolved-managed
  host normally points here (or is a symlink to
  `/run/systemd/resolve/stub-resolv.conf`), and actual upstream DNS resolution is
  proxied through `resolved` itself, which reads real upstream servers from
  `systemd-networkd`/netplan-supplied config. This matches the target host's
  established facts (`systemd-networkd` + `systemd-resolved` + `systemd-timesyncd`
  active, `resolved` on 127.0.0.53 stub) with no new information beyond confirming the
  address is the systemd-standard stub, not host-specific. (Not independently re-cited
  to a primary systemd doc this session beyond general systemd knowledge — treat as
  LIKELY/well-established rather than freshly VERIFIED via a fetched primary source.)
- Sensor expectation: a bare `cat /etc/resolv.conf` showing `127.0.0.53` is *evidence
  that systemd-resolved is in stub mode*, not itself a DNS/network problem or a
  "misconfiguration" finding.

---

## SOURCES

| URL | title | primary/secondary/tertiary | extractor | credibility | supports |
|---|---|---|---|---|---|
| https://discourse.ubuntu.com/t/sshd-now-uses-socket-based-activation-ubuntu-22-10-and-later/30189 | SSHd now uses socket-based activation (Ubuntu 22.10 and later) | primary (Canonical/Ubuntu official discourse, staff post + maintainer replies) | trafilatura | +3 | Q1 |
| https://bugs.launchpad.net/bugs/2020560 | ssh.service and ssh.socket both running | primary (Launchpad, maintainer Nick Rosbrook comment) | WebFetch | +3 | Q1 |
| https://bugs.launchpad.net/ubuntu/+source/openssh/+bug/2017434 | README.Debian.gz instructions for disabling socket activation inaccurate | primary (Launchpad bug on the actual package) | WebSearch snippet | +2 | Q1 |
| https://github.com/openssh/openssh-portable/blob/master/sshd.c (fetched raw via raw.githubusercontent.com) | sshd.c source | primary (upstream OpenSSH source) | curl (raw fetch, grep/sed inspected directly) | +3 | Q2 |
| https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html | sshd_config(5), openssh-server 1:9.6p1-3ubuntu13.19 | primary (Ubuntu-packaged man page, exact version on target host) | trafilatura + WebFetch | +3 | Q1, Q3 |
| https://manpages.ubuntu.com/manpages/noble/man5/machine-id.5.html | machine-id(5), systemd 255.4-1ubuntu8.17 | primary (Ubuntu-packaged systemd man page) | trafilatura | +3 | Q9 |
| https://github.com/canonical/cloud-init/blob/main/cloudinit/distros/__init__.py (raw fetch) | cloud-init distros/__init__.py | primary (upstream cloud-init source) | curl (raw fetch, grep/sed inspected directly) | +3 | Q4 |
| https://docs.cloud-init.io/en/latest/reference/yaml_examples/user_groups.html | Configure users and groups | primary (cloud-init official docs) | WebSearch snippet | +2 | Q4 |
| https://github.com/canonical/cloud-init/issues/4093 | cloud-init leaks credentials | primary (upstream issue tracker, real disclosed bug) | WebSearch snippet | +2 | Q4 |
| https://packages.ubuntu.com/noble/amd64/apparmor/filelist | apparmor package file list, noble | primary (Ubuntu package archive metadata) | WebFetch | +3 | Q5 |
| https://manpages.ubuntu.com/manpages/noble/man7/apparmor.7.html | apparmor(7), noble | primary (Ubuntu-packaged man page) | trafilatura | +3 | Q5 |
| https://github.com/torvalds/linux/blob/master/security/apparmor/apparmorfs.c (raw fetch) | apparmorfs.c | primary (upstream Linux kernel source) | curl (raw fetch, grep inspected directly) | +3 | Q5 |
| https://manpages.ubuntu.com/manpages/noble/man7/kernel_lockdown.7.html | kernel_lockdown(7), noble | primary (Ubuntu-packaged man page) | trafilatura | +3 | Q6 |
| https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html (and 2.9A/2.11 variants returned by search) | UEFI Specification ch. 32 | primary (UEFI Forum specification) | WebSearch snippet | +3 | Q6 |
| https://www.kernel.org/doc/Documentation/admin-guide/sysctl/kernel.rst | kernel.rst sysctl docs | primary (kernel.org documentation) | WebFetch (trafilatura returned empty on this URL) | +3 | Q7 |
| https://lkml.iu.edu/hypermail/linux/kernel/1302.2/03493.html and /1302.3/01830.html | "kmsg: Honor dmesg_restrict sysctl on /dev/kmsg" LKML thread | primary (kernel mailing list, patch discussion) | WebSearch snippet | +2 | Q7 |
| https://github.com/wh5a/uoc/blob/master/etc/apt/apt.conf.d/99update-notifier | 99update-notifier apt hook (mirrored copy) | secondary (third-party mirror of the shipped file, not fetched from the Ubuntu package itself this session) | WebSearch snippet | 0 | Q8 |
| https://bugs.launchpad.net/ubuntu/noble/+source/ubuntu-meta/+bug/2051572 | Always preseed core and snapd snap in server seed | primary (Launchpad bug against ubuntu-meta, the actual seed-defining package) | WebSearch snippet | +2 | Q10 |
| https://bugs.launchpad.net/bugs/2048828 | netplan config too open with cloud-init | primary (Launchpad bug against cloud-init) | WebSearch snippet | +2 | Q10 |
| https://bugs.launchpad.net/bugs/2053157 | Jammy: netplan permissions warnings | primary (Launchpad bug, corroborates Jammy-only backport framing) | WebSearch snippet (title only) | +1 | Q10 |
| https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html | systemd.socket(5) | primary (systemd upstream docs) | WebFetch — **BLOCKED, HTTP 403**, not retrieved this session | n/a | Q1 (gap) |
| https://git.launchpad.net/ubuntu/+source/openssh/plain/debian/ssh.socket , /ssh.service | Ubuntu openssh packaging git, unit files | primary (Ubuntu package source repo) | curl — returned cgit HTML wrapper only, raw plain-text path/branch not resolved this session | n/a | Q1 (gap) |

## LOCAL_REPRO (WSL Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2)

All commands run unprivileged (uid=1000 kldrm, groups ubuntu/adm/cdrom/sudo/dip/plugdev/users — note `sudo` group membership present but never invoked).

- `sshd -T` / `which sshd` / `sshd -V`: **`sshd: command not found`** (exit 127). WSL
  image has no `openssh-server` installed at all. Proves nothing about Ubuntu 24.04
  bare-metal `sshd -T` behaviour; source-code analysis (Q2) is the authoritative answer
  here instead. `ssh -V` (client only) reports `OpenSSH_10.2p1 Ubuntu-2ubuntu3`.
- `cat /sys/module/apparmor/parameters/enabled` → `N`. `ls
  /sys/kernel/security/apparmor/` → "No such file or directory". `cat
  /proc/self/attr/apparmor/current` → `Invalid argument`. **Proves WSL2's kernel has no
  AppArmor LSM compiled in at all** — this is a WSL-specific kernel build choice, not
  informative about real Ubuntu 24.04 kernels (which do have it, per target host facts).
  Do not generalize this negative result. `aa-status` binary is present
  (`/usr/sbin/aa-status`, package `apparmor` per `dpkg -S`), confirming package-vs-
  kernel-flag independence at the tooling level even though the LSM itself is off here.
- `cat /sys/kernel/security/lockdown` → "No such file or directory". **WSL2's kernel has
  no lockdown LSM compiled in either.** Same caveat as above — not representative of
  real Ubuntu 24.04.
- `cat /proc/sys/kernel/dmesg_restrict` → `0`; `dmesg | head` succeeded; `head -c 100
  /dev/kmsg` failed ("Invalid argument", a WSL2-specific quirk of its `/dev/kmsg`
  implementation rather than a `dmesg_restrict` denial, since `dmesg_restrict=0` here
  should permit it — treated as inconclusive/environment noise, not evidence for Q7).
- `ls -la /etc/machine-id` → `-r--r--r-- 1 root root 33 ... /etc/machine-id`, content a
  32-hex-char ID; `/var/lib/dbus/machine-id` is a symlink to it. **Matches the target
  host's established mode (0444) exactly** — this one generalizes fine since it's a
  systemd-wide constant unrelated to WSL's kernel differences.
- `/var/lib/cloud/` absent; `/run/cloud-init/` present but only contains
  `ds-identify.log`, `.ds-identify.result`, `cloud-init-generator.log`, and an empty
  `disabled` marker file — **cloud-init detected it was running in an unsupported/no-
  datasource environment (WSL) and self-disabled.** No `instance-data.json` or
  `instance-data-sensitive.json` exists to inspect here; Q4's file/mode claims rely on
  cloud-init's own source/docs instead, not this LOCAL_REPRO.
- `/etc/sudoers.d/`: only a `README` file, mode `-r--r-----` (0440), directory mode
  `drwxr-xr-x` (0755) — **diverges from the target host's `/etc/sudoers.d` at 0750**;
  this WSL image's sudoers.d directory is more permissive (0755 vs 0750) than the
  target's, so directory-permission specifics should be read from the real host, not
  assumed from this repro. No `90-cloud-init-users` file exists here (cloud-init never
  ran a user-creation pass), consistent with the "disabled" marker above.
  `id` shows the WSL user is already in `sudo` group by default, same pattern as target.
- `/var/run/reboot-required` absent; `update-notifier-common` shows dpkg status `un`
  (not installed) — **directly demonstrates the causal mechanism can be absent by
  simple non-installation**, supporting Q8's core claim about marker absence being
  inconclusive rather than proof of no-drift.
- `unattended-upgrades` package **is** installed (`2.12ubuntu9`);
  `/etc/apt/apt.conf.d/20auto-upgrades` shows both periodic flags set to `"1"`;
  `/etc/apt/apt.conf.d/50unattended-upgrades` shows `Automatic-Reboot` commented out
  (defaults to false when absent).
- `/etc/netplan/` exists but is **empty** (no rendered files at all — WSL doesn't use
  netplan for its virtual adapter), so no permission data obtainable here; Q10's 0600
  claim rests on the cited Launchpad bug threads instead.
- `snap` binary present, zero snaps installed ("No snaps are installed yet").
- `/sys/firmware/efi/efivars/` absent (WSL2 has no UEFI/efivars surface at all — expected,
  not informative for Q6's Setup Mode question, which is answered from the UEFI spec
  text directly instead).
- `dpkg -l | grep ^ii | wc -l` → 544 packages in this WSL image (vs. 355 on the real
  target) — different image profiles entirely; package-count comparisons between the
  two are not meaningful.

## CANDIDATE FACTS

| claim | status | confidence | sources | design impact |
|---|---|---|---|---|
| Both `ssh.socket` and `ssh.service` "active" simultaneously is normal/expected on Ubuntu ≥22.10, not a fault | VERIFIED | high | Launchpad #2020560 (maintainer quote), Ubuntu discourse thread | Sensor must not flag this combination as anomalous; report both states as expected evidence |
| Ubuntu 24.04 pulls sshd's effective listen port/address dynamically from `sshd_config` via a systemd generator, rather than relying solely on static `ListenStream=` in socket drop-ins | VERIFIED | high | Ubuntu discourse post (Canonical staff) | Sensor's "what port is sshd on" check should trust `ss -ltnp` over parsing `sshd_config`'s `Port`/`ListenAddress`, which are cosmetically present but non-authoritative under socket activation |
| `sshd -T` cannot succeed unprivileged under any flag combination when host keys are file-based with normal 0600 permissions and no agent is present | VERIFIED | high | direct read of openssh-portable `sshd.c` (host-key-loading gate precedes test-mode print/exit) | Sensor must never rely on `sshd -T` for evidence; must use config-file parsing + `ss` instead |
| `sshd_config` Include drop-ins are inserted at the point of the `Include` line, and since Ubuntu's `Include` is the first line, drop-in values win over later main-file lines for the same keyword (first-obtained-value-wins) | VERIFIED | high | manpages.ubuntu.com noble sshd_config(5), exact package version matching target host | A conformant parser must process Include inline, not as a final overlay pass, or it inverts precedence |
| `/etc/sudoers.d/90-cloud-init-users` is cloud-init's literal, hardcoded filename, written mode 0440 | VERIFIED | high | direct read of cloud-init `cloudinit/distros/__init__.py` source | Explains target host's EACCES on sudoers.d contents as expected-by-design, not extra hardening; sensor should not flag it as suspicious |
| `/run/cloud-init/instance-data.json` is world-readable (redacted) and `instance-data-sensitive.json` is root-only (unredacted) | VERIFIED (filenames/intent) / LIKELY (no-regression-ever) | med-high | cloud-init docs + `canonical/cloud-init#4093` (a real regression case) | Sensor may read `instance-data.json` only; never touch/attempt the sensitive file |
| `/sys/kernel/security/apparmor/profiles` has kernel-source file mode 0444 (world-readable by mode bits) | VERIFIED (mode bit) / CONTESTED (practical readability, common tutorials assume root) | med | direct read of `torvalds/linux security/apparmor/apparmorfs.c` | Sensor should attempt this file unprivileged first and treat EACCES as real host-specific evidence, not assume it needs root a priori |
| `aa-status` is shipped by the base `apparmor` package (not `apparmor-utils`) on noble | VERIFIED | high | packages.ubuntu.com noble apparmor filelist | Target host's "aa-status not installed" implies the whole `apparmor` userspace package is absent, independent of the kernel LSM flag being Y; sensor must report these as two separate booleans |
| AppArmor kernel-parameter `enabled=Y` proves LSM compiled in only; proves nothing about userspace package presence, profile loading, or actual confinement | VERIFIED (by construction/absence of counter-evidence) | high | apparmor(7) man page structure (profile loading is a distinct step) + packages.ubuntu.com finding above | Sensor must not infer "AppArmor is protecting this system" from the kernel flag alone |
| Ubuntu auto-enables kernel lockdown when booting under EFI Secure Boot (Ubuntu kernel config, in effect since 20.04) | VERIFIED | high | manpages.ubuntu.com noble kernel_lockdown(7) | Target host's lockdown=[none] is the fully-expected consequence of Secure Boot being disabled — not an independent finding needing its own explanation |
| UEFI Setup Mode (`SetupMode=1`) and Secure Boot enforcement are mutually exclusive by spec | VERIFIED | high | UEFI Specification ch. 32 (uefi.org) | Confirms target host's "Secure Boot disabled + Setup Mode" is one consistent fact, not two coincidental ones |
| `dmesg_restrict=1` gates both the `syslog(2)` path and `/dev/kmsg` opens via `capable(CAP_SYSLOG)` in `devkmsg_open()` | VERIFIED | high | kernel.rst + LKML "Honor dmesg_restrict... on /dev/kmsg" patch thread | Sensor should treat both dmesg-via-syslog and direct /dev/kmsg reads as blocked by the same sysctl+capability gate; a single UNKNOWN/EACCES finding covers both attempt paths |
| `/var/run/reboot-required` existence depends on `update-notifier-common` being installed and its apt hook having actually run; absence is not proof of no kernel drift | VERIFIED | high | LOCAL_REPRO (package absent -> marker absent) + secondary docs on the hook mechanism | Sensor must treat reboot-required absence as inconclusive and prefer the uname/vmlinuz-symlink/dpkg triad as primary evidence for kernel-drift findings |
| `unattended-upgrades`' shipped default template has `Automatic-Reboot` commented out (defaults false) | VERIFIED (as packaged default) | high | LOCAL_REPRO reading the actual shipped `50unattended-upgrades` file | Silent unattended kernel-package installs without auto-reboot is the expected steady state, reinforcing the above |
| `/etc/machine-id` is systemd-standard mode 0444, generated by systemd-machine-id-setup or at boot if empty/missing, and is explicitly documented as security-sensitive / not to be exposed to untrusted parties | VERIFIED | high | manpages.ubuntu.com noble machine-id(5) (direct quote captured) | Sensor must never emit the raw machine-id value into findings.json; may report presence/mode only |
| Ubuntu 24.04's default server seed dropped `lxd`/`snapd`/`core22` from preseeding (i.e., not present by default on a minimal 24.04 server image) | VERIFIED (seed-policy level) | med-high | Launchpad ubuntu-meta bug #2051572 | Sensor should not assume snapd/LXD presence as a baseline signal on 24.04; absence is expected |
| cloud-init (23.1+, which Noble ships) writes `/etc/netplan/50-cloud-init.yaml` at mode 0600, not the historical 0644 | LIKELY (explicit for Jammy backport; Noble described as already-correct baseline, not independently fetched from a noble-specific source) | med-high | Launchpad cloud-init bug #2048828 | Sensor should expect 0600 on netplan files on 24.04 and not flag it as unusual |

## INJECTION ATTEMPTS

None found. No fetched web content (WebSearch snippets, WebFetch summaries, or
trafilatura-extracted text) contained instructions directed at an AI agent/assistant.
All fetched content was ordinary technical documentation, man pages, source code, or
bug-tracker discussion between humans.

## Explicitly could not confirm

- The exact Ubuntu-packaged `ssh.socket`/`ssh.service` unit file contents (attempted via
  `git.launchpad.net` cgit raw-file URLs; got the cgit HTML wrapper instead of raw text
  both times, and did not resolve the correct branch/path in the time available). Q1's
  socket-vs-service mechanics rely on the Ubuntu discourse post and Launchpad bug
  discussion instead, which are credible but not the unit file text itself.
- `systemd.socket(5)` primary doc — freedesktop.org blocked the WebFetch with HTTP 403;
  relied on the Ubuntu discourse thread's paraphrase of the same mechanics instead.
- The exact NOPASSWD rule string cloud-init/Latitude.sh injects for the `ubuntu` user on
  this specific image (mechanism and filename/mode are verified from source; the
  specific rule content on this host is unreadable by design and out of scope to probe
  further).
- Whether `/proc/kmsg` (legacy interface) is gated identically to `/dev/kmsg` under
  `dmesg_restrict` — not found in sources retrieved this session.
- Whether `/sys/kernel/security/apparmor/policy/` is a real, separately-useful
  introspection path — not verified this session, flagged SPECULATIVE only.
- Real-host (non-WSL) unprivileged readability of `/sys/kernel/security/apparmor/*` and
  `/sys/kernel/security/lockdown` — inferred from kernel source file-mode bits (0444 for
  apparmor `profiles`) but not empirically confirmed on an actual AppArmor/lockdown-
  enabled kernel this session, since WSL2 lacks both LSMs entirely.
