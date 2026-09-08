# R3 — Sensor Evidence: primary-source technical knowledge base

Track: `r3-sensor-evidence`. Scope: the technical facts behind a read-only, bounded, unprivileged
Linux posture sensor, expressed as engineering law with its evidentiary chain.

Counts: 66 facts in `facts.jsonl`, 77 sources in `sources.jsonl`, 39 laws in `DESIGN_LAWS.md`.
Execution: 5 parallel research streams + lead synthesis + 8 LOCAL_REPRO batches on WSL2
Ubuntu 26.04 / kernel 6.18.33.2-microsoft-standard-WSL2 as uid 1000. See `PROVENANCE.md`.

Reading order for an implementer: topics 2 and 8 are the ones that change the *shape* of the code.
Topics 1, 3, 5, 6, 7 change individual checks. Topic 9 decides what the code refuses to assume.

---

## Topic 1 — Safe unprivileged observation

```
FACT [R3-F01]: Linux v6.8 drivers/firmware/dmi-id.c declares each DMI sysfs attribute with an
explicit mode: product_serial, product_uuid, board_serial and chassis_serial are 0400 (root-only),
while sys_vendor, product_name, product_version, product_sku, product_family, the board_* and
chassis_* names, BOTH asset tags, and all bios_* fields are 0444 [S39]. This host's own EACCES on
exactly those four fields is consistent with the source, not with a distro policy.
DESIGN LAW L01: The sensor MUST attempt the DMI serial/UUID reads and MUST record UNKNOWN with
reason EACCES when they fail; it MUST NOT substitute a weaker identifier and present it at the same
confidence, and it MUST read board_asset_tag/chassis_asset_tag, which are world-readable.
PROBE STRATEGY: os.ReadFile on /sys/class/dmi/id/{product_uuid,product_serial,board_serial,
chassis_serial} and on the 0444 siblings. EACCES = field present, root-only (expected; UNKNOWN).
ENOENT on the whole /sys/class/dmi/id directory = the platform has no DMI at all (WSL2, many
ARM/POWER, some VMs) and is a different finding — see L37. EINVAL/ENODEV would indicate a malformed
SMBIOS table. TIMEOUT is not expected on sysfs; if seen, report it, do not retry blindly.
ADVERSARIAL FIXTURE: `dmi-serial-root-only` — fixture fs with the four fields 0400 and the asset
tags 0444; expect four UNKNOWN/EACCES findings AND a populated asset-tag finding. Under-claim
variant `dmi-asset-tag-not-read`: a sensor that reports "owner unknown" without having read the
readable asset tags fails. Second under-claim variant `dmi-serial-world-readable`: on a fixture
where the fields are 0444 (some cloud images), the sensor must return the value, not a hardcoded
UNKNOWN.
```

```
FACT [R3-F02]: The raw SMBIOS surface is stricter than the parsed one — /sys/firmware/dmi/entries/*/raw
and /sys/firmware/dmi/tables/{DMI,smbios_entry_point} are mode 0400 in v6.8 and additionally gated
by a runtime CAP_SYS_ADMIN check in the read handler [S49][S50].
DESIGN LAW L02: The sensor MUST NOT design any check whose only evidence path is a raw SMBIOS
record; for SMBIOS type 38 (IPMI device) and type 42 (Redfish host interface) it MUST use the
kernel's parsed sysfs objects instead, and report the raw-DMI EACCES as the reason it did so.
PROBE STRATEGY: stat /sys/firmware/dmi/tables/DMI first (metadata only). EACCES = root-only, use the
parsed path. ENOENT = no DMI on this platform. Fallbacks: /sys/class/ipmi/ipmi*,
/sys/devices/platform/ipmi_bmc.*/{ipmi_version,manufacturer_id,product_id,guid} for type 38;
/sys/class/net/*/device USB descriptors for type 42 (L27).
ADVERSARIAL FIXTURE: `smbios-raw-eacces` — assert the BMC checks still produce PASS/FAIL from the
parsed sysfs objects while a separate evidence line records the raw-DMI EACCES. A sensor that
returns UNKNOWN for all BMC facts because raw DMI was unreadable is under-claiming and fails.
```

```
FACT [R3-F03]: kernel.dmesg_restrict=1 causes an unprivileged klogctl to fail with EPERM, not
EACCES, because check_syslog_permissions() in kernel/printk/printk.c gates on CAP_SYSLOG — a
capability, not a file mode [S45][S51][S55]. Relatedly the fs.protected_* family is not uniform:
protected_symlinks/fifos/regular deny with EACCES while protected_hardlinks denies with EPERM, all
in fs/namei.c [R3-F05][S46][S52].
DESIGN LAW L03: The sensor MUST carry EPERM as a reason distinct from EACCES, and MUST record the
syscall and path alongside the errno, because the same errno family means "wrong mode" in one place
and "missing capability" in another and the two have different remediations.
PROBE STRATEGY: read /proc/sys/kernel/dmesg_restrict (world-readable) rather than calling dmesg.
If a kernel-log-derived check is ever needed: EPERM = restricted, UNKNOWN; ENOENT on /dev/kmsg =
absent; and /dev/kmsg is a character device, so it must not be opened at all (L13).
ADVERSARIAL FIXTURE: `dmesg-restrict-eperm` — assert the finding's reason is EPERM and not EACCES,
and that no dmesg subprocess was spawned at all (the sysctl answered it).
```

```
FACT [R3-F06/R3-F07]: Documentation/filesystems/sysfs.rst states sysfs allocates a PAGE_SIZE buffer
(4096 on x86) and calls show() exactly once per read [S48]. Consequently sysfs attributes stat as
4096 and procfs files stat as 0 regardless of content. Go's own stdlib documents the trap:
os/file.go readFileContents() carries the comment "files in Linux's /proc claim size 0 but then do
not work right if read in small pieces" and forces a 512-byte minimum buffer, growing until EOF
[S42]. LOCAL_REPRO (WSL2): /proc/cpuinfo st_size=0; /sys/block/sda/size st_size=4096, mode 0444,
7 bytes of content [S43].
DESIGN LAW L05: Every bounded read MUST take its cap from an explicit per-observation policy, never
from FileInfo.Size(), and MUST NOT treat st_size==0 as an empty file. For sysfs a 4096-byte cap is
provably sufficient; for procfs (not PAGE_SIZE-bounded) the cap must be set per file.
PROBE STRATEGY: os.ReadFile for anything under /sys or /proc — it already implements the growing
read. A hand-rolled `buf := make([]byte, fi.Size()); f.Read(buf)` silently returns zero bytes on
every procfs file and is the single most likely rookie bug in this codebase.
ADVERSARIAL FIXTURE: `zero-stat-size-file` — a fixture file whose Stat reports 0 but which yields
content on read; assert the sensor's value is non-empty. Companion `oversize-sysfs-attr`: a
5000-byte attribute against a 4096 cap must set truncated=true and MUST NOT produce a PASS.
```

```
FACT [R3-F08]: For a sysfs/procfs read the errno classes are semantically distinct: EACCES (exists,
not permitted), ENOENT (absent), EINVAL/ENODEV (attribute exists but the handler rejected the
operation or the device vanished), EIO (backing operation failed) [S53][S54][S44]. procfs
additionally supports hidepid=0|1|2 and subset=pid, which change what an unprivileged process can
see of other processes [R3-F04][S44][S13].
DESIGN LAW L07: The sensor MUST map observations to a closed reason vocabulary
(EACCES/EPERM/ENOENT/EINVAL/ENODEV/EOPNOTSUPP/EIO/TIMEOUT/UTILITY_MISSING/BUDGET_EXHAUSTED/
PARSE_ERROR/EXECUTION_ERROR/CONTESTED) and MUST NOT collapse any two of them; and it MUST read the
/proc mount's hidepid= option out of /proc/self/mountinfo before drawing any conclusion from a
process enumeration.
PROBE STRATEGY: for each probe, document what each class means for THAT probe (done per block in
this report). Only an ENOENT proven by a successful listing of the parent directory may be reported
as "feature absent" — a bare ENOENT on a deep path is indistinguishable from a typo in the probe.
ADVERSARIAL FIXTURE: `hidepid2-empty-proc` — mount-option fixture where /proc reports hidepid=2 and
the process enumeration comes back empty; expect UNKNOWN with reason hidepid=2, not "no processes".
Under-claim variant `hidepid0-full-proc`: with hidepid=0 the same code must return the enumeration
rather than defensively saying UNKNOWN.
```

```
FACT [R3-F09]: kernel.kptr_restrict, kernel.perf_event_paranoid (default 2),
kernel.unprivileged_bpf_disabled (0/1/2) and kernel.yama.ptrace_scope (0-3) are all world-readable
sysctls [S45][S47]; ENOENT on yama/ptrace_scope means the Yama LSM is absent, not that ptrace is
unrestricted.
DESIGN LAW L08: The sensor MUST determine a restriction by READING its sysctl, never by attempting
the restricted operation — attempting perf_event_open(), bpf() or a ptrace attach is a behaviour
change on the target and violates the read-only invariant even when it fails.
PROBE STRATEGY: os.ReadFile the sysctl path. ENOENT = the knob (and usually the feature/LSM) is not
present on this kernel, a different finding from value 0. Cross-check the active LSM list at
/sys/kernel/security/lsm (L37/L38).
ADVERSARIAL FIXTURE: `sysctl-absent-not-permissive` — fixture with kernel/yama/ptrace_scope absent;
expect UNKNOWN "Yama not present", never a PASS or a FAIL derived from an assumed default of 0.
```

## Topic 2 — Bounded subprocesses and bounded reads in Go

This topic produced the highest-confidence, highest-consequence laws in the track, all traceable to
stdlib source at a pinned version (go1.26.2, wording cross-checked against pkg.go.dev @go1.24.0).

```
FACT [R3-F10/R3-F12/R3-F13]: exec.CommandContext's default Cancel is Process.Kill, which the
documentation states "only kills the Process itself, not any other processes it may have started"
[S56][S57]. The resulting hang lives in Wait's copy goroutines — Cmd.Stdout documents that "Wait
does not complete until the goroutine reaches EOF or encounters an error or a nonzero WaitDelay
expires" [S57] — which is exactly golang/go#23019, closed *not planned*, with the accepted fix
shipping as Cancel/WaitDelay in Go 1.20 via #50436 [S60][S61]. Killing the whole group requires
syscall.SysProcAttr{Setpgid:true} plus syscall.Kill(-pid, SIGKILL); kill(2) defines the negative-pid
form, and without Setpgid the child shares the sensor's process group so the group kill would kill
the sensor itself [S58][S59].
DESIGN LAW L09: Every subprocess the sensor starts MUST be started with SysProcAttr{Setpgid:true}
and MUST be terminated with a process-group kill, in exactly one internal runner function; no other
package may construct an exec.Cmd.
PROBE STRATEGY: not a probe — an execution contract. The runner sets Setpgid, a Cancel that
group-kills and normalises ESRCH to os.ErrProcessDone (L11), a non-zero WaitDelay (L10), capped
writers (L12), Stdin=nil and an explicit minimal Env. argv is always a slice; no shell is spawned.
ADVERSARIAL FIXTURE: `grandchild-holds-stdout` — a probe whose child spawns a grandchild that holds
the stdout fd and sleeps past the deadline; assert (a) the runner returns within budget, (b) the
finding is UNKNOWN/TIMEOUT not FAIL, (c) no descendant survives the scan, (d) THE SENSOR IS STILL
ALIVE. Companion negative test `setpgid-omitted`: with Setpgid removed the group kill must be shown
to kill the harness — the fixture that proves why L09 is worded as a single-runner rule.
```

```
FACT [R3-F11]: Cmd.WaitDelay is the only stdlib bound on "the child exited but the pipes are still
open": with WaitDelay zero "I/O pipes will be read until EOF, which might not occur until orphaned
subprocesses of the command have also closed their descriptors", and Wait returns exec.ErrWaitDelay
when the pipes are force-closed after an otherwise successful exit [S57][S56][S61].
DESIGN LAW L10: Every exec.Cmd MUST set a non-zero WaitDelay, and exec.ErrWaitDelay MUST map to
UNKNOWN with reason TIMEOUT (or TRUNCATED where partial output is retained) — never to FAIL, because
the child may have succeeded and only its descendant was slow.
PROBE STRATEGY: WaitDelay is set to a small fraction of the per-check budget so the cancel path and
the pipe-drain path cannot serially consume the whole budget.
ADVERSARIAL FIXTURE: `waitdelay-expired-not-fail` — child exits 0 immediately, grandchild holds the
pipe; assert exit_code=0 AND status=unknown AND reason=TIMEOUT AND wait_delay_expired=true. A sensor
reporting FAIL (or PASS from the empty output) fails.
```

```
FACT [R3-F14]: A user-supplied Cancel must return an error wrapping os.ErrProcessDone when the
process is already gone; nil causes ctx.Err() to be reported and any other error is wrapped as
"exec: canceling Cmd" (os/exec/exec.go:261-268, watchCtx 795-820) [S57].
DESIGN LAW L11: The group-kill Cancel MUST normalise ESRCH to os.ErrProcessDone, so a benign race
between the child exiting and the deadline firing does not manufacture an EXECUTION_ERROR finding.
PROBE STRATEGY: n/a (contract).
ADVERSARIAL FIXTURE: `cancel-race-esrch` — a child that exits in the same millisecond the deadline
fires, run 200 times; assert zero EXECUTION_ERROR findings and a stable verdict.
```

```
FACT [R3-F15/R3-F16]: io.LimitReader signals the cap by returning EOF, not an error [S62]; and
os/exec states "Wait must be called in order to release associated system resources", with
Process.Release needed "only ... if Process.Wait is not" [S57].
DESIGN LAW L12: Output caps MUST be implemented as read(cap+1) with an explicit truncated flag, and
a truncated read MUST NOT yield a PASS. Wait MUST be called exactly once on every path including
timeout and group-kill, because a leaked <defunct> child is a visible mutation of Lava's host.
PROBE STRATEGY: n/a (contract).
ADVERSARIAL FIXTURE: `output-exactly-at-cap` — a child emitting exactly `cap` bytes of valid-looking
output; assert the sensor does not report PASS without also proving it saw EOF. `zombie-after-timeout`
— after a forced timeout, assert no unreaped child remains.
```

```
FACT [R3-F17/R3-F18]: fifo(7) states opening a FIFO normally blocks until the other end is opened,
while open(2) states O_NONBLOCK "has no effect for regular files and block devices" [S63][S53].
os.Root (Go 1.24+) constrains traversal but its own doc says its methods "do not prohibit traversal
of filesystem boundaries, Linux bind mounts, /proc special files, or access to Unix device files",
and Go implements it with component-wise openat + O_NOFOLLOW, not openat2(2) [S64].
DESIGN LAW L13: The sensor MUST have exactly one file-open path —
O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC followed by fstat on the RETURNED DESCRIPTOR and a
FileMode.IsRegular() assertion — and MUST NOT rely on os.Root or on a prior path-Stat for
device-node safety.
PROBE STRATEGY: Lstat-then-Open is a TOCTOU; fstat-after-open closes it. A non-regular result means
UNKNOWN with reason "non-regular file at expected path", which is itself posture-relevant (someone
replaced a config file with a FIFO).
ADVERSARIAL FIXTURE: `fifo-at-config-path` — a FIFO with no writer where a config file is expected;
assert the sensor returns within budget with UNKNOWN and never blocks. `chardev-at-path` — /dev/zero
symlinked into the fixture tree; assert it is never read.
```

```
FACT [R3-F16b]: A blocked read(2) on a regular file is not interruptible by a context —
os.File.SetReadDeadline documents that "on most systems ordinary files do not support deadlines, but
pipes do", returning os.ErrNoDeadline, and the stdlib's own TestNonpollableDeadline asserts it on
Linux [S66].
DESIGN LAW L14: The whole-scan deadline MUST bound scheduling and output, not in-flight reads: each
check runs in its own goroutine, the collector selects on ctx.Done(), emits UNKNOWN/TIMEOUT for
stragglers and writes findings.json — an unconditional WaitGroup.Wait() before output is forbidden.
PROBE STRATEGY: n/a (contract). This is also why every check must be independently registered: the
collector needs a placeholder finding to fill in when a goroutine never returns.
ADVERSARIAL FIXTURE: `stuck-read-does-not-block-output` — a check that blocks forever on a read;
assert findings.json is written within the scan deadline, contains an UNKNOWN/TIMEOUT finding for
that check id, and contains every other check's real verdict.
```

```
FACT [R3-F19]: Neither filepath.Walk nor filepath.WalkDir follows symbolic links [S65] — and /sys is
built out of symlinks (LOCAL_REPRO: /sys/class/net/lo -> ../../devices/virtual/net/lo,
/sys/block/loop0 -> ../devices/virtual/block/loop0) [S43].
DESIGN LAW L15: Under /sys the sensor MUST use os.ReadDir plus explicit, depth-capped symlink
resolution with a visited-inode set and an assertion that the target remains under /sys; under
user-writable trees it MUST use WalkDir and MUST NOT follow symlinks.
PROBE STRATEGY: the failure this prevents is silent — WalkDir over /sys/class/net returns the
symlinks as entries but never descends, so every NIC/disk/BMC topology check reports "no entries"
and looks like a clean scan.
ADVERSARIAL FIXTURE: `sysfs-symlink-topology` — a fixture /sys tree where all device dirs are
reachable only through symlinks; assert the device enumeration is non-empty. Under-claim variant
`sysfs-empty-is-unknown`: if resolution hits the depth cap, the finding is UNKNOWN/BUDGET_EXHAUSTED,
not "no devices". Adversarial variant `symlink-escape`: a /sys symlink pointing to /home/other/;
assert the walker refuses it and records the refusal.
```

## Topic 3 — Effective sshd configuration vs any single file

```
FACT [R3-F20/R3-F21]: sshd_config(5) states "for each keyword, the first obtained value will be
used", and ssh_config(5) uses the identical first-value-wins rule — the two are NOT opposite, only
their read orders differ [S1][S3]. Include is processed at the point it appears, globs expand in
lexical order, and relative paths resolve against /etc/ssh [S1]. So a drop-in included near the top
of the main file beats a contradicting keyword later in that same file.
DESIGN LAW L16: The sensor MUST resolve every sshd directive by walking the Include-expanded chain
in file order and keeping the FIRST occurrence, and MUST emit both the winning {path,line} and every
shadowed occurrence in the evidence block.
PROBE STRATEGY: read /etc/ssh/sshd_config (0644, always readable; an EACCES here is itself
reportable), find the Include line's position, expand its globs lexically, read each drop-in. ENOENT
on sshd_config.d = the older single-file layout, not an error. UTILITY_MISSING is not applicable —
this is pure file reading, no exec.
ADVERSARIAL FIXTURE: `sshd-dropin-shadows-main` — drop-in sets PasswordAuthentication yes, main file
later sets no, Include at line 1; expect effective=yes with the drop-in as winning_source and the
main-file line listed as shadowed. A sensor that greps only sshd_config and reports "no" produces a
false PASS and fails. Mirror fixture `sshd-include-at-bottom`: same files, Include on the last line;
expect effective=no. Same inputs, opposite verdict — this pair is the whole point of L16.
```

```
FACT [R3-F24]: A Match block's keywords override the global section for matching connections until
the next Match or EOF, so per-user/host/address policy can differ arbitrarily and is not
determinable statically without the connection context [S1].
DESIGN LAW L17: When a security-relevant keyword appears inside any Match block, the sensor MUST
degrade that check from a single verdict to evidence-only (global value plus enumerated conditional
overrides) rather than asserting one host-wide answer.
PROBE STRATEGY: parse Match criteria textually (User/Group/Host/Address/LocalAddress/LocalPort/
RDomain) and report count + criteria. No exec, no privilege needed.
ADVERSARIAL FIXTURE: `sshd-match-user-root` — global PermitRootLogin no, plus `Match User root` with
PermitRootLogin yes; assert the finding is not a bare PASS and that the Match override appears in
the evidence.
```

```
FACT [R3-F23]: In openssh-portable at tag V_9_6_P1, sshd.c main() loads host keys unconditionally
BEFORE the test_flag (-T) branch and exits "sshd: no hostkeys available -- exiting." when no key
loaded; unprivileged, the 0600 root-owned host keys are unreadable, so `sshd -T` always fails this
way. The man page does not document -T as privileged [S4][S2].
DESIGN LAW L18: The sensor MUST NOT depend on `sshd -T` for effective-config resolution; if it
attempts it at all, it MUST record the exit code and stderr text as EXECUTION_ERROR evidence
explaining the fallback, and MUST NOT interpret the failure as "the sshd config is invalid".
PROBE STRATEGY: chain = (1) own Include/Match walker (L16), always available; (2) optionally
`sshd -T`, expected EXECUTION_ERROR with that exact stderr on any unprivileged host with 0600 host
keys; (3) `sshd -T -C user=...` is strictly worse (same gate). UTILITY_MISSING if sshd is not in
PATH — a distinct reason from the host-key failure, not to be conflated.
ADVERSARIAL FIXTURE: `sshd-T-no-hostkeys` — assert the sensor still emits a resolved effective
config from its own walker AND an evidence line quoting the -T stderr. Under-claim variant: a sensor
that returns UNKNOWN for all sshd directives because -T failed is under-claiming and fails.
```

```
FACT [R3-F25/R3-F26]: OpenSSH 9.6 upstream defaults are documented in sshd_config(5)
(PermitRootLogin prohibit-password, PasswordAuthentication yes, MaxAuthTries 6, X11Forwarding no,
LoginGraceTime 120, ...) [S1], but UsePAM's upstream default is "no" while Debian/Ubuntu's packaged
effective default is "yes", per Ubuntu noble's own sshd_config(5) [S5]. CONTESTED, both sides cited.
DESIGN LAW L19: When a directive is absent from the entire Include chain, the sensor MUST resolve it
against a cited, VERSION-SCOPED and DISTRO-AWARE default table and MUST put the citation in the
evidence block; when the distro family cannot be established from /etc/os-release ID/ID_LIKE, the
directive is UNKNOWN, not the upstream default.
PROBE STRATEGY: read /etc/os-release (ID then ID_LIKE, never PRETTY_NAME [S27]) and the sshd version
banner; select the default table row; record `defaulted:true` plus `default_source`.
ADVERSARIAL FIXTURE: `usepam-absent-ubuntu` — no UsePAM anywhere, ID=ubuntu; expect effective=yes
with the Ubuntu citation. `usepam-absent-unknown-distro` — same files, /etc/os-release absent;
expect UNKNOWN, not "no". A PASS with `defaulted:true` and no `default_source` fails on both.
```

```
FACT [R3-F27/R3-F30]: On Ubuntu 22.10+ sshd is socket-activated and the listening endpoint comes
from ssh.socket's ListenStream, not from sshd_config's Port/ListenAddress [S6]. Independently,
/proc/net/tcp exposes each socket's uid but inode-to-PID mapping requires reading other users'
/proc/<pid>/fd, which is denied — LOCAL_REPRO on WSL2: unprivileged `ss -tlnp` listed every LISTEN
socket's address:port while leaving the process column empty for other users' sockets
[S12][S13][S14][S43].
DESIGN LAW L20: "What is listening" MUST be answered from the socket table (/proc/net/tcp{,6} or
ss), never from a daemon's config file; and "which process owns a listening socket" MUST be reported
as UNKNOWN/EACCES for other uids, never as a blank field or an absent process.
PROBE STRATEGY: primary /proc/net/tcp and /proc/net/tcp6 (pure file read, no exec, no version
drift); fallback `ss -tuln` (UTILITY_MISSING if iproute2 absent). Cross-check against the config
file's claim and emit CONTESTED when they disagree. Never parse `ss` columns positionally (L38).
ADVERSARIAL FIXTURE: `socket-activated-port-mismatch` — sshd_config says Port 2222, the socket table
shows 22; expect a CONTESTED finding naming both, not a silent pick. `listener-owner-unknown` —
assert the owner field is UNKNOWN/EACCES and the listener itself is still reported PASS/FAIL.
```

```
FACT [R3-F31]: Cloudflare documents cloudflared as an outbound-only daemon with "no open inbound
ports" [S15]; ngrok and frp clients share the architecture. Reverse tunnels are therefore invisible
to listening-socket enumeration.
DESIGN LAW L21: A remote-access finding derived from listening sockets MUST state the
outbound-tunnel blind spot in its own evidence; the sensor MUST NOT report "no remote access
surface" on the basis of LISTEN sockets alone.
PROBE STRATEGY: listeners from /proc/net/tcp; plus established outbound connections; plus a bounded,
EACCES-tolerant scan of readable /proc/*/comm. Every one of these is partial and must say so.
ADVERSARIAL FIXTURE: `outbound-tunnel-no-listener` — a fixture with an established outbound
connection and zero extra listeners; assert the remote-access finding is not a bare PASS and that
its evidence names the limitation.
```

```
FACT [R3-F28/R3-F29]: passwd -S field 2 is L/NP/P and is only meaningfully queryable for one's own
account; /etc/shadow is 0640 root:shadow (LOCAL_REPRO) so other users' password state is unreadable
[S9][S43]. sudoers(5) documents %group syntax and cloud-init documents writing a NOPASSWD drop-in
for the default user [S11][S8]; on this host /etc/sudoers is 0440 and /etc/sudoers.d is 0750.
DESIGN LAW L22: The sensor MUST report group membership as fact and sudo POLICY as UNKNOWN/EACCES,
MUST report other users' password state as UNKNOWN/EACCES, and MUST NOT invoke sudo in any form,
including `sudo -n -l`.
PROBE STRATEGY: /etc/passwd (world-readable) for login shells; getgrouplist/`id` for membership;
stat on /etc/shadow, /etc/sudoers, /etc/sudoers.d for the boundary evidence. EACCES on sudoers is the
expected, reportable outcome — not a failure of the check.
ADVERSARIAL FIXTURE: `shadow-unreadable-not-passwordless` — assert no finding claims "no password
set" for any account other than our own. `sudo-never-invoked` — assert the sensor spawned no
sudo/su/doas at any point in the scan.
```

## Topic 4 — Secrets on disk without leaking values

```
FACT [R3-F33]: Secret-shaped files are identifiable from a bounded header: RFC 7468 defines the PEM
armor "-----BEGIN <label>-----" [S71]; OpenSSH PROTOCOL.key at V_9_6_P1 defines the
"openssh-key-v1" magic [S72]; MIT keytabs begin 0x0502 [S73]; JKS/JCEKS begin
0xFEEDFEED/0xCECECECE (LIKELY — not directly fetched).
DESIGN LAW L23: Secret detection MUST proceed name/extension -> lstat metadata -> at most a 64-byte
header read that is classified and DISCARDED in the same function; the sensor MUST NOT content-scan
arbitrary files, MUST NOT store any prefix of a secret, and MUST NOT emit a hash of one.
PROBE STRATEGY: lstat first (file_type, mode, uid, gid, size). Only for regular files whose
name/location makes them candidates, open via the single safe path (L13) and read <=64 bytes.
EACCES on the file = candidate exists but is unreadable — which is itself the desired posture answer
for a private key, and is recorded as such, not as UNKNOWN-and-forgotten.
ADVERSARIAL FIXTURE: `pem-key-world-readable` — a 0644 file with a PEM private-key armor; expect
FAIL with magic_class=pem-private-key and NO content anywhere in findings.json. Leak fixture
`no-secret-bytes-in-output`: grep the produced findings.json for the fixture's key body and for any
16+ byte substring of it; any hit fails the build.
```

```
FACT [R3-F34]: Several credential formats document their own permission or exposure semantics:
PostgreSQL ignores ~/.pgpass unless 0600 or stricter [S74]; sshd's StrictModes rejects loose
permissions on user key files [S1]; docker config.json "auths" are base64, explicitly not encrypted
[S75]; git-credential-store stores plaintext by design [S76].
DESIGN LAW L24: Where the software itself documents a permission or exposure rule, the sensor's
PASS/FAIL criterion MUST cite that document rather than a house style; where no such rule exists,
the finding is INFO/evidence, not FAIL.
PROBE STRATEGY: metadata only. ENOENT = the credential store is not in use (provable only if the
home directory was listable). EACCES on the home directory = UNKNOWN for that user entirely.
ADVERSARIAL FIXTURE: `pgpass-0644` — expect FAIL citing PostgreSQL. `pgpass-0600` — expect PASS.
`docker-config-present` — expect a finding that names base64-is-not-encryption with the Docker
citation, and never decodes the value.
```

```
FACT [R3-F36]: An unprivileged process cannot enumerate a directory it lacks search permission on —
LOCAL_REPRO: /root is drwx------ root:root and `ls /root` returns EACCES [S43].
DESIGN LAW L25: A secrets/enumeration finding MUST carry its own boundary: the count and a sample of
EACCES directories, the pruned filesystems, and whether any budget was exhausted. "No secrets found"
without a boundary statement is a forbidden output shape.
PROBE STRATEGY: bounded walk with xdev semantics (never cross a mount, checked against
/proc/self/mountinfo, L31), prune /proc /sys /dev /run and any non-native fstype, plus depth, entry
and time caps. BUDGET_EXHAUSTED forces the finding to UNKNOWN.
ADVERSARIAL FIXTURE: `unreadable-home-not-clean` — a 0700 other-user home containing a key; assert
the finding is not PASS and that unreadable_dirs names the home. `entry-cap-hit-is-unknown` — set
the entry cap below the fixture's file count; assert BUDGET_EXHAUSTED and UNKNOWN, not "clean".
```

## Topic 5 — BMC in-band access

```
FACT [R3-F40/R3-F41/R3-F42]: Documentation/driver-api/ipmi.rst defines the module split —
ipmi_msghandler is the central handler with no user interface, ipmi_devintf provides the /dev/ipmiN
IOCTL interface, ipmi_si drives KCS/SMIC/BT, ipmi_ssif drives SMBus BMCs — and documents discovery
from ACPI or SMBIOS tables with hand-configuration via ipmi_si parameters or the write-only
/sys/module/ipmi_si/parameters/hotmod, plus a 5-second IPMB response timeout and the warning that
SMBus discovery itself "can be detrimental to some I2C devices" [S35].
DESIGN LAW L26: The sensor MUST report BMC "interface present" and "access permitted" as two
separate fields, MUST treat the absence of /dev/ipmiN as "ipmi_devintf not loaded" rather than "no
BMC", and MUST NEVER issue an IPMI command — a probe whose documented failure mode is disturbing bus
peers is incompatible with the read-only invariant.
PROBE STRATEGY: /sys/class/ipmi/ipmi* and /sys/devices/platform/ipmi_bmc.*/{ipmi_version,
manufacturer_id,product_id,device_id,guid} (world-readable) for capability; lstat /dev/ipmi* for
access (mode/uid/gid, never open). Discovery provenance from /sys/bus/platform/devices/ipmi_si.* and
the ACPI/DMI device names. EACCES reading hotmod is expected (write-only) and is not a failed check.
UTILITY_MISSING for ipmitool is irrelevant — the sysfs path answers the posture question.
ADVERSARIAL FIXTURE: `bmc-present-node-root-only` — /sys/class/ipmi populated, /dev/ipmi0 0600
root:root; expect capability_present=true AND access_permitted=false, reported as restriction, not
as a FAIL about presence. Under-claim variant `bmc-unknown-because-no-ipmitool`: a sensor returning
UNKNOWN because ipmitool is missing, when sysfs answered it, fails.
```

```
FACT [R3-F43]: DMTF DSP0270 v1.3.1 defines the SMBIOS type 42 Redfish host interface record; §7.3.1
Table 3 gives device type 02h = USB network interface (04h = v2) and §7.3.2 Table 4 sources
Vendor ID / Product ID / Serial Number from the USB idVendor, idProduct and iSerialNumber [S67].
DESIGN LAW L27: When the authoritative record is root-only (type 42 via raw DMI, L02), the sensor
MUST use the documented derived surface — the USB descriptors under /sys/class/net/<if>/device — and
MUST report PASS/FAIL from it rather than UNKNOWN.
PROBE STRATEGY: /sys/class/net/*/device/../{idVendor,idProduct,manufacturer,product} plus the driver
name from the device's driver symlink (rndis_host, cdc_eem), combined with operstate. ENOENT on
device/ means a virtual interface, not a missing BMC.
ADVERSARIAL FIXTURE: `bmc-usb-nic-detected` — fixture /sys with an RNDIS gadget whose manufacturer
string names the BMC SoC; expect the interface classified as a BMC host interface with operstate
evidence, produced entirely without root.
```

## Topic 6 — Storage / infrastructure evidence semantics

```
FACT [R3-F45]: Linux v6.8 block/genhd.c declares DEVICE_ATTR(size, 0444, part_size_show, NULL) and
part_size_show prints bdev_nr_sectors(), i.e. /sys/block/<dev>/size is world-readable in 512-byte
sectors. Notably the attribute is NOT described in Documentation/ABI/stable/sysfs-block for v6.8 —
the unit comes from the source, not the ABI doc [S40][S41].
DESIGN LAW L28: Capacity MUST be computed as size * 512 unconditionally, never as
size * logical_block_size, and the evidence MUST cite the source, because the ABI documentation does
not cover this attribute.
PROBE STRATEGY: os.ReadFile /sys/block/<dev>/size. No exec, no device open, no privilege.
ADVERSARIAL FIXTURE: `4kn-device-capacity` — a fixture device with logical_block_size 4096; assert
the reported capacity is size*512. A sensor multiplying by 4096 over-reports capacity 8x and fails.
```

```
FACT [R3-F46/R3-F46b]: lsblk(8) documents that it reads sysfs and the udev database, falling back to
direct probing only when the udev database is unavailable [S68]. LOCAL_REPRO (WSL2, uid 1000, not in
group disk): `dd if=/dev/sda` returned EACCES while `lsblk -J -o NAME,SERIAL,WWN,FSTYPE` returned
populated SERIAL/WWN/FSTYPE — but UUID came back null for two of four devices, so the fallback is
partial [S43].
DESIGN LAW L29: The sensor MUST NOT report filesystem type or device identity as UNKNOWN merely
because it cannot open the block device — the udev database answers it, and saying UNKNOWN there is
under-claiming; equally it MUST NOT read an EMPTY udev-derived field as "no filesystem".
PROBE STRATEGY: primary /sys/block/* and /run/udev/data/b<maj>:<min>; secondary `lsblk -J` (guarded
by L38); the raw device is never opened. EACCES on /dev/<dev> is expected and is evidence, not
failure.
ADVERSARIAL FIXTURE: `blockdev-eacces-fstype-known` — fixture where /dev/<x> is unreadable but the
udev record has ID_FS_TYPE; expect the fstype reported, not UNKNOWN (under-claim case).
`udev-record-partial` — udev record without ID_FS_UUID; expect UUID=UNKNOWN and NOT "unformatted".
```

```
FACT [R3-F47/R3-F48]: cryptsetup composes DM-UUIDs as CRYPT-<type>-[<uuid>-]<name> with the literal
"CRYPT-" prefix (lib/libdevmapper.c:1163-1189) [S69], so dm-crypt is detectable from the
world-readable /sys/block/dm-*/dm/uuid. Conversely NVMe SMART requires CAP_SYS_ADMIN: v6.8
drivers/nvme/host/ioctl.c nvme_cmd_allowed() ends `return capable(CAP_SYS_ADMIN)` [S70].
DESIGN LAW L30: Encryption-at-rest MUST be answered from dm/uuid unprivileged, and the NEGATIVE MUST
be scoped in words: "no dm-crypt mapping" — never "not encrypted" — because SED/OPAL state, fscrypt
and non-dm swap encryption are unknown by construction. Drive health MUST be UNKNOWN with reason
CAP_SYS_ADMIN/EPERM, never "smartctl not installed", while drive identity (model, serial,
firmware_rev, state from NVMe sysfs) MUST still be reported.
PROBE STRATEGY: /sys/block/dm-*/dm/uuid; the absence of any dm-* entry is a proven absence only
because /sys/block was successfully listed. /sys/class/nvme/*/ for identity. Never open /dev/nvme*.
ADVERSARIAL FIXTURE: `no-dm-not-unencrypted` — fixture with no dm devices; assert the finding's text
is scoped to dm-crypt and does not assert "unencrypted". `smart-eperm-identity-known` — assert
health=UNKNOWN/EPERM in the same run where model and serial are populated (a sensor returning
UNKNOWN for both is under-claiming).
```

```
FACT [R3-F49]: proc_pid_mountinfo(5) documents a VARIABLE number of optional fields between the
super-options block and the filesystem type, terminated by a single hyphen field; the generic
proc(5) page does not carry this table [S77].
DESIGN LAW L31: Mountinfo parsing MUST split on the literal " - " separator and index from both
ends; fixed-column indexing is forbidden.
PROBE STRATEGY: /proc/self/mountinfo, world-readable, no exec. A PARSE_ERROR here must fail loudly
into UNKNOWN rather than silently yielding a wrong fstype.
ADVERSARIAL FIXTURE: `mountinfo-with-propagation-fields` — a line carrying shared:1 master:2
propagate_from:3; assert fstype and mount source parse correctly. A fixed-index parser reads
"shared:1" as the fstype and corrupts every nosuid/nodev/network-storage verdict downstream.
```

## Topic 7 — Machine identity

```
FACT [R3-F50/R3-F51]: machine-id(5) states the ID "should be considered 'confidential', and must not
be exposed in untrusted environments", prescribing a keyed hash
(sd_id128_get_machine_app_specific) for any application identifier; it also documents that reusable
images should ship the file missing or empty, with fallbacks to /var/lib/dbus/machine-id,
container_uuid, the KVM DMI product_uuid, devicetree vm,uuid, the Xen uuid, or a random UUID [S37].
DESIGN LAW L32: The sensor MUST NOT emit /etc/machine-id verbatim into findings.json; it emits an
application-keyed derivation plus the derivation method. It MUST label machine-id as "stable across
reboot, vulnerable to image cloning" rather than as a hardware identity.
PROBE STRATEGY: read /etc/machine-id (0444, LOCAL_REPRO), note whether /var/lib/dbus/machine-id is a
symlink to it. ENOENT or an empty file = "first boot has not established it" — a real finding, not
an error.
ADVERSARIAL FIXTURE: `machine-id-not-emitted-raw` — grep findings.json for the fixture's machine-id
string; any hit fails. `machine-id-empty` — expect a finding naming the uninitialised state, not
UNKNOWN with no reason.
```

```
FACT [R3-F01/R3-F52/R3-F77]: Because both asset tags are 0444 while all four serials are 0400 [S39],
the unprivileged owner-evidence surface on a DMI machine is exactly the asset tags plus vendor and
BIOS strings. And DMI may be absent entirely: LOCAL_REPRO shows WSL2 with ID=ubuntu has no
/sys/class/dmi at all — ENOENT, not EACCES [S43].
DESIGN LAW L33: The sensor MUST rank identity sources by provenance and emit the ranking with the
finding: (1) DMI serials/UUID — strongest, root-only, therefore UNKNOWN here; (2) NVMe/disk serial
from sysfs — strong, survives OS reinstall, changes with the drive; (3) permanent NIC MAC from
/sys/class/net/*/address gated on addr_assign_type; (4) machine-id — stable, clone-vulnerable;
(5) hostname/FQDN — weakest, mutable. It MUST distinguish "no DMI on this platform" (ENOENT) from
"DMI present but restricted" (EACCES).
PROBE STRATEGY: read each tier, record which succeeded and why the others did not, and derive the
host identifier from the highest tier that produced evidence.
ADVERSARIAL FIXTURE: `no-dmi-platform` — fixture without /sys/class/dmi; expect the identity chain
to fall through to disk/MAC/machine-id with reason ENOENT (platform has no DMI), and expect NO
EACCES-flavoured wording. `placeholder-asset-tag` — asset tag "To be filled by O.E.M."; expect the
owner finding to be UNKNOWN with the placeholder quoted as the reason, not a PASS naming the OEM
string as the owner.
```

## Topic 8 — Failure-mode taxonomy for the sensor

```
FACT [R3-F60/R3-F61/R3-F62]: XCCDF 1.2 defines nine rule-result values — pass, fail, error, unknown,
notapplicable, notchecked, notselected, informational, fixed [S19][S20]; OVAL defines six, keeping
"unknown" (could not collect) distinct from "not evaluated" (chose not to run) [S21]; SARIF 2.1.0's
result.kind enumerates notApplicable/pass/fail/review/open/informational and DEFAULTS TO FAIL when
omitted, and separates run-level execution status from findings [S22].
DESIGN LAW L34: Our three-value vocabulary MUST recover XCCDF's lost distinctions in the reason
field (error vs unknown vs notapplicable vs notchecked); every registered check MUST emit exactly
one finding per run even when its code panicked; and a missing or unset verdict MUST NEVER default
to the safe answer — following SARIF, the default for "the sensor forgot" is the loud one, not PASS.
PROBE STRATEGY: the registry emits a placeholder UNKNOWN/notchecked finding for every registered
check before execution and overwrites it with the real result, so a panic or a stuck goroutine
leaves the placeholder rather than a hole. Panics are recovered per check (isolation invariant).
ADVERSARIAL FIXTURE: `panicking-check` — a registered check that panics; assert findings.json still
contains exactly one finding for its id, status=unknown, reason=EXECUTION_ERROR, and that every
other check's verdict is unaffected. `registry-count-invariant` — assert len(findings) ==
len(registry) on every run, including timeout runs.
```

```
FACT [R3-F64]: Wazuh SCA documents a single "not applicable" outcome triggered when the file is
absent, OR permissions are insufficient, OR command execution times out [S24] — a widely deployed
tool collapsing exactly the three classes this project forbids collapsing. Lynis by contrast
attaches a reason to skips [S23], and CIS marks recommendations Automated vs Manual [S25].
DESIGN LAW L35: The sensor's reason vocabulary MUST remain closed and strictly finer-grained than
"not applicable": ENOENT, EACCES/EPERM, TIMEOUT, UTILITY_MISSING and BUDGET_EXHAUSTED are five
different findings about five different remediations, and no two may share a label.
PROBE STRATEGY: enforced by a table-driven unit test over the reason enum, not by review.
ADVERSARIAL FIXTURE: `four-failure-classes-one-check` — run the same check against four fixtures
(file absent / file 0000 / a sleeping helper / helper binary removed); assert four DIFFERENT reasons.
A sensor emitting the same reason for any two fails. This fixture is the direct antidote to the
Wazuh pattern and should be cited in NOTES.md.
```

```
FACT [derived from all sources in this track]: The concrete false-verdict classes with evidence
behind them are: false PASS from an assumed default (L19), from ENOENT-treated-as-safe (L34), from
EACCES-treated-as-absence (L25/L22), from TIMEOUT-treated-as-negative (L10); false FAIL from reading
one config file when another occurrence wins (L16), from "service not running" under socket
activation (L20), from misparsing mount options (L31); false UNKNOWN / under-claiming from giving up
when a documented fallback exists (L18/L27/L29/L30); silent omission from a check that errored, from
a WalkDir that never descended into /sys symlinks (L15), and from a truncated read that looked
complete (L12).
DESIGN LAW L36: Every check in the registry MUST be accompanied by at least one under-claim fixture,
not only a false-PASS fixture, because under-claiming is the failure mode a "safe" implementation
drifts toward and it is invisible to a reviewer who only tests the paranoid direction.
PROBE STRATEGY: n/a (process rule, enforced in review of the fixture matrix).
ADVERSARIAL FIXTURE: `fixture-matrix-coverage` — a meta-test asserting every registry check id
appears in FIXTURE_MATRIX.md with at least one expected-PASS/FAIL row and at least one
expected-UNKNOWN row.
```

## Topic 9 — Portability traps

```
FACT [R3-F74]: kernel.unprivileged_userns_clone is a Debian-carried downstream sysctl, not upstream;
upstream's knob is user.max_user_namespaces and the two are not equivalent (max=0 also blocks root)
[S31][S32]. LOCAL_REPRO makes the trap concrete: on WSL2 with ID=ubuntu, ID_LIKE=debian, the sysctl
is ABSENT while user.max_user_namespaces reads 30839, because the running kernel is Microsoft's
build, not an Ubuntu-patched one [S43]. Similarly /sys/kernel/security/lsm is ENOENT there
[R3-F73][S30], /sys/class/dmi is ENOENT [R3-F77], and /proc/mdstat is ENOENT.
DESIGN LAW L37: The sensor MUST gate on the observed presence of a path or capability, NEVER on
/etc/os-release ID, hostname, vendor or customer; when a knob has multiple distro-specific spellings
it MUST probe each and report UNKNOWN when none exists — never infer the value from the distro.
PROBE STRATEGY: try /proc/sys/kernel/unprivileged_userns_clone, then
/proc/sys/user/max_user_namespaces; ENOENT on both = UNKNOWN "no userns knob on this kernel", which
is a different statement from "userns is unrestricted". os-release ID/ID_LIKE is used ONLY to select
a documented default table (L19), never to predict kernel behaviour; PRETTY_NAME is never parsed
[S27].
ADVERSARIAL FIXTURE: `ubuntu-id-non-ubuntu-kernel` — fixture with ID=ubuntu and neither userns knob
present; expect UNKNOWN, not a value inferred from the distro. This is a fixture we literally
observed in the wild during this run.
```

```
FACT [R3-F71/R3-F72/R3-F75/R3-F76]: sd_booted(3) makes the existence of /run/systemd/system the
canonical systemd test and warns off the legacy cgroup path [S28]; systemd-detect-virt(1) exits 0
when virtualization IS detected — the inverse of the usual convention [S29]; util-linux 2.27 is the
floor for -J/--json on lsblk/findmnt [S33]; the Lockdown LSM landed in 5.4 [S34].
DESIGN LAW L38: Capability gates MUST precede probes: check /run/systemd/system before any
systemd-dependent check; treat systemd-detect-virt's exit code with its documented polarity and
UTILITY_MISSING as UNKNOWN (never "bare metal"); verify a JSON flag is supported before parsing JSON
and NEVER fall back to positional parsing of human-readable columns; and pair every kernel-feature
reading with the running kernel version so "absent because too old" and "absent because disabled"
stay distinguishable.
PROBE STRATEGY: /run/systemd/system (stat); uname release; `lsblk -V`/`ss -V`, or an
unrecognised-option exit mapped to PARSE_ERROR/UNKNOWN, never to a positional parse.
ADVERSARIAL FIXTURE: `detect-virt-polarity` — a stub exiting 0 with "kvm"; assert the sensor reports
virtualized, not bare metal. `no-json-flag` — a stub lsblk rejecting -J; assert UNKNOWN, and assert
the sensor did NOT fall back to column parsing. `no-systemd` — /run/systemd/system absent; assert
every systemd check is UNKNOWN "not systemd", not FAIL.
```

```
FACT [derived from R3-F02/F26/F30/F35/F48]: On this host ipmitool, smartctl, dmidecode, getfacl,
nft, aa-status and getenforce are all absent, yet /sys/class/ipmi, NVMe sysfs, /sys/class/dmi/id,
the xattr syscall, /proc/net/* and /sys/kernel/security/lsm answer the corresponding questions.
DESIGN LAW L39: A missing utility MUST NOT be reported as a missing capability. Every exec-based
probe MUST be a FALLBACK behind a sysfs/procfs primary, and UTILITY_MISSING may only be a finding's
reason when no kernel-exposed path can answer the question.
PROBE STRATEGY: the registry stores, per check, an ordered chain [sysfs/procfs] -> [file parse] ->
[exec]; the evidence block records which tier answered.
ADVERSARIAL FIXTURE: `no-ipmitool-still-answers` — fixture PATH with no ipmitool but a populated
/sys/class/ipmi; expect a real BMC verdict, not UNKNOWN/UTILITY_MISSING. Repeat for smartctl vs
NVMe sysfs and getfacl vs the ACL xattr.
```

---

## Contradiction-hunting pass (Phase 4) — what was found

Four genuine CONTESTED items, each with both sides recorded in `facts.jsonl`:

1. **R3-F25 UsePAM** — upstream OpenSSH default "no" [S1] vs Ubuntu noble's packaged "yes" [S5].
   The law follows the distro default when ID/ID_LIKE identifies the family, because that is what the
   running binary was packaged with; UNKNOWN when the family cannot be established.
2. **R3-F74 unprivileged_userns_clone** — Debian downstream sysctl vs upstream
   user.max_user_namespaces, with a live counter-example (ID=ubuntu, knob absent) reproduced in this
   session. The law follows path-probing over distro inference.
3. **R3-F05 protected_\* errno** — protected_hardlinks denies EPERM while its three siblings deny
   EACCES, from the same source file. Neither source is wrong; the collapsing assumption was.
4. **R3-F20 first-obtained-value** — the R3 brief assumed sshd_config and ssh_config have opposite
   precedence. Both man pages state first-value-wins. The brief's framing is corrected here.

Two further contradictions were resolved rather than left contested: os.Root's containment framing
vs its own device-file caveat (the caveat is in the same doc comment and wins), and golang/go#23019
closed *not planned* vs #50436 accepted (they are the motivating bug and the shipped API
respectively; both are cited).

## Honest limits of this run

- **Topic 4** is the thinnest on primary sources for magic bytes: PEM (RFC 7468) and OpenSSH
  PROTOCOL.key were quoted directly; JKS/JCEKS and keytab magics were not fetched from OpenJDK/MIT
  source and remain LIKELY. No DESIGN LAW rests on them — L23 is about the *procedure*, which is
  sourced independently.
- **NIST SP 800-115** (R3-F66) could not be text-extracted; it is marked SPECULATIVE and supports no
  law. The absence-of-evidence doctrine is instead grounded in XCCDF/OVAL/SARIF, which are stronger.
- **osquery's silent degradation** (R3-F63, LIKELY) rests on maintainer statements, not a spec page.
- No claim here is host-observed by me: I hold no SSH. Every host-specific statement is either from
  the embedded snapshot or an `OBSERVATION_REQUEST`.
- LOCAL_REPRO ran on WSL2 Ubuntu 26.04 / 6.18-microsoft, which is NOT the target (24.04 / 6.8.0-139)
  and has no DMI, no md, no securityfs. It is used only where the mechanism is kernel-generic, and is
  labelled everywhere it appears.

## NOT YET RESEARCHED (explicit gap list)

- POSIX ACL readability via the `system.posix_acl_access` xattr for a file the caller cannot read —
  xattr(7) says filesystem policy decides [S36]; ext4's actual policy was not established. Blocking
  for any ACL-based finding.
- `dmidecode`'s exact unprivileged error text and exit code.
- The precise kernel version that introduced `unprivileged_bpf_disabled=2` (CONTESTED, unpinned).
- iproute2's per-subcommand JSON version floors (LIKELY only).
- Whether a group kill reaches a child that calls setsid() itself — mitigated by a registry rule
  forbidding daemonising probes, but not proven.
- No PAM primary man page was fetched (mirror 404); the PAM account/session claim is secondary-only
  and supports no law.
