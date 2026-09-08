# R3 / Stream A — Safe unprivileged observation: kernel/sysfs/procfs exposure to uid != 0

Scope: what /proc and /sys expose to an unprivileged (uid 1000) reader; DMI sysfs permission
split; dmesg_restrict/kptr_restrict; hidepid=; protected_* sysctls; perf_event_paranoid /
unprivileged_bpf_disabled / yama ptrace_scope; errno semantics for sysfs/procfs reads; why
sysfs/procfs files misreport st_size.

All kernel source/doc citations are pinned to tag **v6.8** (matches the Lava host's
Ubuntu 24.04 6.8.0-139-generic base). LOCAL_REPRO was run on WSL2 Ubuntu 26.04
(`6.18.33.2-microsoft-standard-WSL2`) as unprivileged uid 1000 user `kldrm` — this is a
**different, newer, virtualized** kernel, used only to observe real behavior of documented
mechanisms, never as a stand-in for the Lava host's actual values.

---

## FACTS

FACT: procfs `hidepid=` mount option controls visibility of other users' `/proc/<pid>/`
directories: `hidepid=0` (default) = everybody sees all `/proc/<pid>/`; `hidepid=1` = a user
may not access files/subdirs inside another user's `/proc/<pid>/` (cmdline, sched*, status
protected); `hidepid=2` = as 1, plus other users' `/proc/<pid>/` directories become fully
invisible (blocks learning uid/gid via stat()) [S1][S2].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/mounts`, find the procfs entry, parse the `hidepid=` option value; then
`open("/proc/<other-pid>/status")`. EACCES = hidepid>=1 and target is not self and observer
not in `gid=` group (expected, not a fault). ENOENT = the target process exited between
listing and open (race, not a permission fact — must not be reported as "restricted").
IMPACT: sensor must read the mount option directly as evidence rather than inferring hidepid
level from a failed read of one specific pid (a single EACCES is ambiguous between hidepid=1
and hidepid=2 without also checking directory-entry visibility).
SOURCES: S1 | https://docs.kernel.org/filesystems/proc.html | Linux kernel docs, "Configuring procfs" | primary | webfetch ; S2 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/filesystems/proc.rst | Documentation/filesystems/proc.rst (pinned v6.8, lines ~2203-2238) | primary | curl

FACT: `dmesg_restrict` (0 = unrestricted; 1 = `dmesg(8)`/`klogctl()` requires `CAP_SYSLOG`)
is documented at Documentation/admin-guide/sysctl/kernel.rst lines 241-253 (v6.8); the kernel
enforces it in `kernel/printk/printk.c:check_syslog_permissions()`, which returns `-EPERM`
(not EACCES) when `syslog_action_restricted()` is true and the caller lacks `CAP_SYSLOG`
(and, with a deprecation warning, `CAP_SYS_ADMIN`) [S3][S10]. `syslog(2)` man page confirms
EPERM is the errno for privilege failures on this syscall [S14].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/kernel/dmesg_restrict` directly (authoritative, cheap, no exec). If a
sensor also shells out to `dmesg`, exit code != 0 with EPERM means "restricted", not
"dmesg missing" (UTILITY_MISSING) and not "fail" — must map to unknown/pass-with-reason using
the sysctl value as primary evidence.
IMPACT: never treat a non-zero `dmesg` exit code as a finding by itself; always read the
sysctl value as ground truth, use the exec attempt only as corroboration.
SOURCES: S3 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/admin-guide/sysctl/kernel.rst | kernel.rst pinned v6.8 (lines 241-253) | primary | curl ; S10 | https://elixir.bootlin.com/linux/v6.8/source/kernel/printk/printk.c | printk.c pinned v6.8, check_syslog_permissions() | primary | trafilatura ; S14 | https://man7.org/linux/man-pages/man2/syslog.2.html | syslog(2)/klogctl(2) man page | primary | curl ; S16 | LOCAL_REPRO WSL2 | `cat /proc/sys/kernel/dmesg_restrict` = 0, `dmesg` succeeded | local | wsl

FACT: `kptr_restrict`: 0 (default) = kernel addresses hashed before printing via `%pK`; 1 =
`%pK` prints 0s unless caller has `CAP_SYSLOG` AND effective uid/gid == real uid/gid (checked
at read() time, not open() time, specifically to defeat setuid-elevation-between-open-and-read
attacks); 2 = always 0s regardless of privilege [S3][S17].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/kernel/kptr_restrict` (0/1/2) as the authoritative signal. Do not
infer the restriction level from `/proc/kallsyms` output alone (all-zero addresses are
consistent with kptr_restrict>=1 OR with lacking CAP_SYSLOG at level 1 OR could reflect a
setuid-related euid/uid mismatch at level 1) — read the sysctl first.
IMPACT: a "kernel pointer leakage" check must read the sysctl, not grep kallsyms for
non-zero addresses as its sole evidence.
SOURCES: S3 | (same as above) kernel.rst pinned v6.8, lines 512-532 | primary | curl ; S17 | https://docs.kernel.org/admin-guide/sysctl/kernel.html | kernel.rst rendered docs (unpinned/current) | secondary | webfetch

FACT: `perf_event_paranoid` (default 2) gates `perf_event_open()`/tracing for users without
`CAP_PERFMON`: -1 = allow (almost) all events to all users; >=0 = disallow ftrace
function-tracepoint and raw tracepoint access; >=1 = also disallow CPU event access; >=2 =
also disallow kernel profiling. `CAP_SYS_ADMIN` still works for back-compat but is
discouraged in favor of `CAP_PERFMON` [S3].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/kernel/perf_event_paranoid`; treat any exec of `perf`/tracepoint
access as gated by this value, not by whether the `perf` binary exists.
IMPACT: a check that wants to use perf_event or tracepoints for evidence must read this
sysctl first and short-circuit to unknown ("insufficient privilege, paranoid>=N") rather
than attempting the syscall and reporting a bare EXECUTION_ERROR/fail.
SOURCES: S3 | kernel.rst pinned v6.8, lines 907-933 | primary | curl ; S17 | docs.kernel.org/admin-guide/sysctl/kernel.html | secondary | webfetch

FACT: `unprivileged_bpf_disabled`: 0 = unprivileged `bpf()` enabled; 1 = disabled, and cannot
be re-enabled at runtime; 2 = disabled but an admin can still flip it back to 0/1. Once
disabled, calling `bpf()` without `CAP_SYS_ADMIN`/`CAP_BPF` returns `-EPERM` explicitly per
the doc text [S3].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/kernel/unprivileged_bpf_disabled`. If a check attempts a bpf() syscall
regardless, EPERM there means "disabled by this sysctl", not EXECUTION_ERROR.
IMPACT: same pattern as above — sysctl read is ground truth, EPERM from the syscall itself is
corroborating evidence, not the primary signal.
SOURCES: S3 | kernel.rst pinned v6.8, lines 1566-1585 | primary | curl

FACT: Yama `ptrace_scope` (LSM, `/proc/sys/kernel/yama/ptrace_scope`, readable by anyone,
writable only with `CAP_SYS_PTRACE`): 0 = classic (same-uid ptrace allowed if dumpable); 1 =
restricted to a declared debugger relationship (default: descendants only, or via
`prctl(PR_SET_PTRACER,...)`); 2 = admin-only (`CAP_SYS_PTRACE` required for any
`PTRACE_ATTACH`/`PTRACE_TRACEME`); 3 = no ptrace at all, and once set cannot be changed back
without reboot [S5][S19].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/kernel/yama/ptrace_scope`; ENOENT on this path means `CONFIG_SECURITY_YAMA`
is not compiled in (a capability-absence fact, distinct from the sysctl being set to 0).
IMPACT: a "can this process attach to others" check must treat ENOENT (Yama absent) and value
0 (Yama present, unrestricted) as different findings, not collapse them to the same PASS.
SOURCES: S5 | https://elixir.bootlin.com/linux/v6.8/source/Documentation/admin-guide/LSM/Yama.rst | Yama.rst pinned v6.8 | primary | trafilatura ; S19 | https://docs.kernel.org/admin-guide/LSM/Yama.html | Yama.rst rendered docs (unpinned/current) | secondary | webfetch

FACT: `fs.protected_symlinks` (0 = unrestricted; 1 = a symlink in a sticky world-writable
dir may only be followed if outside such a dir, or uid of symlink==follower, or dir
owner==symlink owner) is enforced in `fs/namei.c:may_follow_link()`, which returns `-EACCES`
on denial [S4][S11].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/fs/protected_symlinks` (0/1). If a bounded file-read helper gets
EACCES specifically while resolving a path through a symlink inside a sticky world-writable
directory, that is consistent with this control, not with a plain DAC permission failure —
recording *which* it is requires checking the sysctl and the path shape, not just the errno.
IMPACT: EACCES from this path must not be treated as "file forbidden by owner"; it is a
kernel-level anti-TOCTOU control and should be surfaced/labelled distinctly if the sensor
walks any world-writable directory.
SOURCES: S4 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/admin-guide/sysctl/fs.rst | fs.rst pinned v6.8, lines 224-241 | primary | curl ; S11 | https://elixir.bootlin.com/linux/v6.8/source/fs/namei.c | namei.c pinned v6.8, may_follow_link() | primary | trafilatura

FACT: `fs.protected_hardlinks` (0 = unrestricted; 1 = a user cannot hardlink to a file they
don't own and don't have rw access to) is enforced in `fs/namei.c:may_linkat()`, which
returns **`-EPERM`**, NOT `-EACCES` — a different errno than the sibling protected_* controls
[S4][S11].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/fs/protected_hardlinks`; if the sensor ever attempts `link()`
(it should not — read-only), EPERM here is this control, not a generic "no permission" state.
IMPACT: if any future code path (even indirectly via a library) creates hardlinks, do not
conflate its EPERM with EACCES-style DAC denial when classifying the finding; see
CONTRADICTIONS below for the asymmetry with the other three protected_* controls.
SOURCES: S4 | fs.rst pinned v6.8, lines 188-203 | primary | curl ; S11 | namei.c pinned v6.8, may_linkat() | primary | trafilatura

FACT: `fs.protected_fifos` / `fs.protected_regular` (0 = unrestricted; 1 = block `O_CREAT`
open of a FIFO/regular file not owned by opener or dir owner in a world-writable sticky dir;
2 = also applies to group-writable sticky dirs) are enforced together in
`fs/namei.c:may_create_in_sticky()`, which returns `-EACCES` on denial [S4][S11], matching
the `open(2)` man page's EACCES clause for this exact case [S12].
STATUS: VERIFIED
APPLIES_TO: both
PROBE: read `/proc/sys/fs/protected_fifos` and `/proc/sys/fs/protected_regular` (0/1/2). The
sensor's bounded file reader must use `O_RDONLY` only (no `O_CREAT`) so this control never
triggers in practice — its role here is purely as an evidence/posture fact about the host,
not a read-path obstacle.
IMPACT: report these sysctl values as posture evidence; do not expect them to affect the
sensor's own read-only opens.
SOURCES: S4 | fs.rst pinned v6.8, lines 168-185 (fifos), 206-221 (regular) | primary | curl ; S11 | namei.c pinned v6.8, may_create_in_sticky() | primary | trafilatura ; S12 | https://man7.org/linux/man-pages/man2/open.2.html | open(2) man page, EACCES clause | primary | webfetch

FACT: DMI sysfs `/sys/class/dmi/id/*` (`drivers/firmware/dmi-id.c`, v6.8): most identity
fields are mode **0444** (world-readable) — `bios_vendor/version/date/release`,
`sys_vendor`, `product_name/version/sku/family`, `board_vendor/name/version/asset_tag`,
`chassis_vendor/type/version/asset_tag`, `modalias` (line 145). Four privacy-sensitive fields
are mode **0400** (root-only): `product_serial` (L49), `product_uuid` (L50),
`board_serial` (L56), `chassis_serial` (L61) — set explicitly via the `_mode` argument to the
`DEFINE_DMI_ATTR_WITH_SHOW` macro at each definition site.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: `stat -c "%a %U" /sys/class/dmi/id/<field>` for each field of interest, or attempt
`open(O_RDONLY)`. EACCES on `product_serial`/`product_uuid`/`board_serial`/`chassis_serial`
as uid 1000 is expected-by-design (report as unknown/reason=root-only, not fail). ENOENT on
any `/sys/class/dmi/id/*` field means the underlying DMI/SMBIOS data for that field is absent
on this machine (BIOS didn't populate it) — capability/data-absence, not a permission issue.
ENODEV on the whole directory would mean `dmi_available` is false (no DMI/SMBIOS at all,
e.g. many VMs) — see LOCAL_REPRO fact below, where the directory doesn't exist at all
(ENOENT one level up) rather than ENODEV, because the `dmi-id` driver's `arch_initcall`
never registers the class if `!dmi_available`.
IMPACT: a DMI-field check must special-case the four 0400 fields as "expected EACCES at
uid 1000", and must not report FAIL for them; the correct evidence is "field exists, mode
0400, unreadable at this privilege — by kernel design, not misconfiguration".
SOURCES: S7 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-id.c | dmi-id.c pinned v6.8, lines 41-62 and 145 | primary | curl

FACT: `/sys/firmware/dmi/entries/<type>-<instance>/raw` (raw SMBIOS structure bytes) and
`/sys/firmware/dmi/tables/{DMI,smbios_entry_point}` (raw full DMI table / entry-point struct)
are all mode **0400** root-only: `dmi-sysfs.c` sets `dmi_entry_raw_attr` `.mode = 0400` at
line 556; `dmi_scan.c` defines `static BIN_ATTR(smbios_entry_point, S_IRUSR, ...)` (line 757)
and `static BIN_ATTR(DMI, S_IRUSR, ...)` (line 758) (`S_IRUSR` == 0400). The per-entry
metadata attributes (`length`, `handle`, `type`, `instance`, `position`, defined via the
`DMI_SYSFS_ATTR` macro, `dmi-sysfs.c` lines 59/76) are *also* mode 0400 AND separately gated
at runtime: `dmi_sysfs_attr_show()` (line ~101-108) explicitly does
`if (!capable(CAP_SYS_ADMIN)) return -EACCES;` before calling the real show() — defense in
depth beyond the file mode alone.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: `ls -l /sys/firmware/dmi/tables/ /sys/firmware/dmi/entries/*/` and attempt
`open(O_RDONLY)` on `raw`/`DMI`/`smbios_entry_point`. EACCES at uid 1000 is expected;
ENOENT/absence of `/sys/firmware/dmi/` entirely means the `dmi-sysfs` module isn't loaded
(it's a separate optional module from the always-built-in `dmi-id`/`dmi_scan` core) —
capability-absence (UNSUPPORTED), not a permission fact.
IMPACT: sensor must never attempt to actually read DMI raw tables (they're root-only by
design and reading them would require privilege the sensor doesn't have); the presence/mode
of these paths is itself the finding, and any EACCES here is expected-PASS-shaped evidence
of "kernel correctly restricts raw firmware table access", not a check failure.
SOURCES: S8 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-sysfs.c | dmi-sysfs.c pinned v6.8, lines 59, 76, 101-108, 555-556 | primary | curl ; S9 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi_scan.c | dmi_scan.c pinned v6.8, lines 757-758 | primary | curl

FACT: sysfs attribute `show()` methods are called with a fixed **PAGE_SIZE** (4096 on x86)
buffer, exactly once per read(2) call; the method must fill the whole buffer; seeking back to
offset 0 (or a fresh `pread(2, offset=0)`) "rearms" show() to be called again. Attributes are
meant to hold one value (or a small homogeneous array) per file, as plain ASCII text.
`show()`/`store()` "can always return errors" but the doc does not enumerate specific errno
codes to use.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: n/a directly (this is a read-path *mechanism* fact, not a probe against one file) —
its consequence is tested by FACT below (st_size mismatch).
IMPACT: a bounded sysfs/procfs reader must always read in a loop until EOF (0-byte read) or a
generous cap, never rely on a single read() of a size derived from stat(); never seek away
and reuse a partially-filled buffer as if it were a stable snapshot mid-read.
SOURCES: S6 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/filesystems/sysfs.rst | sysfs.rst pinned v6.8, lines 195-253 | primary | curl ; S20 | https://docs.kernel.org/filesystems/sysfs.html | sysfs.rst rendered docs (unpinned/current) | secondary | webfetch

FACT: sysfs and procfs files do not report their true content length via `stat()`'s
`st_size`. LOCAL_REPRO on WSL2: `/sys/devices/system/cpu/online` reports `st_size=4096`
(the PAGE_SIZE buffer size from FACT above) while its actual content is 5 bytes (`"0-11\n"`,
verified with `wc -c`); `/sys/kernel/mm/transparent_hugepage/enabled` also reports 4096.
Meanwhile `/proc/sys/kernel/dmesg_restrict` and `/proc/version` both report `st_size=0`
despite being non-empty and readable. Neither convention (flat 4096, or flat 0) reflects the
actual number of bytes read(2) will return.
STATUS: VERIFIED
APPLIES_TO: both
PROBE: `stat(path).st_size` then `read()` in a loop to EOF, compare — expect mismatch as the
norm for `/sys/**` (0 or 4096 reported, real length usually far smaller) and for
`/proc/sys/**` (0 reported, real length nonzero). TIMEOUT applies if a read blocks (rare for
sysfs but possible for some /proc files that do work per read, e.g. slow instrumentation);
EIO applies to a handful of sysfs attributes backed by a live hardware transaction that can
fail (e.g. sensor chips going away mid-read).
IMPACT: never pre-allocate a read buffer sized from `stat()`, never use `st_size==0` as
"file is empty" for a PASS/absence determination — must always attempt a bounded read and
judge presence/absence from the read's own result (open() success + first byte), not from
metadata.
SOURCES: S6 | sysfs.rst pinned v6.8 (mechanism, lines 209-241) | primary | curl ; S16 | LOCAL_REPRO WSL2 | stat/wc/cat on /sys and /proc/sys files | local | wsl

FACT: Generic sysfs/procfs-read errno semantics (from `open(2)`/`read(2)` man pages):
EACCES = permission/capability check failed on an existing path (owner/mode bits, or a
kernel LSM/capability gate as in the DMI/protected_* facts above) — the object exists.
ENOENT = a path component (or the final attribute) does not exist — for sysfs this usually
means the underlying device/feature/data is genuinely absent, not merely unreadable.
EINVAL = "fd is attached to an object which is unsuitable for reading" — for a sysfs
attribute this typically means a malformed request (wrong offset/count) or that the specific
sub-operation isn't implemented by that attribute's `show()`. ENODEV = "path refers to a
device special file and no corresponding device exists" — man7 flags this as arguably a
kernel bug case (ENXIO would be more correct), rare in practice for sysfs/procfs text
attributes. EIO = low-level I/O error, e.g. a hardware read failed while servicing the
attribute. `EOPNOTSUPP`/`ENOTSUP` appear in the open(2) man page only for the `O_TMPFILE`
feature, not as a general sysfs convention — a sysfs driver author who wants to signal
"this operation isn't supported for this attribute" typically returns `-EINVAL` or `-ENOSYS`
by convention, not a POSIX-standard "unsupported" errno.
STATUS: VERIFIED
APPLIES_TO: generic
PROBE: classify every failed `open()`/`read()` on a sysfs/procfs path by errno using this
mapping before deciding pass/fail/unknown; TIMEOUT (a wrapper-imposed deadline, not a kernel
errno) must be tracked separately from all of these since a hung read never returns an errno
at all.
IMPACT: the sensor's evidence layer must carry the raw errno (or "TIMEOUT"/"deadline") for
every failed read, not a boolean, so downstream classification can distinguish "absent" from
"present-but-forbidden" from "hung".
SOURCES: S12 | https://man7.org/linux/man-pages/man2/open.2.html | open(2) man page, ERRORS section | primary | webfetch ; S13 | https://man7.org/linux/man-pages/man2/read.2.html | read(2) man page, ERRORS section | primary | curl

FACT: reading your *own* `/proc/<pid>/*` requires no extra permission beyond the mount's
`hidepid=` setting; reading *another* uid's `/proc/<pid>/*` requires `CAP_SYS_PTRACE` with
`PTRACE_MODE_READ` access — the current (unpinned, rolling) docs.kernel.org rendering of
proc.rst additionally states `CAP_PERFMON` is accepted as an alternative capability for this,
but that sentence is **absent** from the pinned v6.8 tag of `Documentation/filesystems/proc.rst`
fetched from the upstream v6.8 tree.
STATUS: CONTESTED
APPLIES_TO: both
PROBE: attempt `open("/proc/<own-pid>/status")` (expect success) vs
`open("/proc/<other-uid-pid>/status")` (expect EACCES for a plain uid-1000 process without
CAP_SYS_PTRACE, regardless of hidepid). Do not assume CAP_PERFMON grants this access without
confirming the running kernel's actual behavior/version.
IMPACT: do not cite "CAP_PERFMON as alternative" as a host fact without testing it live on
the Lava host's actual 6.8.0-139-generic kernel; treat it as upstream-doc version drift until
confirmed. See GAPS.
SOURCES: S1 | docs.kernel.org/filesystems/proc.html (unpinned, current) | secondary | webfetch ; S2 | raw.githubusercontent.com .../v6.8/Documentation/filesystems/proc.rst (pinned, does NOT contain this sentence) | primary | curl

FACT: On a virtualized kernel with no exposed SMBIOS/DMI data (WSL2, LOCAL_REPRO), the
entire `/sys/class/dmi/id/` directory and `/sys/firmware/dmi/` tree are simply **absent**
(ENOENT one level up, not ENODEV, not EACCES) — because `dmi_id_init()`
(`drivers/firmware/dmi-id.c`) bails out with `-ENODEV` internally and never registers the
class/kobject at all when `dmi_available` is false, so no sysfs nodes are ever created for
uid 1000 to even attempt opening.
STATUS: VERIFIED
APPLIES_TO: generic
PROBE: `ls /sys/class/dmi/id/` → ENOENT means "this machine's kernel found no usable
DMI/SMBIOS table" (a real, reportable capability-absence fact), completely distinct from the
0400-root-only EACCES case documented above for specific fields on a machine that *does*
have DMI. A sensor must not conflate "no DMI subsystem at all" with "DMI present but this
one field is root-gated".
IMPACT: confirms the CLAUDE.md invariant "EACCES ≠ absent" empirically in the reverse
direction too: here, true absence surfaces as ENOENT/whole-directory-missing, never as
EACCES — so a sensor's DMI check needs three-way logic (dir missing → capability absent;
dir present, field missing → data not populated by firmware; dir+field present, EACCES →
root-only-by-design, still "capability present, evidence unreadable at this privilege").
SOURCES: S7 | drivers/firmware/dmi-id.c pinned v6.8 (dmi_id_init, `if (!dmi_available) return -ENODEV;`) | primary | curl ; S16 | LOCAL_REPRO WSL2 | `ls /sys/class/dmi/id/` → "No such file or directory"; `ls /sys/firmware/dmi/tables/` → same | local | wsl

FACT: WSL2 Ubuntu 26.04 (`6.18.33.2-microsoft-standard-WSL2`) baseline sysctl values observed
as uid 1000: `dmesg_restrict=0`, `kptr_restrict=1`, `perf_event_paranoid=2`,
`unprivileged_bpf_disabled=2`, `yama/ptrace_scope=1`, `protected_symlinks=1`,
`protected_hardlinks=1`, `protected_fifos=1`, `protected_regular=2`. `dmesg` succeeded
(consistent with dmesg_restrict=0). `/proc` was mounted with no explicit `hidepid=` in the
`mount` output (defaults apply).
STATUS: VERIFIED (LOCAL_REPRO only, single machine)
APPLIES_TO: generic
PROBE: this is illustrative of one modern Ubuntu-family default hardening posture, not proof
of the Lava host's values — the host runs Ubuntu 24.04 (6.8.0-139-generic, non-virtualized,
bare metal), a different distro release and a real, non-Hyper-V kernel build, and its actual
sysctl values must be independently observed via the lead's TCI/SSH executor, not assumed
from this WSL2 sample.
IMPACT: use this only as a plausibility/regression baseline for what "typical modern Ubuntu
defaults" look like; every one of these values is a required OBSERVATION_REQUEST for the
actual host.
SOURCES: S16 | LOCAL_REPRO WSL2 | direct `cat`/`mount` output, see command block in transcript | local | wsl

---

## SOURCES LIST

S1 | https://docs.kernel.org/filesystems/proc.html | Linux kernel documentation: procfs (Configuring procfs / hidepid, unpinned "current" build) | secondary | webfetch | 2026-09-09T00:00:00Z
S2 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/filesystems/proc.rst | Documentation/filesystems/proc.rst, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S3 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/admin-guide/sysctl/kernel.rst | Documentation/admin-guide/sysctl/kernel.rst, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S4 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/admin-guide/sysctl/fs.rst | Documentation/admin-guide/sysctl/fs.rst, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S5 | https://elixir.bootlin.com/linux/v6.8/source/Documentation/admin-guide/LSM/Yama.rst | Documentation/admin-guide/LSM/Yama.rst, pinned tag v6.8 | primary | trafilatura | 2026-09-09T00:00:00Z
S6 | https://raw.githubusercontent.com/torvalds/linux/v6.8/Documentation/filesystems/sysfs.rst | Documentation/filesystems/sysfs.rst, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S7 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-id.c | drivers/firmware/dmi-id.c, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S8 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi-sysfs.c | drivers/firmware/dmi-sysfs.c, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S9 | https://raw.githubusercontent.com/torvalds/linux/v6.8/drivers/firmware/dmi_scan.c | drivers/firmware/dmi_scan.c, pinned tag v6.8 | primary | curl | 2026-09-09T00:00:00Z
S10 | https://elixir.bootlin.com/linux/v6.8/source/kernel/printk/printk.c | kernel/printk/printk.c, pinned tag v6.8 | primary | trafilatura | 2026-09-09T00:00:00Z
S11 | https://elixir.bootlin.com/linux/v6.8/source/fs/namei.c | fs/namei.c, pinned tag v6.8 | primary | trafilatura | 2026-09-09T00:00:00Z
S12 | https://man7.org/linux/man-pages/man2/open.2.html | open(2) man page | primary | webfetch | 2026-09-09T00:00:00Z
S13 | https://man7.org/linux/man-pages/man2/read.2.html | read(2) man page | primary | curl | 2026-09-09T00:00:00Z
S14 | https://man7.org/linux/man-pages/man2/syslog.2.html | syslog(2)/klogctl(2) man page | primary | curl | 2026-09-09T00:00:00Z
S15 | https://man7.org/linux/man-pages/man5/proc.5.html | proc(5) man page | primary | webfetch | 2026-09-09T00:00:00Z
S16 | LOCAL_REPRO (no URL) | WSL2 Ubuntu 26.04, kernel 6.18.33.2-microsoft-standard-WSL2, uid 1000 user "kldrm" | local | wsl -e bash -lc | 2026-09-09T00:00:00Z
S17 | https://docs.kernel.org/admin-guide/sysctl/kernel.html | kernel.rst rendered docs (unpinned/current) | secondary | webfetch | 2026-09-09T00:00:00Z
S18 | https://docs.kernel.org/admin-guide/sysctl/fs.html | fs.rst rendered docs (unpinned/current) | secondary | webfetch | 2026-09-09T00:00:00Z
S19 | https://docs.kernel.org/admin-guide/LSM/Yama.html | Yama.rst rendered docs (unpinned/current) | secondary | webfetch | 2026-09-09T00:00:00Z
S20 | https://docs.kernel.org/filesystems/sysfs.html | sysfs.rst rendered docs (unpinned/current) | secondary | webfetch | 2026-09-09T00:00:00Z

---

## CONTRADICTIONS

1. **protected_hardlinks vs. its siblings — errno asymmetry.** `protected_symlinks`
   (`may_follow_link()`) and `protected_fifos`/`protected_regular`
   (`may_create_in_sticky()`) all deny with `-EACCES`, but `protected_hardlinks`
   (`may_linkat()`) denies with `-EPERM` — same file (`fs/namei.c`, v6.8), same "sticky/DAC
   overrides" family of protections, different errno. Not a disagreement between sources
   (both confirmed in the same primary source, S4+S11) but an internal kernel inconsistency a
   sensor must not paper over by assuming a single errno means "blocked by protected_*".

2. **CAP_PERFMON as alternative to CAP_SYS_PTRACE for reading other pids' /proc info.**
   docs.kernel.org's current/rolling proc.rst (S1) states this; the pinned v6.8 tag of the
   same file fetched from upstream (S2) does not contain this sentence at all. This is
   version drift between the "latest" doc build docs.kernel.org serves and the v6.8 tag we
   pinned for every other proc.rst citation in this note. Left as CONTESTED in the fact above
   pending host-kernel-version-correct confirmation.

---

## GAPS (host facts that need an OBSERVATION_REQUEST — no SSH from this stream)

- Actual host values (Ubuntu 24.04, kernel 6.8.0-139-generic, bare metal) for:
  `dmesg_restrict`, `kptr_restrict`, `perf_event_paranoid`, `unprivileged_bpf_disabled`,
  `kernel/yama/ptrace_scope`, `fs.protected_symlinks/hardlinks/fifos/regular`.
- Whether `/proc` on the host is mounted with any `hidepid=`/`gid=`/`subset=` option
  (`grep ^proc /proc/mounts` on host).
- Whether `/sys/class/dmi/id/*` exists on the host and, if so, `stat -c "%a %U %n"` on each
  field — confirm the 0444 vs 0400 split from FACT above matches live reality (bare-metal
  Supermicro board should have full DMI, unlike WSL2).
- Whether `dmi-sysfs` is loaded on the host (`ls /sys/firmware/dmi/`) — it's a separate
  optional module from the always-on `dmi-id`/`dmi_scan` core; presence/absence is itself a
  fact, not assumable from DMI-id being present.
- Whether reading another uid's `/proc/<pid>/status` on the host's actual kernel build
  returns EACCES uniformly, or whether some CAP_PERFMON-alternative path exists (resolves the
  CONTESTED fact above) — this needs a live test on the host kernel, not just doc archaeology.
- Ubuntu's kernel package for 6.8.0-139-generic may carry backported doc/behavior deltas
  vs. vanilla upstream v6.8; this note assumes vanilla upstream semantics apply, which is
  usually true for these particular mechanisms (they're old, stable, non-Ubuntu-specific) but
  is unverified against Ubuntu's actual patch set.
