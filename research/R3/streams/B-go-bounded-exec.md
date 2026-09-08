# R3 / STREAM-B — Bounded subprocesses and bounded file reads in Go

Scope: exact, citable Go stdlib behaviour for (a) bounded/cancellable subprocess execution and
(b) bounded, safe reads of /proc, /sys and arbitrary filesystem paths, for a read-only,
unprivileged (uid 1000), Linux-only posture sensor.

Local toolchain used as a PRIMARY source: `go version go1.26.2 windows/amd64`,
stdlib source at `C:\Program Files\Go\src\...` (paths below written POSIX-style as
`/c/Program Files/Go/src/...`). Every source-code claim is cited as file:line + function.
Cross-checked against pkg.go.dev pinned at `@go1.24.0` where wording matters — wording is
identical, so the behaviour is stable Go 1.20 → Go 1.26.

LOCAL_REPRO environment (WSL2): `uname -r` = `6.18.33.2-microsoft-standard-WSL2`,
os-release PRETTY_NAME = `Ubuntu 26.04 LTS`.

---

## A. Subprocess cancellation and process teardown

### FACT 1 — CommandContext's default cancellation kills the CHILD ONLY, never the process group
FACT: `exec.CommandContext` sets `cmd.Cancel = func() error { return cmd.Process.Kill() }` and leaves
`WaitDelay` unset [S1][S2]. `os.Process.Kill` is documented as: "Kill causes the Process to exit
immediately. Kill does not wait until the Process has actually exited. **This only kills the Process
itself, not any other processes it may have started.**" [S3]. On Linux `Kill` sends SIGKILL to the
single child PID; no process-group signal is ever sent by the stdlib.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Do NOT rely on `exec.CommandContext` alone for a timeout budget. A probe like
`sh -c 'ipmitool ... | head'`, `timeout`, or any wrapper that forks will leave grandchildren alive
after ctx cancellation. Convert to failure class TIMEOUT (`unknown` + reason=timeout), and pair
CommandContext with an explicit process-group kill (FACT 4) plus `WaitDelay` (FACT 2).
IMPACT: Ignoring this yields orphaned grandchildren on the Lava host after `sensor scan` exits —
a read-only sensor that leaves running processes behind violates the "never change the target"
invariant, and the scan can still hang (FACT 5).
SOURCES: S1 | /c/Program Files/Go/src/os/exec/exec.go:484-494 `func CommandContext` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S2 | https://pkg.go.dev/os/exec@go1.24.0#CommandContext | os/exec CommandContext doc @go1.24.0 | primary | WebFetch
          S3 | /c/Program Files/Go/src/os/exec.go:333-338 `func (p *Process) Kill` | Go stdlib os source (go1.26.2) | primary | local-source-read

### FACT 2 — `Cmd.WaitDelay` (Go 1.20+) is the ONLY stdlib bound on "child exited but pipes still open"
FACT: Doc comment, verbatim [S4]: "If WaitDelay is non-zero, it bounds the time spent waiting on two
sources of unexpected delay in Wait: a child process that fails to exit after the associated Context
is canceled, and a child process that exits but leaves its I/O pipes unclosed. The WaitDelay timer
starts when either the associated Context is done or a call to Wait observes that the child process
has exited, whichever occurs first. When the delay has elapsed, the command shuts down the child
process and/or its I/O pipes. If the child process has failed to exit ... then it will be terminated
using os.Process.Kill. Then, if the I/O pipes communicating with the child process are still open,
those pipes are closed in order to unblock any goroutines currently blocked on Read or Write calls.
If pipes are closed due to WaitDelay, no Cancel call has occurred, and the command has otherwise
exited with a successful status, Wait and similar methods will return ErrWaitDelay instead of nil.
**If WaitDelay is zero (the default), I/O pipes will be read until EOF, which might not occur until
orphaned subprocesses of the command have also closed their descriptors for the pipes.**"
`var ErrWaitDelay = errors.New("exec: WaitDelay expired before I/O complete")` [S5].
Added in Go 1.20: "The new Cmd fields Cancel and WaitDelay specify the behavior of the Cmd when its
associated Context is canceled or its process exits with I/O pipes still held open by a child
process." [S6]. Accepted proposal: golang/go#50436 "os/exec: add fields for managing termination
signals and pipes", Proposal-Accepted, milestone Go1.20 [S7].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Every `exec.Cmd` the sensor creates MUST set a non-zero `Cmd.WaitDelay` (e.g. 1-2s,
strictly less than the residual scan budget). Treat `errors.Is(err, exec.ErrWaitDelay)` as
failure class TIMEOUT/TRUNCATED (`unknown` + reason), never as `fail`, and keep whatever bytes were
already copied as partial evidence.
IMPACT: Without WaitDelay a single probe whose grandchild inherited stdout blocks `Wait()`
indefinitely; the whole-scan deadline (FACT 13) cannot rescue it because the blocked party is the
sensor's own copy goroutine, not the child.
SOURCES: S4 | /c/Program Files/Go/src/os/exec/exec.go:278-303 `Cmd.WaitDelay` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S5 | /c/Program Files/Go/src/os/exec/exec.go:125-128 `ErrWaitDelay` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S6 | https://go.dev/doc/go1.20 (os/exec section) | Go 1.20 Release Notes | primary | WebFetch
          S7 | https://github.com/golang/go/issues/50436 | "os/exec: add fields for managing termination signals and pipes" | primary | WebFetch

### FACT 2b — WaitDelay works WITHOUT a Context; and the ctx watcher only runs if Cancel or WaitDelay is set
FACT: `Cmd.awaitGoroutines` starts its own `time.NewTimer(c.WaitDelay)` when no ctx timer was handed
to it, so `WaitDelay` bounds the copy goroutines even for a `Cmd` created by plain `exec.Command`
[S8]. Conversely, `Cmd.Start` only spawns the context watcher when
`(c.Cancel != nil || c.WaitDelay != 0) && c.ctx != nil && c.ctx.Done() != nil` [S9] — setting
`Cancel = nil` on a CommandContext-created Cmd disables signalling but keeps WaitDelay effective
(documented: "If Cancel is set to nil, nothing will happen immediately when the command's Context is
done, but a nonzero WaitDelay will still take effect." [S10]).
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: A shared helper `runBounded(ctx, ...)` can set WaitDelay unconditionally; it is not
dependent on the caller passing a cancellable context.
IMPACT: Misbelief that WaitDelay needs a Context leads to unbounded probes on the non-ctx code path.
SOURCES: S8 | /c/Program Files/Go/src/os/exec/exec.go:967-1004 `func (c *Cmd) awaitGoroutines` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S9 | /c/Program Files/Go/src/os/exec/exec.go:780 `func (c *Cmd) Start` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S10 | /c/Program Files/Go/src/os/exec/exec.go:270-274 `Cmd.Cancel` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read

### FACT 3 — `Cmd.Cancel` returning an error wrapping `os.ErrProcessDone` suppresses the injected ctx error
FACT: Doc, verbatim [S11]: "If the command exits with a success status after Cancel is called, and
Cancel does not return an error equivalent to os.ErrProcessDone, then Wait and similar methods will
return a non-nil error: either an error wrapping the one returned by Cancel, or the error from the
Context. (If the command exits with a non-success status, or Cancel returns an error that wraps
os.ErrProcessDone, Wait and similar methods continue to return the command's usual exit status.)"
Implementation in `watchCtx` [S12]: if `Cancel()` returns nil → `err = c.ctx.Err()`; if it returns
an error satisfying `errors.Is(interruptErr, os.ErrProcessDone)` → no error injected ("The process
already finished: we just didn't notice it yet"); otherwise → `wrappedError{prefix: "exec: canceling Cmd"}`.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: A custom `cmd.Cancel` that group-kills must return an error that wraps
`os.ErrProcessDone` (or `nil`) rather than a raw `ESRCH`, otherwise a probe that finished normally
microseconds before the deadline is misreported as an execution error. Map the resulting error with
`errors.Is(err, context.DeadlineExceeded)` → TIMEOUT, `*exec.ExitError` → non-zero exit (still real
evidence), anything else → EXECUTION_ERROR. None of these are `fail`.
IMPACT: Cancel-error mishandling turns benign races into spurious `unknown`/`fail` findings, i.e.
false negatives on checks that actually succeeded — a direct violation of
"EXECUTION_ERROR ≠ false".
SOURCES: S11 | /c/Program Files/Go/src/os/exec/exec.go:261-268 `Cmd.Cancel` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S12 | /c/Program Files/Go/src/os/exec/exec.go:795-820 `func (c *Cmd) watchCtx` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read

### FACT 4 — Killing the whole tree requires `SysProcAttr{Setpgid: true}` + `syscall.Kill(-pgid, SIGKILL)`
FACT: `syscall.SysProcAttr` on Linux documents `Setpgid bool // Setpgid sets the process group ID of
the child to Pgid, or, if Pgid == 0, to the new child's process ID.` and `Pgid int // Child's
process group ID if Setpgid.` [S13]; the child-side implementation issues
`RawSyscall(SYS_SETPGID, 0, uintptr(sys.Pgid), 0)` when `sys.Setpgid || sys.Foreground` [S14].
`kill(2)`: "If pid is less than -1, then sig is sent to every process in the process group whose ID
is -pid." [S15]. So with `Setpgid: true, Pgid: 0` the child's pgid == child's pid, and
`syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)` reaps the child and every grandchild that stayed
in that group.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE:
  `cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`
  `cmd.Cancel = func() error { err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); if err == syscall.ESRCH { return os.ErrProcessDone }; return err }`
  `cmd.WaitDelay = <residualBudget>`
  Build tag: this is `_linux`/`_unix`-only code; the sensor is Linux-only so no portability seam is
  needed, but the field must not appear in shared files compiled for other GOOS.
IMPACT: WITHOUT `Setpgid: true` the child shares the SENSOR's process group, so
`Kill(-pgid, SIGKILL)` **kills the sensor itself**. This is the single most dangerous construct in
the bounded-exec design and must be covered by a test. Without the group kill at all, grandchildren
survive the scan (FACT 1).
Caveats: (a) only valid after `Start()` returns nil (`cmd.Process` is nil before that; `Cancel` is
documented as not called if Start fails [S16]); (b) `ESRCH` after the group is gone is benign and
must be normalised (FACT 3); (c) `EPERM` cannot occur here since we own the child (uid 1000
signalling its own descendants) [S15].
SOURCES: S13 | /c/Program Files/Go/src/syscall/exec_linux.go:67-107 `type SysProcAttr` | Go stdlib syscall source (go1.26.2) | primary | local-source-read
          S14 | /c/Program Files/Go/src/syscall/exec_linux.go:393-402 `forkAndExecInChild` | Go stdlib syscall source (go1.26.2) | primary | local-source-read
          S15 | https://man7.org/linux/man-pages/man2/kill.2.html | kill(2) — Linux manual page | primary | WebFetch
          S16 | /c/Program Files/Go/src/os/exec/exec.go:275 `Cmd.Cancel` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read

### FACT 5 — The classic hang: `Wait` blocks on the copy goroutines, not on the child
FACT: `Cmd.Stdout`/`Stderr` doc, verbatim [S17]: "Otherwise, during the execution of the command a
separate goroutine reads from the process over a pipe and delivers that data to the corresponding
Writer. **In this case, Wait does not complete until the goroutine reaches EOF or encounters an error
or a nonzero WaitDelay expires.**" Same for `Stdin` [S18]. `Cmd.Wait` doc: "Wait waits for the
command to exit **and waits for any copying to stdin or copying from stdout or stderr to complete**
... If any of c.Stdin, c.Stdout or c.Stderr are not an *os.File, Wait also waits for the respective
I/O loop copying to or from the process to complete." [S19]. `Cmd.Output`/`CombinedOutput` set
`c.Stdout`/`c.Stderr` to `*bytes.Buffer` (non-`*os.File`), so they take exactly this path [S20].
The upstream bug is golang/go#23019 "os/exec: consider changing Wait to stop copying goroutines
rather than waiting for them" (ianlancetaylor; closed as not planned — superseded by the WaitDelay
proposal #50436) [S21]; the stdlib source itself points at it: `watchCtx` comments "Close the child
process's I/O pipes, in case it abandoned some subprocess that inherited them and is still holding
them open (see https://go.dev/issue/23019)." [S22].
`StdoutPipe` has the mirror-image trap: "Cmd.Wait will close the pipe after seeing the command exit,
so most callers need not close the pipe themselves. It is thus incorrect to call Wait before all
reads from the pipe have completed. For the same reason, it is incorrect to call Cmd.Run when using
StdoutPipe." [S23].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Prefer a single bounded helper built on `cmd.Stdout = <capped writer>` + `Start`/`Wait`
+ `WaitDelay`; do not use bare `Output()`/`CombinedOutput()` without WaitDelay, and do not use
`StdoutPipe` (its contract fights the timeout design). Realistic triggers on the Lava host: any probe
run through `sh -c`, anything that starts a background helper, `systemctl` invocations that can
attach to a pager, `udevadm`/`lsblk` wrappers.
IMPACT: One such probe hangs the entire scan even though the child already exited — the sensor never
writes `findings.json`.
SOURCES: S17 | /c/Program Files/Go/src/os/exec/exec.go:208-224 `Cmd.Stdout`/`Cmd.Stderr` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S18 | /c/Program Files/Go/src/os/exec/exec.go:192-206 `Cmd.Stdin` field doc | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S19 | /c/Program Files/Go/src/os/exec/exec.go:905-922 `func (c *Cmd) Wait` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S20 | /c/Program Files/Go/src/os/exec/exec.go:1009-1040 `Cmd.Output` / `Cmd.CombinedOutput` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S21 | https://github.com/golang/go/issues/23019 | "os/exec: consider changing Wait to stop copying goroutines rather than waiting for them" | primary | WebFetch
          S22 | /c/Program Files/Go/src/os/exec/exec.go:860-870 `func (c *Cmd) watchCtx` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S23 | /c/Program Files/Go/src/os/exec/exec.go:1074-1082 `func (c *Cmd) StdoutPipe` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read

### FACT 6 — `io.LimitReader` signals the cap with EOF, NOT an error — a cap is silently indistinguishable from a short file
FACT: "LimitReader returns a Reader that reads from r but stops with EOF after n bytes." and
`LimitedReader.Read` returns `(0, EOF)` when `l.N <= 0` [S24]. `io.CopyN` "copies n bytes (or until
an error) from src to dst ... On return, written == n if and only if err == nil"; it is implemented
as `Copy(dst, LimitReader(src, n))` and converts a short read into `io.EOF` [S25].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Never use a bare `io.LimitReader(r, cap)` for output caps — a truncated 10 MiB
`dmesg` becomes indistinguishable from a complete 300-byte answer. Use `io.LimitReader(r, cap+1)`
(or `io.CopyN(dst, src, cap+1)`) and treat `written > cap` as failure class TRUNCATED:
`unknown` + `reason: "output exceeded N bytes"`, and kill the child immediately (FACT 4) so the
producer stops. The disambiguation is purely `written > cap`; the error value alone never tells you.
IMPACT: Silent truncation of a probe's output produces a confidently wrong `pass`/`fail` derived
from a partial parse — the worst possible failure mode for an evidence-based sensor.
SOURCES: S24 | /c/Program Files/Go/src/io/io.go:458-482 `LimitReader`, `LimitedReader.Read` | Go stdlib io source (go1.26.2) | primary | local-source-read
          S25 | /c/Program Files/Go/src/io/io.go:357-373 `func CopyN` | Go stdlib io source (go1.26.2) | primary | local-source-read

### FACT 7 — Zombie reaping: `Wait` (or `Process.Release`) is mandatory after a successful `Start`
FACT: "After a successful call to Start the Cmd.Wait method must be called in order to release
associated system resources." [S26]. "Release releases any resources associated with the Process p,
rendering it unusable in the future. **Release only needs to be called if Process.Wait is not.**"
[S27]. "Wait waits for the Process to exit, and then returns a ProcessState ... Wait releases any
resources associated with the Process." [S28]. On Linux the underlying wait4(2) is what removes the
zombie from the process table; killing without waiting leaves `<defunct>` entries owned by the sensor.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: The bounded-exec helper must `defer`-guarantee exactly one `Wait()` on every path,
including the timeout path and the output-cap path (kill then still Wait). Never `return` from a
probe between `Start` and `Wait`. Note Go >= 1.23 finalizers can reap eventually, but that is not a
contract to rely on.
IMPACT: Leaked zombies mutate the target's process table — a visible, attributable side effect on
Lava's production host, contradicting "read only / never change the target". With ~30-60 probes,
a leak per probe is trivially observable in `ps`.
SOURCES: S26 | /c/Program Files/Go/src/os/exec/exec.go:635-641 `func (c *Cmd) Start` | Go stdlib os/exec source (go1.26.2) | primary | local-source-read
          S27 | /c/Program Files/Go/src/os/exec.go:275-278 `func (p *Process) Release` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S28 | /c/Program Files/Go/src/os/exec.go:340-345 `func (p *Process) Wait` | Go stdlib os source (go1.26.2) | primary | local-source-read

---

## B. Bounded, safe file reads (/proc, /sys, arbitrary paths)

### FACT 8 — `os.ReadFile` treats `st_size` as a HINT and reads until EOF; it is correct on /proc and /sys
FACT: `ReadFile` calls `readFileContents(statOrZero(f), f.Read)`; `statOrZero` returns `fi.Size()` or
0 [S29]. `readFileContents` doc: "The provided size is the stat size of the file, **which might be 0
for a /proc-like file that doesn't report a size**." It sets `zeroSize := statSize == 0`, then
`const minBuf = 512` with the comment "If a file claims a small size, read at least 512 bytes. In
particular, **files in Linux's /proc claim size 0 but then do not work right if read in small
pieces**, so an initial read of 1 byte would not work correctly." The loop grows the buffer by
`minBuf` whenever `capRemain == 0 || (zeroSize && capRemain < minBuf)` and only returns on a non-nil
error, translating `io.EOF` to `nil` [S30]. Referenced hardening: Go issue 72080 ("we always want to
issue Read calls on zero-length files with a non-tiny buffer size").
LOCAL_REPRO (WSL2 6.18.33.2-microsoft-standard-WSL2 / Ubuntu 26.04 LTS):
`stat -c "%n size=%s type=%F"` →
  `/proc/cpuinfo size=0 type=regular empty file`
  `/proc/meminfo size=0 type=regular empty file`
  `/sys/devices/system/cpu/online size=4096 type=regular file`
i.e. procfs reports 0 and sysfs reports the page size 4096, neither of which is the real content
length.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Use `os.ReadFile` for procfs/sysfs scalars — it is already correct. Do NOT hand-roll
`Stat` → `make([]byte, fi.Size())` → single `Read`: that returns "" for every /proc file and a
4096-byte NUL-padded blob for sysfs. For an explicit byte cap, wrap manually
(`os.Open` + `io.CopyN(buf, f, cap+1)`) rather than trusting `fi.Size()` as the cap.
IMPACT: A size-based reader silently reports every /proc-derived check as empty → mass `unknown`
(or worse, `fail` if empty is parsed as "feature absent"), directly violating
"Absence is only provable from a successful listing."
SOURCES: S29 | /c/Program Files/Go/src/os/file.go:860-879 `func ReadFile`, `statOrZero` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S30 | /c/Program Files/Go/src/os/file.go:881-925 `func readFileContents` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S31 | LOCAL_REPRO WSL2 `uname -r`=6.18.33.2-microsoft-standard-WSL2, Ubuntu 26.04 LTS, `stat -c %s` | local experiment | primary | Bash/wsl

### FACT 9 — Only open regular files: `FileMode.IsRegular()` == "no mode type bits set"
FACT: "IsRegular reports whether m describes a regular file. That is, it tests that no mode type bits
are set" → `return m&ModeType == 0`, where
`ModeType = ModeDir | ModeSymlink | ModeNamedPipe | ModeSocket | ModeDevice | ModeCharDevice | ModeIrregular`
[S32]. Individual bits: `ModeDevice` (D), `ModeNamedPipe` (p: FIFO), `ModeSocket` (S: Unix domain
socket), `ModeCharDevice` (c, only meaningful when ModeDevice is set) [S32].
LOCAL_REPRO: `stat -c "%n %F %a"` → `/dev/null character special file 666`,
`/dev/kmsg character special file 644` [S31].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Gate every file read with `fi, err := os.Lstat(p)` then `fi.Mode().IsRegular()`.
Use `Lstat`, not `Stat`, when the decision is "is this path itself safe" — `Stat` follows symlinks
and reports the target's type. `IsRegular()` is a single check that simultaneously excludes
directories, symlinks, FIFOs, sockets and device nodes. A non-regular path is failure class
UNSUPPORTED/SKIPPED → `unknown` + reason `"not a regular file: <type>"`, never `fail`.
IMPACT: Opening `/dev/kmsg` or a random char device on Lava's bare-metal host can block, return
garbage, or (for some drivers) have side effects — the sensor must be provably side-effect free.
SOURCES: S32 | /c/Program Files/Go/src/io/fs/fs.go:197-247 `ModeDevice`/`ModeNamedPipe`/`ModeSocket`/`ModeCharDevice`/`ModeType`, `func (m FileMode) IsRegular` | Go stdlib io/fs source (go1.26.2) | primary | local-source-read

### FACT 10 — Opening a FIFO blocks without `O_NONBLOCK`; `O_NONBLOCK` does NOT help for regular files or block devices
FACT: `fifo(7)`: "Normally, opening the FIFO blocks until the other end is opened also." With
O_NONBLOCK, "opening for read-only succeeds even if no one has opened on the write side yet", and
"opening for write-only fails with ENXIO (no such device or address) unless the other end has
already been opened." [S33]. `open(2)`: "Note that this flag [O_NONBLOCK] **has no effect for regular
files and block devices**; that is, I/O operations will (briefly) block when device activity is
required, regardless of whether O_NONBLOCK is set." and `ENXIO`: "O_NONBLOCK | O_WRONLY is set, the
named file is a FIFO, and no process has the FIFO open for reading." [S34]. `O_NOFOLLOW`: "If the
trailing component (i.e., basename) of path is a symbolic link, then the open fails, with the error
ELOOP. Symbolic links in earlier components of the pathname will still be followed." [S34].
`O_PATH`: "Obtain a file descriptor that can be used ... to indicate a location in the filesystem
tree and to perform operations that act purely at the file descriptor level. The file itself is not
opened" [S34].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: Defense in depth — `os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)`
as the ONLY open path in the sensor, then re-check `f.Stat()`'s `IsRegular()` on the OPEN fd before
reading (this closes the TOCTOU of FACT 11). Note the read itself must then tolerate `EAGAIN`.
Also note O_NONBLOCK does NOT make a slow block-device or NFS read interruptible — that class of
hang can only be bounded by running the read in a goroutine with its own budget and abandoning it.
IMPACT: A blocking `open()` on a FIFO is unkillable by context (FACT 13) and stalls the scan
forever. On a bare-metal host `/run/**` and `/tmp/**` legitimately contain FIFOs and sockets.
SOURCES: S33 | https://man7.org/linux/man-pages/man7/fifo.7.html | fifo(7) — Linux manual page | primary | WebFetch
          S34 | https://man7.org/linux/man-pages/man2/open.2.html | open(2) — Linux manual page | primary | WebFetch

### FACT 11 — Stat-then-Open is a TOCTOU; `os.Root` (Go 1.24+) constrains traversal but does NOT block device nodes
FACT: Go 1.24 release notes: "The new os.Root type provides the ability to perform filesystem
operations within a specific directory. The os.OpenRoot function opens a directory and returns an
os.Root. Methods on os.Root operate within the directory and **do not permit paths that refer to
locations outside the directory, including ones that follow symbolic links out of the directory.**"
[S35]. `os.Root` doc: "Methods on Root will follow symbolic links, but symbolic links may not
reference a location outside the root. Symbolic links must not be absolute." and, critically,
"**Methods on Root do not prohibit traversal of filesystem boundaries, Linux bind mounts, /proc
special files, or access to Unix device files.**" [S36]. `os.OpenInRoot(dir, name)` is
`OpenRoot(dir)` + `r.Open(name)` [S37]. Implementation on Unix: component-wise
`unix.Openat(parent, name, syscall.O_NOFOLLOW|syscall.O_CLOEXEC|flag, ...)` with manual symlink
resolution capped at `rootMaxSymlinks = 8` (`__POSIX_SYMLOOP_MAX`) [S38][S39] — i.e. **Go does NOT
use `openat2(2)`** for `os.Root` even though `openat2Trap` exists in `internal/syscall/unix` [S40].
The kernel primitive that would do this atomically is `openat2(2)` (Linux 5.6) with
`RESOLVE_BENEATH` ("Do not permit the path resolution to succeed if any component of the resolution
is not a descendant of the directory indicated by dirfd"), `RESOLVE_NO_SYMLINKS` ("Disallow
resolution of symbolic links during path resolution. This option implies RESOLVE_NO_MAGICLINKS"),
`RESOLVE_NO_MAGICLINKS` ("Disallow all magic-link resolution ... most notably found in proc(5)") and
`RESOLVE_NO_XDEV` ("Disallow traversal of mount points ... including all bind mounts") [S41].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: `os.Root` is NOT a substitute for the `IsRegular` gate — by its own doc it will happily
open `/dev/kmsg` if that path is inside the root. Sensor rule: (1) open with
`O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC`, (2) `f.Stat()` on the fd and re-verify `IsRegular()` before the
first `Read`, (3) cap with `io.CopyN(dst, f, cap+1)`. Reserve `os.Root`/`os.OpenInRoot` for the
test-only fs-root seam (CLAUDE.md forbids a production "override root" flag) — and note it requires
Go 1.24+, satisfied by the local go1.26.2 toolchain but it must be recorded in go.mod. Do NOT
introduce a cgo/`golang.org/x/sys` openat2 dependency: the stdlib path plus the fd re-stat is
sufficient for a read-only sensor, and openat2 would additionally need a Linux < 5.6 fallback.
Note also RESOLVE_NO_MAGICLINKS would break `/proc/self/*` magic-link reads, so it is the wrong tool
for a procfs-heavy sensor anyway.
IMPACT: Ignoring the TOCTOU is low-severity here (the sensor is unprivileged and read-only, and the
target's world-writable dirs are not on the check list), but ignoring the "Root does not prohibit
device files" caveat re-opens the FIFO/device hang of FACT 10.
SOURCES: S35 | https://go.dev/doc/go1.24 ("Directory-limited filesystem access") | Go 1.24 Release Notes | primary | WebFetch
          S36 | /c/Program Files/Go/src/os/root.go:34-70 `type Root` doc | Go stdlib os source (go1.26.2) | primary | local-source-read
          S37 | /c/Program Files/Go/src/os/root.go:25-32 `func OpenInRoot` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S38 | /c/Program Files/Go/src/os/root_unix.go:67,85,117 `rootOpenDir`/`rootOpenFileNolog` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S39 | /c/Program Files/Go/src/os/root.go:72-77 `rootMaxSymlinks = 8` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S40 | /c/Program Files/Go/src/internal/syscall/unix/sysnum_linux_amd64.go:12 `openat2Trap uintptr = 437` (defined but unused by os.Root) | Go stdlib source (go1.26.2) | primary | local-source-read
          S41 | https://man7.org/linux/man-pages/man2/openat2.2.html | openat2(2) — Linux manual page | primary | WebFetch

### FACT 12 — Neither `filepath.Walk` nor `filepath.WalkDir` follows symlinks — and /sys is symlink topology
FACT: "WalkDir does not follow symbolic links." [S42]; "Walk does not follow symbolic links. Walk is
less efficient than WalkDir, introduced in Go 1.16, which avoids calling os.Lstat on every visited
file or directory." [S43]. Both read an entire directory into memory to sort it lexically before
descending [S42][S43].
LOCAL_REPRO: `/sys/class/net/lo -> ../../devices/virtual/net/lo`,
`/sys/block/loop0 -> ../devices/virtual/block/loop0` — every entry under `/sys/class/*` and
`/sys/block/*` is a symlink into `/sys/devices/**` [S31].
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: `filepath.WalkDir("/sys/class/net", ...)` visits the symlinks and stops — it will NOT
enumerate per-interface attributes. For sysfs device topology use `os.ReadDir(dir)` + explicit
`filepath.EvalSymlinks`/`os.Readlink` on each entry, with (a) an explicit depth cap, (b) an explicit
entry-count cap, (c) a visited-inode set to break `/sys` device cycles, and (d) an assertion that the
resolved target stays under `/sys`. For any user-writable tree (`/tmp`, `/var/tmp`, `/run/user/*`,
`$HOME`) do the opposite: use `WalkDir` and never resolve symlinks. Also: `WalkDir` buffers a whole
directory in memory — cap entries before walking anything under `/proc/*/`.
IMPACT: Naively using WalkDir on /sys yields empty results → every NIC/disk/BMC topology check
reports `unknown` with a bogus reason ("no entries") instead of real evidence — under-claiming,
which CLAUDE.md classifies as a bug. Naively following symlinks in `/tmp` is the classic escape.
SOURCES: S42 | /c/Program Files/Go/src/path/filepath/path.go:381-396 `func WalkDir` | Go stdlib path/filepath source (go1.26.2) | primary | local-source-read
          S43 | /c/Program Files/Go/src/path/filepath/path.go:409-423 `func Walk` | Go stdlib path/filepath source (go1.26.2) | primary | local-source-read

### FACT 13 — A blocked `read(2)` on a regular file is NOT interruptible by context or by a deadline
FACT: `os.File.SetDeadline` doc, verbatim: "Only some kinds of files support setting a deadline.
Calls to SetDeadline for files that do not support deadlines will return ErrNoDeadline. **On most
systems ordinary files do not support deadlines, but pipes do.**" [S44]. `SetReadDeadline`: "sets the
deadline for future Read calls and any currently-blocked Read call ... Not all files support setting
deadlines; see SetDeadline." [S45]. `os.ErrNoDeadline = poll.ErrNoDeadline` with message
`"file type does not support deadline"` [S46]. The stdlib's own test `TestNonpollableDeadline`
asserts this explicitly for Linux and Windows: a file from `os.CreateTemp` returns `os.ErrNoDeadline`
from `SetDeadline`, `SetReadDeadline` and `SetWriteDeadline` [S47]. Regular files are not registered
with the netpoller, so `context.WithDeadline` cannot abort an in-flight `read(2)`.
STATUS: VERIFIED
APPLIES_TO: both
PROBE/RULE: The whole-scan `context.WithDeadline` bounds SCHEDULING, not in-flight file I/O. Design
consequence: (1) never read a path that can block (FACT 9/10 gate); (2) run each check on its own
goroutine and select on `ctx.Done()` so the SCAN can finish and emit `unknown` + reason=timeout for
the stuck check while the goroutine leaks; (3) accept that a leaked goroutine blocked on a hung
NFS/`/proc/<pid>` read cannot be reclaimed — the process must be able to exit anyway
(don't `WaitGroup.Wait()` unconditionally at the end of the scan). Deadlines DO work on
`exec` pipes ("pipes do"), which is why the exec path can be bounded properly.
IMPACT: Believing `ctx` bounds file reads produces a sensor that hangs past its deadline and never
writes `findings.json` — the single-artifact deliverable is lost entirely, and per CLAUDE.md every
registered check must emit exactly one finding per run.
SOURCES: S44 | /c/Program Files/Go/src/os/file.go:650-676 `func (f *File) SetDeadline` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S45 | /c/Program Files/Go/src/os/file.go:678-682 `func (f *File) SetReadDeadline` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S46 | /c/Program Files/Go/src/os/error.go:26,30 `ErrNoDeadline` | Go stdlib os source (go1.26.2) | primary | local-source-read
          S47 | /c/Program Files/Go/src/os/timeout_test.go:20-44 `TestNonpollableDeadline` | Go stdlib os test source (go1.26.2) | primary | local-source-read

### FACT 14 — Composite rule: the sensor's bounded-exec helper (synthesis)
FACT: Combining FACTS 1-7, the minimal correct Linux bounded-exec construct is:
`ctx, cancel := context.WithTimeout(parent, perProbeBudget)`; `cmd := exec.CommandContext(ctx, ...)`;
`cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}`;
`cmd.Cancel = <group-kill normalising ESRCH to os.ErrProcessDone>`; `cmd.WaitDelay = grace`;
`cmd.Stdout, cmd.Stderr = <capped writers>`; `cmd.Stdin = nil` (reads from os.DevNull [S18]);
`cmd.Env = <minimal, explicit>`; `cmd.Dir = "/"`; `Start()` then exactly one `Wait()`.
Error mapping: `ctx.Err()==DeadlineExceeded` → TIMEOUT; `exec.ErrWaitDelay` → TIMEOUT/TRUNCATED with
partial bytes retained; `*exec.ExitError` → real exit status (evidence, may be a legitimate `fail`);
`exec.ErrNotFound`/`ENOENT` on the binary → UNSUPPORTED (missing utility ≠ missing capability);
`EACCES` → PERMISSION_DENIED. All non-ExitError classes → `unknown` + reason, never `fail`.
STATUS: LIKELY (each component VERIFIED; the composition is this stream's recommendation)
APPLIES_TO: both
PROBE/RULE: One `internal/run` package with a single exported
`Run(ctx, spec) (stdout, stderr []byte, class, err)`; no other package may construct an `exec.Cmd`.
Enforce with a grep-based test or a lint rule.
IMPACT: Per-call-site duplication of this construct is how the `Setpgid` omission (self-kill) and the
missing `Wait` (zombies) get introduced.
SOURCES: S1-S28 above.

---

## SOURCES LIST

| id | url / file:line | title | type | extractor | fetched_at (UTC) |
|----|-----------------|-------|------|-----------|------------------|
| S1  | /c/Program Files/Go/src/os/exec/exec.go:484-494 | os/exec `CommandContext` (go1.26.2) | primary | local-source-read | 2026-09-09T00:00Z |
| S2  | https://pkg.go.dev/os/exec@go1.24.0#CommandContext | os/exec docs pinned @go1.24.0 | primary | WebFetch | 2026-09-09T00:00Z |
| S3  | /c/Program Files/Go/src/os/exec.go:333-338 | os `Process.Kill` (go1.26.2) | primary | local-source-read | 2026-09-09T00:00Z |
| S4  | /c/Program Files/Go/src/os/exec/exec.go:278-303 | `Cmd.WaitDelay` field doc | primary | local-source-read | 2026-09-09T00:00Z |
| S5  | /c/Program Files/Go/src/os/exec/exec.go:125-128 | `exec.ErrWaitDelay` | primary | local-source-read | 2026-09-09T00:00Z |
| S6  | https://go.dev/doc/go1.20 | Go 1.20 Release Notes (os/exec) | primary | WebFetch | 2026-09-09T00:00Z |
| S7  | https://github.com/golang/go/issues/50436 | golang/go#50436 "os/exec: add fields for managing termination signals and pipes" (Proposal-Accepted, Go1.20) | primary | WebFetch | 2026-09-09T00:00Z |
| S8  | /c/Program Files/Go/src/os/exec/exec.go:967-1004 | `Cmd.awaitGoroutines` | primary | local-source-read | 2026-09-09T00:00Z |
| S9  | /c/Program Files/Go/src/os/exec/exec.go:780 | `Cmd.Start` ctx-watcher condition | primary | local-source-read | 2026-09-09T00:00Z |
| S10 | /c/Program Files/Go/src/os/exec/exec.go:270-274 | `Cmd.Cancel` nil semantics | primary | local-source-read | 2026-09-09T00:00Z |
| S11 | /c/Program Files/Go/src/os/exec/exec.go:261-268 | `Cmd.Cancel` + os.ErrProcessDone doc | primary | local-source-read | 2026-09-09T00:00Z |
| S12 | /c/Program Files/Go/src/os/exec/exec.go:795-820 | `Cmd.watchCtx` cancel-error handling | primary | local-source-read | 2026-09-09T00:00Z |
| S13 | /c/Program Files/Go/src/syscall/exec_linux.go:67-107 | `syscall.SysProcAttr` (Linux) | primary | local-source-read | 2026-09-09T00:00Z |
| S14 | /c/Program Files/Go/src/syscall/exec_linux.go:393-402 | `forkAndExecInChild` SYS_SETPGID | primary | local-source-read | 2026-09-09T00:00Z |
| S15 | https://man7.org/linux/man-pages/man2/kill.2.html | kill(2) — Linux manual page | primary | WebFetch | 2026-09-09T00:00Z |
| S16 | /c/Program Files/Go/src/os/exec/exec.go:275 | "Cancel will not be called if Start returns a non-nil error" | primary | local-source-read | 2026-09-09T00:00Z |
| S17 | /c/Program Files/Go/src/os/exec/exec.go:208-224 | `Cmd.Stdout`/`Cmd.Stderr` field doc | primary | local-source-read | 2026-09-09T00:00Z |
| S18 | /c/Program Files/Go/src/os/exec/exec.go:192-206 | `Cmd.Stdin` field doc | primary | local-source-read | 2026-09-09T00:00Z |
| S19 | /c/Program Files/Go/src/os/exec/exec.go:905-922 | `Cmd.Wait` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S20 | /c/Program Files/Go/src/os/exec/exec.go:1009-1040 | `Cmd.Output` / `Cmd.CombinedOutput` | primary | local-source-read | 2026-09-09T00:00Z |
| S21 | https://github.com/golang/go/issues/23019 | golang/go#23019 "os/exec: consider changing Wait to stop copying goroutines rather than waiting for them" (ianlancetaylor; closed as not planned) | primary | WebFetch | 2026-09-09T00:00Z |
| S22 | /c/Program Files/Go/src/os/exec/exec.go:860-870 | watchCtx comment citing go.dev/issue/23019 | primary | local-source-read | 2026-09-09T00:00Z |
| S23 | /c/Program Files/Go/src/os/exec/exec.go:1074-1082 | `Cmd.StdoutPipe` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S24 | /c/Program Files/Go/src/io/io.go:458-482 | `io.LimitReader` / `LimitedReader.Read` | primary | local-source-read | 2026-09-09T00:00Z |
| S25 | /c/Program Files/Go/src/io/io.go:357-373 | `io.CopyN` | primary | local-source-read | 2026-09-09T00:00Z |
| S26 | /c/Program Files/Go/src/os/exec/exec.go:635-641 | `Cmd.Start` ("Wait must be called") | primary | local-source-read | 2026-09-09T00:00Z |
| S27 | /c/Program Files/Go/src/os/exec.go:275-278 | `os.Process.Release` | primary | local-source-read | 2026-09-09T00:00Z |
| S28 | /c/Program Files/Go/src/os/exec.go:340-345 | `os.Process.Wait` | primary | local-source-read | 2026-09-09T00:00Z |
| S29 | /c/Program Files/Go/src/os/file.go:860-879 | `os.ReadFile` / `statOrZero` | primary | local-source-read | 2026-09-09T00:00Z |
| S30 | /c/Program Files/Go/src/os/file.go:881-925 | `readFileContents` (/proc size-0 handling, issue 72080) | primary | local-source-read | 2026-09-09T00:00Z |
| S31 | LOCAL_REPRO: WSL2 6.18.33.2-microsoft-standard-WSL2, Ubuntu 26.04 LTS, `stat`/`ls -ld` | local experiment | primary | Bash/wsl | 2026-09-09T00:00Z |
| S32 | /c/Program Files/Go/src/io/fs/fs.go:197-247 | `io/fs` FileMode bits + `IsRegular` | primary | local-source-read | 2026-09-09T00:00Z |
| S33 | https://man7.org/linux/man-pages/man7/fifo.7.html | fifo(7) — Linux manual page | primary | WebFetch | 2026-09-09T00:00Z |
| S34 | https://man7.org/linux/man-pages/man2/open.2.html | open(2) — Linux manual page | primary | WebFetch | 2026-09-09T00:00Z |
| S35 | https://go.dev/doc/go1.24 | Go 1.24 Release Notes ("Directory-limited filesystem access") | primary | WebFetch | 2026-09-09T00:00Z |
| S36 | /c/Program Files/Go/src/os/root.go:34-70 | `os.Root` type doc | primary | local-source-read | 2026-09-09T00:00Z |
| S37 | /c/Program Files/Go/src/os/root.go:25-32 | `os.OpenInRoot` | primary | local-source-read | 2026-09-09T00:00Z |
| S38 | /c/Program Files/Go/src/os/root_unix.go:67,85,117 | `os.Root` Unix impl: Openat + O_NOFOLLOW\|O_CLOEXEC | primary | local-source-read | 2026-09-09T00:00Z |
| S39 | /c/Program Files/Go/src/os/root.go:72-77 | `rootMaxSymlinks = 8` | primary | local-source-read | 2026-09-09T00:00Z |
| S40 | /c/Program Files/Go/src/internal/syscall/unix/sysnum_linux_amd64.go:12 | `openat2Trap = 437` (unused by os.Root) | primary | local-source-read | 2026-09-09T00:00Z |
| S41 | https://man7.org/linux/man-pages/man2/openat2.2.html | openat2(2) — Linux manual page (Linux 5.6) | primary | WebFetch | 2026-09-09T00:00Z |
| S42 | /c/Program Files/Go/src/path/filepath/path.go:381-396 | `filepath.WalkDir` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S43 | /c/Program Files/Go/src/path/filepath/path.go:409-423 | `filepath.Walk` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S44 | /c/Program Files/Go/src/os/file.go:650-676 | `os.File.SetDeadline` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S45 | /c/Program Files/Go/src/os/file.go:678-682 | `os.File.SetReadDeadline` doc | primary | local-source-read | 2026-09-09T00:00Z |
| S46 | /c/Program Files/Go/src/os/error.go:26,30 | `os.ErrNoDeadline` = "file type does not support deadline" | primary | local-source-read | 2026-09-09T00:00Z |
| S47 | /c/Program Files/Go/src/os/timeout_test.go:20-44 | `TestNonpollableDeadline` | primary | local-source-read | 2026-09-09T00:00Z |

Source composition: 47 sources, all primary — 36 pinned local stdlib source reads at go1.26.2,
4 man7.org man pages, 2 go.dev release notes, 2 golang/go issue threads, 1 pkg.go.dev pinned
@go1.24.0, 1 LOCAL_REPRO experiment. Secondary / AI-summary / content-farm sources used: 0.

---

## CONTRADICTIONS

C-1 — "os.Root protects you" vs its own doc. The Go 1.24 release notes market `os.Root` as
directory-limited filesystem access [S35], which is commonly read as "safe path handling". The type's
own doc contradicts the strong reading: "Methods on Root do not prohibit traversal of filesystem
boundaries, Linux bind mounts, /proc special files, or access to Unix device files." [S36].
RESOLUTION: both are true at different scopes — `os.Root` guarantees *containment* (no escape via
symlink or `..`), not *object-type safety*. The sensor needs BOTH: containment is optional here, the
`IsRegular` gate is mandatory. Recorded as contested framing, not a factual conflict.

C-2 — Which issue "caused" WaitDelay. #23019 (2017, ianlancetaylor) describes the grandchild-holds-pipe
hang and proposes changing `Wait` semantics; it is closed as **not planned** [S21]. #50436 (2022) is
the **accepted** proposal that actually shipped `Cancel`/`WaitDelay` in Go 1.20 [S7]. Both are
load-bearing and neither alone is "the" issue; the stdlib source cites #23019 as the motivating bug
[S22] while #50436 is the API's provenance. Verified by fetching both, not by inference.

C-3 — `syscall` package is frozen. `syscall` is documented as deprecated/frozen in favour of
`golang.org/x/sys/unix`, yet `Cmd.SysProcAttr` is typed `*syscall.SysProcAttr` [S13], so the stdlib
itself forces use of `syscall` for `Setpgid`. Not a real conflict for this project: use `syscall`
(stdlib-only, per CLAUDE.md's "stdlib → native OS primitive → justified dependency"), and do not add
`golang.org/x/sys` for this.

---

## GAPS

G-1 — LOCAL_REPRO was done on WSL2 (kernel 6.18.33.2-microsoft-standard-WSL2, Ubuntu 26.04), NOT on
the Lava target (Ubuntu 24.04.4, kernel 6.8.0-139-generic). The procfs size=0 / sysfs size=4096
behaviour is kernel-generic and low-risk, but the exact set of symlinks under `/sys/class/*` and the
presence of FIFOs/sockets under `/run` on the real host is unverified from this stream. Suggested
OBSERVATION_REQUEST: `stat -c "%n %F %s" /proc/cpuinfo /proc/meminfo /sys/class/dmi/id/sys_vendor`
and `find /run -maxdepth 2 \( -type p -o -type s \) | head -20`.

G-2 — Not measured: whether `syscall.Kill(-pgid, SIGKILL)` from an unprivileged uid-1000 process
reliably reaches every descendant when a probe's child calls `setsid()` itself (a new session leaves
our process group). `systemd-run`, `at`, and some daemon-spawning helpers do this. Mitigation is
policy, not code: the probe registry must not invoke anything that daemonises. Worth a registry
review rule.

G-3 — Not benchmarked: the cost of the `Setpgid` fork path vs plain fork for ~30-60 probes. Expected
negligible (one extra `setpgid(2)` per child) but unmeasured.

G-4 — `exec.ErrWaitDelay` vs partial output: the stdlib closes the pipes and returns ErrWaitDelay,
but I did not empirically confirm that bytes already written to `cmd.Stdout` before the close are
retained. Source reading says yes (the copy goroutine writes as it reads, and `closeDescriptors`
only unblocks it), but the "retain partial bytes" half of FACT 2's PROBE/RULE is LIKELY rather than
VERIFIED; a short test in the sensor's own suite would settle it.

G-5 — Windows behaviour is out of scope (sensor is Linux-only), but the local stdlib read was done on
a windows/amd64 toolchain. All `_linux.go`/`_unix.go` files cited are the files the Linux build
selects, so the citations are correct for GOOS=linux; cross-compilation
(`GOOS=linux GOARCH=amd64`) does not change which source files apply.
