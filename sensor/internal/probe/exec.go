package probe

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Exec bounds. Every subprocess the sensor starts is bounded by all of these at
// once; no code path outside this file constructs an exec.Cmd (L09, L41).
const (
	// ExecTimeout is the default per-command budget.
	ExecTimeout = 3 * time.Second
	// ExecWaitDelay bounds the extra time allowed after cancellation for a
	// grandchild that is still holding our pipes open (golang/go#23019).
	ExecWaitDelay = 2 * time.Second
	// ExecOutCap bounds captured stdout.
	ExecOutCap int64 = 256 << 10
	// ExecErrCap bounds captured stderr.
	ExecErrCap int64 = 8 << 10
	// stderrExcerptCap bounds what reaches evidence.
	stderrExcerptCap = 256
)

// execEnv is the minimal environment every child gets. No inherited environment
// means no inherited secrets and no locale-dependent output parsing.
var execEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}

// Spec describes one bounded subprocess. Argv is passed directly to execve:
// there is no shell and no pipeline anywhere in the sensor, so the exit status
// we record is always the child's own (L41, F1).
type Spec struct {
	Name    string
	Args    []string
	Budget  time.Duration
	OutCap  int64
	ErrCap  int64
	Purpose string
}

// Runner is the exec surface the checks use. Production is *ExecRunner; tests
// substitute a fake keyed on name+args.
type Runner interface {
	Run(ctx context.Context, spec Spec) Observation
}

// ExecRunner is the one bounded subprocess runner.
type ExecRunner struct{}

// NewRunner returns the production runner.
func NewRunner() *ExecRunner { return &ExecRunner{} }

// limitWriter caps what a child can make us hold in memory and reports whether
// the cap was hit. Once over the cap it asks to be killed rather than silently
// dropping output.
type limitWriter struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	cap       int64
	written   int64
	Truncated bool
	overflow  func()
	fired     bool
}

func (w *limitWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.written += int64(len(p))
	room := w.cap - int64(w.buf.Len())
	if room > 0 {
		n := int64(len(p))
		if n > room {
			n = room
		}
		w.buf.Write(p[:n])
	}
	if int64(w.buf.Len()) >= w.cap && w.written > w.cap {
		w.Truncated = true
		if !w.fired && w.overflow != nil {
			w.fired = true
			kill := w.overflow
			// A panic in a goroutine takes the whole process with it, and
			// runOne's recover cannot reach it.
			go func() {
				defer func() { _ = recover() }()
				kill()
			}()
		}
	}
	// Always report a full write: a short write would make the child see EPIPE
	// and could change its behaviour, which is an observation side effect.
	return len(p), nil
}

func (w *limitWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func (w *limitWriter) stats() (string, int64, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String(), w.written, w.Truncated
}

// Run executes spec under every bound at once: a context deadline, its own
// process group, a group SIGKILL on cancellation, a WaitDelay, capped
// stdout/stderr writers that kill the child on overflow, stdin from /dev/null
// and a minimal environment.
func (ExecRunner) Run(ctx context.Context, spec Spec) Observation {
	if spec.Budget <= 0 {
		spec.Budget = ExecTimeout
	}
	if spec.OutCap <= 0 {
		spec.OutCap = ExecOutCap
	}
	if spec.ErrCap <= 0 {
		spec.ErrCap = ExecErrCap
	}
	argv := append([]string{spec.Name}, spec.Args...)
	obs := Observation{
		Source: strings.Join(argv, " "),
		Kind:   KindCommandExec,
		Meta:   &Meta{Command: argv},
	}

	// Resolving the binary first separates UTILITY_MISSING from EACCES on the
	// binary itself, which are different findings (L39, EVIDENCE_MODEL §4).
	resolved, lookErr := resolveBinary(spec.Name)
	if lookErr != nil {
		obs.Status, obs.Errno = Classify(lookErr)
		if obs.Status == StatusENOENT {
			obs.Status = StatusUtilityMissing
		}
		obs.Detail = shortErr(lookErr)
		return obs
	}
	obs.Meta.BinaryResolvedPath = resolved

	if err := ctx.Err(); err != nil {
		obs.Status = StatusTimeout
		obs.Meta.TimedOut = true
		obs.Detail = "scan budget exhausted before the command started"
		return obs
	}

	cctx, cancel := context.WithTimeout(ctx, spec.Budget)
	defer cancel()

	cmd := exec.CommandContext(cctx, resolved, spec.Args...)
	cmd.SysProcAttr = procAttr()
	// CommandContext's default Cancel kills only the leader; a group kill is
	// what actually leaves no survivors (R5-F14).
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		return killGroup(cmd.Process.Pid)
	}
	cmd.WaitDelay = ExecWaitDelay

	kill := func() {
		if cmd.Process != nil {
			_ = killGroup(cmd.Process.Pid)
		}
	}
	stdout := &limitWriter{cap: spec.OutCap, overflow: kill}
	stderr := &limitWriter{cap: spec.ErrCap, overflow: kill}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.Env = execEnv

	if in, err := os.Open(devNull); err == nil {
		defer in.Close()
		cmd.Stdin = in
	} else {
		cmd.Stdin = strings.NewReader("")
	}

	start := time.Now()
	err := cmd.Run()
	obs.Elapsed = time.Since(start)

	out, outWritten, outTrunc := stdout.stats()
	errOut, errWritten, _ := stderr.stats()
	obs.Value = out
	obs.Bytes = int64(len(out))
	obs.Truncated = outTrunc
	obs.Meta.StdoutBytes = outWritten
	obs.Meta.StderrBytes = errWritten
	obs.Meta.StdoutTruncated = outTrunc
	obs.Meta.StderrExcerpt = excerpt(errOut, stderrExcerptCap)
	obs.Signal = signalOf(err)

	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		code := int64(ee.ExitCode())
		obs.ExitCode = &code
	} else if err == nil {
		zero := int64(0)
		obs.ExitCode = &zero
	}

	switch {
	case errors.Is(err, exec.ErrWaitDelay):
		// The child exited but a grandchild held the pipes past WaitDelay.
		// That is a distinct failure mode from a plain timeout, and it is
		// never a fail (L10).
		obs.Status = StatusTimeout
		obs.Meta.WaitDelayExpired = true
		obs.Meta.TimedOut = true
		obs.Detail = "wait delay expired with descendants holding stdout"
	case cctx.Err() != nil:
		// CommandContext surfaces "signal: killed", not the context error, so
		// the context has to be consulted explicitly (R5-F11).
		obs.Status = StatusTimeout
		obs.Meta.TimedOut = true
		obs.Detail = "command exceeded its " + spec.Budget.String() + " budget and its process group was killed"
	case outTrunc:
		obs.Status = StatusExecError
		obs.Detail = "output exceeded the capture cap; the process group was killed"
	case err != nil:
		// "The tool ran and failed for its own reasons" and "the tool never
		// started" are different findings. An ExitError means the child ran;
		// anything else is a fork/exec failure and keeps its errno, so a
		// non-executable binary reads as EACCES, not EXECUTION_ERROR.
		if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
			obs.Status = StatusExecError
			// A tool whose own stderr says it was refused is a denial, not a
			// malfunction. EXECUTION_ERROR would be the least actionable of the
			// available answers, and the distinction decides the remediation.
			if name, ok := deniedByPrivilege(errOut); ok {
				obs.Status, obs.Errno = StatusEACCES, name
			}
		} else {
			obs.Status, obs.Errno = Classify(err)
			if obs.Status == StatusENOENT {
				obs.Status = StatusUtilityMissing
			}
		}
		obs.Detail = shortErr(err)
	default:
		obs.Status = StatusOK
	}
	return obs
}

// binaryDirs is the entire search set. The inherited PATH is never consulted:
// a user-writable directory early in it could supply nvme, iptables, ss or
// mokutil and so shape the evidence. That is not an escalation - same uid - but
// a planted mokutil printing "SecureBoot enabled" is a lie the sensor would
// repeat.
var binaryDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

// resolveBinary finds a binary by absolute path or in binaryDirs. A name that
// is in neither is UTILITY_MISSING, whatever PATH says.
func resolveBinary(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		fi, err := os.Stat(name)
		if err != nil {
			return "", err
		}
		if !fi.Mode().IsRegular() {
			return "", errNotRegular
		}
		return name, nil
	}
	for _, dir := range binaryDirs {
		cand := dir + "/" + name
		if fi, err := os.Stat(cand); err == nil && fi.Mode().IsRegular() {
			return cand, nil
		}
	}
	return "", &os.PathError{Op: "stat", Path: name, Err: syscall.ENOENT}
}

func excerpt(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// privilegeDenialPatterns are the ways the standard host tools say "you are not
// allowed to do this". Matching on the tool's own words is how a non-zero exit
// becomes a classified denial rather than an unexplained failure.
var privilegeDenialPatterns = []struct {
	needle string
	errno  string
}{
	{"permission denied", "EACCES"},
	{"you must be root", "EACCES"},
	{"must be run as root", "EACCES"},
	{"need to be root", "EACCES"},
	{"are you root", "EACCES"},
	{"operation not permitted", "EPERM"},
	{"requires root privileges", "EPERM"},
	{"insufficient privileges", "EPERM"},
}

func deniedByPrivilege(stderr string) (string, bool) {
	s := strings.ToLower(stderr)
	for _, p := range privilegeDenialPatterns {
		if strings.Contains(s, p.needle) {
			return p.errno, true
		}
	}
	return "", false
}
