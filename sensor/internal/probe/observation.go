// Package probe holds the two load-bearing host-access primitives of the sensor:
// one bounded file-read path and one bounded subprocess runner. Every observation
// the sensor makes flows through this package so that boundedness, read-only
// behaviour and errno fidelity are enforced in exactly one place.
package probe

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"time"
)

// ObsStatus is the coarse outcome class of a single observation.
//
// The set is frozen (LD-9 / Direction Lock item 2). The finer, symbolic errno
// lives in Observation.Errno so that EPERM stays distinguishable from EACCES
// (DESIGN_LAWS L03) without widening this enum.
type ObsStatus string

const (
	// StatusOK means the observation succeeded and Value is meaningful.
	StatusOK ObsStatus = "OK"
	// StatusEACCES means the object exists but this uid may not read it.
	StatusEACCES ObsStatus = "EACCES"
	// StatusENOENT means the object does not exist.
	StatusENOENT ObsStatus = "ENOENT"
	// StatusTimeout means the observation was attempted and did not finish in budget.
	StatusTimeout ObsStatus = "TIMEOUT"
	// StatusUtilityMissing means the helper binary is not installed. It never
	// means the underlying capability is absent (L39).
	StatusUtilityMissing ObsStatus = "UTILITY_MISSING"
	// StatusUnsupported means the object exists but the operation is not
	// supported here (EINVAL/ENODEV/EOPNOTSUPP, or a non-regular file).
	StatusUnsupported ObsStatus = "UNSUPPORTED"
	// StatusExecError means a tool ran and failed for its own reasons.
	StatusExecError ObsStatus = "EXEC_ERROR"
	// StatusContradiction means two observations of the same fact disagree.
	StatusContradiction ObsStatus = "CONTRADICTION"
)

// Observation kinds, mirroring R3/EVIDENCE_MODEL.md observation types.
const (
	KindFileRead     = "file_read"
	KindFileMetadata = "file_metadata"
	KindDirWalk      = "dir_walk"
	KindCommandExec  = "command_exec"
)

// Observation is one attempt to learn one fact from the host.
//
// It records the observation, never the conclusion: a failed attempt is as much
// an Observation as a successful one, and carries why it failed.
type Observation struct {
	// Source is the absolute path opened or the argv of the command run.
	Source string
	// Kind is one of the Kind* constants (the evidence observation_type).
	Kind string
	// Value is the bytes read or the stdout captured, already capped.
	Value string
	// Status is the coarse outcome class.
	Status ObsStatus
	// Errno is the symbolic errno (EACCES, EPERM, ENOENT, EINVAL, ENODEV,
	// EOPNOTSUPP, EIO, ...) when the failure came from a syscall.
	Errno string
	// ExitCode is the child's own exit status (never read through a pipeline).
	ExitCode *int64
	// Signal names the signal that killed the child, when one did.
	Signal string
	// Truncated is true when a policy cap was hit; a truncated value never
	// supports a pass (L05, L12).
	Truncated bool
	// Bytes is how many bytes were actually read/captured.
	Bytes int64
	// Elapsed is how long the observation took.
	Elapsed time.Duration
	// AbsenceProven marks an ENOENT that IS the answer rather than a gap in
	// it: a stat that resolved the path and found nothing there. Without this
	// distinction "the file is not present" and "we could not look" collapse
	// into one status, which is the failure the evidence model exists to stop.
	AbsenceProven bool
	// LoadBearing marks an observation the check's verdict depends on. A
	// pass/fail whose load-bearing observations are not OK is downgraded to
	// unknown centrally in scan.finalize (L07/L39).
	LoadBearing bool
	// Detail is a short human-readable note. Never contains a secret value.
	Detail string
	// Meta carries observation-type-specific metadata (file mode/uid/gid,
	// walk boundaries, command resolution). Optional.
	Meta *Meta
}

// Meta is the optional type-specific payload of an Observation.
type Meta struct {
	// file_metadata / file_read
	Exists        *bool
	FileType      string
	Mode          *int64
	UID           *int64
	GID           *int64
	Size          *int64
	SymlinkTarget string
	ResolvedPath  string

	// command_exec
	Command            []string
	BinaryResolvedPath string
	TimedOut           bool
	StdoutBytes        int64
	StderrBytes        int64
	StderrExcerpt      string
	StdoutTruncated    bool
	WaitDelayExpired   bool

	// dir_walk
	Root            string
	EntriesScanned  int64
	DirsPruned      []string
	BudgetExhausted string
	CrossedMounts   bool
	UnreadableDirs  []string
}

// OK reports whether the observation succeeded.
func (o Observation) OK() bool { return o.Status == StatusOK }

// Bearing returns a copy of o marked load-bearing.
func (o Observation) Bearing() Observation { o.LoadBearing = true; return o }

// Classify maps an error returned by a read or an exec into the frozen status
// set plus a symbolic errno. It never collapses distinct failure classes:
// callers get both the coarse class and the exact errno.
func Classify(err error) (ObsStatus, string) {
	if err == nil {
		return StatusOK, ""
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return StatusTimeout, ""
	}
	if errors.Is(err, exec.ErrNotFound) {
		return StatusUtilityMissing, "ENOENT"
	}
	if errors.Is(err, errNotRegular) {
		return StatusUnsupported, "ENOTREG"
	}
	if errors.Is(err, errSymlinkEscape) {
		return StatusUnsupported, "EXDEV"
	}
	name, ok := errnoName(err)
	if !ok {
		// Not a syscall error: os.Root refusals ("path escapes from parent"),
		// fs.ErrInvalid and friends land here.
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return StatusENOENT, "ENOENT"
		case errors.Is(err, fs.ErrPermission):
			return StatusEACCES, "EACCES"
		case errors.Is(err, os.ErrDeadlineExceeded):
			return StatusTimeout, ""
		}
		return StatusUnsupported, ""
	}
	switch name {
	case "ENOENT", "ENOTDIR", "ENXIO":
		return StatusENOENT, name
	case "EACCES":
		return StatusEACCES, name
	case "EPERM":
		// A capability gate, not a mode bit. Reported as a denial at the
		// coarse level, but the symbolic errno keeps the distinction (L03).
		return StatusEACCES, name
	case "EINVAL", "ENODEV", "EOPNOTSUPP", "ENOTSUP", "ENODATA", "ENOSYS":
		return StatusUnsupported, name
	case "ETIMEDOUT":
		return StatusTimeout, name
	case "ELOOP", "ENAMETOOLONG", "EISDIR", "EIO", "EAGAIN", "EWOULDBLOCK":
		return StatusUnsupported, name
	}
	return StatusUnsupported, name
}

// Reason maps an observation onto the closed finding-level reason vocabulary of
// R3/EVIDENCE_MODEL.md §7. The symbolic errno wins over the coarse status so
// that EPERM, EINVAL and ENODEV survive into the finding.
func (o Observation) Reason() string {
	switch o.Status {
	case StatusOK:
		return ""
	case StatusTimeout:
		return "TIMEOUT"
	case StatusUtilityMissing:
		return "UTILITY_MISSING"
	case StatusExecError:
		return "EXECUTION_ERROR"
	case StatusContradiction:
		return "CONTESTED"
	}
	if o.Errno != "" {
		return o.Errno
	}
	return string(o.Status)
}
