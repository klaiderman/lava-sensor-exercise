//go:build unix

package probe

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// openFlags are the flags used for every direct open the sensor performs.
// O_NONBLOCK is what stops a FIFO with no writer from blocking the open
// (LOCAL_REPRO R5-F24 measured a plain open blocking indefinitely). O_CLOEXEC
// keeps descriptors out of any child we spawn.
const (
	openBase      = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	openNoFollow  = syscall.O_NOFOLLOW
	openDirectory = syscall.O_DIRECTORY
)

var errnoNames = map[syscall.Errno]string{
	syscall.EACCES:       "EACCES",
	syscall.EPERM:        "EPERM",
	syscall.ENOENT:       "ENOENT",
	syscall.ENOTDIR:      "ENOTDIR",
	syscall.EISDIR:       "EISDIR",
	syscall.EINVAL:       "EINVAL",
	syscall.ENODEV:       "ENODEV",
	syscall.ENXIO:        "ENXIO",
	syscall.EOPNOTSUPP:   "EOPNOTSUPP",
	syscall.ENODATA:      "ENODATA",
	syscall.ENOSYS:       "ENOSYS",
	syscall.EIO:          "EIO",
	syscall.ELOOP:        "ELOOP",
	syscall.ENAMETOOLONG: "ENAMETOOLONG",
	syscall.EAGAIN:       "EAGAIN",
	syscall.ETIMEDOUT:    "ETIMEDOUT",
	syscall.ESRCH:        "ESRCH",
	syscall.EMFILE:       "EMFILE",
	syscall.ENFILE:       "ENFILE",
	syscall.EROFS:        "EROFS",
	syscall.ENOMEM:       "ENOMEM",
	syscall.EXDEV:        "EXDEV",
}

func errnoName(err error) (string, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "", false
	}
	if n, ok := errnoNames[errno]; ok {
		return n, true
	}
	return "E" + errno.Error(), true
}

// procAttr puts the child in its own process group so the whole group can be
// killed on timeout (L09; WaitDelay alone provably leaves grandchildren running,
// R5-F14).
func procAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// killGroup SIGKILLs the child's entire process group. ESRCH (the child already
// exited between the deadline firing and the kill) is normalised to
// os.ErrProcessDone so the race does not surface as an execution error (L11).
func killGroup(pid int) error {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

// ownerOf extracts uid/gid/dev/ino from a stat result.
func ownerOf(fi os.FileInfo) (uid, gid, dev, ino int64, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, 0, false
	}
	return int64(st.Uid), int64(st.Gid), int64(st.Dev), int64(st.Ino), true
}

var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP:  "SIGHUP",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGILL:  "SIGILL",
	syscall.SIGABRT: "SIGABRT",
	syscall.SIGFPE:  "SIGFPE",
	syscall.SIGKILL: "SIGKILL",
	syscall.SIGSEGV: "SIGSEGV",
	syscall.SIGPIPE: "SIGPIPE",
	syscall.SIGALRM: "SIGALRM",
	syscall.SIGTERM: "SIGTERM",
	syscall.SIGXCPU: "SIGXCPU",
}

// signalOf reports the signal that terminated the child, if any. Signal and
// exit code are separate evidence fields: a SIGKILL after a deadline is not a
// clean non-zero exit (EVIDENCE_MODEL §4).
func signalOf(err error) string {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return ""
	}
	ws, ok := ee.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return ""
	}
	if n, ok := signalNames[ws.Signal()]; ok {
		return n
	}
	return ws.Signal().String()
}

// devNull is the read end every child gets as stdin.
const devNull = os.DevNull

// getxattr reads an extended attribute without following the final symlink.
func getxattr(path, attr string) ([]byte, error) {
	sz, err := syscall.Getxattr(path, attr, nil)
	if err != nil {
		return nil, err
	}
	if sz <= 0 {
		return nil, nil
	}
	if sz > 64<<10 {
		sz = 64 << 10
	}
	buf := make([]byte, sz)
	n, err := syscall.Getxattr(path, attr, buf)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	return buf[:n], nil
}
