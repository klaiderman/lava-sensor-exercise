//go:build unix

package probe

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
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

// getxattr reads an extended attribute of the named object itself.
//
// Lgetxattr, not Getxattr: getxattr(2) resolves the final symlink, so on a
// symlink candidate it would describe the target rather than the object whose
// mode the caller reported from lstat. In a user-writable tree the target is
// attacker-chosen, so the ACL evidence would be attributed to the wrong inode.
func getxattr(path, attr string) ([]byte, error) {
	sz, err := lgetxattr(path, attr, nil)
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
	n, err := lgetxattr(path, attr, buf)
	if err != nil {
		return nil, err
	}
	if n > len(buf) {
		n = len(buf)
	}
	return buf[:n], nil
}

// lgetxattr is lgetxattr(2). Go's syscall package wraps getxattr but not the
// symlink-safe variant, and golang.org/x/sys is not a dependency of this
// binary, so the one syscall is issued directly.
func lgetxattr(path, attr string, dest []byte) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	a, err := syscall.BytePtrFromString(attr)
	if err != nil {
		return 0, err
	}
	var buf unsafe.Pointer
	if len(dest) > 0 {
		buf = unsafe.Pointer(&dest[0])
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_LGETXATTR,
		uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(a)),
		uintptr(buf), uintptr(len(dest)), 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}
