//go:build !unix

package probe

import (
	"errors"
	"os"
	"syscall"
)

// This file exists only so the sensor's packages compile (and `go vet`) on a
// developer workstation that is not a unix. The shipped artifact is
// linux/amd64; nothing here is reachable on the target.

const (
	openBase      = os.O_RDONLY
	openNoFollow  = 0
	openDirectory = 0
)

func errnoName(err error) (string, bool) {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return "", false
	}
	switch {
	case errors.Is(errno, os.ErrNotExist):
		return "ENOENT", true
	case errors.Is(errno, os.ErrPermission):
		return "EACCES", true
	}
	return "", false
}

func procAttr() *syscall.SysProcAttr { return nil }

func killGroup(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func ownerOf(os.FileInfo) (uid, gid, dev, ino int64, ok bool) { return 0, 0, 0, 0, false }

func signalOf(error) string { return "" }

const devNull = os.DevNull
