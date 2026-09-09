//go:build unix

package checks

import "syscall"

func mkfifoPlatform(p string) error { return syscall.Mkfifo(p, 0o600) }
