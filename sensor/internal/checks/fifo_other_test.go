//go:build !unix

package checks

import "errors"

func mkfifoPlatform(string) error { return errors.New("mkfifo is not available on this platform") }
