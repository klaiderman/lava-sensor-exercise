//go:build !unix

package probe

import "errors"

func mkfifo(string) error { return errors.New("mkfifo is not available on this platform") }
