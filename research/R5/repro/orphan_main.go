//go:build linux

// LOCAL_REPRO A2: does WaitDelay alone leave orphan grandchildren alive on the host?
package main

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func count(marker string) int {
	out, _ := exec.Command("/bin/sh", "-c", "pgrep -f '"+marker+"' | wc -l").Output()
	var n int
	fmt.Sscanf(string(out), "%d", &n)
	return n
}

func try(label, marker string, pgid, customCancel bool, wd time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	c := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 20 "+marker+" | cat")
	if pgid {
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if customCancel {
		c.Cancel = func() error { return syscall.Kill(-c.Process.Pid, syscall.SIGKILL) }
	}
	c.WaitDelay = wd
	_ = c.Run()
	time.Sleep(300 * time.Millisecond)
	fmt.Printf("[%s] pgid=%v customCancel=%v wd=%v => survivors matching %q: %d\n", label, pgid, customCancel, wd, marker, count(marker)-1)
}

func main() {
	try("waitdelay-only", "MARKER_A", false, false, 200*time.Millisecond)
	try("pgid-groupkill", "MARKER_B", true, true, 200*time.Millisecond)
}
