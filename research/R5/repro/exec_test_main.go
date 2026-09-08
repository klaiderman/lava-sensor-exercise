//go:build linux

// LOCAL_REPRO A: bounded exec semantics (Setpgid, Cancel, WaitDelay, pipe-holding grandchild).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func killGroup(c *exec.Cmd) error {
	if c.Process == nil {
		return nil
	}
	return syscall.Kill(-c.Process.Pid, syscall.SIGKILL)
}

// case: sh spawns a grandchild that inherits stdout and sleeps; parent sh exits fast.
const grandchildScript = `sleep 30 & echo parent-done; exit 0`

func run(name string, script string, pgid bool, customCancel bool, wd time.Duration, ctxTO time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), ctxTO)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script)
	if pgid {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	if customCancel {
		cmd.Cancel = func() error { return killGroup(cmd) }
	}
	cmd.WaitDelay = wd
	start := time.Now()
	out, err := cmd.Output()
	el := time.Since(start)
	fmt.Printf("[%s] pgid=%v customCancel=%v WaitDelay=%v ctxTO=%v => elapsed=%.2fs len(out)=%d err=%v errWaitDelay=%v ctxErr=%v\n",
		name, pgid, customCancel, wd, ctxTO, el.Seconds(), len(out), err, errors.Is(err, exec.ErrWaitDelay), ctx.Err())
}

func main() {
	fmt.Println("go runtime:", os.Getenv("GOVER"))
	// 1. grandchild holds stdout open; process itself exits immediately. No WaitDelay -> hang expected.
	run("grandchild-nopgid-nowd", grandchildScript, false, false, 0, 3*time.Second)
	run("grandchild-nopgid-wd200ms", grandchildScript, false, false, 200*time.Millisecond, 3*time.Second)
	run("grandchild-pgid-wd200ms", grandchildScript, true, false, 200*time.Millisecond, 3*time.Second)
	// 2. child ignores SIGKILL? cannot. Instead: child traps SIGTERM and sleeps; default Cancel sends Kill (SIGKILL) so it dies.
	run("sleep-nopgid-default-cancel", "sleep 30", false, false, 0, 500*time.Millisecond)
	// 3. sleep in a subshell: default Cancel kills only /bin/sh, grandchild sleep survives and holds the pipe
	run("subshell-sleep-nopgid-nowd", "sleep 30 | cat", false, false, 0, 500*time.Millisecond)
	run("subshell-sleep-pgid-groupkill", "sleep 30 | cat", true, true, 0, 500*time.Millisecond)
	run("subshell-sleep-pgid-defaultcancel-wd", "sleep 30 | cat", true, false, 300*time.Millisecond, 500*time.Millisecond)
}
