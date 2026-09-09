package probe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shim writes an executable /bin/sh script and returns its path.
func shim(t *testing.T, name, body string) string {
	t.Helper()
	linuxOnly(t)
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// A child that outlives its budget is killed as a GROUP, and control returns
// well inside the budget. WaitDelay alone provably leaves a grandchild running
// on the machine (R5-F14), which is why both are required.
func TestExecTimeoutKillsTheWholeProcessGroup(t *testing.T) {
	linuxOnly(t)
	marker := filepath.Join(t.TempDir(), "alive")
	p := shim(t, "hang", "sh -c 'sleep 30; touch "+marker+"' & sleep 30\n")

	start := time.Now()
	obs := NewRunner().Run(context.Background(), Spec{Name: p, Budget: 300 * time.Millisecond})
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Fatalf("the runner took %s for a 300ms budget", elapsed)
	}
	if obs.Status != StatusTimeout {
		t.Errorf("status = %s, want TIMEOUT (a timeout is never a fail)", obs.Status)
	}
	if obs.Meta == nil || !obs.Meta.TimedOut {
		t.Errorf("timed_out must be recorded in evidence")
	}
	if obs.Reason() != "TIMEOUT" {
		t.Errorf("reason = %q", obs.Reason())
	}

	// Give an escaped grandchild ample time to prove it survived.
	time.Sleep(1500 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Errorf("a descendant survived the deadline: the process-group kill is not working")
	}
}

// A child that exits promptly while a grandchild keeps stdout open is a
// distinct failure mode from a plain timeout, and WaitDelay is what bounds it.
func TestExecWaitDelayBoundsAHeldPipe(t *testing.T) {
	linuxOnly(t)
	p := shim(t, "holder", "sleep 20 &\necho hello\nexit 0\n")
	start := time.Now()
	obs := NewRunner().Run(context.Background(), Spec{Name: p, Budget: 10 * time.Second})
	elapsed := time.Since(start)

	if elapsed > ExecWaitDelay+4*time.Second {
		t.Fatalf("took %s; WaitDelay did not bound the held pipe", elapsed)
	}
	if obs.Status != StatusTimeout {
		t.Errorf("status = %s, want TIMEOUT", obs.Status)
	}
	if obs.Meta == nil || !obs.Meta.WaitDelayExpired {
		t.Errorf("wait_delay_expired must be recorded: it is not the same fact as a budget timeout")
	}
	// Partial output gathered before the delay expired is still evidence.
	if !strings.Contains(obs.Value, "hello") {
		t.Errorf("partial output was discarded: %q", obs.Value)
	}
}

// A flooding child is capped, the truncation is recorded, and the child is
// killed rather than allowed to keep writing.
func TestExecOutputCapAndKillOnOverflow(t *testing.T) {
	linuxOnly(t)
	p := shim(t, "flood", "i=0\nwhile [ $i -lt 100000 ]; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done\n")
	start := time.Now()
	obs := NewRunner().Run(context.Background(), Spec{Name: p, Budget: 10 * time.Second, OutCap: 8 << 10})
	if time.Since(start) > 8*time.Second {
		t.Fatalf("the flood was not bounded")
	}
	if int64(len(obs.Value)) > 8<<10 {
		t.Errorf("captured %d bytes over an 8 KiB cap", len(obs.Value))
	}
	if !obs.Truncated {
		t.Errorf("truncated must be recorded; a partial parse can never support a pass")
	}
}

// A missing binary is UTILITY_MISSING, never "capability absent", and it is
// distinguishable from every other failure class.
func TestExecMissingUtility(t *testing.T) {
	obs := NewRunner().Run(context.Background(), Spec{Name: "/nonexistent/definitely-not-installed"})
	if obs.Status != StatusUtilityMissing {
		t.Errorf("status = %s, want UTILITY_MISSING", obs.Status)
	}
	if obs.Reason() != "UTILITY_MISSING" {
		t.Errorf("reason = %q", obs.Reason())
	}
}

// The child's own exit code is recorded, not a pipeline's: the sensor never
// runs a shell and never reads a status through a pipe.
func TestExecRecordsTheChildsOwnExitCode(t *testing.T) {
	linuxOnly(t)
	p := shim(t, "rc", "echo out\necho err 1>&2\nexit 3\n")
	obs := NewRunner().Run(context.Background(), Spec{Name: p})
	if obs.Status != StatusExecError {
		t.Errorf("status = %s, want EXEC_ERROR", obs.Status)
	}
	if obs.ExitCode == nil || *obs.ExitCode != 3 {
		t.Errorf("exit_code = %v, want 3", obs.ExitCode)
	}
	if obs.Signal != "" {
		t.Errorf("signal = %q on a clean non-zero exit; the two are separate facts", obs.Signal)
	}
	if obs.Meta == nil || !strings.Contains(obs.Meta.StderrExcerpt, "err") {
		t.Errorf("stderr excerpt is the actual evidence for an EXEC_ERROR, got %+v", obs.Meta)
	}
	if !strings.Contains(obs.Value, "out") {
		t.Errorf("stdout = %q", obs.Value)
	}
}

// The child gets a minimal environment and /dev/null on stdin: no inherited
// secrets, no locale-dependent output, no chance of blocking on a read.
func TestExecEnvironmentIsMinimalAndStdinIsClosed(t *testing.T) {
	linuxOnly(t)
	t.Setenv("SENSOR_SECRET_CANARY", "must-not-be-inherited")
	p := shim(t, "env", "env | sort\ncat\n")
	start := time.Now()
	obs := NewRunner().Run(context.Background(), Spec{Name: p, Budget: 3 * time.Second})
	if time.Since(start) > 2*time.Second {
		t.Errorf("`cat` blocked: stdin is not /dev/null")
	}
	if strings.Contains(obs.Value, "SENSOR_SECRET_CANARY") {
		t.Errorf("the sensor's environment leaked into a child:\n%s", obs.Value)
	}
	if !strings.Contains(obs.Value, "LC_ALL=C") {
		t.Errorf("LC_ALL=C must be set so output parsing is locale-independent: %q", obs.Value)
	}
}

// The four failure classes stay four: absent binary, denied binary, timeout and
// a tool that ran and failed must each produce a different reason (L35).
func TestFourFailureClassesStayDistinct(t *testing.T) {
	linuxOnly(t)
	notRoot(t)
	runner := NewRunner()

	missing := runner.Run(context.Background(), Spec{Name: "/nonexistent/nope"})

	denied := filepath.Join(t.TempDir(), "denied")
	if err := os.WriteFile(denied, []byte("#!/bin/sh\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	deniedObs := runner.Run(context.Background(), Spec{Name: denied})

	slow := shim(t, "slow", "sleep 20\n")
	timeout := runner.Run(context.Background(), Spec{Name: slow, Budget: 200 * time.Millisecond})

	bad := shim(t, "bad", "exit 7\n")
	failed := runner.Run(context.Background(), Spec{Name: bad})

	reasons := map[string]string{
		"missing": missing.Reason(),
		"denied":  deniedObs.Reason(),
		"timeout": timeout.Reason(),
		"failed":  failed.Reason(),
	}
	seen := map[string]string{}
	for name, reason := range reasons {
		if reason == "" {
			t.Errorf("%s produced no reason", name)
		}
		if other, dup := seen[reason]; dup {
			t.Errorf("%s and %s collapsed to the same reason %q", name, other, reason)
		}
		seen[reason] = name
	}
	t.Logf("failure classes: %+v", reasons)
}

// The sensor never invokes an escalation tool. This greps the whole production
// tree rather than trusting a code review.
func TestNoPrivilegeEscalationAnywhere(t *testing.T) {
	banned := []string{`"sudo"`, `"su"`, `"doas"`, `"pkexec"`, "/bin/sh", "/bin/bash", `"sh", "-c"`}
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, s := range banned {
			if strings.Contains(string(b), s) {
				t.Errorf("%s contains %s: the sensor never escalates and never spawns a shell", p, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// exec.Cmd is constructed in exactly one place. Any other package building one
// would bypass Setpgid, the group kill, WaitDelay and the output caps.
func TestOnlyOneExecCmdConstructionSite(t *testing.T) {
	var sites []string
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if strings.Contains(string(b), "exec.Command") {
			sites = append(sites, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || !strings.HasSuffix(filepath.ToSlash(sites[0]), "internal/probe/exec.go") {
		t.Errorf("exec.Command is built in %v; it must appear only in internal/probe/exec.go", sites)
	}
	var _ = exec.Command
}
