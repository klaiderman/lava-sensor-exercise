package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// Fixture profiles are committed as plain files under testdata/ and
// materialised into t.TempDir() before each test, because the two things that
// make a sysfs fixture honest — symlinks and permission bits — cannot be
// committed portably.
//
//	_symlinks.txt  "<relative path> -> <target>"   one per line
//	_dirs.txt      "<relative path>"               empty directories
//	_modes.txt     "<relative path> <octal mode>"  permissions
//
// A path component may be percent-encoded (%3A for ':') so the tree can be
// checked out on a filesystem that forbids the character.
func buildProfile(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("fixture profile %s: %v", name, err)
	}
	dst := t.TempDir()

	var symlinks, dirs, modes []string
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, decodePath(rel)), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		switch d.Name() {
		case "_symlinks.txt":
			symlinks = append(symlinks, lines(string(b))...)
			return nil
		case "_dirs.txt":
			dirs = append(dirs, lines(string(b))...)
			return nil
		case "_modes.txt":
			modes = append(modes, lines(string(b))...)
			return nil
		}
		target := filepath.Join(dst, decodePath(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
			// A filesystem that forbids the character (Windows and ':') loses
			// that fixture file; the test using it must skip, not silently pass.
			t.Logf("fixture %s: could not create %s: %v", name, rel, err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("building fixture %s: %v", name, err)
	}

	for _, d := range dirs {
		if err := os.MkdirAll(filepath.Join(dst, decodePath(d)), 0o755); err != nil {
			t.Fatalf("fixture %s: mkdir %s: %v", name, d, err)
		}
	}
	for _, ln := range symlinks {
		link, tgt, ok := strings.Cut(ln, " -> ")
		if !ok {
			t.Fatalf("fixture %s: malformed symlink line %q", name, ln)
		}
		full := filepath.Join(dst, decodePath(strings.TrimSpace(link)))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("fixture %s: %v", name, err)
		}
		if err := os.Symlink(strings.TrimSpace(tgt), full); err != nil {
			// Creating a symlink needs a privilege on Windows. Every fixture
			// whose point is symlink traversal must therefore run on Linux.
			t.Skipf("fixture %s needs symlinks, which this platform refused: %v", name, err)
		}
	}
	for _, ln := range modes {
		p, m, ok := strings.Cut(strings.TrimSpace(ln), " ")
		if !ok {
			continue
		}
		mode, err := strconv.ParseUint(strings.TrimSpace(m), 8, 32)
		if err != nil {
			t.Fatalf("fixture %s: bad mode %q", name, m)
		}
		if err := os.Chmod(filepath.Join(dst, decodePath(p)), os.FileMode(mode)); err != nil {
			t.Logf("fixture %s: chmod %s: %v", name, p, err)
		}
	}
	t.Cleanup(func() { restorePermissions(dst) })
	return dst
}

// restorePermissions makes the tree removable again after a test chmod-ed part
// of it to 0000.
func restorePermissions(root string) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			_ = os.Chmod(p, 0o755)
			return nil
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o755)
		}
		return nil
	})
}

func lines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out
}

func decodePath(p string) string { return strings.ReplaceAll(p, "%3A", ":") }

// fakeRunner answers exec observations from a table keyed on the command line,
// so a test can exercise the oracle path without an sshd on the machine.
type fakeRunner struct {
	byCmd map[string]probe.Observation
	calls []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{byCmd: map[string]probe.Observation{}}
}

func (f *fakeRunner) set(cmd string, obs probe.Observation) *fakeRunner {
	obs.Kind = probe.KindCommandExec
	obs.Source = cmd
	if obs.Meta == nil {
		obs.Meta = &probe.Meta{Command: strings.Fields(cmd), BinaryResolvedPath: strings.Fields(cmd)[0]}
	}
	f.byCmd[cmd] = obs
	return f
}

func (f *fakeRunner) ok(cmd, stdout string) *fakeRunner {
	zero := int64(0)
	return f.set(cmd, probe.Observation{Status: probe.StatusOK, Value: stdout, Bytes: int64(len(stdout)), ExitCode: &zero})
}

func (f *fakeRunner) Run(_ context.Context, spec probe.Spec) probe.Observation {
	key := strings.TrimSpace(spec.Name + " " + strings.Join(spec.Args, " "))
	f.calls = append(f.calls, key)
	if obs, ok := f.byCmd[key]; ok {
		return obs
	}
	// A command the test did not stub is treated as not installed, which is the
	// conservative answer: never "capability absent".
	return probe.Observation{
		Source: key, Kind: probe.KindCommandExec, Status: probe.StatusUtilityMissing,
		Detail: "not stubbed by the test",
		Meta:   &probe.Meta{Command: append([]string{spec.Name}, spec.Args...)},
	}
}

// fixedClock makes the output deterministic in tests.
func fixedClock() func() time.Time {
	t := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func newTestEnv(t *testing.T, root string, runner probe.Runner) *scan.Env {
	t.Helper()
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	if runner == nil {
		runner = newFakeRunner()
	}
	return scan.NewEnv(r, runner, fixedClock(), time.Time{}, 1000)
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("uid 0 bypasses the mode bits this fixture depends on")
	}
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("linux-only behaviour; this test is executed under WSL/Docker (GOOS=%s here)", runtime.GOOS)
	}
}

// mkfifoForTest creates a FIFO where the platform supports one.
func mkfifoForTest(p string) error { return mkfifoPlatform(p) }

// ownGroupLine describes the group the test process creates files under, so a
// fixture's mode bits mean what the test intends rather than resolving against
// a gid the fixture never declared.
func ownGroupLine() string {
	gid := os.Getgid()
	if gid < 0 {
		gid = 0
	}
	return "testgroup:x:" + strconv.Itoa(gid) + ":\n"
}
