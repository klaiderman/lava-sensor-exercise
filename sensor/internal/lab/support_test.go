// Package lab is the independent testing-phase package for the sensor.
//
// It is written by a different agent than the one that implemented
// internal/checks, internal/probe and internal/scan (author != reviewer,
// CLAUDE.md "Process gates"). It never edits those packages; it only imports
// their exported surface (checks.All, checks.CollectMachine, scan.*, probe.*)
// and the fixture trees the author committed under
// internal/checks/testdata/profile{A,B,C} (read-only — this package builds its
// own copies under t.TempDir(), it never writes into the author's tree).
//
// Everything in this file is test-only support code: a fixture materialiser
// (mirroring internal/checks/fixture_test.go's _dirs.txt/_modes.txt/_symlinks.txt
// convention so the same committed fixtures can be reused from here), a fake
// exec.Runner, a fixed clock and a scan.Env builder.
package lab

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/checks"
	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// checksTestdata is the author's fixture root, read-only from here.
const checksTestdata = "../checks/testdata"

// labTestdata is this package's own fixture root (storage matrix, fault
// injection scenarios not already covered by the author's fixtures).
const labTestdata = "testdata"

// buildProfileFrom materialises a fixture tree rooted at srcRoot/name into a
// fresh t.TempDir(), honouring the _dirs.txt/_modes.txt/_symlinks.txt seams.
// This is a deliberate, independent reimplementation (not an import of the
// author's unexported test helper, which is not visible outside package
// checks) so that a bug in the author's materialiser cannot mask a bug here,
// and vice versa.
func buildProfileFrom(t *testing.T, srcRoot, name string) string {
	t.Helper()
	src := filepath.Join(srcRoot, name)
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
			symlinks = append(symlinks, fixtureLines(string(b))...)
			return nil
		case "_dirs.txt":
			dirs = append(dirs, fixtureLines(string(b))...)
			return nil
		case "_modes.txt":
			modes = append(modes, fixtureLines(string(b))...)
			return nil
		}
		target := filepath.Join(dst, decodePath(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, b, 0o644); err != nil {
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

// buildAuthorProfile builds one of the author's committed profileA/B/C trees.
func buildAuthorProfile(t *testing.T, name string) string {
	t.Helper()
	return buildProfileFrom(t, checksTestdata, name)
}

// buildLabFixture builds one of this package's own fixture trees.
func buildLabFixture(t *testing.T, name string) string {
	t.Helper()
	return buildProfileFrom(t, labTestdata, name)
}

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

func fixtureLines(s string) []string {
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

// chmodPath chmods a path relative to a fixture root, for tests that need to
// deny access to a subtree the tree()/buildProfile materialisers already built.
func chmodPath(root, rel string, mode os.FileMode) error {
	return os.Chmod(filepath.Join(root, filepath.FromSlash(rel)), mode)
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
		t.Skipf("linux-only behaviour; run this test under WSL/Docker (GOOS=%s here)", runtime.GOOS)
	}
}

// fakeRunner answers exec observations from a table keyed on the full command
// line ("name arg1 arg2 ..."). Unstubbed commands come back UTILITY_MISSING,
// the conservative default (never "capability absent").
type fakeRunner struct {
	byCmd map[string]probe.Observation
	calls []string
}

func newFakeRunner() *fakeRunner { return &fakeRunner{byCmd: map[string]probe.Observation{}} }

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

func (f *fakeRunner) execError(cmd, stdout, stderr string, code int64) *fakeRunner {
	return f.set(cmd, probe.Observation{
		Status: probe.StatusExecError, Value: stdout, Bytes: int64(len(stdout)), ExitCode: &code,
		Meta: &probe.Meta{Command: strings.Fields(cmd), BinaryResolvedPath: strings.Fields(cmd)[0], StderrExcerpt: stderr},
	})
}

func (f *fakeRunner) timeout(cmd string) *fakeRunner {
	return f.set(cmd, probe.Observation{Status: probe.StatusTimeout, Detail: "command exceeded its budget and its process group was killed",
		Meta: &probe.Meta{Command: strings.Fields(cmd), BinaryResolvedPath: strings.Fields(cmd)[0], TimedOut: true}})
}

func (f *fakeRunner) Run(_ context.Context, spec probe.Spec) probe.Observation {
	key := strings.TrimSpace(spec.Name + " " + strings.Join(spec.Args, " "))
	f.calls = append(f.calls, key)
	if obs, ok := f.byCmd[key]; ok {
		return obs
	}
	return probe.Observation{
		Source: key, Kind: probe.KindCommandExec, Status: probe.StatusUtilityMissing,
		Detail: "not stubbed by the test lab",
		Meta:   &probe.Meta{Command: append([]string{spec.Name}, spec.Args...)},
	}
}

// sshdGOutput mirrors a realistic `sshd -G` dump.
func sshdGOutput(permitRootLogin string) string {
	return strings.Join([]string{
		"port 22",
		"addressfamily any",
		"permitrootlogin " + permitRootLogin,
		"passwordauthentication no",
		"kbdinteractiveauthentication no",
		"pubkeyauthentication yes",
		"permitemptypasswords no",
		"usepam yes",
		"maxauthtries 6",
		"logingracetime 120",
		"x11forwarding yes",
		"",
	}, "\n")
}

// fixedClock makes scan output deterministic.
func fixedClock() func() time.Time {
	ts := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return ts }
}

func newLabEnv(t *testing.T, root string, runner probe.Runner) *scan.Env {
	t.Helper()
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	if runner == nil {
		runner = newFakeRunner()
	}
	return scan.NewEnv(r, runner, fixedClock(), time.Time{}, 1000)
}

// runFullScan runs the whole registered roster (checks.All()) through the
// engine and returns the findings keyed by check_id, failing the test if any
// check_id is missing or duplicated — the one invariant every other assertion
// in this package depends on.
func runFullScan(t *testing.T, env *scan.Env) map[string]scan.Finding {
	t.Helper()
	roster := checks.All()
	if err := scan.ValidateRoster(roster); err != nil {
		t.Fatalf("roster invalid: %v", err)
	}
	findings, _ := scan.Run(context.Background(), roster, env)
	byID := make(map[string]scan.Finding, len(roster))
	for _, f := range findings {
		if _, dup := byID[f.CheckID]; dup {
			t.Errorf("check_id %s produced more than one finding", f.CheckID)
		}
		byID[f.CheckID] = f
	}
	for _, c := range roster {
		if _, ok := byID[c.ID()]; !ok {
			t.Errorf("registered check %s produced no finding at all (silent omission)", c.ID())
		}
	}
	return byID
}
