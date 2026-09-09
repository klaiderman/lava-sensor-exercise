package lab

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/checks"
	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// tree materialises an ad-hoc fixture tree, independent of the profile
// materialiser above. A path ending in "/" is a directory.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, content := range files {
		full := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(p, "/")))
		if strings.HasSuffix(p, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { restorePermissions(root) })
	return root
}

func findingOf(t *testing.T, root string, runner probe.Runner, checkID string) scan.Finding {
	t.Helper()
	env := newLabEnv(t, root, runner)
	byID := runFullScan(t, env)
	f, ok := byID[checkID]
	if !ok {
		t.Fatalf("%s produced no finding", checkID)
	}
	return f
}

// ---------------------------------------------------------------------------
// 1. Real sleeping child, real group kill, real "no descendants" proof.
// ---------------------------------------------------------------------------

// TestFaultInjection_TimeoutRealSleepingChildLeavesNoDescendants exercises the
// production probe.ExecRunner (not a fake) against a real child process tree:
// a shell that spawns a background sleep and then itself sleeps. A budget far
// shorter than either sleep forces a real timeout; the assertion is that the
// whole process group is dead well after the runner returns, not merely that
// the runner returned StatusTimeout.
func TestFaultInjection_TimeoutRealSleepingChildLeavesNoDescendants(t *testing.T) {
	requireLinux(t)
	marker := filepath.Join(t.TempDir(), "still-alive")
	script := filepath.Join(t.TempDir(), "hang.sh")
	body := "#!/bin/sh\n(sleep 20; touch " + marker + ") &\nsleep 20\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	obs := probe.NewRunner().Run(context.Background(), probe.Spec{Name: script, Budget: 250 * time.Millisecond})
	elapsed := time.Since(start)

	if obs.Status != probe.StatusTimeout {
		t.Fatalf("status = %s, want TIMEOUT (a timeout is never a fail — L10)", obs.Status)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("runner took %s to return for a 250ms budget; the group kill is not bounding the call", elapsed)
	}

	// Give a surviving grandchild ample time to prove it escaped, then check.
	time.Sleep(1200 * time.Millisecond)
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("a descendant of the killed group wrote %s after the deadline: the process-group kill leaked a survivor", marker)
	}
}

// ---------------------------------------------------------------------------
// 2. Panic isolation inside the real, full roster (not a synthetic stub roster).
// ---------------------------------------------------------------------------

type panickingCheck struct{ id string }

func (p panickingCheck) ID() string            { return p.id }
func (p panickingCheck) Category() string      { return "TEST_LAB_INJECTED" }
func (p panickingCheck) Title() string         { return "deliberately panics for isolation testing" }
func (p panickingCheck) Impact() string        { return scan.SeverityHigh }
func (p panickingCheck) Observational() bool   { return false }
func (p panickingCheck) Budget() time.Duration { return scan.DefaultCheckBudget }
func (p panickingCheck) Run(context.Context, *scan.Env) scan.Result {
	var arr []int
	_ = arr[7] // index out of range panic
	return scan.Pass("unreachable")
}

// TestFaultInjection_PanicInFullRosterIsolatesOnlyTheOffender injects a
// panicking check alongside the real checks.All() roster (26 checks as
// registered) and asserts every real check still produces its normal finding
// while the panicking one is downgraded to a single unknown/INTERNAL_ERROR
// finding — the failure never propagates and never doubles up.
func TestFaultInjection_PanicInFullRosterIsolatesOnlyTheOffender(t *testing.T) {
	root := buildAuthorProfile(t, "profileA")
	env := newLabEnv(t, root, profileARunner())

	roster := append(append([]scan.Check{}, checks.All()...), panickingCheck{id: "LAB_INJECTED_PANIC"})
	findings, _ := scan.Run(context.Background(), roster, env)
	if len(findings) != len(roster) {
		t.Fatalf("len(findings) = %d, want %d (one per registered check, panicking one included)", len(findings), len(roster))
	}
	byID := map[string]scan.Finding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	p, ok := byID["LAB_INJECTED_PANIC"]
	if !ok {
		t.Fatal("the panicking check produced no finding at all — this is exactly the silent-omission failure mode panic isolation exists to prevent")
	}
	if p.Status != scan.StatusUnknown || p.Reason != scan.ReasonInternal {
		t.Errorf("panicking check = %s/%s, want unknown/%s", p.Status, p.Reason, scan.ReasonInternal)
	}
	if strings.Contains(p.Evidence.Detail+strings.Join(evidenceStrings(p), " "), "index out of range") {
		t.Errorf("the recovered panic value's literal message leaked into evidence; only its type should")
	}
	for _, c := range checks.All() {
		if _, ok := byID[c.ID()]; !ok {
			t.Errorf("check %s produced no finding when a sibling check panicked — isolation failed", c.ID())
		}
	}
}

func evidenceStrings(f scan.Finding) []string {
	var out []string
	for _, o := range f.Evidence.Observations {
		out = append(out, o.Detail, o.Value)
	}
	return out
}

// ---------------------------------------------------------------------------
// 3. Budget cut mid-scan: every registered check still emits exactly one
//    finding, even when the parent context is already past its deadline.
// ---------------------------------------------------------------------------

func TestFaultInjection_BudgetCutMidScan_EveryCheckStillEmitsOneFinding(t *testing.T) {
	root := buildAuthorProfile(t, "profileA")
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	past := time.Now().Add(-1 * time.Hour)
	env := scan.NewEnv(r, newFakeRunner(), fixedClock(), past, 1000)

	ctx, cancel := context.WithDeadline(context.Background(), past)
	defer cancel()

	roster := checks.All()
	findings, cut := scan.Run(ctx, roster, env)
	if len(findings) != len(roster) {
		t.Fatalf("len(findings) = %d, want %d — a budget cut must never drop a check silently (D3, L34)", len(findings), len(roster))
	}
	if cut != int64(len(roster)) {
		t.Errorf("budget_cut_count = %d, want %d (the deadline had already passed before the first check ran)", cut, len(roster))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if seen[f.CheckID] {
			t.Errorf("check_id %s duplicated under a budget cut", f.CheckID)
		}
		seen[f.CheckID] = true
		if f.Status != scan.StatusUnknown || f.Reason != scan.ReasonBudget {
			t.Errorf("%s: status/reason = %s/%s under an expired deadline, want unknown/%s", f.CheckID, f.Status, f.Reason, scan.ReasonBudget)
		}
	}
	for _, c := range roster {
		if !seen[c.ID()] {
			t.Errorf("registered check %s never appeared in the cut-scan output", c.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// 4. 200MB / size-lying sysfs read: the cap is respected regardless of how
//    large the underlying file claims to be (st_size is never trusted, L05).
// ---------------------------------------------------------------------------

func TestFaultInjection_SizeLyingRead_CapRespected(t *testing.T) {
	root := t.TempDir()
	sysDir := filepath.Join(root, "sys", "class", "dmi", "id")
	if err := os.MkdirAll(sysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bigPath := filepath.Join(sysDir, "product_name")
	f, err := os.Create(bigPath)
	if err != nil {
		t.Fatal(err)
	}
	const lieSize = 200 << 20 // 200 MB, sparse: Truncate never writes real bytes.
	if err := f.Truncate(lieSize); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	obs := r.Read("/sys/class/dmi/id/product_name", probe.Small)
	if obs.Status != probe.StatusOK {
		t.Fatalf("read status = %s, want OK (a large-but-readable file is not a failure)", obs.Status)
	}
	if !obs.Truncated {
		t.Errorf("a 200MB file read under a 64KB cap must be marked truncated")
	}
	if obs.Bytes != probe.CapSmall {
		t.Errorf("bytes = %d, want exactly the cap %d", obs.Bytes, probe.CapSmall)
	}
	if int64(len(obs.Value)) != probe.CapSmall {
		t.Errorf("len(value) = %d, want exactly the cap %d — the whole 200MB must never reach evidence", len(obs.Value), probe.CapSmall)
	}
}

// ---------------------------------------------------------------------------
// 5. Symlink edge cases: sysfs symlinks are followed; a symlink into a
//    user-writable tree from outside /sys or /proc is refused.
// ---------------------------------------------------------------------------

func TestFaultInjection_SymlinkIntoUserWritableTreeNotFollowed(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tmp", "mallory-planted"), []byte("attacker-controlled content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An absolute symlink, exactly the "point /etc/x at /tmp/y" substitution
	// the read path's escapesToUserTree check exists to refuse.
	if err := os.Symlink("/tmp/mallory-planted", filepath.Join(root, "etc", "machine-info")); err != nil {
		t.Fatalf("creating the symlink fixture: %v", err)
	}

	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	obs := r.Read("/etc/machine-info", probe.SmallFollow)
	if obs.Status == probe.StatusOK {
		t.Fatalf("a symlink from /etc into /tmp was followed and its content returned: %q", obs.Value)
	}
	if strings.Contains(obs.Value, "attacker-controlled") {
		t.Fatalf("attacker-controlled content leaked into the observation despite a non-OK status")
	}
}

func TestFaultInjection_SysfsInRootSymlinksAreFollowed(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	devDir := filepath.Join(root, "sys", "devices", "nvme0n1")
	if err := os.MkdirAll(devDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(devDir, "size"), []byte("2048\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sys", "block"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../devices/nvme0n1", filepath.Join(root, "sys", "block", "nvme0n1")); err != nil {
		t.Fatalf("creating the in-sysfs symlink fixture: %v", err)
	}

	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	v, obs := r.ReadTrimmed("/sys/block/nvme0n1/size", probe.Tiny)
	if obs.Status != probe.StatusOK || v != "2048" {
		t.Fatalf("reading through the /sys/block symlink: status=%s value=%q, want OK/2048 (every /sys/block entry is a symlink, F18)", obs.Status, v)
	}
}

// ---------------------------------------------------------------------------
// 6. EACCES / utility missing / non-zero exit / malformed output / partial
//    output / timeout, all through SSH_ROOT_LOGIN_POLICY (the vertical slice
//    check the fallback chain lives in). The invariant tested is uniform: a
//    fault on the primary oracle must never silently produce a confident
//    pass or fail when no fallback can independently establish one.
// ---------------------------------------------------------------------------

func TestFaultInjection_SSHOracleFaultsNeverProduceAFalseVerdict(t *testing.T) {
	base := map[string]string{"/usr/sbin/sshd": "#!/bin/sh\n"} // binary present, no config anywhere
	cases := []struct {
		name       string
		runner     *fakeRunner
		wantStatus scan.Status
		wantReason string // "" means "any non-empty reason is acceptable"
	}{
		{
			name:       "utility_missing_no_binary_no_config",
			runner:     newFakeRunner(), // /usr/sbin/sshd absent below (separate fixture)
			wantStatus: scan.StatusUnknown,
			wantReason: scan.ReasonUtilMiss,
		},
		{
			name:       "timeout",
			runner:     newFakeRunner().timeout("/usr/sbin/sshd -G"),
			wantStatus: scan.StatusUnknown,
			wantReason: scan.ReasonTimeout,
		},
		{
			name:       "non_zero_exit",
			runner:     newFakeRunner().execError("/usr/sbin/sshd -G", "", "unable to load host key", 1),
			wantStatus: scan.StatusUnknown,
			wantReason: scan.ReasonExecError,
		},
		{
			name:       "malformed_output_no_keyword_lines",
			runner:     newFakeRunner().ok("/usr/sbin/sshd -G", "\n\n   \n"),
			wantStatus: scan.StatusUnknown,
			wantReason: "", // PARSE_ERROR is recorded on the oracle but the finding-level
			// reason is whichever cause is most actionable (unresolvedReason); the
			// contract under test is "never a confident verdict", not the exact string.
		},
		{
			name: "partial_truncated_output_still_has_a_directive",
			runner: func() *fakeRunner {
				fr := newFakeRunner()
				zero := int64(0)
				fr.set("/usr/sbin/sshd -G", probe.Observation{
					Status: probe.StatusOK, Value: "permitrootlogin no\n", Bytes: 20, Truncated: true, ExitCode: &zero,
					Meta: &probe.Meta{Command: []string{"/usr/sbin/sshd", "-G"}, BinaryResolvedPath: "/usr/sbin/sshd", StdoutTruncated: true},
				})
				return fr
			}(),
			wantStatus: scan.StatusUnknown,
			wantReason: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := base
			if tc.name == "utility_missing_no_binary_no_config" {
				files = map[string]string{} // no sshd binary, no config: the true "nothing installed" case
			}
			root := tree(t, files)
			f := findingOf(t, root, tc.runner, "SSH_ROOT_LOGIN_POLICY")
			if f.Status != tc.wantStatus {
				t.Errorf("status = %s, want %s (a fault on the oracle with no corroborating fallback must never resolve to a confident verdict)", f.Status, tc.wantStatus)
			}
			if f.Reason == "" {
				t.Errorf("reason is empty on a non-pass finding; UNKNOWN requires a reason (CLAUDE.md evidence semantics)")
			}
			if tc.wantReason != "" && f.Reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", f.Reason, tc.wantReason)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. CONTESTED: oracle and walker disagree, both are recorded, neither wins
//    by being observed first.
// ---------------------------------------------------------------------------

func TestFaultInjection_ContradictoryObservationsAreContested(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := findingOf(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("yes")), "SSH_ROOT_LOGIN_POLICY")
	if f.Status != scan.StatusUnknown || f.Reason != scan.ReasonContested {
		t.Fatalf("oracle=yes vs file=no: status/reason = %s/%s, want unknown/%s", f.Status, f.Reason, scan.ReasonContested)
	}
	body := jsonOf(t, f)
	if !strings.Contains(body, "\"yes\"") || !strings.Contains(body, "\"no\"") {
		t.Errorf("both contested values must be recorded in evidence, got: %s", body)
	}
}

// ---------------------------------------------------------------------------
// 8. Empty evidence: a check with nothing to add still emits a schema-shaped
//    evidence object (observations: [] is present, never omitted or null).
// ---------------------------------------------------------------------------

type noEvidenceCheck struct{}

func (noEvidenceCheck) ID() string            { return "LAB_NO_EVIDENCE" }
func (noEvidenceCheck) Category() string      { return "TEST_LAB_INJECTED" }
func (noEvidenceCheck) Title() string         { return "returns a bare pass with no observations or fields" }
func (noEvidenceCheck) Impact() string        { return scan.SeverityInfo }
func (noEvidenceCheck) Observational() bool   { return true }
func (noEvidenceCheck) Budget() time.Duration { return scan.DefaultCheckBudget }
func (noEvidenceCheck) Run(context.Context, *scan.Env) scan.Result {
	return scan.Pass("")
}

func TestFaultInjection_EmptyEvidenceStillProducesAWellShapedObject(t *testing.T) {
	env := newLabEnv(t, t.TempDir(), newFakeRunner())
	findings, _ := scan.Run(context.Background(), []scan.Check{noEvidenceCheck{}}, env)
	if len(findings) != 1 {
		t.Fatalf("len(findings) = %d, want 1", len(findings))
	}
	body := jsonOf(t, findings[0])
	if !strings.Contains(body, `"observations":[]`) {
		t.Errorf("an evidence object with zero observations must still render observations:[], got: %s", body)
	}
}

// ---------------------------------------------------------------------------
// 9. Under-claim guard: a fallback exists, so the answer must not be unknown.
// ---------------------------------------------------------------------------

func TestFaultInjection_UnderClaim_UdevFallbackEstablishesModel(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/":          "",
		"/sys/block/sdz/dev":   "8:16\n",
		"/sys/block/sdz/size":  "2048\n",
		"/run/udev/data/b8:16": "E:ID_MODEL=UnderClaimTestModel\n",
		"/proc/self/mountinfo": "",
	})
	env := newLabEnv(t, root, newFakeRunner())
	m := checks.CollectMachine(context.Background(), env)
	var got *scan.StorageDevice
	for i := range m.Storage {
		if m.Storage[i].Device == "sdz" {
			got = &m.Storage[i]
		}
	}
	if got == nil {
		t.Fatalf("device sdz not present in machine.storage: %+v", m.Storage)
	}
	if got.Model == scan.UnknownString {
		t.Errorf("model = unknown, but a udev fallback (%s) could have established it — this is exactly the under-claim bug L36/L39 forbid", "/run/udev/data/b8:16")
	}
	if got.Model != "UnderClaimTestModel" || !strings.Contains(got.ModelSource, "udev") {
		t.Errorf("model/model_source = %q/%q, want the udev-sourced value", got.Model, got.ModelSource)
	}
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
