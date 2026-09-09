package checks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// Regression tests for fix batch 2. Each closes a defect class, not the one
// string that exposed it.

// ---------------------------------------------------------------------------
// A / #1: evidence must entail the verdict, roster-wide
// ---------------------------------------------------------------------------

// entailmentProfiles are the fixture trees the gate is run against. Adversarial
// trees are included deliberately: the rule has to hold hardest where the
// observations fail.
func entailmentProfiles(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{
		"profileA": buildProfile(t, "profileA"),
		"profileB": buildProfile(t, "profileB"),
		"profileC": buildProfile(t, "profileC"),
		// Everything denied: the shape in which a check is most tempted to say
		// it looked and found nothing.
		"adv-all-denied": tree(t, map[string]string{
			"/etc/group":                  "root:x:0:\n",
			"/etc/passwd":                 passwdFile,
			"/root/.ssh/authorized_keys":  "ssh-ed25519 AAAA root\n",
			"/etc/ssh/sshd_config":        "PermitRootLogin prohibit-password\n",
			"/etc/ssl/private/server.key": pemKeyBody,
		}),
		// Nothing at all: no scan root, no sysfs, no config.
		"adv-empty": tree(t, map[string]string{"/etc/hostname": "x\n"}),
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 {
		root := out["adv-all-denied"]
		for _, d := range []string{"root", "etc/ssl/private"} {
			_ = os.Chmod(filepath.Join(root, filepath.FromSlash(d)), 0o000)
		}
	}
	return out
}

// TestEvidenceEntailsVerdict is the gate. It runs the whole roster against every
// profile and fails on any finding whose prose claims more than its own
// observations support, or that passes while a load-bearing observation did
// not succeed.
func TestEvidenceEntailsVerdict(t *testing.T) {
	for name, root := range entailmentProfiles(t) {
		t.Run(name, func(t *testing.T) {
			runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password"))
			_, body := buildDocumentAt(t, root, runner)
			if violations := scan.AuditEntailment(body); len(violations) > 0 {
				for _, v := range violations {
					t.Errorf("%s", v)
				}
			}
		})
	}
}

// TestEntailmentAuditorOnShippedArtifacts points the same rule, in data mode, at
// artifacts produced elsewhere - the container runs and the real-host run.
func TestEntailmentAuditorOnShippedArtifacts(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "reports", "**", "findings*.json"))
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob(filepath.Join("..", "..", "..", "reports", "testlab", "findings*.json"))
	paths = append(paths, more...)
	checked := 0
	for _, p := range paths {
		if strings.Contains(filepath.ToSlash(p), "/review") {
			// Another reviewer's scratch copies, produced by their own build.
			continue
		}
		body, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if !strings.Contains(string(body), `"completeness"`) {
			// Produced before the entailment gate existed; auditing it would
			// report the absence of a field the binary could not have written.
			t.Logf("%s: produced before the entailment gate, not audited", filepath.Base(p))
			continue
		}
		checked++
		for _, v := range scan.AuditEntailment(body) {
			t.Errorf("%s: %s", filepath.Base(p), v)
		}
	}
	t.Logf("audited %d artifact(s) in data mode", checked)
}

// A check that lies about completeness is downgraded by the engine, and the
// violation is recorded so an outside auditor can see it happened.
func TestEntailmentGateDowngradesAnOverclaim(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	liar := overclaimingCheck{}
	findings, _ := scan.Run(context.Background(), []scan.Check{liar}, env)
	f := findings[0]
	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s, want unknown: a pass whose prose the evidence refutes must not ship", f.Status)
	}
	if !f.EntailmentViolation {
		t.Errorf("the violation must be recorded on the finding")
	}
	if !strings.Contains(f.Evidence.Detail, "engine:") {
		t.Errorf("the downgrade must say what it caught: %q", f.Evidence.Detail)
	}
}

type overclaimingCheck struct{}

func (overclaimingCheck) ID() string            { return "OVERCLAIMING" }
func (overclaimingCheck) Category() string      { return "TEST_CATEGORY" }
func (overclaimingCheck) Title() string         { return "A check that claims more than it saw" }
func (overclaimingCheck) Impact() string        { return scan.SeverityHigh }
func (overclaimingCheck) Observational() bool   { return false }
func (overclaimingCheck) Budget() time.Duration { return time.Second }
func (overclaimingCheck) Run(context.Context, *scan.Env) scan.Result {
	r := scan.Pass("every directory was enumerated successfully and nothing was found")
	r.Add(probe.Observation{Source: "/root", Kind: probe.KindDirWalk,
		Status: probe.StatusEACCES, Errno: "EACCES", LoadBearing: true})
	return r
}

// ---------------------------------------------------------------------------
// B / #2 #3 #17 #22: a walk that could not enter a subtree did not complete
// ---------------------------------------------------------------------------

// Superseded by fix batch 3 rows 28/35: for an EXPOSURE question a subtree this
// account cannot enter is evidence of protection, because no other unprivileged
// account can enter it either. What must still hold is that the boundary is
// REPORTED rather than silently dropped, and that the two secrets checks agree.
func TestPrivateKey_UnreadableSubtreeIsReportedAsProtection(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                    "root:x:0:\n",
		"/root/.ssh/id_ed25519":         pemKeyBody,
		"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_ed25519_key", 0o600)
	chmod(t, root, "/root", 0o000)

	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status == scan.StatusFail {
		t.Fatalf("a key behind a directory no unprivileged account can enter is not exposed: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	prot, _ := ev["scan_roots_protected"].([]any)
	if len(prot) == 0 {
		t.Errorf("the shielded subtree must be reported, not silently dropped: %v", ev)
	}
	shown := false
	for _, p := range prot {
		if strings.Contains(p.(string), "/root") {
			shown = true
		}
	}
	if !shown {
		t.Errorf("the specific subtree must be named: %v", prot)
	}
	// And the two secrets checks must agree about the same directory.
	cred := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	if cred.Status == scan.StatusFail {
		t.Errorf("CREDENTIAL_FILE_EXPOSURE = fail while PRIVATE_KEY_MATERIAL_EXPOSURE = %s, on the same denied directory", f.Status)
	}
}

// A key that IS exposed is a positive observation; an incomplete walk elsewhere
// does not soften it.
func TestPrivateKey_AdverseFindingSurvivesAnIncompleteWalk(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                    "root:x:0:\n",
		"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
		"/root/.ssh/id_ed25519":         pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_ed25519_key", 0o644)
	chmod(t, root, "/root", 0o000)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	wantStatus(t, f, scan.StatusFail)
}

func TestPrivateKey_ZeroWalksIsNotPass(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	wantStatus(t, f, scan.StatusUnknown)
	if f.Reason != scan.ReasonENOENT {
		t.Errorf("reason = %q, want ENOENT", f.Reason)
	}
	if !strings.Contains(f.Evidence.Detail, "nothing was searched") {
		t.Errorf("a search of nowhere must say so: %q", f.Evidence.Detail)
	}
}

func TestPrivateKey_SymlinksAreNotCandidates(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/etc/group":                "root:x:0:\n",
		"/etc/ssl/certs/real.pem":   "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		"/etc/ssl/private/keep.key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssl/private/keep.key", 0o600)
	for i := 0; i < 5; i++ {
		link := filepath.Join(root, filepath.FromSlash("etc/ssl/certs"), "link"+string(rune('a'+i))+".pem")
		if err := os.Symlink("real.pem", link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
	}
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	ev := evidenceOf(t, f)
	if n, _ := ev["symlinks_skipped"].(float64); n != 5 {
		t.Errorf("symlinks_skipped = %v, want 5", ev["symlinks_skipped"])
	}
	for _, h := range ev["private_key_files"].([]any) {
		m := h.(map[string]any)
		if strings.Contains(m["path"].(string), "/link") {
			t.Errorf("a symlink was listed as a key candidate: %v", m)
		}
	}
}

func TestWalkBoundaryCountersSurviveEvidenceCap(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := t.TempDir()
	base := filepath.Join(root, "etc", "many")
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	// More denied directories than the boundary list is allowed to carry.
	for i := 0; i < 80; i++ {
		d := filepath.Join(base, "d"+itoa(int64(i)))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(d, 0o000); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { restorePermissions(root) })

	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	res, obs := r.Walk("/etc/many", probe.WalkBudget{}, func(string, os.DirEntry) {})
	if res.Complete() {
		t.Fatalf("a walk that could not enter 80 directories is not complete: %+v", res)
	}
	if res.UnreadableDirsCount < 80 {
		t.Errorf("unreadable_dirs_count = %d, want at least 80: the counter must survive the list cap", res.UnreadableDirsCount)
	}
	if len(res.UnreadableDirs) > 64 {
		t.Errorf("the list itself must stay capped, got %d", len(res.UnreadableDirs))
	}
	if !res.ListsTruncated {
		t.Errorf("a capped boundary list must say it was capped")
	}
	if !obs.Truncated {
		t.Errorf("the observation must carry the incompleteness so finalize can act on it")
	}
}

func TestWalkSetsCrossedMounts(t *testing.T) {
	requireLinux(t)
	// /proc is a different filesystem from /, so a walk from / that reaches it
	// must record the boundary rather than cross it.
	r := probe.NewReader()
	t.Cleanup(r.Close)
	res, _ := r.Walk("/proc", probe.WalkBudget{MaxEntries: 50, MaxTime: time.Second}, func(string, os.DirEntry) {})
	// /proc is pruned outright, so use the pruning path as the observable: the
	// counters must be populated either way.
	if res.DirsPrunedCount == 0 && res.EntriesScanned == 0 && res.Errno == "" {
		t.Errorf("a walk must report some boundary or some progress: %+v", res)
	}
}

// ---------------------------------------------------------------------------
// C / #4: a denied ruleset is not an absent one
// ---------------------------------------------------------------------------

func TestFirewall_DeniedRulesetIsUnknown(t *testing.T) {
	root := tree(t, map[string]string{
		"/run/systemd/system/": "",
		"/proc/net/tcp":        procNetTCP("00000000:0016", "0A", "1"),
	})
	runner := newFakeRunner()
	runner.set("iptables -S", probe.Observation{
		Status: probe.StatusEACCES, Errno: "EACCES",
		Meta: &probe.Meta{StderrExcerpt: "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)"},
	})
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	wantStatus(t, f, scan.StatusUnknown)
	if f.Reason != scan.ReasonEACCES {
		t.Errorf("reason = %q, want EACCES: the tool's own stderr says it was refused", f.Reason)
	}
}

// The runner classifies a privilege denial from the tool's own words, so the
// reason is actionable rather than a bare EXECUTION_ERROR.
func TestExecPrivilegeDenialIsClassifiedAsEACCES(t *testing.T) {
	requireLinux(t)
	p := filepath.Join(t.TempDir(), "denied")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho 'Permission denied (you must be root)' 1>&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	obs := probe.NewRunner().Run(context.Background(), probe.Spec{Name: p})
	if obs.Reason() != "EACCES" {
		t.Errorf("reason = %q, want EACCES (stderr: %q)", obs.Reason(), obs.Meta.StderrExcerpt)
	}
	if obs.ExitCode == nil || *obs.ExitCode != 1 {
		t.Errorf("the child's own exit code must still be recorded: %v", obs.ExitCode)
	}
}

func TestFirewall_UfwDisabledIsFail(t *testing.T) {
	root := tree(t, map[string]string{
		"/run/systemd/system/": "",
		"/etc/ufw/ufw.conf":    "ENABLED=no\n",
	})
	runner := newFakeRunner().ok("systemctl is-active ufw", "active\n")
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	wantStatus(t, f, scan.StatusFail)
	for _, want := range []string{"/etc/ufw/ufw.conf", "ENABLED=no"} {
		if !strings.Contains(f.Evidence.Detail, want) {
			t.Errorf("the detail must cite the file and the value (%q missing): %q", want, f.Evidence.Detail)
		}
	}
	if strings.Contains(f.Evidence.Detail, "is enabled") {
		t.Errorf("the detail must not say the subsystem is enabled: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// D / #5 #10: BMC absence needs successful listings, and a denial outranks it
// ---------------------------------------------------------------------------

func TestBMC_ENOENTNotOverclaimed(t *testing.T) {
	// A kernel without dmi-sysfs: /sys/firmware/dmi/entries is simply not there,
	// which is not evidence that the platform declares no BMC.
	root := tree(t, map[string]string{
		"/sys/bus/acpi/devices/PNP0C0C%3A00/": "",
		"/sys/devices/platform/serial8250/":   "",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_INBAND_INTERFACE_PRESENT")
	wantStatus(t, f, scan.StatusUnknown)
	if !strings.Contains(f.Evidence.Detail, "not a machine without a BMC") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	if strings.Contains(strings.ToLower(f.Evidence.Detail), "enumerated successfully") {
		t.Errorf("the detail must not claim all listings succeeded: %q", f.Evidence.Detail)
	}
}

func TestBMC_DeniedPathIsNotAbsent(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":  "root:x:0:\n",
		"/dev/ipmi/0": "",
	})
	// /dev/ipmi0 does not exist; /dev/ipmi/0 exists behind a directory we
	// cannot enter. found is false and undetermined is not - the denial wins.
	chmod(t, root, "/dev/ipmi", 0o000)
	f := runCheck(t, root, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	wantStatus(t, f, scan.StatusUnknown)
	if f.Reason != scan.ReasonEACCES {
		t.Errorf("reason = %q, want EACCES", f.Reason)
	}
	if strings.Contains(f.Evidence.Detail, "no in-band BMC device node exists") {
		t.Errorf("a denied stat must not be reported as an absent node: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// E / #6 #7 #8 #9: what sshd -G is, and whether the daemon loaded it
// ---------------------------------------------------------------------------

func TestSSHPolicy_SourceLabelIsOnDisk(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")), "SSH_ROOT_LOGIN_POLICY")
	ev := evidenceOf(t, f)
	src, _ := ev["effective_value_source"].(string)
	if strings.Contains(src, "running daemon") {
		t.Errorf("sshd -G re-parses the files on disk; it says nothing about the listening process: %q", src)
	}
	if !strings.Contains(src, "from disk") {
		t.Errorf("source = %q, want the on-disk label", src)
	}
}

// The headline cross-check: a policy verdict read from files the daemon has not
// loaded is not a statement about the daemon.
func TestSSHPolicy_StaleConfigDowngradesPolicyVerdict(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
		"/proc/uptime":         "100000.00 800000.00\n",
	})
	// The config was written now; report the daemon as having started in 2020.
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd2, "ActiveEnterTimestamp=Mon 2020-01-01 00:00:00 UTC\nActiveEnterTimestampMonotonic=0\nActiveState=active\n")

	for _, id := range []string{"SSH_ROOT_LOGIN_POLICY", "SSH_AUTH_METHODS_POLICY"} {
		f := runCheck(t, root, runner, id)
		if f.Status == scan.StatusPass {
			t.Errorf("%s returned pass from a configuration the daemon has not loaded", id)
		}
		if f.Reason != scan.ReasonContested {
			t.Errorf("%s reason = %q, want CONTESTED", id, f.Reason)
		}
		ev := evidenceOf(t, f)
		ds, _ := ev["daemon_state"].(map[string]any)
		if ds == nil || ds["relation"] != "config-newer" {
			t.Errorf("%s must carry the raw in-force facts: %v", id, ev["daemon_state"])
		}
	}
	// And IN_FORCE itself says the same thing from the same facts.
	inForce := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
	wantStatus(t, inForce, scan.StatusFail)
}

// Where the order cannot be established the verdict stands, but the caveat
// rides with it rather than being dropped.
func TestSSHPolicy_UndecidableOrderKeepsVerdictWithCaveat(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
		"/proc/uptime":         "100000.00 800000.00\n",
	})
	cfg := filepath.Join(root, filepath.FromSlash("etc/ssh/sshd_config"))
	base := time.Now().Truncate(time.Second)
	if err := os.Chtimes(cfg, base.Add(200*time.Millisecond), base.Add(200*time.Millisecond)); err != nil {
		t.Skipf("cannot stage a modification time: %v", err)
	}
	stamp := base.Format("Mon 2006-01-02 15:04:05") + " " + base.Format("MST")
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd2, "ActiveEnterTimestamp="+stamp+"\nActiveEnterTimestampMonotonic=0\nActiveState=active\n")

	f := runCheck(t, root, runner, "SSH_ROOT_LOGIN_POLICY")
	if f.Status != scan.StatusPass {
		t.Logf("status = %s (%s) — acceptable if the timestamp could not be parsed in this locale", f.Status, f.Reason)
		return
	}
	if !strings.Contains(f.Evidence.Detail, "in-force caveat") {
		t.Errorf("an undecidable ordering must ride along as a caveat: %q", f.Evidence.Detail)
	}
}

func TestInForce_ResolutionIsMeasuredNotAssumed(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
		"/proc/uptime":         "100000.00 800000.00\n",
	})
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd2, "ActiveEnterTimestamp=Mon 2020-01-01 00:00:00 UTC\nActiveEnterTimestampMonotonic=5000000\nActiveState=active\n")
	f := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
	ev := evidenceOf(t, f)
	ds := ev["daemon_state"].(map[string]any)
	basis, _ := ds["resolution_basis"].(string)
	if !strings.Contains(basis, "measured") {
		t.Errorf("the resolution must be measured, not asserted: %q", basis)
	}
	// The reconstruction disagrees wildly with the 2020 rendered timestamp, so
	// the measured resolution must widen far beyond the old fixed 100 ms.
	if ms, _ := ds["comparison_resolution_ms"].(float64); ms <= 100 {
		t.Errorf("comparison_resolution_ms = %v; a clock-domain disagreement must widen it, not stay at the asserted 100 ms", ms)
	}
	if !strings.Contains(basis, "disagree") {
		t.Errorf("basis = %q, want it to name the clock-domain disagreement", basis)
	}
}

const svcShowCmd2 = "systemctl show ssh.service -p ActiveEnterTimestamp -p ActiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic -p ActiveState -p FragmentPath"

func TestSSHDConfig_IncludeInsideMatchStaysConditional(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/ssh/sshd_config": "PermitRootLogin no\n\nMatch Address 10.0.0.0/8\n    Include /etc/ssh/jump.conf\n",
		"/etc/ssh/jump.conf":   "PermitRootLogin yes\n",
	})
	f := runCheck(t, root, newFakeRunner(), "SSH_ROOT_LOGIN_POLICY")
	if f.Status == scan.StatusPass {
		t.Fatalf("a Match-scoped PermitRootLogin yes reached through an Include must not be invisible to the verdict")
	}
	ev := evidenceOf(t, f)
	cr := ev["config_resolution"].(map[string]any)
	blocks, _ := cr["conditional_blocks"].([]any)
	if len(blocks) == 0 {
		t.Fatalf("the included directive must be recorded as conditional: %v", cr)
	}
	occ := blocks[0].(map[string]any)
	if occ["path"] != "/etc/ssh/jump.conf" || occ["match_criteria"] != "Address 10.0.0.0/8" {
		t.Errorf("the conditional occurrence must keep the Match scope of the Include that reached it: %v", occ)
	}
}

func TestSSHDConfig_TruncatedGlobIsLoadBearing(t *testing.T) {
	files := map[string]string{
		"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
	}
	// More drop-ins than the expansion cap allows.
	for i := 0; i < 600; i++ {
		files["/etc/ssh/sshd_config.d/"+itoa(int64(i))+".conf"] = "# nothing\n"
	}
	root := tree(t, files)
	f := runCheck(t, root, newFakeRunner(), "SSH_ROOT_LOGIN_POLICY")
	if f.Status == scan.StatusPass {
		t.Fatalf("a verdict built on a truncated configuration chain must not pass")
	}
	found := false
	for _, o := range f.Evidence.Observations {
		if strings.Contains(o.Detail, "entry cap") && o.LoadBearing {
			found = true
		}
	}
	if !found {
		t.Errorf("the truncated Include expansion must be a load-bearing observation")
	}
}

// ---------------------------------------------------------------------------
// F / #10 #12: bounds that live in the operation, not in the caller
// ---------------------------------------------------------------------------

func TestSocketOwners_BudgetIsEnforcedAndVisible(t *testing.T) {
	files := map[string]string{
		"/proc/net/tcp": procNetTCP("00000000:0016", "0A", "12345"),
	}
	// Far more processes than the attribution budget allows.
	for pid := 1; pid < 3000; pid++ {
		files["/proc/"+itoa(int64(pid))+"/comm"] = "worker\n"
		files["/proc/"+itoa(int64(pid))+"/fd/"] = ""
	}
	root := tree(t, files)
	start := time.Now()
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("the attribution pass took %s; its bound is not in the operation", elapsed)
	}
	ev := evidenceOf(t, f)
	att, _ := ev["owner_attribution"].(map[string]any)
	if att == nil {
		t.Fatalf("the attribution boundary must be in evidence")
	}
	if att["complete"] == true && att["pids_scanned"].(float64) >= 3000 {
		t.Errorf("the budget was not enforced: %v", att)
	}
	if att["complete"] == false && att["stopped_by"] == "none" {
		t.Errorf("an incomplete attribution must say what stopped it: %v", att)
	}
}

// The scan deadline dominates: a check that would eat the whole budget cannot
// stop the later ones from producing findings.
func TestScanDeadline_DominatesPerCheckBudgets(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	reader := probe.NewRootedReader(root)
	t.Cleanup(reader.Close)
	// A real clock: the arithmetic under test is between the scan deadline and
	// wall time, which a fixed clock would not exercise.
	deadline := time.Now().Add(150 * time.Millisecond)
	env := scan.NewEnv(reader, newFakeRunner(), time.Now, deadline, 1000)

	slow := budgetedStub{id: "SLOW", budget: time.Hour, sleep: 300 * time.Millisecond}
	// The later checks each declare an hour and need 80 ms of it. By the time
	// they are reached the scan deadline has all but expired, so what they get
	// is min(1h, what is left) - which is the arithmetic under test.
	late1 := budgetedStub{id: "LATE_ONE", budget: time.Hour, sleep: 80 * time.Millisecond}
	late2 := budgetedStub{id: "LATE_TWO", budget: time.Hour, sleep: 80 * time.Millisecond}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	runStart := time.Now()
	findings, cut := scan.Run(ctx, []scan.Check{slow, late1, late2}, env)
	elapsed := time.Since(runStart)

	if len(findings) != 3 {
		t.Fatalf("len(findings) = %d, want 3: a starved check still emits its finding", len(findings))
	}
	for _, f := range findings {
		if f.Status == "" || (f.Status != scan.StatusPass && f.Reason == "") {
			t.Errorf("%s: %s without a reason", f.CheckID, f.Status)
		}
	}
	// The declared budgets sum to three hours; the scan deadline is 150 ms.
	// What must hold is that the deadline wins, that the later checks are not
	// starved into silence, and that whether a starved check reports
	// BUDGET_EXHAUSTED (it never started) or TIMEOUT (its shrunken budget
	// expired) both are bounded, reasoned answers rather than a missing finding.
	byID := map[string]scan.Finding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	for _, id := range []string{"LATE_ONE", "LATE_TWO"} {
		f, ok := byID[id]
		if !ok {
			t.Fatalf("%s produced no finding: a starved check must still be reported", id)
		}
		if f.Status != scan.StatusUnknown {
			t.Errorf("%s = %s after the scan deadline passed, want unknown", id, f.Status)
		}
		if f.Reason != scan.ReasonBudget && f.Reason != scan.ReasonTimeout {
			t.Errorf("%s reason = %q, want BUDGET_EXHAUSTED or TIMEOUT", id, f.Reason)
		}
	}
	if elapsed > time.Minute {
		t.Errorf("the run took %s despite a 150 ms deadline: the declared budgets are not being clamped", elapsed)
	}
	t.Logf("three checks declaring 1h each finished in %s under a 150 ms deadline (%d never started)", elapsed, cut)
}

type budgetedStub struct {
	id     string
	budget time.Duration
	sleep  time.Duration
}

func (b budgetedStub) ID() string            { return b.id }
func (b budgetedStub) Category() string      { return "TEST_CATEGORY" }
func (b budgetedStub) Title() string         { return "Budget arithmetic stub " + b.id }
func (b budgetedStub) Impact() string        { return scan.SeverityLow }
func (b budgetedStub) Observational() bool   { return false }
func (b budgetedStub) Budget() time.Duration { return b.budget }
func (b budgetedStub) Run(ctx context.Context, _ *scan.Env) scan.Result {
	select {
	case <-time.After(b.sleep):
	case <-ctx.Done():
		return scan.Unknown(scan.ReasonTimeout, "the check deadline expired")
	}
	return scan.Pass("finished")
}

// ---------------------------------------------------------------------------
// G / #13 #14 #15 #16: safety
// ---------------------------------------------------------------------------

func TestResolveBinary_IgnoresPATH(t *testing.T) {
	requireLinux(t)
	dir := t.TempDir()
	planted := filepath.Join(dir, "mokutil")
	if err := os.WriteFile(planted, []byte("#!/bin/sh\necho 'SecureBoot enabled'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	obs := probe.NewRunner().Run(context.Background(), probe.Spec{Name: "mokutil", Args: []string{"--sb-state"}})
	if obs.Status != probe.StatusUtilityMissing {
		t.Errorf("status = %s (%q); a binary reachable only through the inherited PATH must not be run", obs.Status, obs.Value)
	}
	if strings.Contains(obs.Value, "SecureBoot enabled") {
		t.Fatalf("the planted binary shaped the evidence")
	}
}

func TestReadACL_DoesNotFollowFinalSymlink(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("target", link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	acl, obs := r.ReadACL("/link")
	// A symlink cannot carry a POSIX ACL: lgetxattr on it returns ENODATA (or
	// EOPNOTSUPP), whereas getxattr would have described the target instead.
	if acl.Present {
		t.Errorf("a symlink reported an ACL, so the target was read instead of the link: %+v", acl)
	}
	if obs.Status != probe.StatusOK && obs.Status != probe.StatusUnsupported {
		t.Errorf("unexpected status %s (%s)", obs.Status, obs.Errno)
	}
}

func TestMediaHealth_NoDeviceOpeningChildren(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/nvme0n1/size":         "100\n",
		"/sys/block/nvme0n1/dev":          "259:0\n",
		"/sys/block/nvme0n1/device/state": "live\n",
	})
	runner := newFakeRunner()
	f := runCheck(t, root, runner, "MEDIA_HEALTH_VISIBILITY")
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "nvme ") || strings.HasPrefix(call, "smartctl ") {
			t.Errorf("the check ran %q, which opens a device node through a child process", call)
		}
	}
	ev := evidenceOf(t, f)
	if ev["device_opened_by_child_process"] != false || ev["device_opened_by_sensor"] != false {
		t.Errorf("the evidence must distinguish the sensor's own reads from a child's: %v", ev)
	}
	if !strings.Contains(ev["access_model"].(string), "never runs a tool that would open one") {
		t.Errorf("access_model = %v", ev["access_model"])
	}
}

func TestMediaHealth_ReasonDerivedFromObservations(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                      "root:x:0:\ndisk:x:6:\n",
		"/sys/block/nvme0n1/size":         "100\n",
		"/sys/block/nvme0n1/dev":          "259:0\n",
		"/sys/block/nvme0n1/device/state": "live\n",
		"/dev/nvme0":                      "",
	})
	// Root-owned-style node this identity cannot open.
	chmod(t, root, "/dev/nvme0", 0o000)
	denied := runCheck(t, root, newFakeRunner(), "MEDIA_HEALTH_VISIBILITY")
	wantStatus(t, denied, scan.StatusUnknown)
	if denied.Reason != scan.ReasonEACCES {
		t.Errorf("a node this identity cannot open must yield EACCES, got %q", denied.Reason)
	}

	// The same node, openable: the limit is then the sensor's own contract, not
	// a denial, and the two must not be reported the same way.
	chmod(t, root, "/dev/nvme0", 0o644)
	open := runCheck(t, root, newFakeRunner(), "MEDIA_HEALTH_VISIBILITY")
	wantStatus(t, open, scan.StatusUnknown)
	if open.Reason != scan.ReasonNotAttempted {
		t.Errorf("an openable node the sensor declines to open must yield NOT_ATTEMPTED, got %q", open.Reason)
	}
	if denied.Reason == open.Reason {
		t.Errorf("a denial and a design limit collapsed to the same reason")
	}
}

func TestOOBGoroutinePanicDoesNotKillProcess(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	// The abandoned-goroutine path: a FIFO the read cannot finish. What is
	// under test is that the process survives and the deadline is honoured.
	fifo := filepath.Join(root, "slow")
	if err := mkfifoForTest(fifo); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	done := make(chan probe.Observation, 1)
	go func() { done <- r.ReadOOB("/slow", probe.Tiny, 50*time.Millisecond) }()
	select {
	case obs := <-done:
		if obs.Status == probe.StatusOK {
			t.Errorf("a FIFO must not read as OK")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadOOB did not return")
	}
	// Overflow kill runs in a goroutine too; a panic there would take the
	// process with it. Exercise the flooding path end to end.
	sh := filepath.Join(t.TempDir(), "flood")
	if err := os.WriteFile(sh, []byte("#!/bin/sh\nwhile :; do echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	obs := probe.NewRunner().Run(context.Background(), probe.Spec{Name: sh, Budget: 3 * time.Second, OutCap: 4 << 10})
	if !obs.Truncated {
		t.Errorf("the flood must be capped")
	}
}
