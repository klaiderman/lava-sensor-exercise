package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lava.sh/sensor/internal/probe"
	"lava.sh/sensor/internal/scan"
)

// tree materialises an ad-hoc fixture tree. A path ending in "/" is a directory.
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

// sshdGOutput is a realistic `sshd -G` block: the daemon prints every effective
// directive in lowercase, and prints without-password for prohibit-password.
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

// runSlice runs the whole engine over the roster and returns the
// SSH_ROOT_LOGIN_POLICY finding, so every assertion below covers finalize(),
// the severity rule and the evidence builder as well as the check itself.
func runSlice(t *testing.T, root string, runner probe.Runner) scan.Finding {
	t.Helper()
	env := newTestEnv(t, root, runner)
	findings, _ := scan.Run(context.Background(), All(), env)
	for _, f := range findings {
		if f.CheckID == "SSH_ROOT_LOGIN_POLICY" {
			return f
		}
	}
	t.Fatal("SSH_ROOT_LOGIN_POLICY produced no finding; every registered check must emit exactly one")
	return scan.Finding{}
}

func evidenceMap(t *testing.T, f scan.Finding) map[string]any {
	t.Helper()
	b, err := json.Marshal(f.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// The oracle is primary: what the running daemon reports wins over anything the
// files say, and it must produce a real verdict.
func TestSSHRootLogin_OracleSaysNo_Passes(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no"))
	f := runSlice(t, root, runner)

	if f.Status != scan.StatusPass {
		t.Fatalf("status = %s (%s), want pass", f.Status, f.Reason)
	}
	// LD-2: a pass is always reported at severity info, whatever the impact.
	if f.Severity != scan.SeverityInfo {
		t.Errorf("severity = %s, want info on a pass", f.Severity)
	}
	if f.Reason != "" {
		t.Errorf("a pass must not carry a reason, got %q", f.Reason)
	}
	ev := evidenceMap(t, f)
	if ev["effective_value"] != "no" {
		t.Errorf("evidence effective_value = %v", ev["effective_value"])
	}
	if !strings.Contains(ev["effective_value_source"].(string), "sshd -G") {
		t.Errorf("the oracle must be named as the source, got %v", ev["effective_value_source"])
	}
}

func TestSSHRootLogin_OracleSaysYes_Fails(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin yes\n",
	})
	f := runSlice(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("yes")))
	if f.Status != scan.StatusFail {
		t.Fatalf("status = %s, want fail", f.Status)
	}
	if f.Severity != scan.SeverityHigh {
		t.Errorf("severity = %s, want the declared impact high on a fail", f.Severity)
	}
	if f.Reason == "" {
		t.Errorf("a fail must carry a reason")
	}
}

// The live branch on the Lava host: the daemon permits key-based root login and
// /root/.ssh cannot be read, so root key material can neither be confirmed nor
// excluded. EACCES is not absence, and a pass here would be a lie.
func TestSSHRootLogin_ProhibitPasswordWithDeniedRootSSH_IsUnknown(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin prohibit-password\n",
		"/root/.ssh/":          "",
	})
	if err := os.WriteFile(filepath.Join(root, "root/.ssh/authorized_keys"), []byte("ssh-ed25519 AAAA...\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "root/.ssh"), 0o000); err != nil {
		t.Fatal(err)
	}

	// The daemon prints without-password where the file says prohibit-password;
	// folding the two spellings must not produce a false CONTESTED.
	f := runSlice(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password")))

	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s (%s), want unknown", f.Status, f.Reason)
	}
	if f.Reason != scan.ReasonEACCES {
		t.Errorf("reason = %q, want EACCES; denied is not absent", f.Reason)
	}
	// LD-2: an unverifiable control is an assurance gap of the same weight.
	if f.Severity != scan.SeverityHigh {
		t.Errorf("severity = %s, want high on an unknown with impact high", f.Severity)
	}
	ev := evidenceMap(t, f)
	rk, _ := ev["root_authorized_keys"].(map[string]any)
	if rk == nil || rk["status"] == "OK" {
		t.Errorf("evidence must record the denied stat of %s, got %v", rootAuthKeysPath, ev["root_authorized_keys"])
	}
	if !strings.Contains(f.Evidence.Detail, "prohibit-password") {
		t.Errorf("the detail must name the effective policy, got %q", f.Evidence.Detail)
	}
}

// Readable root key material under prohibit-password is a definite fail.
func TestSSHRootLogin_ProhibitPasswordWithReadableRootKey_Fails(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":             "#!/bin/sh\n",
		"/etc/ssh/sshd_config":       "PermitRootLogin prohibit-password\n",
		"/root/.ssh/authorized_keys": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 root@build\n",
	})
	f := runSlice(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password")))
	if f.Status != scan.StatusFail {
		t.Fatalf("status = %s (%s), want fail", f.Status, f.Reason)
	}
	// The key file's metadata is the evidence; its contents never are.
	body, _ := json.Marshal(f)
	if strings.Contains(string(body), "AAAAC3NzaC1lZDI1NTE5") {
		t.Errorf("key material leaked into the finding")
	}
}

// CONTESTED: the daemon and the file disagree. Both are recorded and neither
// wins; first-observation-wins is forbidden.
func TestSSHRootLogin_OracleAndWalkerDisagree_IsContested(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := runSlice(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("yes")))

	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s, want unknown", f.Status)
	}
	if f.Reason != scan.ReasonContested {
		t.Fatalf("reason = %q, want CONTESTED", f.Reason)
	}
	ev := evidenceMap(t, f)
	if ev["oracle_value"] != "yes" || ev["walker_value"] != "no" {
		t.Errorf("both observations must be recorded, got oracle=%v walker=%v", ev["oracle_value"], ev["walker_value"])
	}
}

// Under-claim guard: sshd is absent, but the config chain resolves the
// directive. A blanket UNKNOWN here would be a bug (L36).
func TestSSHRootLogin_NoSSHDBinary_FallsBackToWalker(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := runSlice(t, root, newFakeRunner())
	if f.Status != scan.StatusPass {
		t.Fatalf("status = %s (%s), want pass from the walker when sshd is not installed", f.Status, f.Reason)
	}
	ev := evidenceMap(t, f)
	if !strings.Contains(ev["effective_value_source"].(string), "configuration chain") {
		t.Errorf("source = %v, want the walker", ev["effective_value_source"])
	}
	cr := ev["config_resolution"].(map[string]any)
	ws := cr["winning_source"].(map[string]any)
	if ws["path"] != "/etc/ssh/sshd_config" || ws["line"].(float64) != 1 {
		t.Errorf("winning_source = %v, want /etc/ssh/sshd_config:1", ws)
	}
}

// Include position decides the answer: OpenSSH takes the FIRST obtained value.
// The same two files give opposite verdicts depending on where Include sits.
func TestSSHRootLogin_IncludePositionDecides(t *testing.T) {
	dropin := "PermitRootLogin yes\n"

	top := tree(t, map[string]string{
		"/etc/ssh/sshd_config":             "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n",
		"/etc/ssh/sshd_config.d/50-x.conf": dropin,
	})
	f := runSlice(t, top, newFakeRunner())
	if f.Status != scan.StatusFail {
		t.Errorf("Include at the top: status = %s, want fail (the drop-in wins)", f.Status)
	}
	ev := evidenceMap(t, f)
	cr := ev["config_resolution"].(map[string]any)
	if ws := cr["winning_source"].(map[string]any); ws["path"] != "/etc/ssh/sshd_config.d/50-x.conf" {
		t.Errorf("winning_source = %v, want the drop-in", ws)
	}
	if sh := cr["shadowed_occurrences"].([]any); len(sh) != 1 {
		t.Errorf("the main file's shadowed occurrence must be listed, got %v", sh)
	}

	bottom := tree(t, map[string]string{
		"/etc/ssh/sshd_config":             "PermitRootLogin no\nInclude /etc/ssh/sshd_config.d/*.conf\n",
		"/etc/ssh/sshd_config.d/50-x.conf": dropin,
	})
	f2 := runSlice(t, bottom, newFakeRunner())
	if f2.Status != scan.StatusPass {
		t.Errorf("Include at the bottom: status = %s (%s), want pass — same files, opposite answer", f2.Status, f2.Reason)
	}
}

// A Match block scoping the keyword makes a host-wide verdict evidence-only.
func TestSSHRootLogin_MatchBlockIsNotABarePass(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/ssh/sshd_config": "PermitRootLogin no\n\nMatch User root Address 10.0.0.0/8\n    PermitRootLogin yes\n",
	})
	f := runSlice(t, root, newFakeRunner())
	if f.Status == scan.StatusPass {
		t.Fatalf("a Match block that re-permits root login must not yield a bare pass")
	}
	if f.Reason != scan.ReasonContested {
		t.Errorf("reason = %q, want CONTESTED", f.Reason)
	}
	ev := evidenceMap(t, f)
	if ev["match_override"] == nil {
		t.Errorf("the Match override must appear in evidence")
	}
	if blocks, _ := ev["conditional_blocks"].([]any); len(blocks) == 0 {
		t.Errorf("conditional_blocks must list the Match block")
	}
}

// A timed-out oracle with no readable config is unknown/TIMEOUT — never a fail,
// never "unsupported" (L10).
func TestSSHRootLogin_OracleTimeout_IsUnknownTimeout(t *testing.T) {
	root := tree(t, map[string]string{"/usr/sbin/sshd": "#!/bin/sh\n"})
	runner := newFakeRunner().set("/usr/sbin/sshd -G", probe.Observation{
		Status: probe.StatusTimeout, Signal: "SIGKILL",
		Meta: &probe.Meta{TimedOut: true, Command: []string{"/usr/sbin/sshd", "-G"}},
	})
	f := runSlice(t, root, runner)
	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s, want unknown", f.Status)
	}
	if f.Reason != scan.ReasonTimeout {
		t.Errorf("reason = %q, want TIMEOUT", f.Reason)
	}
}

// No daemon, no config, no identifiable distribution: an assumed compiled-in
// default would be a guess, so the answer is unknown (L19).
func TestSSHRootLogin_UnknownDistroNoConfig_IsUnknown(t *testing.T) {
	f := runSlice(t, tree(t, map[string]string{"/etc/hostname": "x\n"}), newFakeRunner())
	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s, want unknown", f.Status)
	}
	if f.Reason == "" {
		t.Errorf("an unknown must carry a reason")
	}
}

// A known distribution with a readable os-release but no directive anywhere
// resolves against the cited compiled-in default rather than staying unknown.
func TestSSHRootLogin_KnownDistroDefaultIsCited(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/os-release":      "ID=ubuntu\nID_LIKE=debian\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n",
		"/etc/ssh/sshd_config": "# nothing relevant here\nX11Forwarding no\n",
	})
	f := runSlice(t, root, newFakeRunner())
	ev := evidenceMap(t, f)
	cr, _ := ev["config_resolution"].(map[string]any)
	if cr == nil || cr["defaulted"] != true {
		t.Fatalf("expected a defaulted resolution, got %v", cr)
	}
	if cr["default_source"] == nil || cr["default_source"] == "" {
		t.Errorf("a defaulted value without a citation is a bug (L19)")
	}
}

// Every registered check emits exactly one finding, and its id is unique.
func TestRosterEmitsExactlyOneFindingPerCheck(t *testing.T) {
	env := newTestEnv(t, tree(t, map[string]string{"/etc/hostname": "x\n"}), newFakeRunner())
	roster := All()
	if err := scan.ValidateRoster(roster); err != nil {
		t.Fatalf("roster is invalid: %v", err)
	}
	findings, _ := scan.Run(context.Background(), roster, env)
	if len(findings) != len(roster) {
		t.Fatalf("len(findings) = %d, len(registry) = %d", len(findings), len(roster))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		if seen[f.CheckID] {
			t.Errorf("duplicate finding for %s", f.CheckID)
		}
		seen[f.CheckID] = true
	}
}

// No daemon and no configuration: a compiled-in default would invent a policy
// for software that is not installed. The answer is unknown, and it says that
// "no SSH listener" is not "no remote access".
func TestSSHRootLogin_NoDaemonAtAll_IsUtilityMissing(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/os-release": "ID=ubuntu\nID_LIKE=debian\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n",
	})
	f := runSlice(t, root, newFakeRunner())
	if f.Status != scan.StatusUnknown {
		t.Fatalf("status = %s, want unknown", f.Status)
	}
	if f.Reason != scan.ReasonUtilMiss {
		t.Errorf("reason = %q, want UTILITY_MISSING", f.Reason)
	}
	if !strings.Contains(f.Evidence.Detail, "not the absence of remote access") {
		t.Errorf("the blind spot must be named: %q", f.Evidence.Detail)
	}
}

// `sshd -T` loads the host keys first and exits 1 unprivileged, which looks
// like a config error. It is never invoked anywhere.
func TestSSHDMinusTIsNeverInvoked(t *testing.T) {
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if strings.Contains(string(b), `"-T"`) {
			t.Errorf("%s passes -T to a command; sshd -T is never used (F26, L18)", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
