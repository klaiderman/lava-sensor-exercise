package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// runCheck runs the whole engine over the roster and returns one finding, so
// every assertion also covers finalize(), the severity rule and the shared
// evidence builder.
func runCheck(t *testing.T, root string, runner probe.Runner, id string) scan.Finding {
	t.Helper()
	env := newTestEnv(t, root, runner)
	findings, _ := scan.Run(context.Background(), All(), env)
	for _, f := range findings {
		if f.CheckID == id {
			return f
		}
	}
	t.Fatalf("%s produced no finding", id)
	return scan.Finding{}
}

func wantStatus(t *testing.T, f scan.Finding, want scan.Status) {
	t.Helper()
	if f.Status != want {
		t.Fatalf("%s: status = %s (reason %q, detail %q), want %s", f.CheckID, f.Status, f.Reason, f.Evidence.Detail, want)
	}
}

func evidenceOf(t *testing.T, f scan.Finding) map[string]any {
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

func chmod(t *testing.T, root, rel string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash(rel)), mode); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// Titles
// ---------------------------------------------------------------------------

// A title names what was checked. It must read correctly above pass, fail and
// unknown alike, so it may not assert a state.
func TestTitlesAreStatusNeutral(t *testing.T) {
	// A title that starts by naming the question ("Whether ...") is
	// interrogative by construction. Everything else must avoid a phrase that
	// presumes the outcome.
	assertive := []string{
		" is not ", " are not ", " never ", " no ", " only ", " enabled",
		" follows ", " keeps ", " survives ", " is the ", " are the ",
	}
	for _, c := range All() {
		lower := strings.ToLower(c.Title())
		if strings.Contains(lower, "whether") {
			continue
		}
		for _, a := range assertive {
			if strings.Contains(lower, a) {
				t.Errorf("%s: title %q asserts a state; a title names what was checked and the status says the outcome",
					c.ID(), c.Title())
				break
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SSH_AUTH_METHODS_POLICY
// ---------------------------------------------------------------------------

func TestSSHAuthMethods_KeyOnlyPasses(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PasswordAuthentication no\n",
	})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")), "SSH_AUTH_METHODS_POLICY")
	wantStatus(t, f, scan.StatusPass)
	if f.Severity != scan.SeverityInfo {
		t.Errorf("severity = %s, want info on a pass", f.Severity)
	}
}

// The classic false pass: passwordauthentication no while kbdinteractive yes
// still reaches PAM passwords.
func TestSSHAuthMethods_KbdInteractiveReachesPAM(t *testing.T) {
	out := strings.Replace(sshdGOutput("no"), "kbdinteractiveauthentication no", "kbdinteractiveauthentication yes", 1)
	root := tree(t, map[string]string{"/usr/sbin/sshd": "#!/bin/sh\n"})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", out), "SSH_AUTH_METHODS_POLICY")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "kbdinteractive") {
		t.Errorf("the detail must name why passwordauthentication no is not enough: %q", f.Evidence.Detail)
	}
}

func TestSSHAuthMethods_EmptyPasswordsFail(t *testing.T) {
	out := strings.Replace(sshdGOutput("no"), "permitemptypasswords no", "permitemptypasswords yes", 1)
	root := tree(t, map[string]string{"/usr/sbin/sshd": "#!/bin/sh\n"})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", out), "SSH_AUTH_METHODS_POLICY")
	wantStatus(t, f, scan.StatusFail)
}

// Context directives are reported but explicitly marked non-contributing.
func TestSSHAuthMethods_ContextDirectivesAreMarked(t *testing.T) {
	root := tree(t, map[string]string{"/usr/sbin/sshd": "#!/bin/sh\n"})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")), "SSH_AUTH_METHODS_POLICY")
	ev := evidenceOf(t, f)
	rows, _ := ev["directives"].([]any)
	seenContext := false
	for _, row := range rows {
		m := row.(map[string]any)
		if m["directive"] == "maxauthtries" {
			seenContext = true
			if m["verdict_contributing"] != false {
				t.Errorf("maxauthtries must be marked verdict_contributing:false")
			}
		}
	}
	if !seenContext {
		t.Errorf("operator-context directives must be reported: %v", ev["directives"])
	}
}

// ---------------------------------------------------------------------------
// SSH_POLICY_IN_FORCE
// ---------------------------------------------------------------------------

func TestSSHPolicyInForce_NoSystemdIsUnknownNotFail(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")), "SSH_POLICY_IN_FORCE")
	wantStatus(t, f, scan.StatusUnknown)
	if !strings.Contains(f.Evidence.Detail, "systemd is not booted") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

func TestSSHPolicyInForce_ConfigNewerThanServiceStartFails(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
	})
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd,
			"ActiveEnterTimestamp=Mon 2020-01-01 00:00:00 UTC\nActiveState=active\nFragmentPath=/lib/systemd/system/ssh.service\n")
	f := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "after the daemon started") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

// An equal or later start time is a pass: the restart IS the propagation.
func TestSSHPolicyInForce_ServiceStartedAfterConfigPasses(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
	})
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd,
			"ActiveEnterTimestamp=Mon 2099-01-01 00:00:00 UTC\nActiveState=active\n")
	f := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
	wantStatus(t, f, scan.StatusPass)
}

// ---------------------------------------------------------------------------
// REMOTE_LISTENING_SURFACE
// ---------------------------------------------------------------------------

// procNetTCP renders a socket table line the way the kernel does.
func procNetTCP(localHex, stateHex, inode string) string {
	return "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: " + localHex + " 00000000:0000 " + stateHex + " 00000000:00000000 00:00000000 00000000     0        0 " + inode + " 1 0000 100 0\n"
}

func TestRemoteListeningSurface_SSHOnlyPasses(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/net/tcp":  procNetTCP("00000000:0016", "0A", "12345"),
		"/proc/net/tcp6": "  sl  local_address\n",
	})
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	blind, _ := ev["blind_spots"].([]any)
	if len(blind) == 0 {
		t.Errorf("the outbound-tunnel blind spot is mandatory in the evidence")
	}
	ls := ev["listeners"].([]any)
	l := ls[0].(map[string]any)
	if l["port"].(float64) != 22 || l["scope"] != "global" || l["class"] != "ssh" {
		t.Errorf("listener = %v", l)
	}
}

func TestRemoteListeningSurface_TelnetFails(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/net/tcp": procNetTCP("00000000:0017", "0A", "999"),
	})
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "telnet") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

// A loopback-only listener is not exposure.
func TestRemoteListeningSurface_LoopbackIsNotExposure(t *testing.T) {
	root := tree(t, map[string]string{
		// 127.0.0.53:53 in the kernel's little-endian hex rendering.
		"/proc/net/tcp": procNetTCP("3500007F:0035", "0A", "77"),
	})
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	l := ev["listeners"].([]any)[0].(map[string]any)
	if l["scope"] != "loopback" {
		t.Errorf("127.0.0.53 must be scoped loopback, got %v (addr %v)", l["scope"], l["local_addr"])
	}
}

// ss is a cross-check, never a verdict: unprivileged it omits ownership by
// silent omission.
func TestRemoteListeningSurface_ProcNetUnreadableDoesNotTrustSS(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	runner := newFakeRunner().ok("ss -tulnH", "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
	f := runCheck(t, root, runner, "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusUnknown)
	if !strings.Contains(f.Evidence.Detail, "omits ownership") {
		t.Errorf("the ss silent-omission reason must be stated: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// LOGIN_AND_ESCALATION_SURFACE
// ---------------------------------------------------------------------------

const passwdFile = "root:x:0:0:root:/root:/bin/bash\n" +
	"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
	"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"

func TestLoginSurface_DockerGroupMemberIsRootEquivalent(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/passwd":                       passwdFile,
		"/etc/group":                        "root:x:0:\nsudo:x:27:ubuntu\ndocker:x:998:ubuntu\n",
		"/etc/nsswitch.conf":                "passwd: files\ngroup: files\n",
		"/etc/shadow":                       "root:!:19000:0:99999:7:::\nubuntu:!:19000:0:99999:7:::\n",
		"/etc/sudoers":                      "root ALL=(ALL:ALL) ALL\n",
		"/home/ubuntu/.ssh/authorized_keys": "ssh-ed25519 AAAA test\n",
		"/root/.ssh/authorized_keys":        "ssh-ed25519 AAAA root\n",
	})
	f := runCheck(t, root, newFakeRunner(), "LOGIN_AND_ESCALATION_SURFACE")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "docker") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	// No key body may reach the artifact.
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "ssh-ed25519") {
		t.Errorf("key material leaked into the finding")
	}
}

// An unreadable /etc/shadow means the password state of other accounts is
// unknown; it must never be reported as "no password set".
func TestLoginSurface_UnreadableShadowIsUnknownNotPassword(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":        passwdFile,
		"/etc/group":         "root:x:0:\nsudo:x:27:ubuntu\n",
		"/etc/nsswitch.conf": "passwd: files\ngroup: files\n",
		"/etc/shadow":        "root::19000:0:99999:7:::\n",
		"/etc/sudoers":       "root ALL=(ALL:ALL) ALL\n",
	})
	chmod(t, root, "/etc/shadow", 0o000)
	f := runCheck(t, root, newFakeRunner(), "LOGIN_AND_ESCALATION_SURFACE")
	wantStatus(t, f, scan.StatusUnknown)
	if strings.Contains(f.Evidence.Detail, "empty password field") {
		t.Errorf("an unreadable shadow file must not produce a password claim: %q", f.Evidence.Detail)
	}
	if !strings.Contains(f.Evidence.Detail, "not 'no password set'") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

// An empty privileged group makes group-mode objects root-only in practice —
// a stronger statement than absence.
func TestLoginSurface_EmptyPrivilegedGroupIsRootOnly(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/passwd":        passwdFile,
		"/etc/group":         "root:x:0:\ndisk:x:6:\nsudo:x:27:ubuntu\n",
		"/etc/nsswitch.conf": "passwd: files\ngroup: files\n",
	})
	f := runCheck(t, root, newFakeRunner(), "LOGIN_AND_ESCALATION_SURFACE")
	ev := evidenceOf(t, f)
	groups := ev["privileged_groups"].([]any)
	found := false
	for _, g := range groups {
		m := g.(map[string]any)
		if m["group"] == "disk" {
			found = true
			if m["effectively_root_only"] != true {
				t.Errorf("an empty disk group is root-only in practice: %v", m)
			}
		}
	}
	if !found {
		t.Errorf("privileged groups must be enumerated even when empty")
	}
}

func TestLoginSurface_NologinAccountsAreNotLoginCapable(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/passwd":        passwdFile,
		"/etc/group":         "root:x:0:\n",
		"/etc/nsswitch.conf": "passwd: files\ngroup: files\n",
	})
	f := runCheck(t, root, newFakeRunner(), "LOGIN_AND_ESCALATION_SURFACE")
	ev := evidenceOf(t, f)
	for _, a := range ev["accounts"].([]any) {
		m := a.(map[string]any)
		if m["name"] == "daemon" && m["shell_class"] != "nologin" {
			t.Errorf("a /usr/sbin/nologin account must not be classed login-capable: %v", m)
		}
	}
}

// ---------------------------------------------------------------------------
// HOST_FIREWALL_STATE
// ---------------------------------------------------------------------------

func TestFirewall_ActiveButUnreadableRulesIsUnknown(t *testing.T) {
	root := tree(t, map[string]string{
		"/run/systemd/system/": "",
		"/etc/ufw/ufw.conf":    "ENABLED=yes\n",
		"/etc/default/ufw":     "DEFAULT_INPUT_POLICY=\"DROP\"\n",
	})
	runner := newFakeRunner().ok("systemctl is-active ufw", "active\n")
	runner.set("iptables -S", probe.Observation{
		Status: probe.StatusExecError,
		Meta:   &probe.Meta{StderrExcerpt: "Permission denied (you must be root)"},
	})
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	wantStatus(t, f, scan.StatusUnknown)
	if strings.Contains(f.Evidence.Detail, "no rules") && !strings.Contains(f.Evidence.Detail, "never reported as") {
		t.Errorf("an unreadable ruleset must never be reported as no rules: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	for _, s := range ev["subsystems"].([]any) {
		m := s.(map[string]any)
		if m["name"] == "ufw" {
			cv := m["config_values"].(map[string]any)
			if cv["DEFAULT_INPUT_POLICY"] != "DROP" {
				t.Errorf("the readable ufw defaults must be reported rather than discarded: %v", cv)
			}
		}
	}
}

// A missing nft says nothing about whether nftables rules exist.
func TestFirewall_MissingNftIsNotNoRules(t *testing.T) {
	root := tree(t, map[string]string{"/run/systemd/system/": ""})
	runner := newFakeRunner().ok("systemctl is-active ufw", "active\n")
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	wantStatus(t, f, scan.StatusUnknown)
}

// A host can be filtered by something this sensor does not know the name of:
// an iptables-restore ExecStartPre, rc.local, a config-management run, a
// provider's own unit. Not recognising the mechanism is not observing its
// absence, so a global listener plus no recognised unit is unknown, not fail.
func TestFirewall_UnknownImplementationIsUnknown(t *testing.T) {
	root := tree(t, map[string]string{
		"/run/systemd/system/": "",
		"/proc/net/tcp":        procNetTCP("00000000:0016", "0A", "1"),
	})
	runner := newFakeRunner().set("systemctl is-active ufw", probe.Observation{
		Status: probe.StatusExecError, Value: "inactive\n",
	})
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	wantStatus(t, f, scan.StatusUnknown)
	if !strings.Contains(f.Evidence.Detail, "invisible here") {
		t.Errorf("the detail must name the blind spot rather than assert the host is unfiltered: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// SECRETS_ON_DISK
// ---------------------------------------------------------------------------

const pemKeyBody = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n-----END OPENSSH PRIVATE KEY-----\n"

func TestPrivateKeyExposure_WorldReadableKeyFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                    "root:x:0:\nssh_keys:x:105:\n",
		"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_ed25519_key", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	wantStatus(t, f, scan.StatusFail)
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "b3BlbnNzaC1rZXktdjEA") {
		t.Errorf("key body leaked into the finding")
	}
	ev := evidenceOf(t, f)
	hits := ev["private_key_files"].([]any)
	if hits[0].(map[string]any)["magic_class"] != "openssh-private-key" {
		t.Errorf("classification = %v", hits[0])
	}
}

// A .pem holding a certificate is not key material.
func TestPrivateKeyExposure_CertificateIsNotAKey(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":             "root:x:0:\n",
		"/etc/ssl/ca-bundle.pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
	})
	chmod(t, root, "/etc/ssl/ca-bundle.pem", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	wantStatus(t, f, scan.StatusPass)
}

// A 0640 key whose group has no members is owner-only in practice.
func TestPrivateKeyExposure_EmptyGroupIsNotExposure(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":                   "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":                    "root:x:0:\n" + ownGroupLine(),
		"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_ed25519_key", 0o640)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	wantStatus(t, f, scan.StatusPass)
}

func TestCredentialExposure_PgpassRuleIsCited(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":          passwdFile,
		"/etc/group":           "root:x:0:\nubuntu:x:1000:\n",
		"/home/ubuntu/.pgpass": "host:5432:db:user:secretvalue\n",
	})
	chmod(t, root, "/home/ubuntu/.pgpass", 0o644)
	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "PostgreSQL") {
		t.Errorf("the rule's own source must be cited: %q", f.Evidence.Detail)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "secretvalue") {
		t.Errorf("credential content leaked into the finding")
	}
}

func TestCredentialExposure_CorrectlyRestrictedPasses(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":          passwdFile,
		"/etc/group":           "root:x:0:\nubuntu:x:1000:\n",
		"/home/ubuntu/.pgpass": "host:5432:db:user:secretvalue\n",
	})
	chmod(t, root, "/home/ubuntu/.pgpass", 0o600)
	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	wantStatus(t, f, scan.StatusPass)
}

func TestProvisioningData_WorldReadableUserDataFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                            "root:x:0:\n",
		"/var/lib/cloud/instance/user-data.txt": "#cloud-config\nchpasswd: {list: 'ubuntu:hunter2'}\n",
	})
	chmod(t, root, "/var/lib/cloud/instance/user-data.txt", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusFail)
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "hunter2") {
		t.Errorf("provisioning payload leaked into the finding")
	}
}

// Proven absence is a real answer, not an unknown.
func TestProvisioningData_ProvenAbsenceIsAPass(t *testing.T) {
	root := tree(t, map[string]string{"/etc/group": "root:x:0:\n"})
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusPass)
	// The completeness sentence is generated by the engine now, so the check's
	// own detail states the finding and the scope comes from evidence.
	if !strings.Contains(f.Evidence.Detail, "carries no provisioning artifact") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

func TestSystemSecretStores_WorldReadableShadowFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":  "root:x:0:\nshadow:x:42:\n",
		"/etc/shadow": "root:!:19000:0:99999:7:::\n",
	})
	chmod(t, root, "/etc/shadow", 0o644)
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	wantStatus(t, f, scan.StatusFail)
}

// A group-readable store whose group is empty is effectively root-only, and
// failing it would be a false positive.
func TestSystemSecretStores_EmptyShadowGroupIsNotAFailure(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":  "root:x:0:\nshadow:x:42:\n" + ownGroupLine(),
		"/etc/shadow": "root:!:19000:0:99999:7:::\n",
	})
	chmod(t, root, "/etc/shadow", 0o640)
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	wantStatus(t, f, scan.StatusPass)
}

// ---------------------------------------------------------------------------
// BMC
// ---------------------------------------------------------------------------

func TestBMC_InterfaceDeclaredFromSMBIOS(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/dmi/entries/38-0/type": "38\n",
		"/sys/bus/acpi/devices/IPI0001%3A00/": "",
		"/sys/devices/platform/ipmi_bmc.0/":   "",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_INBAND_INTERFACE_PRESENT")
	wantStatus(t, f, scan.StatusPass)
	if f.Severity != scan.SeverityInfo {
		t.Errorf("an observational check is always info, got %s", f.Severity)
	}
	ev := evidenceOf(t, f)
	if ev["interface_declared"] != true || ev["decoded_fields"] != nil {
		t.Errorf("declared must be true and decoded fields must stay null: %v", ev)
	}
}

// A VM with readable listings and no BMC is a proven negative, reported as pass.
func TestBMC_ProvenAbsenceIsAPass(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/dmi/entries/0-0/type":  "0\n",
		"/sys/bus/acpi/devices/PNP0C0C%3A00/": "",
		"/sys/devices/platform/serial8250/":   "",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_INBAND_INTERFACE_PRESENT")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	if ev["interface_declared"] != false {
		t.Errorf("interface_declared = %v", ev["interface_declared"])
	}
}

// The BMC answering is proved by a populated identity attribute, never by a
// loaded module.
func TestBMC_RespondsWhenIdentityAttributeReads(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/devices/platform/ipmi_bmc.0/ipmi_version":      "2.0\n",
		"/sys/devices/platform/ipmi_bmc.0/manufacturer_id":   "0x002a7c\n",
		"/sys/devices/platform/ipmi_bmc.0/firmware_revision": "1.5\n",
		"/proc/modules": "ipmi_si 90112 1 - Live 0x0000000000000000\n",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_RESPONDS_IN_BAND")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	if ev["never_issued_ipmi_command"] != true {
		t.Errorf("the no-command claim is mandatory and auditable")
	}
	mid := ev["manufacturer_id"].(map[string]any)
	if mid["iana_pen_decimal"].(float64) != 10876 {
		t.Errorf("manufacturer id must be decoded to its IANA PEN: %v", mid)
	}
}

// Driver loaded but controller not identified is the "declared but not usable"
// middle state — unknown, not "no BMC".
func TestBMC_DriverLoadedWithoutIdentityIsUnknown(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/modules":             "ipmi_si 90112 1 - Live 0x0\n",
		"/sys/class/ipmi/ipmi0/dev": "238:0\n",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_RESPONDS_IN_BAND")
	wantStatus(t, f, scan.StatusUnknown)
	if !strings.Contains(f.Evidence.Detail, "not 'no BMC'") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

// Capability present and access permitted are two different findings.
func TestBMC_RootOnlyNodePassesWithThePreciseReason(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group": "root:x:0:\n",
		"/dev/ipmi0": "",
	})
	chmod(t, root, "/dev/ipmi0", 0o600)
	f := runCheck(t, root, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	wantStatus(t, f, scan.StatusPass)
	if !strings.Contains(f.Evidence.Detail, "rather than a capability check") {
		t.Errorf("the precise, actionable statement is missing: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if ev["node_opened"] != false {
		t.Errorf("the node must never be opened")
	}
}

func TestBMC_WorldAccessibleNodeFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{"/etc/group": "root:x:0:\n", "/dev/ipmi0": ""})
	chmod(t, root, "/dev/ipmi0", 0o666)
	f := runCheck(t, root, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	wantStatus(t, f, scan.StatusFail)
	if f.Severity != scan.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
}

// A missing client tool must never set another check to unknown.
func TestBMC_MissingToolingDoesNotAffectOtherChecks(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/bin/ls": "",
		"/sys/devices/platform/ipmi_bmc.0/ipmi_version": "2.0\n",
	})
	inv := runCheck(t, root, newFakeRunner(), "BMC_CLIENT_TOOLING_INVENTORY")
	wantStatus(t, inv, scan.StatusPass)
	if !strings.Contains(inv.Evidence.Detail, "carries no IPMI client tooling") {
		t.Errorf("detail = %q", inv.Evidence.Detail)
	}
	responds := runCheck(t, root, newFakeRunner(), "BMC_RESPONDS_IN_BAND")
	wantStatus(t, responds, scan.StatusPass)
}

// A USB NIC is not automatically a BMC NIC, and down is not absent.
func TestBMC_HostInterfaceDownIsALatentPass(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/dmi/entries/42-0/type":       "42\n",
		"/sys/class/net/enx001/operstate":           "down\n",
		"/sys/class/net/enx001/carrier":             "0\n",
		"/sys/class/net/enx001/address":             "00:00:00:00:00:00\n",
		"/sys/class/net/enx001/device/manufacturer": "Linux 5.4.62 with aspeed_vhub\n",
		"/sys/class/net/enx001/device/product":      "RNDIS/Ethernet Gadget\n",
	})
	// The driver link is what classifies it; without symlinks this profile
	// cannot be built, so the test skips where symlinks are unavailable.
	if err := os.Symlink("../../../bus/usb/drivers/rndis_host",
		filepath.Join(root, filepath.FromSlash("sys/class/net/enx001/device/driver"))); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	f := runCheck(t, root, newFakeRunner(), "BMC_HOST_INTERFACE_EXPOSURE")
	wantStatus(t, f, scan.StatusPass)
	if !strings.Contains(f.Evidence.Detail, "down is its current state") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if !strings.Contains(ev["oob_lan_exposure"].(string), "unknown by construction") {
		t.Errorf("the out-of-band blind spot statement is mandatory")
	}
}

// ---------------------------------------------------------------------------
// STORAGE_POSTURE
// ---------------------------------------------------------------------------

func TestDiskEncryption_NoDMIsScopedNotUnencrypted(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/sda/size":  "1000\n",
		"/sys/block/sda/dev":   "8:0\n",
		"/proc/self/mountinfo": "24 30 8:0 / / rw,relatime - ext4 /dev/sda rw\n",
	})
	f := runCheck(t, root, newFakeRunner(), "DISK_ENCRYPTION_AT_REST")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "scoped to dm-crypt/LUKS") {
		t.Errorf("the verdict must be scoped, not a claim that the media is unencrypted: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	spots := ev["blind_spots"].([]any)
	if len(spots) < 3 {
		t.Errorf("every named blind spot is mandatory in the evidence: %v", spots)
	}
}

func TestDiskEncryption_LUKSMappingPasses(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/dm-0/dm/uuid":      "CRYPT-LUKS2-3f2b1c-root\n",
		"/sys/block/dm-0/dm/name":      "root_crypt\n",
		"/sys/block/dm-0/dev":          "252:0\n",
		"/sys/block/dm-0/slaves/sda2/": "",
		"/sys/block/sda/size":          "1000\n",
		"/sys/block/sda/dev":           "8:0\n",
		"/proc/self/mountinfo":         "24 30 252:0 / / rw,relatime - ext4 /dev/mapper/root_crypt rw\n",
	})
	f := runCheck(t, root, newFakeRunner(), "DISK_ENCRYPTION_AT_REST")
	wantStatus(t, f, scan.StatusPass)
}

func TestUnusedDevices_IdleDiskFailsWithoutOpeningIt(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/nvme0n1/size":                "100\n",
		"/sys/block/nvme0n1/dev":                 "259:0\n",
		"/sys/block/nvme0n1/nvme0n1p1/partition": "1\n",
		"/sys/block/nvme1n1/size":                "100\n",
		"/sys/block/nvme1n1/dev":                 "259:3\n",
		"/proc/self/mountinfo":                   "24 30 259:1 / / rw - ext4 /dev/nvme0n1p1 rw\n",
		"/proc/swaps":                            "Filename\tType\tSize\tUsed\tPriority\n",
	})
	f := runCheck(t, root, newFakeRunner(), "UNUSED_ATTACHED_BLOCK_DEVICES")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "nvme1n1") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	// The exact wording matters: "no partition table and no filesystem
	// signature known to udev", never "empty disk".
	if strings.Contains(f.Evidence.Detail, "empty disk") {
		t.Errorf("the sensor must not claim the device is empty: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if ev["device_not_opened"] != true {
		t.Errorf("the refusal to open the device is the point of the check")
	}
	if !strings.Contains(ev["remanence"].(string), "does not open the device") {
		t.Errorf("remanence = %v", ev["remanence"])
	}
}

func TestRootRedundancy_SingleDeviceFails(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/nvme0n1/size":                "100\n",
		"/sys/block/nvme0n1/dev":                 "259:0\n",
		"/sys/block/nvme0n1/nvme0n1p2/partition": "2\n",
		"/sys/block/nvme0n1/nvme0n1p2/dev":       "259:2\n",
		"/proc/mdstat":                           "Personalities : [raid1] [raid6] [raid5]\nunused devices: <none>\n",
		"/proc/self/mountinfo":                   "24 30 259:2 / / rw - ext4 /dev/nvme0n1p2 rw\n",
	})
	f := runCheck(t, root, newFakeRunner(), "ROOT_FILESYSTEM_REDUNDANCY")
	wantStatus(t, f, scan.StatusFail)
	// A populated Personalities: line is not an array.
	if !strings.Contains(f.Evidence.Detail, "single physical device") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	if f.Severity != scan.SeverityLow {
		t.Errorf("severity = %s, want the lead-resolved impact low", f.Severity)
	}
}

func TestRootRedundancy_HealthyRaid1Passes(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/md0/dev":           "9:0\n",
		"/sys/block/md0/md/level":      "raid1\n",
		"/sys/block/md0/md/degraded":   "0\n",
		"/sys/block/md0/md/raid_disks": "2\n",
		"/sys/block/md0/slaves/sda1/":  "",
		"/sys/block/md0/slaves/sdb1/":  "",
		"/proc/mdstat":                 "Personalities : [raid1]\nmd0 : active raid1 sda1[0] sdb1[1]\n",
		"/proc/self/mountinfo":         "24 30 9:0 / / rw - ext4 /dev/md0 rw\n",
	})
	f := runCheck(t, root, newFakeRunner(), "ROOT_FILESYSTEM_REDUNDANCY")
	wantStatus(t, f, scan.StatusPass)
}

// SMART denial is the demonstration: health is unknown, and the readable
// adjacent signals are still reported rather than discarded.
func TestMediaHealth_SmartDeniedKeepsPartialEvidence(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/nvme0n1/size":                      "100\n",
		"/sys/block/nvme0n1/dev":                       "259:0\n",
		"/sys/block/nvme0n1/device/state":              "live\n",
		"/sys/fs/ext4/nvme0n1p2/errors_count":          "0\n",
		"/sys/fs/ext4/nvme0n1p2/lifetime_write_kbytes": "12345\n",
	})
	runner := newFakeRunner()
	runner.set("nvme smart-log /dev/nvme0n1", probe.Observation{
		Status: probe.StatusExecError, Meta: &probe.Meta{StderrExcerpt: "Permission denied"},
	})
	f := runCheck(t, root, runner, "MEDIA_HEALTH_VISIBILITY")
	wantStatus(t, f, scan.StatusUnknown)
	ev := evidenceOf(t, f)
	if len(ev["readable_signals"].([]any)) == 0 {
		t.Errorf("the readable adjacent signals must not be discarded")
	}
	// Recommending the disk group would be a wrong instruction to an operator.
	if !strings.Contains(ev["remediation_note"].(string), "would not grant it") {
		t.Errorf("remediation note = %v", ev["remediation_note"])
	}
}

func TestMediaHealth_ExtErrorCounterFails(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/fs/ext4/sda1/errors_count":     "7\n",
		"/sys/fs/ext4/sda1/first_error_time": "1700000000\n",
	})
	f := runCheck(t, root, newFakeRunner(), "MEDIA_HEALTH_VISIBILITY")
	wantStatus(t, f, scan.StatusFail)
}

// ---------------------------------------------------------------------------
// BOOT_CHAIN
// ---------------------------------------------------------------------------

// efivar renders a UEFI variable file: a 4-byte attribute prefix then the value.
func efivar(value byte) string {
	return string([]byte{0x06, 0x00, 0x00, 0x00, value})
}

func TestSecureBoot_ReadsByteFourNotByteZero(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/efi/": "",
		"/sys/firmware/efi/efivars/SecureBoot-" + efiGlobalGUID: efivar(1),
	})
	f := runCheck(t, root, newFakeRunner(), "SECURE_BOOT_ENABLED")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	fr := ev["file_read"].(map[string]any)
	if fr["value_byte"].(float64) != 1 || fr["attribute_prefix_hex"] != "06000000" {
		t.Errorf("the offset arithmetic must be reviewable: %v", fr)
	}
}

func TestSecureBoot_DisabledFails(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/efi/": "",
		"/sys/firmware/efi/efivars/SecureBoot-" + efiGlobalGUID: efivar(0),
	})
	f := runCheck(t, root, newFakeRunner(), "SECURE_BOOT_ENABLED")
	wantStatus(t, f, scan.StatusFail)
}

// No efivars is legacy BIOS: not applicable, never a failure.
func TestSecureBoot_NoEFIIsNotApplicableNotFail(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	f := runCheck(t, root, newFakeRunner(), "SECURE_BOOT_ENABLED")
	wantStatus(t, f, scan.StatusUnknown)
	ev := evidenceOf(t, f)
	if ev["applicable"] != false {
		t.Errorf("applicable = %v", ev["applicable"])
	}
}

// Setup Mode is its own check, at critical, and is not folded into Secure Boot.
func TestSetupMode_NoPlatformKeyIsCritical(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/firmware/efi/": "",
		"/sys/firmware/efi/efivars/SetupMode-" + efiGlobalGUID:  efivar(1),
		"/sys/firmware/efi/efivars/SecureBoot-" + efiGlobalGUID: efivar(0),
	})
	f := runCheck(t, root, newFakeRunner(), "UEFI_PLATFORM_SETUP_MODE")
	wantStatus(t, f, scan.StatusFail)
	if f.Severity != scan.SeverityCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	sb := runCheck(t, root, newFakeRunner(), "SECURE_BOOT_ENABLED")
	wantStatus(t, sb, scan.StatusFail)
	if sb.CheckID == f.CheckID {
		t.Errorf("the two observations must stay two findings")
	}
}

func TestLockdown_ParsesTheBracketedSelection(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/kernel/security/lockdown": "[none] integrity confidentiality\n",
		"/sys/kernel/security/lsm":      "lockdown,capability,landlock,yama,apparmor\n",
	})
	f := runCheck(t, root, newFakeRunner(), "KERNEL_LOCKDOWN_MODE")
	wantStatus(t, f, scan.StatusFail)
	ev := evidenceOf(t, f)
	fr := ev["file_read"].(map[string]any)
	if fr["selected"] != "none" || len(fr["options_offered"].([]any)) != 3 {
		t.Errorf("the bracketed selection must be parsed, not the option list: %v", fr)
	}
}

func TestLockdown_IntegrityPasses(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/kernel/security/lockdown": "none [integrity] confidentiality\n",
	})
	f := runCheck(t, root, newFakeRunner(), "KERNEL_LOCKDOWN_MODE")
	wantStatus(t, f, scan.StatusPass)
}

// securityfs unmounted, file absent and read denied are three different reasons.
func TestLockdown_UnmountedSecurityfsIsItsOwnReason(t *testing.T) {
	noFS := runCheck(t, tree(t, map[string]string{"/etc/hostname": "x\n"}), newFakeRunner(), "KERNEL_LOCKDOWN_MODE")
	wantStatus(t, noFS, scan.StatusUnknown)
	if noFS.Reason != scan.ReasonEINVAL {
		t.Errorf("securityfs unmounted reason = %q", noFS.Reason)
	}
	noFile := runCheck(t, tree(t, map[string]string{"/sys/kernel/security/lsm": "capability\n"}), newFakeRunner(), "KERNEL_LOCKDOWN_MODE")
	wantStatus(t, noFile, scan.StatusUnknown)
	if noFile.Reason != scan.ReasonENOENT {
		t.Errorf("lockdown attribute absent reason = %q", noFile.Reason)
	}
	if noFS.Reason == noFile.Reason {
		t.Errorf("the two states collapsed to the same reason")
	}
}

func TestTaint_DecodesBitsAndAttributesTheModule(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/sys/kernel/tainted":                  "12288\n",
		"/sys/module/bnxt_en/taint":                 "OE\n",
		"/sys/module/ixgbe/initstate":               "live\n",
		"/sys/module/module/parameters/sig_enforce": "N\n",
	})
	f := runCheck(t, root, newFakeRunner(), "UNSIGNED_OR_OUT_OF_TREE_MODULES")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "bnxt_en") {
		t.Errorf("the offending module must be named: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	bits := ev["file_read"].(map[string]any)["decoded_bits"].([]any)
	if len(bits) < 18 {
		t.Errorf("the whole taint table must be decoded as data, got %d bits", len(bits))
	}
	// /sys/module also lists built-in modules; the per-module taint file is the
	// discriminator, so ixgbe must not appear as a tainting module.
	for _, m := range ev["tainting_modules"].([]any) {
		if m.(map[string]any)["name"] == "ixgbe" {
			t.Errorf("a module without a taint file must not be reported as tainting")
		}
	}
	if !strings.Contains(ev["enforcement_note"].(string), "never inferred from taint") {
		t.Errorf("enforcement must never be inferred from taint")
	}
}

func TestTaint_CleanKernelPasses(t *testing.T) {
	root := tree(t, map[string]string{"/proc/sys/kernel/tainted": "0\n"})
	f := runCheck(t, root, newFakeRunner(), "UNSIGNED_OR_OUT_OF_TREE_MODULES")
	wantStatus(t, f, scan.StatusPass)
}

func TestTPM_PresenceIsNotUse(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/class/tpm/tpm0/tpm_version_major": "2\n",
	})
	f := runCheck(t, root, newFakeRunner(), "TPM_PRESENCE")
	wantStatus(t, f, scan.StatusPass)
	if f.Severity != scan.SeverityInfo {
		t.Errorf("an observational check is always info")
	}
	if !strings.Contains(f.Evidence.Detail, "presence is not use") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if !strings.Contains(ev["measured_boot_state"].(string), "not evidence that measured boot is unused") {
		t.Errorf("the measured-boot blind spot is mandatory: %v", ev["measured_boot_state"])
	}
}

func TestTPM_EmptyClassDirIsAProvenNegative(t *testing.T) {
	root := tree(t, map[string]string{"/sys/class/tpm/": ""})
	f := runCheck(t, root, newFakeRunner(), "TPM_PRESENCE")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	if ev["tpm_present"] != false {
		t.Errorf("tpm_present = %v", ev["tpm_present"])
	}
}

func TestBootArtifacts_WorldReadableInitramfsFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/proc/sys/kernel/osrelease":         "6.8.0-139-generic\n",
		"/boot/initrd.img-6.8.0-139-generic": "compressed\n",
		"/boot/vmlinuz-6.8.0-139-generic":    "kernel\n",
		"/proc/self/mountinfo":               "24 30 8:0 / / rw - ext4 /dev/sda1 rw\n",
	})
	chmod(t, root, "/boot/initrd.img-6.8.0-139-generic", 0o644)
	f := runCheck(t, root, newFakeRunner(), "BOOT_ARTIFACT_READABILITY")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "running kernel booted from") {
		t.Errorf("the live initramfs must be weighted above a stale one: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if ev["initramfs_not_opened"] != true {
		t.Errorf("the initramfs must never be opened")
	}
}

func TestBootArtifacts_RestrictedPasses(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/proc/sys/kernel/osrelease":         "6.8.0-139-generic\n",
		"/boot/initrd.img-6.8.0-139-generic": "compressed\n",
		"/proc/self/mountinfo":               "24 30 8:0 / / rw - ext4 /dev/sda1 rw\n",
	})
	chmod(t, root, "/boot/initrd.img-6.8.0-139-generic", 0o600)
	f := runCheck(t, root, newFakeRunner(), "BOOT_ARTIFACT_READABILITY")
	wantStatus(t, f, scan.StatusPass)
}

func TestKernelDrift_NewerInstalledKernelFails(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/sys/kernel/osrelease":      "6.8.0-139-generic\n",
		"/boot/vmlinuz-6.8.0-139-generic": "k\n",
		"/boot/vmlinuz-7.0.0-31-generic":  "k\n",
		"/lib/modules/6.8.0-139-generic/": "",
		"/lib/modules/7.0.0-31-generic/":  "",
	})
	f := runCheck(t, root, newFakeRunner(), "BOOT_KERNEL_DRIFT")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "7.0.0-31-generic") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	// The absence of the marker is not evidence that no reboot is pending.
	ev := evidenceOf(t, f)
	marker := ev["reboot_required_marker"].(map[string]any)
	if marker["present"] != false || !strings.Contains(marker["note"].(string), "not evidence") {
		t.Errorf("marker = %v", marker)
	}
}

func TestKernelDrift_RunningNewestPasses(t *testing.T) {
	root := tree(t, map[string]string{
		"/proc/sys/kernel/osrelease":      "7.0.0-31-generic\n",
		"/boot/vmlinuz-6.8.0-139-generic": "k\n",
		"/boot/vmlinuz-7.0.0-31-generic":  "k\n",
	})
	f := runCheck(t, root, newFakeRunner(), "BOOT_KERNEL_DRIFT")
	wantStatus(t, f, scan.StatusPass)
}

func TestKernelVersionOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"7.0.0-31-generic", "6.8.0-139-generic", 1},
		{"6.8.0-139-generic", "6.8.0-140-generic", -1},
		{"6.8.0-139-generic", "6.8.0-139-generic", 0},
		{"6.10.0-1-generic", "6.9.0-99-generic", 1},
	}
	for _, tc := range cases {
		if got := compareKernelVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q,%q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
