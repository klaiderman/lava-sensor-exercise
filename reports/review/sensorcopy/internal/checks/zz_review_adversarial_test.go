package checks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/scan"
)

// ADV-1: same-second config mtime vs 1s-resolution systemd timestamp.
func TestADV_SSHPolicyInForce_SameSecondIsNotAFail(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
	})
	// service entered active at 17:37:29 (systemd prints whole seconds);
	// the file was written at 17:37:29.400 -- same second, could be before or after.
	mt := time.Date(2026, 9, 8, 17, 37, 29, 400_000_000, time.UTC)
	if err := os.Chtimes(filepath.Join(root, "etc/ssh/sshd_config"), mt, mt); err != nil {
		t.Fatal(err)
	}
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok("systemctl show ssh.service -p ActiveEnterTimestamp -p ActiveState -p FragmentPath",
			"ActiveEnterTimestamp=Tue 2026-09-08 17:37:29 UTC\nActiveState=active\nFragmentPath=/lib/systemd/system/ssh.service\n")
	f := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
	t.Logf("calls=%q", runner.calls)
	t.Logf("status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if f.Status == scan.StatusFail {
		t.Errorf("FALSE FAIL: same-second mtime reported as 'changed after the daemon started' (real-host reproduction)")
	}
}

// ADV-2: default Ubuntu cloud-init layout (registry says PASS).
func TestADV_Provisioning_DefaultCloudInitLayoutIsNotAFail(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                                     "root:x:0:\n",
		"/var/lib/cloud/instance/user-data.txt":          "",
		"/run/cloud-init/instance-data.json":             "{\"ds\": {\"meta_data\": \"redacted for non-root user\"}}\n",
		"/run/cloud-init/instance-data-sensitive.json":   "{\"secret\": 1}\n",
		"/etc/cloud/cloud.cfg.d/90_dpkg.cfg":             "datasource_list: [ Ec2 ]\n",
		"/etc/cloud/cloud.cfg.d/README":                  "drop-ins\n",
		"/var/lib/cloud/instances/i-abc/":                "",
	})
	chmod(t, root, "/var/lib/cloud/instance/user-data.txt", 0o600)
	chmod(t, root, "/run/cloud-init/instance-data.json", 0o644)
	chmod(t, root, "/run/cloud-init/instance-data-sensitive.json", 0o600)
	chmod(t, root, "/etc/cloud/cloud.cfg.d/90_dpkg.cfg", 0o644)
	chmod(t, root, "/etc/cloud/cloud.cfg.d/README", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	t.Logf("status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if f.Status == scan.StatusFail {
		t.Errorf("FALSE FAIL: package-shipped 0644 cloud.cfg.d drop-ins / redacted instance-data.json reported as credential exposure")
	}
}

// ADV-3: unreadable /root walk root must not be 'clean' (registry UNKNOWN condition).
func TestADV_PrivateKey_UnreadableRootIsNotClean(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":              "root:x:0:\n",
		"/root/.ssh/id_ed25519":   pemKeyBody,
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
	})
	chmod(t, root, "/root/.ssh/id_ed25519", 0o644) // world-readable key hidden behind 0700 /root
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o600)
	chmod(t, root, "/root", 0o700)
	// make it unreadable for us: 0000 on /root (we are not root)
	chmod(t, root, "/root", 0o000)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	t.Logf("status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if f.Status == scan.StatusPass {
		t.Errorf("OVER-CLAIM: pass while a scan root (/root) was unreadable; detail claims 'every enumeration completed'")
	}
}

// ADV-4: Match block flips PasswordAuthentication while sshd -G reports the global value.
func TestADV_SSHAuth_MatchFlipsDirective(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd": "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PasswordAuthentication no\nMatch Address 10.0.0.0/8\n    PasswordAuthentication yes\n",
	})
	runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no"))
	f := runCheck(t, root, runner, "SSH_AUTH_METHODS_POLICY")
	t.Logf("status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if f.Status == scan.StatusPass {
		t.Errorf("a Match block re-enabling passwords must not yield a bare pass (L17)")
	}
	f2 := runCheck(t, root, runner, "SSH_ROOT_LOGIN_POLICY")
	t.Logf("root-login status=%s reason=%s", f2.Status, f2.Reason)
}

// ADV-5: sysfs block device with no size attribute.
func TestADV_Machine_MissingSizeIsMarkedUnknown(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/sda/device/model": "FakeDisk\n",
		"/sys/block/sda/removable":    "0\n",
		"/proc/cpuinfo":               "model name\t: X\nprocessor\t: 0\n",
		"/proc/meminfo":               "MemTotal:  1024 kB\n",
		"/etc/os-release":             "ID=debian\nVERSION_ID=12\nNAME=Debian\n",
		"/proc/sys/kernel/osrelease":  "6.1.0\n",
		"/proc/sys/kernel/hostname":   "h\n",
		"/etc/machine-id":             "0123456789abcdef0123456789abcdef\n",
	})
	env := newTestEnv(t, root, nil)
	m := CollectMachine(context.Background(), env)
	b, _ := json.Marshal(m)
	t.Logf("storage=%s", string(b)[:min(len(b), 900)])
	if strings.Contains(string(b), "0123456789abcdef0123456789abcdef") {
		t.Errorf("raw machine-id leaked")
	}
	found := false
	for _, d := range m.Storage {
		if d.Device == "sda" {
			found = true
			if d.SizeBytes != 0 {
				t.Errorf("size_bytes=%d with no size attribute", d.SizeBytes)
			}
			if !strings.Contains(d.SizeSource, "unknown") && !strings.Contains(strings.ToLower(d.SizeSource), "enoent") {
				t.Errorf("size_source does not say unknown: %q", d.SizeSource)
			}
		}
	}
	if !found {
		t.Logf("sda not listed in storage (other_block_devices=%d)", len(m.OtherBlockDevs))
	}
}

// ADV-6: ufw unit active but ufw.conf ENABLED=no -> detail must not say 'enabled'.
func TestADV_Firewall_UfwUnitActiveButDisabledInConf(t *testing.T) {
	root := tree(t, map[string]string{
		"/run/systemd/system/": "",
		"/etc/ufw/ufw.conf":    "ENABLED=no\nLOGLEVEL=low\n",
		"/etc/default/ufw":     "DEFAULT_INPUT_POLICY=\"DROP\"\n",
		"/proc/net/tcp":        procNetTCP("00000000:0016", "0A", "1"),
	})
	runner := newFakeRunner().ok("systemctl is-active ufw", "active\n")
	f := runCheck(t, root, runner, "HOST_FIREWALL_STATE")
	t.Logf("status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if strings.Contains(f.Evidence.Detail, "is enabled") {
		t.Errorf("detail says a filtering subsystem is enabled while ufw.conf ENABLED=no was read and ignored")
	}
}
