package checks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// Regression tests for fix batch 1, each named after the wrong answer it stops
// the sensor from giving.

// ---------------------------------------------------------------------------
// 1. A root with no local block device is not a single disk
// ---------------------------------------------------------------------------

// A network or overlay root resolves to zero local devices. Reporting that with
// the single-disk FAIL claims a hardware fact about hardware that is not there.
func TestRootRedundancy_NetworkRootIsUnknownNotSingleDevice(t *testing.T) {
	root := tree(t, map[string]string{
		"/sys/block/":          "",
		"/proc/mdstat":         "Personalities : [raid1]\nunused devices: <none>\n",
		"/proc/self/mountinfo": "24 30 0:52 / / rw,relatime - nfs4 10.0.0.9:/export/root rw,vers=4.2\n",
	})
	f := runCheck(t, root, newFakeRunner(), "ROOT_FILESYSTEM_REDUNDANCY")
	wantStatus(t, f, scan.StatusUnknown)
	if strings.Contains(f.Evidence.Detail, "single physical device") {
		t.Errorf("a diskless root must not be reported as a single physical device: %q", f.Evidence.Detail)
	}
	for _, want := range []string{"nfs4", "10.0.0.9:/export/root", "no local block device"} {
		if !strings.Contains(f.Evidence.Detail, want) {
			t.Errorf("the detail must name the root source and fstype (%q missing): %q", want, f.Evidence.Detail)
		}
	}
	ev := evidenceOf(t, f)
	rm := ev["root_mount"].(map[string]any)
	if rm["source"] != "10.0.0.9:/export/root" || rm["fstype"] != "nfs4" {
		t.Errorf("the mountinfo root line must stay in evidence: %v", rm)
	}
}

// An overlay root behaves the same way, and the single-disk verdict is still
// reserved for a root that really does sit on one disk.
func TestRootRedundancy_OverlayRootIsUnknownButRealSingleDiskStillFails(t *testing.T) {
	overlay := tree(t, map[string]string{
		"/sys/block/":          "",
		"/proc/mdstat":         "Personalities :\n",
		"/proc/self/mountinfo": "24 30 0:61 / / rw,relatime - overlay overlay rw,lowerdir=/a,upperdir=/b\n",
	})
	wantStatus(t, runCheck(t, overlay, newFakeRunner(), "ROOT_FILESYSTEM_REDUNDANCY"), scan.StatusUnknown)

	single := tree(t, map[string]string{
		"/sys/block/sda/size":           "1000\n",
		"/sys/block/sda/dev":            "8:0\n",
		"/sys/block/sda/sda1/partition": "1\n",
		"/sys/block/sda/sda1/dev":       "8:1\n",
		"/proc/mdstat":                  "Personalities : [raid1]\n",
		"/proc/self/mountinfo":          "24 30 8:1 / / rw - ext4 /dev/sda1 rw\n",
	})
	f := runCheck(t, single, newFakeRunner(), "ROOT_FILESYSTEM_REDUNDANCY")
	wantStatus(t, f, scan.StatusFail)
}

// ---------------------------------------------------------------------------
// 2. SMART health was parsed rather than sniffed in batch 1; in batch 2 the
//    child executions that would have produced it were removed entirely, so the
//    parser and its tests went with them. See fixbatch2_test.go.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 3. Two events inside one second cannot be ordered
// ---------------------------------------------------------------------------

func policyInForceTree(t *testing.T) string {
	t.Helper()
	return tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
		"/run/systemd/system/": "",
		"/proc/uptime":         "100000.00 800000.00\n",
	})
}

const svcShowCmd = "systemctl show ssh.service -p ActiveEnterTimestamp -p ActiveEnterTimestampMonotonic -p ExecMainStartTimestampMonotonic -p ActiveState -p FragmentPath"

// The host case: a provisioning run rewrote the configuration and restarted the
// daemon inside the same second. A whole-second timestamp cannot order those two
// events, and calling it drift asserts something the evidence does not carry.
func TestSSHPolicyInForce_SameSecondIsUndecidable(t *testing.T) {
	requireLinux(t)
	// Stage the drop-in's mtime a fraction of a second after a whole-second
	// unit start time — exactly the shape observed on the real host.
	base := time.Date(2026, 9, 8, 17, 37, 29, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		mtime   time.Time
		want    scan.Status
		wantWhy string
	}{
		{"config 291 ms after the unit start", base.Add(291 * time.Millisecond), scan.StatusUnknown, "order cannot be established"},
		{"config exactly at the unit start", base, scan.StatusUnknown, "order cannot be established"},
		{"config 4 s after the unit start", base.Add(4 * time.Second), scan.StatusFail, "changed after the daemon started"},
		{"config 4 s before the unit start", base.Add(-4 * time.Second), scan.StatusPass, "older than the daemon's start time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := policyInForceTree(t)
			cfg := filepath.Join(root, filepath.FromSlash("etc/ssh/sshd_config"))
			if err := os.Chtimes(cfg, tc.mtime, tc.mtime); err != nil {
				t.Skipf("cannot stage a modification time here: %v", err)
			}
			stamp := base.Format("Mon 2006-01-02 15:04:05") + " UTC"
			runner := newFakeRunner().
				ok("/usr/sbin/sshd -G", sshdGOutput("no")).
				ok(svcShowCmd, "ActiveEnterTimestamp="+stamp+"\nActiveEnterTimestampMonotonic=0\nActiveState=active\n")
			f := runCheck(t, root, runner, "SSH_POLICY_IN_FORCE")
			wantStatus(t, f, tc.want)
			if !strings.Contains(f.Evidence.Detail, tc.wantWhy) {
				t.Errorf("detail = %q, want it to say %q", f.Evidence.Detail, tc.wantWhy)
			}
			if tc.want == scan.StatusUnknown && f.Reason != scan.ReasonTimestampRes {
				t.Errorf("reason = %q, want TIMESTAMP_RESOLUTION", f.Reason)
			}
			ev := evidenceOf(t, f)
			ds, _ := ev["daemon_state"].(map[string]any)
			if ds == nil {
				t.Fatalf("the raw in-force facts must be in evidence: %v", ev)
			}
			if ms, _ := ds["comparison_resolution_ms"].(float64); ms != 1000 {
				t.Errorf("the whole-second path must declare a 1000 ms resolution: %v", ds["comparison_resolution_ms"])
			}
		})
	}
}

// A config file clearly newer than the daemon's start is still a fail.
func TestSSHPolicyInForce_ClearlyNewerConfigStillFails(t *testing.T) {
	requireLinux(t)
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd, "ActiveEnterTimestamp=Mon 2020-01-01 00:00:00 UTC\nActiveEnterTimestampMonotonic=0\nActiveState=active\n")
	f := runCheck(t, policyInForceTree(t), runner, "SSH_POLICY_IN_FORCE")
	wantStatus(t, f, scan.StatusFail)
	ev := evidenceOf(t, f)
	ds, _ := ev["daemon_state"].(map[string]any)
	if ds == nil {
		t.Fatalf("the raw in-force facts must be in evidence: %v", ev)
	}
	if ds["start_time_source"] != "ActiveEnterTimestamp (whole-second resolution)" {
		t.Errorf("source = %v; without a monotonic property the whole-second path must be used", ds["start_time_source"])
	}
	if ms, _ := ds["comparison_resolution_ms"].(float64); ms != 1000 {
		t.Errorf("the whole-second path must declare a 1000 ms resolution: %v", ds["comparison_resolution_ms"])
	}
}

// When systemd offers the monotonic property the reconstruction is used, and
// the resolution it declares is measured rather than asserted. Batch 2 replaced
// the fixed 100 ms claim: see TestInForce_ResolutionIsMeasuredNotAssumed.
func TestSSHPolicyInForce_MonotonicSourceIsUsedWhenOffered(t *testing.T) {
	requireLinux(t)
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd, "ActiveEnterTimestamp=Mon 2020-01-01 00:00:00 UTC\nActiveEnterTimestampMonotonic=5000000\nActiveState=active\n")
	f := runCheck(t, policyInForceTree(t), runner, "SSH_POLICY_IN_FORCE")
	ev := evidenceOf(t, f)
	ds, _ := ev["daemon_state"].(map[string]any)
	if ds == nil {
		t.Fatalf("the raw in-force facts must be in evidence: %v", ev)
	}
	src, _ := ds["start_time_source"].(string)
	if !strings.Contains(src, "Monotonic") || !strings.Contains(src, "/proc/uptime") {
		t.Errorf("source = %q, want the monotonic reconstruction", src)
	}
	if ds["delta_ms"] == nil {
		t.Errorf("the millisecond delta must be reported alongside the second one")
	}
	if basis, _ := ds["resolution_basis"].(string); !strings.Contains(basis, "measured") {
		t.Errorf("resolution_basis = %q, want a measured figure", basis)
	}
}

// The socket-activation note survives the rework.
func TestSSHPolicyInForce_SocketActivationNoteIsKept(t *testing.T) {
	requireLinux(t)
	runner := newFakeRunner().
		ok("/usr/sbin/sshd -G", sshdGOutput("no")).
		ok(svcShowCmd, "ActiveEnterTimestamp=Mon 2099-01-01 00:00:00 UTC\nActiveEnterTimestampMonotonic=0\nActiveState=active\n").
		ok("systemctl show ssh.socket -p ListenStream -p ActiveState", "ListenStream=[::]:22\nActiveState=active\n")
	f := runCheck(t, policyInForceTree(t), runner, "SSH_POLICY_IN_FORCE")
	ev := evidenceOf(t, f)
	sa, _ := ev["socket_activation"].(map[string]any)
	if sa == nil || !strings.Contains(sa["note"].(string), "sshd_config never decides the listen address") {
		t.Errorf("socket_activation = %v", ev["socket_activation"])
	}
}

// ---------------------------------------------------------------------------
// 4. cloud-init publishes instance-data.json readable by design
// ---------------------------------------------------------------------------

// The host case: user-data is root-only, and everything world-readable is what
// cloud-init publishes that way on purpose. That is a pass.
func TestProvisioning_PublicByDesignArtifactsAreNotExposure(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                               "root:x:0:\n",
		"/var/lib/cloud/instance/user-data.txt":    "#cloud-config\nchpasswd: {list: 'x:secretvalue'}\n",
		"/run/cloud-init/instance-data.json":       `{"v1": {"cloud_name": "latitude", "platform": "ec2"}, "ds": {"meta_data": {"public-keys": "redacted for non-root user"}}}`,
		"/run/cloud-init/cloud-id":                 "latitude\n",
		"/etc/cloud/cloud.cfg.d/90-datasource.cfg": "datasource_list: [ Ec2, None ]\n",
	})
	chmod(t, root, "/var/lib/cloud/instance/user-data.txt", 0o600)
	chmod(t, root, "/run/cloud-init/instance-data.json", 0o644)
	chmod(t, root, "/run/cloud-init/cloud-id", 0o644)
	chmod(t, root, "/etc/cloud/cloud.cfg.d/90-datasource.cfg", 0o644)

	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusPass)

	ev := evidenceOf(t, f)
	if ev["redaction_observed"] != true {
		t.Errorf("redaction must still be observed and reported: %v", ev["redaction_observed"])
	}
	if ev["datasource_class"] != "latitude" {
		t.Errorf("datasource_class = %v, want the identifiable datasource", ev["datasource_class"])
	}
	byPath := map[string]map[string]any{}
	for _, a := range ev["artifacts"].([]any) {
		m := a.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	idj := byPath["/run/cloud-init/instance-data.json"]
	if idj == nil || idj["class"] != "public-by-design" || idj["adverse"] != false {
		t.Errorf("instance-data.json must be inventory, not a finding: %v", idj)
	}
	ud := byPath["/var/lib/cloud/instance/user-data.txt"]
	if ud == nil || ud["class"] != "payload" || ud["adverse"] != false {
		t.Errorf("root-only user-data must be a non-adverse payload artifact: %v", ud)
	}
	body, _ := jsonMarshal(f)
	if strings.Contains(body, "secretvalue") {
		t.Errorf("provisioning payload leaked into the finding")
	}
}

// A readable payload artifact is still a fail — the rule was narrowed, not
// removed.
func TestProvisioning_ReadablePayloadStillFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                            "root:x:0:\n",
		"/var/lib/cloud/instance/user-data.txt": "#cloud-config\n",
		"/run/cloud-init/instance-data.json":    `{"v1": {"cloud_name": "nocloud"}}`,
	})
	chmod(t, root, "/var/lib/cloud/instance/user-data.txt", 0o644)
	chmod(t, root, "/run/cloud-init/instance-data.json", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "user-data.txt") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
	if strings.Contains(f.Evidence.Detail, "instance-data.json") {
		t.Errorf("the by-design readable artifact must not appear in the reason: %q", f.Evidence.Detail)
	}
}

// A readable user-data inside an instance directory is found by name, because
// the directory is named after the instance id.
func TestProvisioning_InstanceDirectoryPayloadIsFoundByName(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group": "root:x:0:\n",
		"/var/lib/cloud/instances/i-0abc123/user-data.txt": "#cloud-config\n",
	})
	chmod(t, root, "/var/lib/cloud/instances/i-0abc123/user-data.txt", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "i-0abc123") {
		t.Errorf("detail = %q", f.Evidence.Detail)
	}
}

// A world-readable drop-in that declares a credential-bearing key name is
// promoted out of the public class.
func TestProvisioning_DropInDeclaringCredentialKeysIsPayload(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group":                         "root:x:0:\n",
		"/etc/cloud/cloud.cfg.d/99-keys.cfg": "ssh_authorized_keys:\n  - ssh-ed25519 AAAA someone\n",
	})
	chmod(t, root, "/etc/cloud/cloud.cfg.d/99-keys.cfg", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusFail)
	ev := evidenceOf(t, f)
	for _, a := range ev["artifacts"].([]any) {
		m := a.(map[string]any)
		if m["path"] == "/etc/cloud/cloud.cfg.d/99-keys.cfg" {
			if m["class"] != "payload" {
				t.Errorf("a drop-in declaring ssh_authorized_keys is payload: %v", m)
			}
			keys, _ := m["declares_credential_keys"].([]any)
			if len(keys) == 0 {
				t.Errorf("the declared key NAMES must be recorded: %v", m)
			}
		}
	}
	body, _ := jsonMarshal(f)
	if strings.Contains(body, "AAAA someone") {
		t.Errorf("a key value leaked into the finding")
	}
}

func TestCloudNameFrom(t *testing.T) {
	if got := cloudNameFrom(`{"v1": {"cloud_name": "latitude"}}`); got != "latitude" {
		t.Errorf("cloud_name = %q", got)
	}
	if got := cloudNameFrom(`{"v1": {"cloud_name": "unknown", "platform": "ec2"}}`); got != "ec2" {
		t.Errorf("platform fallback = %q", got)
	}
	if got := cloudNameFrom(`not json`); got != "" {
		t.Errorf("unparseable input must yield no datasource, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// 5. Service accounts do not have homes worth walking
// ---------------------------------------------------------------------------

func TestCredentialHomes_SkipsSystemDirsAndDeduplicates(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"sync:x:4:65534:sync:/bin:/bin/sync\n" +
		"nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n" +
		"sys:x:3:3:sys:/dev:/usr/sbin/nologin\n" +
		"toor:x:0:0:root:/root:/bin/bash\n" +
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"

	homes, skipped := credentialHomes(passwd)
	want := map[string]bool{"/root": true, "/home/ubuntu": true}
	if len(homes) != len(want) {
		t.Fatalf("homes = %v, want exactly %v", homes, want)
	}
	for _, h := range homes {
		if !want[h] {
			t.Errorf("unexpected home %q", h)
		}
	}
	for _, bad := range []string{"/", "/bin", "/usr/sbin", "/dev", "/nonexistent"} {
		for _, h := range homes {
			if h == bad {
				t.Errorf("%q is a service-account placeholder home and must not be walked", bad)
			}
		}
	}
	if len(skipped) == 0 {
		t.Errorf("the skipped placeholder homes must be reported, not silently dropped")
	}
}

// The end-to-end shape: no system directory in homes_inspected, no duplicate in
// unreadable_homes.
func TestCredentialExposure_HomesAreCleanAndDeduplicated(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/group": "root:x:0:\nubuntu:x:1000:\n",
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n" +
			"bin:x:2:2:bin:/bin:/usr/sbin/nologin\n" +
			"sync:x:4:65534:sync:/bin:/bin/sync\n" +
			"toor:x:0:0:root:/root:/bin/bash\n" +
			"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
		"/root/.pgpass":        "host:5432:db:user:secret\n",
		"/home/ubuntu/.pgpass": "host:5432:db:user:secret\n",
	})
	chmod(t, root, "/home/ubuntu/.pgpass", 0o600)
	chmod(t, root, "/root/.pgpass", 0o600)
	// root's home is unreadable to this uid, which is the normal shape of an
	// unprivileged run: root's credential exposure is then unknown, not clean.
	chmod(t, root, "/root", 0o000)

	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	ev := evidenceOf(t, f)

	var inspected []string
	for _, h := range ev["homes_inspected"].([]any) {
		inspected = append(inspected, h.(string))
	}
	for _, bad := range []string{"/", "/bin", "/usr/sbin", "/dev"} {
		for _, h := range inspected {
			if h == bad {
				t.Errorf("homes_inspected contains the system directory %q: %v", bad, inspected)
			}
		}
	}
	seen := map[string]bool{}
	for _, h := range inspected {
		if seen[h] {
			t.Errorf("homes_inspected has a duplicate %q: %v", h, inspected)
		}
		seen[h] = true
	}
	unreadable := map[string]bool{}
	for _, h := range ev["unreadable_homes"].([]any) {
		if unreadable[h.(string)] {
			t.Errorf("unreadable_homes has a duplicate %q", h)
		}
		unreadable[h.(string)] = true
	}
	if ev["homes_skipped"] == nil {
		t.Errorf("the skipped placeholder homes must be reported")
	}
	// Fix batch 3 rows 28/35 changed the verdict here on purpose: root's home
	// is unreadable BECAUSE it excludes every unprivileged account, which is
	// the answer this check asks for. What must still hold is that the
	// shielding is counted and reported rather than silently assumed.
	if f.Status == scan.StatusFail {
		t.Errorf("a credential behind a 0700 home is not exposed: %q", f.Evidence.Detail)
	}
	if n, _ := ev["protected_by_ancestor"].(float64); n < 1 {
		t.Errorf("the shielded candidates must be counted: %v", ev["protected_by_ancestor"])
	}
}

// jsonMarshal renders a finding for the leak greps above.
func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// probe is referenced so this file keeps compiling on its own terms if the
// shared helpers move.
var _ = probe.StatusOK
