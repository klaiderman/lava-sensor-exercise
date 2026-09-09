package lab

import (
	"fmt"
	"testing"

	"lava-sensor-exercise/sensor/internal/scan"
)

// expectedSet is the set of statuses research/CHECK_REGISTRY.md §5.3 allows for
// one check on profile B or C. Several cells in that table are themselves an
// explicit "p or f" / "p or u" — a fixed fixture necessarily lands on one
// concrete value, so both are accepted here.
type expectedSet map[scan.Status]bool

func set(ss ...scan.Status) expectedSet {
	m := expectedSet{}
	for _, s := range ss {
		m[s] = true
	}
	return m
}

var (
	pass    = set(scan.StatusPass)
	fail    = set(scan.StatusFail)
	unknown = set(scan.StatusUnknown)
	passU   = set(scan.StatusPass, scan.StatusUnknown)
	passF   = set(scan.StatusPass, scan.StatusFail)
	anyS    = set(scan.StatusPass, scan.StatusFail, scan.StatusUnknown)
)

// expectedProfileA is research/CHECK_REGISTRY.md §5.3, column A, corrected
// 2026-09-09 02:20Z after the external adversarial review (H2 — the original
// prose "9 pass · 8 fail · 8 unknown" was arithmetically wrong; the table's own
// rows sum to 12/8/5 for the 25 registry checks), plus the lead-added
// BOOT_KERNEL_DRIFT row (fail: running 6.8.0-139-generic while /boot/vmlinuz
// points at the newer installed 7.0.0-31-generic). This is a single required
// value per check, not a range: profile A is the fixture meant to reproduce
// the Lava host's predicted outcome exactly, and reports/CLOSURE_TABLE.md row
// 20 records the corrected total as 12 pass / 9 fail / 5 unknown = 26.
//
// This is scored as a hard gate (t.Errorf on every mismatch, external review
// "Tests" item 1: "A test that logs is not a test"). It is expected to be RED
// right now against internal/checks/testdata/profileA: that fixture predates
// several fixture-completeness gaps this exact test surfaced in the previous
// pass (no /sys/firmware/efi, /sys/class/tpm, /sys/kernel/security,
// /sys/devices/platform/ipmi_bmc.*, /proc/sys/kernel/tainted, /etc/passwd,
// /proc/swaps, /proc/net/*, /boot/initramfs-*, a systemd unit tree) and on the
// implementation-side CLOSURE_TABLE.md defects the author is fixing
// concurrently (rows 1-5, 18-19) in a batch this test is not gated behind. The
// gate's job is to go red on exactly those gaps until they close, and green
// once they do — not to be pre-massaged into passing. See TEST_REPORT.md for
// the current run's mismatch list and which CLOSURE_TABLE row each maps to.
var expectedProfileA = map[string]scan.Status{
	"SSH_ROOT_LOGIN_POLICY":           scan.StatusUnknown,
	"SSH_AUTH_METHODS_POLICY":         scan.StatusPass,
	"SSH_POLICY_IN_FORCE":             scan.StatusPass,
	"REMOTE_LISTENING_SURFACE":        scan.StatusPass,
	"LOGIN_AND_ESCALATION_SURFACE":    scan.StatusUnknown,
	"HOST_FIREWALL_STATE":             scan.StatusUnknown,
	"PRIVATE_KEY_MATERIAL_EXPOSURE":   scan.StatusPass,
	"CREDENTIAL_FILE_EXPOSURE":        scan.StatusUnknown, // corrected 02:20Z: /root unreadable ⇒ unknown per the registry's own §2.2 rule
	"PROVISIONING_DATA_PROTECTION":    scan.StatusPass,
	"SYSTEM_SECRET_STORE_PROTECTION":  scan.StatusPass,
	"BMC_INBAND_INTERFACE_PRESENT":    scan.StatusPass,
	"BMC_RESPONDS_IN_BAND":            scan.StatusPass,
	"BMC_DEVICE_NODE_ACCESS":          scan.StatusPass,
	"BMC_CLIENT_TOOLING_INVENTORY":    scan.StatusPass,
	"BMC_HOST_INTERFACE_EXPOSURE":     scan.StatusPass,
	"DISK_ENCRYPTION_AT_REST":         scan.StatusFail,
	"ROOT_FILESYSTEM_REDUNDANCY":      scan.StatusFail,
	"UNUSED_ATTACHED_BLOCK_DEVICES":   scan.StatusFail,
	"MEDIA_HEALTH_VISIBILITY":         scan.StatusUnknown,
	"SECURE_BOOT_ENABLED":             scan.StatusFail,
	"UEFI_PLATFORM_SETUP_MODE":        scan.StatusFail,
	"KERNEL_LOCKDOWN_MODE":            scan.StatusFail,
	"UNSIGNED_OR_OUT_OF_TREE_MODULES": scan.StatusFail,
	"TPM_PRESENCE":                    scan.StatusPass,
	"BOOT_ARTIFACT_READABILITY":       scan.StatusFail,
	"BOOT_KERNEL_DRIFT":               scan.StatusFail,
}

func init() {
	if len(expectedProfileA) != 26 {
		panic(fmt.Sprintf("expectedProfileA has %d entries, want 26", len(expectedProfileA)))
	}
	counts := map[scan.Status]int{}
	for _, v := range expectedProfileA {
		counts[v]++
	}
	if counts[scan.StatusPass] != 12 || counts[scan.StatusFail] != 9 || counts[scan.StatusUnknown] != 5 {
		panic(fmt.Sprintf("expectedProfileA sums to %d pass / %d fail / %d unknown, want 12/9/5 (CLOSURE_TABLE.md row 20)",
			counts[scan.StatusPass], counts[scan.StatusFail], counts[scan.StatusUnknown]))
	}
}

// registryMatrixBC is research/CHECK_REGISTRY.md §5.3, columns B and C,
// transcribed as documented ranges (the registry itself says "p or f" / "u"
// for these profiles — they are not the reproduction target profile A is).
var registryMatrixBC = map[string][2]expectedSet{
	"SSH_ROOT_LOGIN_POLICY":           {passF, unknown},
	"SSH_AUTH_METHODS_POLICY":         {passF, unknown},
	"SSH_POLICY_IN_FORCE":             {passU, unknown},
	"REMOTE_LISTENING_SURFACE":        {passF, unknown},
	"LOGIN_AND_ESCALATION_SURFACE":    {unknown, unknown},
	"HOST_FIREWALL_STATE":             {set(scan.StatusFail, scan.StatusUnknown), unknown},
	"PRIVATE_KEY_MATERIAL_EXPOSURE":   {passF, unknown},
	"CREDENTIAL_FILE_EXPOSURE":        {passF, passF},
	"PROVISIONING_DATA_PROTECTION":    {pass, pass},
	"SYSTEM_SECRET_STORE_PROTECTION":  {pass, passU},
	"BMC_INBAND_INTERFACE_PRESENT":    {pass, unknown},
	"BMC_RESPONDS_IN_BAND":            {pass, unknown},
	"BMC_DEVICE_NODE_ACCESS":          {pass, unknown},
	"BMC_CLIENT_TOOLING_INVENTORY":    {pass, pass},
	"BMC_HOST_INTERFACE_EXPOSURE":     {pass, unknown},
	"DISK_ENCRYPTION_AT_REST":         {passF, unknown},
	"ROOT_FILESYSTEM_REDUNDANCY":      {fail, unknown},
	"UNUSED_ATTACHED_BLOCK_DEVICES":   {pass, unknown},
	"MEDIA_HEALTH_VISIBILITY":         {unknown, unknown},
	"SECURE_BOOT_ENABLED":             {anyS, unknown},
	"UEFI_PLATFORM_SETUP_MODE":        {anyS, unknown},
	"KERNEL_LOCKDOWN_MODE":            {set(scan.StatusFail, scan.StatusUnknown), unknown},
	"UNSIGNED_OR_OUT_OF_TREE_MODULES": {passF, set(scan.StatusFail, scan.StatusUnknown)},
	"TPM_PRESENCE":                    {pass, unknown},
	"BOOT_ARTIFACT_READABILITY":       {passF, pass},
	"BOOT_KERNEL_DRIFT":               {anyS, anyS}, // not in the registry's §5.3 table (added after it was drafted)
}

// TestProfileMatrix_ProfileA_HardGate is the promotion CLOSURE_TABLE.md row 18
// and the external review's "Tests" item 1 and item 3 (item 3: "the change
// that makes the existing one worth having") both ask for: every mismatch
// against expectedProfileA is a build failure (t.Errorf), not a log line.
func TestProfileMatrix_ProfileA_HardGate(t *testing.T) {
	root := buildAuthorProfile(t, "profileA")
	runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("prohibit-password"))
	env := newLabEnv(t, root, runner)
	byID := runFullScan(t, env)

	counts := map[scan.Status]int{}
	for id, want := range expectedProfileA {
		f, ok := byID[id]
		if !ok {
			continue // already reported as a hard failure by runFullScan
		}
		counts[f.Status]++
		if f.Status != want {
			t.Errorf("%s: research/CHECK_REGISTRY.md §5.3 (profile A) requires %s, observed %s (reason=%q, detail=%.180q)",
				id, want, f.Status, f.Reason, f.Evidence.Detail)
		}
	}
	t.Logf("profile A observed distribution: %d pass / %d fail / %d unknown (target: 12/9/5)",
		counts[scan.StatusPass], counts[scan.StatusFail], counts[scan.StatusUnknown])
}

// TestProfileMatrix_ProfilesBC_HardGate is the same promotion for profiles B
// and C: every status outside the registry's documented range is a build
// failure, not a log line.
func TestProfileMatrix_ProfilesBC_HardGate(t *testing.T) {
	profiles := []struct {
		name   string
		col    int
		runner *fakeRunner
	}{
		{"profileB", 0, newFakeRunner()}, // no /usr/sbin/sshd in profileB at all -> UTILITY_MISSING
		{"profileC", 1, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no"))},
	}
	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			root := buildAuthorProfile(t, p.name)
			env := newLabEnv(t, root, p.runner)
			byID := runFullScan(t, env)

			for id, cell := range registryMatrixBC {
				f, ok := byID[id]
				if !ok {
					continue
				}
				allowed := cell[p.col]
				if !allowed[f.Status] {
					var allowedList []string
					for s := range allowed {
						allowedList = append(allowedList, string(s))
					}
					t.Errorf("%s: research/CHECK_REGISTRY.md §5.3 (profile %s) requires one of %v, observed %s (reason=%q, detail=%.140q)",
						id, p.name, allowedList, f.Status, f.Reason, f.Evidence.Detail)
				}
			}
		})
	}
}

// TestProfileBIsGenericNoHostAssumptions asserts the specific negative claim
// the task calls out for profile B: no NVMe/IPMI/systemd/sshd fixtures are
// present, so every check whose primary evidence needs one of those must
// answer honestly (unknown or a proven pass/fail from a *generic* fallback),
// never a value that could only be produced by assuming the Lava host's shape.
func TestProfileBIsGenericNoHostAssumptions(t *testing.T) {
	root := buildAuthorProfile(t, "profileB")
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)

	// BMC_* checks must not claim BMC presence: profileB's DMI/sysfs tree
	// carries no IPMI declaration at all.
	for _, id := range []string{"BMC_INBAND_INTERFACE_PRESENT", "BMC_RESPONDS_IN_BAND", "BMC_DEVICE_NODE_ACCESS"} {
		f := byID[id]
		if f.Status == scan.StatusFail {
			t.Errorf("%s: profile B has no BMC fixture at all; fail is not a legal outcome here (status=%s reason=%s)", id, f.Status, f.Reason)
		}
	}
	// No systemd unit tree in profile B: SSH_POLICY_IN_FORCE must not assert a
	// timestamp comparison it cannot have evidence for.
	if f := byID["SSH_POLICY_IN_FORCE"]; f.Status == scan.StatusFail {
		t.Errorf("SSH_POLICY_IN_FORCE: profile B has no systemd/service data; fail requires evidence this profile cannot supply (reason=%s detail=%s)", f.Reason, f.Evidence.Detail)
	}
	// Root login policy: profile B ships no /usr/sbin/sshd at all, so the
	// honest answer is UNKNOWN/UTILITY_MISSING, never a value implying a
	// running daemon was consulted.
	if f := byID["SSH_ROOT_LOGIN_POLICY"]; f.Status != scan.StatusUnknown {
		t.Errorf("SSH_ROOT_LOGIN_POLICY: profile B ships no sshd binary; want unknown, got %s (reason=%s)", f.Status, f.Reason)
	}
}

// TestProfileCNeverPassesOrFailsWhatItCannotObserve encodes the second
// task-level claim: restricted/EACCES/missing-utility conditions must produce
// unknown, never a confident pass or fail, for the checks whose primary
// evidence profile C's fixture deliberately removes ("/sys" absent entirely,
// sshd_config chmod 0000).
func TestProfileCNeverPassesOrFailsWhatItCannotObserve(t *testing.T) {
	root := buildAuthorProfile(t, "profileC")
	env := newLabEnv(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")))
	byID := runFullScan(t, env)

	// Every check whose primary evidence is under /sys must be unknown: the
	// fixture has no /sys tree at all (os.Root over it degrades to "unavailable").
	// BMC_DEVICE_NODE_ACCESS is deliberately excluded: its primary evidence is
	// /dev/ipmi{0,/0}, /dev/ipmidev/0 (stat only), not /sys, so a fixture with
	// no /sys tree can still legitimately prove those nodes absent and pass
	// (verified against internal/checks/bmc.go:224 — ipmiNodes).
	sysDependent := []string{
		"BMC_INBAND_INTERFACE_PRESENT", "BMC_RESPONDS_IN_BAND",
		"BMC_HOST_INTERFACE_EXPOSURE", "SECURE_BOOT_ENABLED", "UEFI_PLATFORM_SETUP_MODE",
		"TPM_PRESENCE", "DISK_ENCRYPTION_AT_REST", "UNUSED_ATTACHED_BLOCK_DEVICES",
		"ROOT_FILESYSTEM_REDUNDANCY",
	}
	for _, id := range sysDependent {
		f, ok := byID[id]
		if !ok {
			continue
		}
		if f.Status != scan.StatusUnknown {
			t.Errorf("%s: profile C has no /sys tree; a %s verdict claims evidence this fixture cannot provide (reason=%s detail=%.160q)",
				id, f.Status, f.Reason, f.Evidence.Detail)
		}
	}
}
