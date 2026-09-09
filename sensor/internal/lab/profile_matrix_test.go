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
// points at the newer installed 7.0.0-31-generic). This started as a single
// required value per check taken straight from research/CHECK_REGISTRY.md's
// corrected 12/9/5 target (CLOSURE_TABLE.md row 20); two entries below were
// then deliberately corrected again, with reasoning, after building a fixture
// faithful enough to the real host to actually exercise them — see the
// comments on those two rows and TEST_REPORT.md's final section for the full
// account of why the target changed a second time and what that implies for
// the pending real-host run.
var expectedProfileA = map[string]scan.Status{
	"SSH_ROOT_LOGIN_POLICY":           scan.StatusUnknown,
	"SSH_AUTH_METHODS_POLICY":         scan.StatusPass,
	"SSH_POLICY_IN_FORCE":             scan.StatusPass,
	"REMOTE_LISTENING_SURFACE":        scan.StatusPass,
	"LOGIN_AND_ESCALATION_SURFACE":    scan.StatusUnknown,
	"HOST_FIREWALL_STATE":             scan.StatusUnknown,
	"CREDENTIAL_FILE_EXPOSURE":        scan.StatusUnknown, // corrected 02:20Z: /root unreadable ⇒ unknown per the registry's own §2.2 rule
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

	// --- Deliberate second correction, found while building a real-host-faithful
	//     fixture (internal/checks/testdata/profileA now chmods /root 0000, the
	//     account's actual 0700 root:root mode per state/HOST_SNAPSHOT.evidence.json
	//     users.root_home_ls — the sensor runs as an unprivileged account, so this
	//     is not optional fidelity, it is the fixture telling the truth): ---
	//
	// PRIVATE_KEY_MATERIAL_EXPOSURE's own fixed walk-root list
	// (internal/checks/secrets.go:132) includes "/root" directly. With /root
	// genuinely EACCES, the walk cannot enumerate that root, and the new
	// entailment engine (scan/entailment.go, CLOSURE_TABLE.md row 1) correctly
	// downgrades what used to be a "pass, boundary noted" into "unknown" — the
	// walk did not complete, so an absence claim is not entailed by its own
	// evidence. research/CHECK_REGISTRY.md's "Host: pass (scope printed)" line
	// predates this stricter engine; it is very likely stale, not this fixture.
	"PRIVATE_KEY_MATERIAL_EXPOSURE": scan.StatusUnknown,
	// PROVISIONING_DATA_PROTECTION's candidate list includes /root/anaconda-ks.cfg
	// et al.; the same /root EACCES makes that candidate's status EACCES rather
	// than a proven absence, and the same entailment engine downgrades the same
	// way. research/CHECK_REGISTRY.md's "Host: pass" line is very likely stale
	// for the identical reason.
	"PROVISIONING_DATA_PROTECTION": scan.StatusUnknown,
}

func init() {
	if len(expectedProfileA) != 26 {
		panic(fmt.Sprintf("expectedProfileA has %d entries, want 26", len(expectedProfileA)))
	}
	counts := map[scan.Status]int{}
	for _, v := range expectedProfileA {
		counts[v]++
	}
	// CLOSURE_TABLE.md row 20 records 12/9/5. This asserts 10/9/7: the two
	// deliberate corrections above (PRIVATE_KEY_MATERIAL_EXPOSURE and
	// PROVISIONING_DATA_PROTECTION, both pass -> unknown once /root is
	// genuinely EACCES against the stricter entailment engine) move two checks
	// from the pass column to the unknown column. If this panics, the map
	// drifted from the two corrected rows without updating this assertion —
	// fix the assertion together with a justification, never the other way
	// around silently.
	if counts[scan.StatusPass] != 10 || counts[scan.StatusFail] != 9 || counts[scan.StatusUnknown] != 7 {
		panic(fmt.Sprintf("expectedProfileA sums to %d pass / %d fail / %d unknown, want 10/9/7 (12/9/5 per CLOSURE_TABLE.md row 20, minus the two corrections above)",
			counts[scan.StatusPass], counts[scan.StatusFail], counts[scan.StatusUnknown]))
	}
}

// registryMatrixBC is research/CHECK_REGISTRY.md §5.3, columns B and C,
// transcribed as documented ranges (the registry itself says "p or f" / "u"
// for these profiles — they are not the reproduction target profile A is).
// Deliberate correction (coordinator-directed, third lab pass): profile C's
// own fixture ships a real, executable /usr/sbin/sshd and a readable
// sshd_config (only some *other* paths are denied — see Dockerfile.profileC
// and profileC's own _modes.txt for what actually is). The lab's runner
// stubs a real, successful `sshd -G` for it (sshdRunnerFor/fault_injection's
// profileC cases), and a real daemon that can answer -G is not "restricted"
// for the SSH family specifically — a genuinely hostile container can still
// happen to have a working, readable sshd. So `pass` here is a legitimate
// outcome of a stubbed-but-real oracle, not an over-claim; it is added to C's
// allowed set rather than forced to unknown.
// Profile B's own fixture (internal/checks/testdata/profileB) is, by design,
// a genuinely minimal image: no /sys/firmware/dmi at all (not even an empty
// directory), no BMC, no TPM class, no /etc/passwd, no /boot, no systemd unit
// tree, no /proc/net. That is not a fixture gap to close — it is the profile's
// entire point (research/CHECK_REGISTRY.md's own "Generic" prose for these
// checks: "no-DMI ⇒ unknown with ENOENT on the directory, a capability class
// absent, not a denial"). Fabricating DMI/BMC/TPM sysfs content for profile B
// to force the narrower "[pass]"-only cells the table's summary column
// implies would defeat the profile's purpose of proving genericness on a host
// that truly has none of those subsystems. Every row below marked "(B: ENOENT
// on the capability, not a denial)" is widened to allow `unknown` for exactly
// that reason — verified in TEST_REPORT.md against the real observed reason
// string (ENOENT on the listing, never EACCES/a confident guess).
var registryMatrixBC = map[string][2]expectedSet{
	"SSH_ROOT_LOGIN_POLICY":           {anyS, passU}, // B: no sshd binary shipped at all -> UTILITY_MISSING
	"SSH_AUTH_METHODS_POLICY":         {anyS, passU}, // B: same
	"SSH_POLICY_IN_FORCE":             {passU, unknown},
	"REMOTE_LISTENING_SURFACE":        {anyS, unknown}, // B: /proc/net not shipped -> UTILITY_MISSING
	"LOGIN_AND_ESCALATION_SURFACE":    {unknown, unknown},
	"HOST_FIREWALL_STATE":             {set(scan.StatusFail, scan.StatusUnknown), unknown},
	"PRIVATE_KEY_MATERIAL_EXPOSURE":   {passU, unknown}, // B: no /etc/passwd -> no candidate scan root at all
	"CREDENTIAL_FILE_EXPOSURE":        {passU, anyS},    // B: /etc/passwd absent (ENOENT), not denied
	"PROVISIONING_DATA_PROTECTION":    {pass, passU},
	"SYSTEM_SECRET_STORE_PROTECTION":  {pass, passU},
	"BMC_INBAND_INTERFACE_PRESENT":    {passU, unknown}, // B: /sys/firmware/dmi/entries ENOENT, capability class absent
	"BMC_RESPONDS_IN_BAND":            {passU, unknown}, // B: /sys/devices/platform/ipmi_bmc.* ENOENT, same
	"BMC_DEVICE_NODE_ACCESS":          {passU, unknown}, // B: /dev/ipmi* ENOENT via /sys, same
	"BMC_CLIENT_TOOLING_INVENTORY":    {passU, pass},    // B: PATH dirs EACCES-listable in this minimal image
	"BMC_HOST_INTERFACE_EXPOSURE":     {passU, unknown}, // B: /sys/class/net ENOENT in this minimal image
	"DISK_ENCRYPTION_AT_REST":         {passF, unknown},
	"ROOT_FILESYSTEM_REDUNDANCY":      {anyS, unknown},  // B: /proc/swaps and /proc/mdstat not shipped -> incomplete, not the registry's "fail" claim
	"UNUSED_ATTACHED_BLOCK_DEVICES":   {passU, unknown}, // B: /proc/swaps ENOENT -> incomplete
	"MEDIA_HEALTH_VISIBILITY":         {unknown, unknown},
	"SECURE_BOOT_ENABLED":             {anyS, unknown},
	"UEFI_PLATFORM_SETUP_MODE":        {anyS, unknown},
	"KERNEL_LOCKDOWN_MODE":            {set(scan.StatusFail, scan.StatusUnknown), unknown},
	"UNSIGNED_OR_OUT_OF_TREE_MODULES": {anyS, set(scan.StatusFail, scan.StatusUnknown)}, // B: /proc/sys/kernel/tainted not shipped
	"TPM_PRESENCE":                    {passU, unknown},                                 // B: /sys/class/tpm ENOENT in this minimal image
	"BOOT_ARTIFACT_READABILITY":       {passF, pass},
	"BOOT_KERNEL_DRIFT":               {anyS, anyS}, // not in the registry's §5.3 table (added after it was drafted)
}

// TestProfileMatrix_ProfileA_HardGate is the promotion CLOSURE_TABLE.md row 18
// and the external review's "Tests" item 1 and item 3 (item 3: "the change
// that makes the existing one worth having") both ask for: every mismatch
// against expectedProfileA is a build failure (t.Errorf), not a log line.
func TestProfileMatrix_ProfileA_HardGate(t *testing.T) {
	// profileA's _modes.txt now chmods /root, /dev/ipmi0 and a boot artifact to
	// non-default modes (root 0000, dev/ipmi0 0600, the initramfs 0600) to be
	// faithful to the real host's actual permissions. os.Chmod is a no-op for
	// these bits on Windows and this package's symlink materialisation is only
	// reliable on Linux (fixture_test.go-style convention used throughout this
	// codebase), so this whole gate is Linux-only: running it on Windows would
	// silently produce a different, platform-dependent distribution rather than
	// a real pass/fail, which is exactly the "non-reproducible across runs"
	// defect the fresh adversarial review caught (H3) — this guard is the fix.
	requireLinux(t)
	skipIfRoot(t)
	root := buildAuthorProfile(t, "profileA")
	runner := profileARunner()
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
	t.Logf("profile A observed distribution: %d pass / %d fail / %d unknown (target: 10/9/7 — see expectedProfileA's two corrections)",
		counts[scan.StatusPass], counts[scan.StatusFail], counts[scan.StatusUnknown])
}

// TestProfileMatrix_ProfilesBC_HardGate is the same promotion for profiles B
// and C: every status outside the registry's documented range is a build
// failure, not a log line.
func TestProfileMatrix_ProfilesBC_HardGate(t *testing.T) {
	// profileC's _modes.txt chmods /root and a boot artifact (same reasoning
	// as TestProfileMatrix_ProfileA_HardGate above); Linux-only for the same
	// reason.
	requireLinux(t)
	skipIfRoot(t)
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
	// profileC's _modes.txt now includes chmod entries (see
	// TestProfileMatrix_ProfilesBC_HardGate); guarded for the same reason even
	// though none of the checks asserted on below currently depend on them, so
	// this stays true if that ever changes.
	requireLinux(t)
	skipIfRoot(t)
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
