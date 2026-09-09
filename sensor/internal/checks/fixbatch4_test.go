package checks

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// Fix batch 4 — REVIEW_FINDINGS_3, closure rows 42-48.
//
// The whole batch has one root cause: the sensor's model of "who can reach this
// object" counted the file's OWNER as another member of its own primary group,
// and asked the READ bit of a directory when the question was traversal. Every
// test below is written against a layout a stock distribution actually ships,
// because that is what the defect hid behind.

func gidStr() string { return strconv.Itoa(os.Getgid()) }

// ---------------------------------------------------------------------------
// Row 42 (R3-C, CRITICAL): the owner is not another reader of its own file.
// ---------------------------------------------------------------------------

func TestR3C_OwnerIsNotAnotherReaderOfItsOwnFile(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// /etc/sudoers 0440 root:root, the mode every Debian, Ubuntu and RHEL host
	// ships. Group root's only effective member is root, which owns the file.
	root := tree(t, map[string]string{
		"/etc/passwd":           passwdFile,
		"/etc/group":            "root:x:0:\nubuntu:x:" + gidStr() + ":\n",
		"/etc/sudoers":          "root ALL=(ALL:ALL) ALL\n",
		"/etc/sudoers.d/README": "#\n",
	})
	chmod(t, root, "/etc/sudoers", 0o440)
	chmod(t, root, "/etc/sudoers.d/README", 0o440)
	chmod(t, root, "/etc/sudoers.d", 0o755)
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	if f.Status != scan.StatusPass {
		t.Errorf("0440 root:root is reachable by its owner alone; got %s/%s: %s", f.Status, f.Reason, f.Evidence.Detail)
	}

	root2 := tree(t, map[string]string{
		"/etc/passwd":               passwdFile,
		"/etc/group":                "root:x:0:\nubuntu:x:" + gidStr() + ":\n",
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
	})
	chmod(t, root2, "/etc/ssh/ssh_host_rsa_key", 0o640)
	f2 := runCheck(t, root2, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f2.Status != scan.StatusPass {
		t.Errorf("0640 key whose group has only the owner: got %s/%s: %s", f2.Status, f2.Reason, f2.Evidence.Detail)
	}
}

func TestReadersSubtractsTheOwner(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd": "root:x:0:0:root:/root:/bin/bash\npostgres:x:1500:1500::/var/lib/postgresql:/bin/bash\n",
		"/etc/group":  "root:x:0:\npostgres:x:1500:\n",
	})
	env := newTestEnv(t, root, newFakeRunner())
	mode, rootUID, rootGID := int64(0o440), int64(0), int64(0)
	r := env.Readers(&mode, &rootUID, &rootGID)
	if !r.Determined || r.BeyondOwner {
		t.Errorf("0440 root:root must be owner-only, got %+v", r)
	}
	// The same group, a DIFFERENT owner: now group root does have a reader
	// beyond the owner, and the answer has to flip.
	pgUID := int64(1500)
	r2 := env.Readers(&mode, &pgUID, &rootGID)
	if !r2.Determined || !r2.BeyondOwner {
		t.Errorf("0440 postgres:root is readable by root, who is not the owner: %+v", r2)
	}
}

// ---------------------------------------------------------------------------
// Row 43 (R3-B, HIGH): an undetermined account model is UNKNOWN, never a fail.
// ---------------------------------------------------------------------------

func TestR3B_UndeterminedGroupModelIsUnknownNotFail(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	for _, deny := range []string{"/etc/passwd", "/etc/group"} {
		root := tree(t, map[string]string{
			"/etc/passwd": passwdFile,
			"/etc/group":  "root:x:0:\nshadow:x:" + gidStr() + ":\n",
			"/etc/shadow": "root:*:19000:0:99999:7:::\n",
		})
		chmod(t, root, "/etc/shadow", 0o640)
		chmod(t, root, deny, 0o000)
		f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
		if f.Status != scan.StatusUnknown {
			t.Errorf("%s unreadable: want unknown, got %s/%s: %s", deny, f.Status, f.Reason, f.Evidence.Detail)
		}

		root2 := tree(t, map[string]string{
			"/etc/passwd":                   passwdFile,
			"/etc/group":                    "root:x:0:\nkeys:x:" + gidStr() + ":\n",
			"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
		})
		chmod(t, root2, "/etc/ssh/ssh_host_ed25519_key", 0o640)
		chmod(t, root2, deny, 0o000)
		f2 := runCheck(t, root2, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
		if f2.Status == scan.StatusFail {
			t.Errorf("%s unreadable (PRIVATE_KEY): an unknown reader set was reported as exposure: %s", deny, f2.Evidence.Detail)
		}
		if f2.Status == scan.StatusPass {
			t.Errorf("%s unreadable (PRIVATE_KEY): an unknown reader set must not pass either", deny)
		}
	}
}

func TestUndeterminedGidIsNeitherExposureNorSafety(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// gid 900 is served by a directory service this sensor cannot query: it is
	// in neither file. "We cannot say who is in it" is not "nobody is in it".
	root := tree(t, map[string]string{
		"/etc/passwd": passwdFile,
		"/etc/group":  "root:x:0:\n" + ownGroupLine(),
	})
	env := newTestEnv(t, root, newFakeRunner())
	mode, uid, gid := int64(0o640), int64(0), int64(900)
	r := env.Readers(&mode, &uid, &gid)
	if r.Determined {
		t.Errorf("a gid in neither database cannot be resolved: %+v", r)
	}
	if r.BeyondOwner {
		t.Errorf("undetermined must not be asserted as an exposure: %+v", r)
	}
	if r.Reason == "" || !scan.ReasonVocabulary[r.Reason] {
		t.Errorf("an undetermined answer carries a vocabulary reason, got %q", r.Reason)
	}
}

// ---------------------------------------------------------------------------
// Row 44 (R3-A, HIGH): protection is decided by the TRAVERSE bit.
// ---------------------------------------------------------------------------

func TestR3A_GroupTraversableAncestorIsNotProtection(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// The Ubuntu shape: /etc/ssl/private has no group-READ bit at all, yet
	// every member of its group can walk in and open a 0640 key inside.
	root := tree(t, map[string]string{
		"/etc/passwd":                   passwdFile + "postgres:x:1500:1500::/var/lib/postgresql:/bin/bash\n",
		"/etc/group":                    "root:x:0:\nsslcert:x:" + gidStr() + ":postgres\n",
		"/etc/ssl/private/snakeoil.key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssl/private/snakeoil.key", 0o640)
	chmod(t, root, "/etc/ssl/private", 0o010)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status == scan.StatusPass {
		t.Errorf("group-traversable ancestor with a populated group is not protection: %s", f.Evidence.Detail)
	}
	f2 := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	ev2 := evidenceOf(t, f2)
	if n, _ := ev2["protected_by_ancestor"].(float64); n > 0 {
		t.Errorf("protected_by_ancestor=%v for a directory postgres can traverse", n)
	}
}

func TestTraversersUsesTheExecuteBitNotTheReadBit(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd": passwdFile + "postgres:x:1500:1500::/var/lib/postgresql:/bin/bash\n",
		"/etc/group":  "root:x:0:\nsslcert:x:900:postgres\n",
	})
	env := newTestEnv(t, root, newFakeRunner())
	mode, uid, gid := int64(0o710), int64(0), int64(900)
	if trav := env.Traversers(&mode, &uid, &gid); !trav.BeyondOwner {
		t.Errorf("0710 root:sslcert is traversable by postgres: %+v", trav)
	}
	if rd := env.Readers(&mode, &uid, &gid); rd.BeyondOwner {
		t.Errorf("0710 has no group-read bit, so nobody beyond the owner READS it: %+v", rd)
	}
	// 0700: neither.
	mode = 0o700
	if trav := env.Traversers(&mode, &uid, &gid); trav.BeyondOwner {
		t.Errorf("0700 shields what is behind it: %+v", trav)
	}
}

// ---------------------------------------------------------------------------
// Row 45 (R3-I, HIGH): a denial judged protection is opted out, once, centrally.
// ---------------------------------------------------------------------------

func TestR3I_ProtectedSecretStoreIsPassNotPermanentUnknown(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":            "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":             "root:x:0:\n" + ownGroupLine(),
		"/etc/ssl/private/x.key": pemKeyBody,
		"/etc/shadow":            "root:*:1::::::\n",
	})
	chmod(t, root, "/etc/shadow", 0o640)
	chmod(t, root, "/etc/ssl/private", 0o000)
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	if f.Status != scan.StatusPass {
		t.Errorf("a denial counted as protection must not also downgrade the verdict: got %s/%s: %s",
			f.Status, f.Reason, f.Evidence.Detail)
	}
	found := false
	for _, o := range f.Evidence.Observations {
		if strings.HasPrefix(o.OptOut, "protection (ancestor ") {
			found = true
			if !strings.Contains(o.OptOut, "readers beyond owner:") {
				t.Errorf("the opt-out must name the reader set it relied on: %q", o.OptOut)
			}
		}
	}
	if !found {
		t.Errorf("no observation carries the shared protection opt-out text")
	}
}

func TestProtectionOptOutTextIsSharedByEveryExposureCheck(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":               passwdFile,
		"/etc/group":                "root:x:0:\n" + ownGroupLine(),
		"/root/anaconda-ks.cfg":     "#version=RHEL9\n",
		"/root/.pgpass":             "x\n",
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o600)
	chmod(t, root, "/root", 0o000)
	for _, id := range []string{"PROVISIONING_DATA_PROTECTION", "CREDENTIAL_FILE_EXPOSURE", "PRIVATE_KEY_MATERIAL_EXPOSURE"} {
		f := runCheck(t, root, newFakeRunner(), id)
		if f.Status != scan.StatusPass {
			t.Errorf("%s: an unenterable /root answers the exposure question; got %s/%s: %s",
				id, f.Status, f.Reason, f.Evidence.Detail)
		}
	}
}

// ---------------------------------------------------------------------------
// Row 46 (R3-E, M1/M2): proven exposure beats incompleteness.
// ---------------------------------------------------------------------------

func TestR3E_UnreadableMountTableCannotHideAFoundKey(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":               passwdFile,
		"/etc/group":                "root:x:0:\n",
		"/proc/self/mountinfo":      "x\n",
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o644)
	chmod(t, root, "/proc/self/mountinfo", 0o000)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status != scan.StatusFail {
		t.Errorf("a world-readable key was observed directly; incompleteness elsewhere cannot soften it: %s/%s: %s",
			f.Status, f.Reason, f.Evidence.Detail)
	}
}

func TestWalkObservationIsCopiedOnlyOnceItsTruncationIsFinal(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// One unreadable subtree, and it is shielded: the walk is then not a prefix
	// of a longer one, and the recorded observation must not still say it was.
	root := tree(t, map[string]string{
		"/etc/passwd":               passwdFile,
		"/etc/group":                "root:x:0:\n" + ownGroupLine(),
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
		"/etc/ssl/private/x.key":    pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o600)
	chmod(t, root, "/etc/ssl/private", 0o000)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status != scan.StatusPass {
		t.Fatalf("want pass, got %s/%s: %s", f.Status, f.Reason, f.Evidence.Detail)
	}
	for _, o := range f.Evidence.Observations {
		if o.ObservationType == string(probe.KindDirWalk) && o.Source == "/etc/ssl" && o.Truncated {
			t.Errorf("the /etc/ssl walk is recorded truncated although every subtree it missed is shielded")
		}
	}
}

// ---------------------------------------------------------------------------
// Row 47 (R3-G, M3): symlinked walk roots, and a closed reason vocabulary.
// ---------------------------------------------------------------------------

func TestR3G_SymlinkedWalkRootIsFollowedOnce(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":                   passwdFile,
		"/etc/group":                    "root:x:0:\n",
		"/data/homes/alice/.ssh/id_rsa": pemKeyBody,
	})
	chmod(t, root, "/data/homes/alice/.ssh/id_rsa", 0o644)
	if err := os.Symlink(filepath.Join(root, "data", "homes"), filepath.Join(root, "home")); err != nil {
		t.Skip(err)
	}
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status != scan.StatusFail {
		t.Errorf("a world-readable key under the real /home must be found: got %s/%s: %s", f.Status, f.Reason, f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	followed, _ := ev["root_symlink_followed"].([]any)
	if len(followed) == 0 {
		t.Errorf("following a symlinked root is a fact about the search and must be recorded: %v", ev["root_symlink_followed"])
	}
}

func TestSymlinkedWalkRootToAWritableTargetIsRefusedInWords(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":                   passwdFile,
		"/etc/group":                    "root:x:0:\n",
		"/data/homes/alice/.ssh/id_rsa": pemKeyBody,
	})
	chmod(t, root, "/data/homes/alice/.ssh/id_rsa", 0o644)
	if err := os.Symlink(filepath.Join(root, "data", "homes"), filepath.Join(root, "home")); err != nil {
		t.Skip(err)
	}
	// A target another account can replace would let that account choose what
	// this sensor reports; the walk declines and says so.
	chmod(t, root, "/data/homes", 0o777)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status == scan.StatusPass {
		t.Errorf("a root that was not enumerated cannot support a pass: %s", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	skipped, _ := ev["scan_roots_not_enumerated"].([]any)
	if len(skipped) == 0 {
		t.Fatalf("the refusal must be recorded, got %v", ev["scan_roots_not_enumerated"])
	}
	if s, _ := skipped[0].(string); !strings.Contains(s, "writable by other accounts") {
		t.Errorf("the reason must say what was wrong, got %q", s)
	}
}

func TestEveryFindingReasonIsInTheClosedVocabulary(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// Several shapes at once, including the ones that used to produce ENOTREG,
	// ENOTDIR and ENOTSUP: no internal errno token may reach a finding.
	root := tree(t, map[string]string{
		"/etc/passwd":                   passwdFile,
		"/etc/group":                    "root:x:0:\n" + ownGroupLine(),
		"/proc/self/mountinfo":          "22 1 8:1 / / rw - ext4 /dev/sda1 rw\n",
		"/data/homes/alice/.ssh/id_rsa": pemKeyBody,
		"/etc/ssh/ssh_host_rsa_key":     pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o600)
	if err := os.Symlink(filepath.Join(root, "data", "homes", "alice", ".ssh", "id_rsa"), filepath.Join(root, "home")); err != nil {
		t.Skip(err)
	}
	env := newTestEnv(t, root, newFakeRunner())
	findings, _ := scan.Run(context.Background(), All(), env)
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range findings {
		if f.Reason == "" {
			continue
		}
		if !scan.ReasonVocabulary[f.Reason] {
			t.Errorf("%s: reason %q is outside the closed vocabulary", f.CheckID, f.Reason)
		}
	}
}

func TestNormalizeReasonMapsEveryInternalToken(t *testing.T) {
	for _, tok := range []string{"ENOTREG", "ENOTDIR", "ENOTSUP", "ELOOP", "EISDIR", "ENXIO", "ENODATA"} {
		got := scan.NormalizeReason(tok)
		if !scan.ReasonVocabulary[got] {
			t.Errorf("NormalizeReason(%q) = %q, outside the vocabulary", tok, got)
		}
		if got == tok {
			t.Errorf("%q reached a finding unchanged", tok)
		}
	}
	if scan.NormalizeReason(scan.ReasonEACCES) != scan.ReasonEACCES {
		t.Errorf("a vocabulary reason must pass through unchanged")
	}
	if scan.NormalizeReason("") != "" {
		t.Errorf("a pass has no reason and must keep none")
	}
}

// ---------------------------------------------------------------------------
// Row 48: the Lows.
// ---------------------------------------------------------------------------

// L1: declining to touch network storage is a decision, not an exhausted budget.
func TestR3F_NetworkRootRefusalIsNotABudgetExhaustion(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	mi := "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
		"36 22 0:32 / /home rw,relatime shared:2 - nfs4 fileserver:/export/home rw,vers=4.2\n"
	root := tree(t, map[string]string{
		"/etc/passwd":               passwdFile,
		"/etc/group":                "root:x:0:\n",
		"/proc/self/mountinfo":      mi,
		"/home/alice/.ssh/id_rsa":   pemKeyBody,
		"/etc/ssh/ssh_host_rsa_key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssh/ssh_host_rsa_key", 0o600)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status != scan.StatusUnknown {
		t.Errorf("want unknown (home not walked), got %s", f.Status)
	}
	if f.Reason != scan.ReasonNotAttempted {
		t.Errorf("a deliberate refusal is NOT_ATTEMPTED, got %q", f.Reason)
	}
}

// L2: the absence-prose gate is defence in depth, so it covers the wordings a
// check could reach for next.
type r3Smuggler struct{}

func (r3Smuggler) ID() string            { return "R3_SMUGGLER" }
func (r3Smuggler) Category() string      { return "TEST_CATEGORY" }
func (r3Smuggler) Title() string         { return "x" }
func (r3Smuggler) Impact() string        { return scan.SeverityHigh }
func (r3Smuggler) Observational() bool   { return false }
func (r3Smuggler) Budget() time.Duration { return time.Second }
func (r3Smuggler) Run(context.Context, *scan.Env) scan.Result {
	r := scan.Pass("the search did not find any exposed key; 0 candidates, every root covered")
	r.Add(probe.Observation{Source: "/etc/hostname", Kind: probe.KindFileRead, Status: probe.StatusOK, Value: "h"})
	r.Add(probe.Observation{Source: "/root", Kind: probe.KindDirWalk, Status: probe.StatusEACCES, Errno: "EACCES", OptOut: "background"})
	return r
}

func TestR3H_AbsenceProseIsRejectedHoweverItIsWorded(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	fs, _ := scan.Run(context.Background(), []scan.Check{r3Smuggler{}}, env)
	if fs[0].Status == scan.StatusPass && !fs[0].EntailmentViolation {
		t.Errorf("a check-authored completeness claim must be flagged: %s", fs[0].Evidence.Detail)
	}
}

// L3: the reason names the failure the detail names.
func TestSSHPolicyReasonFollowsTheFailingObservation(t *testing.T) {
	root := tree(t, map[string]string{
		"/usr/sbin/sshd":       "#!/bin/sh\n",
		"/etc/ssh/sshd_config": "PermitRootLogin no\n",
	})
	f := runCheck(t, root, newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no")), "SSH_POLICY_IN_FORCE")
	if f.Status == scan.StatusPass {
		return // the daemon state resolved; nothing to check here
	}
	if !scan.ReasonVocabulary[f.Reason] {
		t.Fatalf("reason %q outside the vocabulary", f.Reason)
	}
	if strings.Contains(f.Evidence.Detail, "UTILITY_MISSING") && f.Reason == scan.ReasonEINVAL {
		t.Errorf("the detail names a missing utility while the reason says EINVAL: %q / %s", f.Reason, f.Evidence.Detail)
	}
}

// L4: bmc.go asks the same account model as everything else.
func TestR3L4_BMCNodeUsesTheSharedAccountModel(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// 0660 root:root: group root's only member is the owner.
	root := tree(t, map[string]string{
		"/etc/passwd": passwdFile,
		"/etc/group":  "root:x:0:\n" + ownGroupLine(),
		"/dev/ipmi0":  "",
	})
	chmod(t, root, "/dev/ipmi0", 0o660)
	f := runCheck(t, root, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	if f.Status == scan.StatusFail {
		t.Errorf("0660 root:root grants nothing beyond the owner: %s", f.Evidence.Detail)
	}
	// The same node with a populated group must still be adverse. The fixture
	// node is owned by the test account, so the group that gains a member
	// beyond the owner is the test account's own group.
	root2 := tree(t, map[string]string{
		"/etc/passwd": passwdFile + "operator:x:1600:1600::/h:/bin/bash\n",
		"/etc/group":  "root:x:0:\ntestgroup:x:" + gidStr() + ":operator\n",
		"/dev/ipmi0":  "",
	})
	chmod(t, root2, "/dev/ipmi0", 0o660)
	f2 := runCheck(t, root2, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	if f2.Status == scan.StatusPass {
		t.Errorf("a node whose group has a member beyond the owner is reachable by that member: %s", f2.Evidence.Detail)
	}
}

// L5: an absent credential candidate is an observation of absence, not silence.
func TestR3L5_AbsentCredentialCandidatesAreRecorded(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":              passwdFile,
		"/etc/group":               "root:x:0:\n" + ownGroupLine(),
		"/home/ubuntu/.ssh/config": "Host *\n",
	})
	chmod(t, root, "/home/ubuntu/.ssh/config", 0o600)
	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	if f.Status != scan.StatusPass {
		t.Fatalf("want pass, got %s/%s: %s", f.Status, f.Reason, f.Evidence.Detail)
	}
	absent := 0
	for _, o := range f.Evidence.Observations {
		if o.AbsenceProven {
			absent++
		}
	}
	if absent == 0 {
		t.Errorf("a pass that rests on candidates not being there must show the stats that proved it")
	}
}

// L6: a rule the software writes about MODE BITS is tested on mode bits.
func TestR3L6_ModeBitRulesAreTestedOnModeBits(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// libpq refuses a group-readable .pgpass whether or not the group has a
	// member: the predicate must match the sentence the finding cites.
	root := tree(t, map[string]string{
		"/etc/passwd":          passwdFile,
		"/etc/group":           "root:x:0:\n" + ownGroupLine(),
		"/home/ubuntu/.pgpass": "h:5432:db:user:pw\n",
	})
	chmod(t, root, "/home/ubuntu/.pgpass", 0o640)
	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	if f.Status != scan.StatusFail {
		t.Errorf("a 0640 .pgpass violates libpq's own rule regardless of group membership: got %s/%s: %s",
			f.Status, f.Reason, f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// Rows 28-41 re-verification: the R2 fixtures, kept green by this batch.
// ---------------------------------------------------------------------------

func TestR2A_UnreadableGroupReadableKeyStillFails(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":      passwdFile + "a:x:1501:1501::/h:/bin/bash\nb:x:1502:1502::/h:/bin/bash\n",
		"/etc/group":       "root:x:0:\nsslcert:x:" + gidStr() + ":a,b\n",
		"/etc/ssl/app.key": pemKeyBody,
	})
	chmod(t, root, "/etc/ssl/app.key", 0o040)
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status == scan.StatusPass {
		t.Errorf("a key readable by two other accounts is exposed: %s", f.Evidence.Detail)
	}
}

func TestR2D2_StockSudoersDDoesNotFail(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":           "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":            "root:x:0:\n" + ownGroupLine(),
		"/etc/sudoers":          "x\n",
		"/etc/sudoers.d/README": "x\n",
	})
	chmod(t, root, "/etc/sudoers", 0o440)
	chmod(t, root, "/etc/sudoers.d/README", 0o440)
	chmod(t, root, "/etc/sudoers.d", 0o755)
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	if f.Status == scan.StatusFail {
		t.Errorf("the stock sudo layout is not an exposure: %s", f.Evidence.Detail)
	}
}

func TestR3D_RootDir0550IsStillProtection(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":           passwdFile,
		"/etc/group":            "root:x:0:\nubuntu:x:" + gidStr() + ":\n",
		"/root/anaconda-ks.cfg": "#version=RHEL9\n",
		"/root/.pgpass":         "x\n",
	})
	chmod(t, root, "/root", 0o050)
	if f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION"); f.Status != scan.StatusPass {
		t.Errorf("PROVISIONING: /root 0550 whose group has only the owner shields its contents; got %s/%s: %s",
			f.Status, f.Reason, f.Evidence.Detail)
	}
	if f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE"); f.Status != scan.StatusPass {
		t.Errorf("CREDENTIAL: got %s/%s: %s", f.Status, f.Reason, f.Evidence.Detail)
	}
}
