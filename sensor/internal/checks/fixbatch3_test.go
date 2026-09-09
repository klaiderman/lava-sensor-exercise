package checks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// Regression tests for fix batch 3. The theme is one distinction: an EXPOSURE
// question and an EXISTENCE question read a denial in opposite directions.

// ---------------------------------------------------------------------------
// Row 28 / R2-A: a candidate we could not read is not a candidate we may drop
// ---------------------------------------------------------------------------

func TestPrivateKey_UnreadableCandidateIsJudgedFromItsMode(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":      passwdFile + "reader:x:1500:1500::/home/reader:/bin/bash\n",
		"/etc/group":       "root:x:0:\nsslcert:x:1500:reader\n",
		"/etc/ssl/app.key": pemKeyBody,
	})
	// Readable by a populated group, not by us: the 64-byte sniff gets EACCES.
	chown := filepath.Join(root, filepath.FromSlash("etc/ssl/app.key"))
	if err := os.Chmod(chown, 0o040); err != nil {
		t.Fatal(err)
	}
	f := runCheck(t, root, newFakeRunner(), "PRIVATE_KEY_MATERIAL_EXPOSURE")
	if f.Status == scan.StatusPass {
		t.Fatalf("a key we could not read, readable by a populated group, must not produce a pass: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	found := false
	for _, h := range ev["private_key_files"].([]any) {
		if m := h.(map[string]any); strings.HasSuffix(m["path"].(string), "app.key") {
			found = true
			if !strings.Contains(m["magic_class"].(string), "unclassified") {
				t.Errorf("an unread candidate must be kept and marked unclassified: %v", m)
			}
		}
	}
	if !found {
		t.Errorf("the candidate was dropped instead of judged: %v", ev["private_key_files"])
	}
}

// ---------------------------------------------------------------------------
// Rows 29, 33 / R2-B, R2-D: who is in a group
// ---------------------------------------------------------------------------

func TestEffectiveReaders_PrimaryGidCounts(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// mallory's PRIMARY gid is the file's group, and she appears in no member
	// list. Counting only /etc/group field 4 calls this group empty.
	root := tree(t, map[string]string{
		"/etc/passwd":                   "root:x:0:0:root:/root:/bin/bash\nmallory:x:1001:900::/home/mallory:/bin/bash\n",
		"/etc/group":                    "root:x:0:\nsecret:x:900:\n",
		"/etc/ssh/ssh_host_ed25519_key": pemKeyBody,
	})
	if err := os.Chmod(filepath.Join(root, filepath.FromSlash("etc/ssh/ssh_host_ed25519_key")), 0o640); err != nil {
		t.Fatal(err)
	}
	env := newTestEnv(t, root, newFakeRunner())
	gid := int64(900)
	mode := int64(0o640)
	readers := env.Readers(&mode, &gid)
	if !readers.BeyondOwner {
		t.Errorf("an account whose primary gid is the file's group reads the file: %+v", readers)
	}
	if len(readers.GroupMember) == 0 || readers.GroupMember[0] != "mallory" {
		t.Errorf("effective members = %v, want mallory", readers.GroupMember)
	}
}

func TestGroupDBDenied_IsUnknownNotEmpty(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd": passwdFile,
		"/etc/group":  "root:x:0:\nshadow:x:42:someone\n",
		"/etc/shadow": "root:!:19000:0:99999:7:::\n",
	})
	chmod(t, root, "/etc/shadow", 0o640)
	chmod(t, root, "/etc/group", 0o000)
	env := newTestEnv(t, root, newFakeRunner())
	if env.Groups().Determined() {
		t.Fatalf("an unreadable /etc/group must not produce a determined group model")
	}
	gid := int64(42)
	mode := int64(0o640)
	readers := env.Readers(&mode, &gid)
	if readers.Determined {
		t.Errorf("group-based reasoning must be unknown when the database is unreadable: %+v", readers)
	}
	if !readers.BeyondOwner {
		t.Errorf("an unknown reader set is not an empty one: %+v", readers)
	}
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	if f.Status == scan.StatusPass {
		t.Errorf("a group-readable /etc/shadow with an unreadable group database must not pass: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// Row 30 / R2-D2: stock sudo ships a world-listable /etc/sudoers.d
// ---------------------------------------------------------------------------

func TestSecretStore_StockSudoersDIsNotExposure(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":           "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":            "root:x:0:\n" + ownGroupLine(),
		"/etc/sudoers":          "root ALL=(ALL:ALL) ALL\n",
		"/etc/sudoers.d/README": "As a special exception...\n",
	})
	chmod(t, root, "/etc/sudoers", 0o440)
	chmod(t, root, "/etc/sudoers.d/README", 0o440)
	chmod(t, root, "/etc/sudoers.d", 0o755) // exactly what the sudo package ships
	f := runCheck(t, root, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	if f.Status == scan.StatusFail {
		t.Fatalf("the stock sudo layout must not fail: %q", f.Evidence.Detail)
	}

	// A readable drop-in inside that same directory is the real exposure.
	root2 := tree(t, map[string]string{
		"/etc/passwd":             "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/group":              "root:x:0:\n" + ownGroupLine(),
		"/etc/sudoers.d/90-cloud": "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
	})
	chmod(t, root2, "/etc/sudoers.d/90-cloud", 0o644)
	chmod(t, root2, "/etc/sudoers.d", 0o755)
	f2 := runCheck(t, root2, newFakeRunner(), "SYSTEM_SECRET_STORE_PROTECTION")
	wantStatus(t, f2, scan.StatusFail)
	if !strings.Contains(f2.Evidence.Detail, "90-cloud") {
		t.Errorf("the readable file, not the directory, must be named: %q", f2.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// Row 31 / R2-C: the predicate is the rule that was cited
// ---------------------------------------------------------------------------

func TestCredentialRules_PredicateMatchesRuleText(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	// 0644 ~/.ssh/config is the default on every distribution and StrictModes
	// objects to WRITABLE, not readable.
	root := tree(t, map[string]string{
		"/etc/passwd":              passwdFile,
		"/etc/group":               "root:x:0:\nubuntu:x:1000:\n",
		"/home/ubuntu/.ssh/config": "Host *\n  ServerAliveInterval 60\n",
	})
	chmod(t, root, "/home/ubuntu/.ssh/config", 0o644)
	f := runCheck(t, root, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	if f.Status == scan.StatusFail {
		t.Fatalf("a 0644 ~/.ssh/config is the documented default and must not fail: %q", f.Evidence.Detail)
	}

	// 0664 is what the rule actually objects to.
	root2 := tree(t, map[string]string{
		"/etc/passwd":              passwdFile,
		"/etc/group":               "root:x:0:\nubuntu:x:1000:ubuntu,other\n",
		"/home/ubuntu/.ssh/config": "Host *\n",
	})
	chmod(t, root2, "/home/ubuntu/.ssh/config", 0o664)
	f2 := runCheck(t, root2, newFakeRunner(), "CREDENTIAL_FILE_EXPOSURE")
	wantStatus(t, f2, scan.StatusFail)
	if !strings.Contains(f2.Evidence.Detail, "writable") {
		t.Errorf("the reason must be the writability the rule names: %q", f2.Evidence.Detail)
	}

	// And the rule text and the predicate come from one declaration.
	for _, cr := range homeCredentialRules {
		if cr.rel == ".ssh/config" && cr.kind != kindNotWritableByOthers {
			t.Errorf("~/.ssh/config must be judged on writability")
		}
		if cr.rel == ".pgpass" && cr.kind != kindNotReadableByOthers {
			t.Errorf(".pgpass must be judged on readability")
		}
		if !strings.Contains(cr.rule(), "writable") && !strings.Contains(cr.rule(), "readable") {
			t.Errorf("rule text for %s is not derived from its kind: %q", cr.rel, cr.rule())
		}
	}
}

// ---------------------------------------------------------------------------
// Row 32 / R2-G: the gate is not a phrase blacklist
// ---------------------------------------------------------------------------

func TestEntailment_UnlistedAbsenceProseIsCaught(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	findings, _ := scan.Run(context.Background(), []scan.Check{freshlyWordedLiar{}}, env)
	f := findings[0]
	if f.Status == scan.StatusPass {
		t.Fatalf("an absence claim worded around the phrase list must not ship as a pass: %q", f.Evidence.Detail)
	}
	if !f.EntailmentViolation {
		t.Errorf("the violation must be recorded")
	}
}

type freshlyWordedLiar struct{}

func (freshlyWordedLiar) ID() string            { return "FRESHLY_WORDED" }
func (freshlyWordedLiar) Category() string      { return "TEST_CATEGORY" }
func (freshlyWordedLiar) Title() string         { return "A check wording its way around the phrase list" }
func (freshlyWordedLiar) Impact() string        { return scan.SeverityHigh }
func (freshlyWordedLiar) Observational() bool   { return false }
func (freshlyWordedLiar) Budget() time.Duration { return time.Second }
func (freshlyWordedLiar) Run(context.Context, *scan.Env) scan.Result {
	r := scan.Pass("no exposed key material was found anywhere on this machine")
	r.Add(probe.Observation{Source: "/root", Kind: probe.KindDirWalk, Status: probe.StatusEACCES, Errno: "EACCES"})
	return r
}

// A verdict with nothing behind it is not a verdict, however it is worded.
func TestEntailment_VerdictWithoutEvidenceIsNoEvidence(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	findings, _ := scan.Run(context.Background(), []scan.Check{witnesslessCheck{}}, env)
	f := findings[0]
	wantStatus(t, f, scan.StatusUnknown)
	if f.Reason != scan.ReasonNoEvidence {
		t.Errorf("reason = %q, want NO_EVIDENCE", f.Reason)
	}
}

type witnesslessCheck struct{}

func (witnesslessCheck) ID() string            { return "WITNESSLESS" }
func (witnesslessCheck) Category() string      { return "TEST_CATEGORY" }
func (witnesslessCheck) Title() string         { return "A check that concludes without looking" }
func (witnesslessCheck) Impact() string        { return scan.SeverityHigh }
func (witnesslessCheck) Observational() bool   { return false }
func (witnesslessCheck) Budget() time.Duration { return time.Second }
func (witnesslessCheck) Run(context.Context, *scan.Env) scan.Result {
	return scan.Pass("everything is in order here")
}

// Opting out is now the deliberate act, and it has to be justified in writing.
func TestEntailment_OptOutRequiresARecordedReason(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	findings, _ := scan.Run(context.Background(), []scan.Check{optOutCheck{}}, env)
	f := findings[0]
	wantStatus(t, f, scan.StatusPass)
	seen := false
	for _, o := range f.Evidence.Observations {
		if o.Source == "/etc/context" {
			seen = true
			if o.OptOut == "" {
				t.Errorf("the exemption must carry its reason into the artifact: %+v", o)
			}
			if o.LoadBearing {
				t.Errorf("an opted-out observation must not read as load-bearing")
			}
		}
	}
	if !seen {
		t.Errorf("the opted-out observation must still appear in the evidence")
	}
}

type optOutCheck struct{}

func (optOutCheck) ID() string            { return "OPT_OUT" }
func (optOutCheck) Category() string      { return "TEST_CATEGORY" }
func (optOutCheck) Title() string         { return "A check with one observation that is context only" }
func (optOutCheck) Impact() string        { return scan.SeverityLow }
func (optOutCheck) Observational() bool   { return false }
func (optOutCheck) Budget() time.Duration { return time.Second }
func (optOutCheck) Run(context.Context, *scan.Env) scan.Result {
	r := scan.Pass("the observed setting is the safe one")
	r.Add(probe.Observation{Source: "/etc/verdict", Kind: probe.KindFileRead, Status: probe.StatusOK, Value: "safe"})
	r.Add(probe.Observation{Source: "/etc/context", Kind: probe.KindFileRead, Status: probe.StatusEACCES, Errno: "EACCES",
		OptOut: "recorded as background; the verdict is taken from /etc/verdict"})
	return r
}

// ---------------------------------------------------------------------------
// Row 35 / R2-E2: a 0700 /root is the ordinary case on every host
// ---------------------------------------------------------------------------

func TestProvisioning_UnreadableRootDirIsProtectionNotAGap(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":                           passwdFile,
		"/etc/group":                            "root:x:0:\n",
		"/root/anaconda-ks.cfg":                 "#version=RHEL9\n",
		"/var/lib/cloud/instance/user-data.txt": "#cloud-config\n",
	})
	chmod(t, root, "/var/lib/cloud/instance/user-data.txt", 0o600)
	// The fixture tree is owned by the test user, so 0000 is how a
	// root-owned 0700 /root looks from an unprivileged account.
	chmod(t, root, "/root", 0o000)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f, scan.StatusPass)
	ev := evidenceOf(t, f)
	if n, _ := ev["protected_by_ancestor"].(float64); n < 1 {
		t.Errorf("the denied artifact must be counted as protected, not as a gap: %v", ev["protected_by_ancestor"])
	}
}

// ---------------------------------------------------------------------------
// Row 36 / R2-F: a table that was cut short still showed what it showed
// ---------------------------------------------------------------------------

func TestListeners_TruncatedTableKeepsPartialEvidence(t *testing.T) {
	// A telnet listener inside the prefix, then enough padding rows to blow the
	// read cap.
	body := procNetTCP("00000000:0017", "0A", "999")
	pad := strings.Repeat("   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000 100 0\n", 12000)
	root := tree(t, map[string]string{"/proc/net/tcp": body + pad})
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusFail)
	if !strings.Contains(f.Evidence.Detail, "telnet") {
		t.Errorf("a listener seen inside the prefix must still be reported: %q", f.Evidence.Detail)
	}
	ev := evidenceOf(t, f)
	if ls, _ := ev["listeners"].([]any); len(ls) == 0 {
		t.Errorf("the rows that were read are partial evidence and must be kept")
	}
}

func TestListeners_TruncationWithoutAdverseIsUnknown(t *testing.T) {
	pad := strings.Repeat("   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000 100 0\n", 12000)
	root := tree(t, map[string]string{"/proc/net/tcp": "  sl  local_address\n" + pad})
	f := runCheck(t, root, newFakeRunner(), "REMOTE_LISTENING_SURFACE")
	wantStatus(t, f, scan.StatusUnknown)
	ev := evidenceOf(t, f)
	if tt, _ := ev["truncated_tables"].([]any); len(tt) == 0 {
		t.Errorf("the truncation and the rows read must be named: %v", ev["truncated_tables"])
	}
	if !strings.Contains(f.Evidence.Detail, "row(s)") {
		t.Errorf("the detail must say how much was read: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// Row 37 / R2-I: a machine with no BMC
// ---------------------------------------------------------------------------

func TestBMCNode_ProvenAbsenceIsAnAnswer(t *testing.T) {
	root := tree(t, map[string]string{
		"/etc/passwd": passwdFile,
		"/etc/group":  "root:x:0:\n",
		"/dev/null":   "",
	})
	f := runCheck(t, root, newFakeRunner(), "BMC_DEVICE_NODE_ACCESS")
	wantStatus(t, f, scan.StatusPass)
	if strings.Contains(f.Evidence.Detail, "downgraded") {
		t.Errorf("a proven absence must not be downgraded: %q", f.Evidence.Detail)
	}
}

// ---------------------------------------------------------------------------
// Row 38 / R2-E: a comment is not a configuration key
// ---------------------------------------------------------------------------

func TestProvisioning_CommentIsNotACredentialKey(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	root := tree(t, map[string]string{
		"/etc/passwd":                         passwdFile,
		"/etc/group":                          "root:x:0:\n",
		"/etc/cloud/cloud.cfg.d/90-notes.cfg": "# ssh_pwauth is left at the default; no password is set here\ndatasource_list: [ Ec2 ]\n",
	})
	chmod(t, root, "/etc/cloud/cloud.cfg.d/90-notes.cfg", 0o644)
	f := runCheck(t, root, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	if f.Status == scan.StatusFail {
		t.Fatalf("a comment mentioning a key name must not promote a public drop-in: %q", f.Evidence.Detail)
	}

	real := tree(t, map[string]string{
		"/etc/passwd":                        passwdFile,
		"/etc/group":                         "root:x:0:\n",
		"/etc/cloud/cloud.cfg.d/91-real.cfg": "# provisioning\nssh_pwauth: true\n",
	})
	chmod(t, real, "/etc/cloud/cloud.cfg.d/91-real.cfg", 0o644)
	f2 := runCheck(t, real, newFakeRunner(), "PROVISIONING_DATA_PROTECTION")
	wantStatus(t, f2, scan.StatusFail)
}

func TestDeclaredKeys(t *testing.T) {
	if got := declaredKeys("# ssh_pwauth and password are only mentioned here\n"); len(got) != 0 {
		t.Errorf("comments must be stripped, got %v", got)
	}
	if got := declaredKeys("ssh_pwauth: true\n"); len(got) != 1 || got[0] != "ssh_pwauth" {
		t.Errorf("a real key must be found, got %v", got)
	}
	if got := declaredKeys("some_note: 'the password policy'\n"); len(got) != 0 {
		t.Errorf("a key name inside a VALUE is not a declaration, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Row 40: a check that cannot be interrupted must not take the scan with it
// ---------------------------------------------------------------------------

func TestEngine_StuckCheckIsAbandonedAndOutputIsStillProduced(t *testing.T) {
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	env := newTestEnv(t, root, newFakeRunner())
	stuck := blockedCheck{}
	after := budgetedStub{id: "AFTER_THE_STUCK_ONE", budget: time.Second}

	start := time.Now()
	findings, _ := scan.Run(context.Background(), []scan.Check{stuck, after}, env)
	elapsed := time.Since(start)

	if elapsed > 20*time.Second {
		t.Fatalf("the scan waited %s on a check that never returns", elapsed)
	}
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2: the abandoned check still reports and the next one still runs", len(findings))
	}
	byID := map[string]scan.Finding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	if got := byID["BLOCKED"]; got.Status != scan.StatusUnknown || got.Reason != scan.ReasonTimeout {
		t.Errorf("BLOCKED = %s/%s, want unknown/TIMEOUT", got.Status, got.Reason)
	}
	if !strings.Contains(byID["BLOCKED"].Evidence.Detail, "abandoned") {
		t.Errorf("the detail must say the goroutine was abandoned: %q", byID["BLOCKED"].Evidence.Detail)
	}
	if _, ok := byID["AFTER_THE_STUCK_ONE"]; !ok {
		t.Errorf("the check after the stuck one must still produce a finding")
	}
}

// blockedCheck stands in for a read of a hung network filesystem: no context,
// no deadline and no close gets control back from it.
type blockedCheck struct{}

func (blockedCheck) ID() string            { return "BLOCKED" }
func (blockedCheck) Category() string      { return "TEST_CATEGORY" }
func (blockedCheck) Title() string         { return "A check blocked in an uninterruptible read" }
func (blockedCheck) Impact() string        { return scan.SeverityMedium }
func (blockedCheck) Observational() bool   { return false }
func (blockedCheck) Budget() time.Duration { return 200 * time.Millisecond }
func (blockedCheck) Run(context.Context, *scan.Env) scan.Result {
	// Deliberately ignores the context, exactly as a D-state syscall does.
	time.Sleep(30 * time.Second)
	return scan.Pass("never reached")
}

func TestWalk_RefusesToStartOnNetworkStorage(t *testing.T) {
	requireLinux(t)
	root := tree(t, map[string]string{"/mnt/nfshome/id_rsa": pemKeyBody})
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	res, obs := r.Walk("/mnt/nfshome", probe.WalkBudget{
		NetworkFSMounts: map[string]string{"/mnt/nfshome": "nfs4"},
	}, func(string, os.DirEntry) {
		t.Errorf("the walk entered a network filesystem")
	})
	if res.SkippedFSType != "nfs4" {
		t.Errorf("the skip and its filesystem type must be recorded: %+v", res)
	}
	if !strings.Contains(obs.Detail, "no deadline can interrupt") {
		t.Errorf("the observation must say why: %q", obs.Detail)
	}
	// And a local root is still walked.
	local := tree(t, map[string]string{"/etc/ssh/id_rsa": pemKeyBody})
	lr := probe.NewRootedReader(local)
	t.Cleanup(lr.Close)
	seen := 0
	if _, _ = lr.Walk("/etc/ssh", probe.WalkBudget{NetworkFSMounts: map[string]string{"/mnt": "nfs4"}},
		func(string, os.DirEntry) { seen++ }); seen == 0 {
		t.Errorf("a local root must still be walked")
	}
}

// ---------------------------------------------------------------------------
// Row 41 and the Lows
// ---------------------------------------------------------------------------

func TestBMCTooling_ReasonComesFromTheStats(t *testing.T) {
	// No binary directory exists at all: the reason is ENOENT, not EACCES.
	root := tree(t, map[string]string{"/etc/hostname": "x\n"})
	f := runCheck(t, root, newFakeRunner(), "BMC_CLIENT_TOOLING_INVENTORY")
	wantStatus(t, f, scan.StatusUnknown)
	if f.Reason == scan.ReasonEACCES {
		t.Errorf("absent directories must not be reported as denied ones")
	}
	if strings.Contains(f.Evidence.Detail, "()") {
		t.Errorf("the detail must name the directories rather than print an empty list: %q", f.Evidence.Detail)
	}
}

// L1: a symlink refused by policy must land inside the closed vocabulary.
func TestSymlinkRefusalIsInTheClosedVocabulary(t *testing.T) {
	requireLinux(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "real"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "etc", "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	r := probe.NewRootedReader(root)
	t.Cleanup(r.Close)
	obs := r.Read("/etc/link", probe.Policy{Cap: 1024}) // Follow off
	allowed := map[string]bool{
		scan.ReasonEACCES: true, scan.ReasonEPERM: true, scan.ReasonENOENT: true,
		scan.ReasonEINVAL: true, scan.ReasonTimeout: true, scan.ReasonUtilMiss: true,
		scan.ReasonBudget: true, scan.ReasonParse: true, scan.ReasonExecError: true,
		scan.ReasonContested: true, scan.ReasonPolicy: true, "ELOOP": true, "EOPNOTSUPP": true,
	}
	if !allowed[obs.Reason()] {
		t.Errorf("reason %q is outside the closed vocabulary", obs.Reason())
	}
}
