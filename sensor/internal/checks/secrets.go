package checks

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// The entire secrets surface is metadata: path, type, mode, owner, group, ACL,
// size. A candidate's first 64 bytes are read only to classify it and are
// discarded immediately; no byte of them ever reaches the artifact (L23).

// secretHit is one credential-shaped object. There is no field here that could
// carry a secret value, by construction.
type secretHit struct {
	Path             string            `json:"path"`
	FileType         string            `json:"file_type"`
	Mode             *int64            `json:"mode,omitempty"`
	UID              *int64            `json:"uid,omitempty"`
	GID              *int64            `json:"gid,omitempty"`
	Size             *int64            `json:"size,omitempty"`
	MagicClass       string            `json:"magic_class"`
	GroupName        string            `json:"group_name,omitempty"`
	GroupMembers     int64             `json:"group_member_count"`
	EffectiveReaders string            `json:"effective_readers"`
	ACL              *probe.ACL        `json:"acl,omitempty"`
	Errno            string            `json:"errno,omitempty"`
	Adverse          bool              `json:"adverse"`
	Protection       *protection       `json:"protection,omitempty"`
	Rule             string            `json:"rule,omitempty"`
	RuleSource       string            `json:"rule_source,omitempty"`
	Walk             *probe.WalkResult `json:"-"`
}

// keyNameCandidates select files worth an lstat. Name selection is a filter,
// never the classification: a .pem holding a certificate is not a private key.
var keyNameSuffixes = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keytab", ".pk8", ".p8"}
var keyNamePrefixes = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "ssh_host_"}

func looksLikeKeyName(name string) bool {
	l := strings.ToLower(name)
	for _, s := range keyNameSuffixes {
		if strings.HasSuffix(l, s) {
			return true
		}
	}
	for _, p := range keyNamePrefixes {
		if strings.HasPrefix(l, p) && !strings.HasSuffix(l, ".pub") {
			return true
		}
	}
	return strings.HasSuffix(l, "server.key") || strings.HasSuffix(l, "privkey")
}

// classifyHeader reads at most 64 bytes, decides what the file is, and returns
// only the label. The bytes are not retained.
func classifyHeader(f *probe.Reader, path string) (string, probe.Observation) {
	obs := f.Read(path, probe.Policy{Cap: probe.CapHeaderSniff})
	head := obs.Value
	obs.Value = "" // the header never leaves this function
	if obs.Status != probe.StatusOK {
		return "unknown", obs
	}
	switch {
	case strings.Contains(head, "-----BEGIN OPENSSH PRIVATE KEY-----"):
		return "openssh-private-key", obs
	case strings.Contains(head, "PRIVATE KEY-----"):
		return "pem-private-key", obs
	case strings.Contains(head, "-----BEGIN CERTIFICATE-----"):
		return "pem-certificate", obs
	case strings.Contains(head, "-----BEGIN PUBLIC KEY-----"):
		return "pem-public-key", obs
	case strings.HasPrefix(head, "openssh-key-v1"):
		return "openssh-private-key", obs
	case len(head) > 2 && head[0] == 0x30 && head[1] == 0x82:
		return "der-asn1", obs
	case strings.HasPrefix(head, "\x05\x02") || strings.HasPrefix(head, "\x05\x01"):
		return "keytab", obs
	}
	if strings.HasSuffix(strings.ToLower(path), ".jks") || strings.HasPrefix(head, "\xfe\xed\xfe\xed") {
		return "jks", obs
	}
	return "unknown", obs
}

var privateKeyClasses = map[string]bool{
	"openssh-private-key": true, "pem-private-key": true, "der-asn1": true,
	"jks": true, "keytab": true,
}

// effectiveReaders is the one question "who can read this" is asked through.
// It delegates the membership model to scan.Env so secrets, BMC nodes and drive
// nodes cannot disagree about the same file.
func effectiveReaders(env *scan.Env, mode, uid, gid *int64) (desc string, adverse bool, groupName string, members int64) {
	r := env.Readers(mode, uid, gid)
	return r.Description, r.BeyondOwner, r.GroupName, int64(len(r.GroupMember))
}

// An EXPOSURE question ("who can read X") and an EXISTENCE question ("is X
// there", "what does it say") read a denial in opposite directions.
//
// For an existence question EACCES is a gap: we cannot say. For an exposure
// question a denial is EVIDENCE, and it points towards protection - if this
// unprivileged account cannot reach the object, neither can any other
// unprivileged account with the same standing. Dropping such a candidate, or
// letting it force the whole check to unknown, throws away the answer.
//
// protection is what a denied candidate contributes: the nearest ancestor that
// IS stat-able decides, because a directory an unprivileged user cannot
// traverse hides everything under it.
type protection struct {
	Protected          bool     `json:"protected"`
	Undetermined       bool     `json:"undetermined,omitempty"`
	Reason             string   `json:"reason,omitempty"`
	Basis              string   `json:"basis"`
	Ancestor           string   `json:"ancestor,omitempty"`
	Mode               *int64   `json:"ancestor_mode,omitempty"`
	ReadersBeyondOwner []string `json:"readers_beyond_owner,omitempty"`
}

// protectionFromDenial walks up from a path we were refused and asks whether an
// ancestor explains the refusal in a way that also excludes every other
// unprivileged account.
//
// The question is TRAVERSAL, not readability. Ubuntu ships /etc/ssl/private as
// 0710 root:ssl-cert: there is no group-read bit at all, so a read-bit test
// says "owner only" - while every member of ssl-cert can walk into it and open
// a 0640 key inside. An ancestor shields only when nobody beyond the owner can
// pass through it.
func protectionFromDenial(env *scan.Env, path string) (protection, []probe.Observation) {
	var obs []probe.Observation
	for dir := parentDir(path); dir != "/" && dir != "."; dir = parentDir(dir) {
		st := env.Files.Stat(dir)
		if st.Status != probe.StatusOK || st.Meta == nil || st.Meta.Mode == nil {
			continue
		}
		m := *st.Meta.Mode
		trav := env.Traversers(st.Meta.Mode, st.Meta.UID, st.Meta.GID)
		st.Detail = "ancestor of a denied candidate; traversal decides what is reachable behind it (" + trav.Description + ")"
		// A protection decision is itself an observation, and it belongs in the
		// evidence: a pass that says "N shielded" with no observation for the
		// shield is a claim, not a finding.
		obs = append(obs, st)

		if !trav.Determined {
			return protection{
				Ancestor: dir, Mode: st.Meta.Mode,
				Basis: "the ancestor " + dir + " (mode " + octalMode(m) + ") is group-traversable and the group model is unavailable (" +
					trav.Reason + "), so whether it shields what is behind it is undetermined",
				Undetermined: true, Reason: trav.Reason,
			}, obs
		}
		if !trav.BeyondOwner {
			return protection{
				Protected: true, Ancestor: dir, Mode: st.Meta.Mode,
				ReadersBeyondOwner: trav.GroupMember,
				Basis: "the ancestor " + dir + " (mode " + octalMode(m) + ") cannot be traversed by anyone beyond its owner" +
					", so nothing beneath it is reachable by another unprivileged account - which is also why this sensor could not read it",
			}, obs
		}
		return protection{
			Ancestor: dir, Mode: st.Meta.Mode, ReadersBeyondOwner: trav.GroupMember,
			Basis: "the ancestor " + dir + " (mode " + octalMode(m) + ") does not shield what is behind it: " + trav.Description,
		}, obs
	}
	return protection{Basis: "no stat-able ancestor explains the denial", Undetermined: true, Reason: scan.ReasonEACCES}, obs
}

// recordProtection is the ONE place a denial that was judged protection is
// turned into evidence. Every exposure check goes through it, so none can
// count a denial as protection while leaving it load-bearing - which is what
// kept SYSTEM_SECRET_STORE_PROTECTION permanently unknown on Ubuntu while its
// own detail said it had passed.
func recordProtection(r *scan.Result, denied probe.Observation, prot protection, ancestors []probe.Observation) {
	for _, a := range ancestors {
		r.Add(a)
	}
	if !prot.Protected {
		r.Add(denied)
		return
	}
	beyond := "none"
	if len(prot.ReadersBeyondOwner) > 0 {
		beyond = strings.Join(prot.ReadersBeyondOwner, ", ")
	}
	denied.OptOut = scan.ProtectionOptOut + prot.Ancestor + " mode " + octalMode(derefMode(prot.Mode)) +
		", readers beyond owner: " + beyond + ")"
	r.Add(denied)
}

func derefMode(m *int64) int64 {
	if m == nil {
		return 0
	}
	return *m
}

func octalMode(m int64) string {
	if m == 0 {
		return "0000"
	}
	var b []byte
	for m > 0 {
		b = append([]byte{byte('0' + m%8)}, b...)
		m /= 8
	}
	return "0" + string(b)
}

// ---------------------------------------------------------------------------
// PRIVATE_KEY_MATERIAL_EXPOSURE
// ---------------------------------------------------------------------------

type privateKeyMaterialExposure struct{ meta }

func (c privateKeyMaterialExposure) Budget() time.Duration { return 20 * time.Second }

var keyWalkRoots = []string{
	"/etc/ssh", "/etc/ssl", "/etc/pki", "/etc/kubernetes", "/etc/docker",
	"/etc/nginx", "/etc/apache2", "/etc/httpd", "/opt", "/srv", "/home", "/root",
}

func (c privateKeyMaterialExposure) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var hits []secretHit
	var walks []probe.WalkResult
	var boundaries []string
	var rootsPresent, rootsAbsent, protectedRoots []string
	// The mount table decides which roots are on storage that can stop
	// answering; the walk refuses to start on those.
	netMounts := map[string]string{}
	mounts := env.Mounts()
	r.Add(mounts.Obs)
	for _, m := range mounts.Entries {
		if probe.NetworkFSTypes[m.FSType] {
			netMounts[m.MountPoint] = m.FSType
		}
	}
	var walkSources []string
	var skippedNetworkRoots []string
	var followedRootSymlinks []string
	var skippedRoots []string
	networkSkipped := false
	symlinksSkipped := int64(0)
	nonRegularSkipped := int64(0)
	aclUndetermined := 0
	var undeterminedKeys []string
	deadline, hasDeadline := ctx.Deadline()

	for _, root := range keyWalkRoots {
		// A root that is not there is not a boundary: its absence is proved by
		// the stat, and the stat is recorded.
		st := env.Files.Stat(root)
		if st.Status == probe.StatusENOENT {
			// A root that is not on this machine is an answer, not a gap.
			rootsAbsent = append(rootsAbsent, root)
			st.AbsenceProven = true
			r.Add(st)
			continue
		}
		if st.Status != probe.StatusOK {
			st.LoadBearing = true
			st.Detail = "scan root for key material; it could not be stat-ed, so its contents are unknown"
			r.Add(st)
			boundaries = append(boundaries, root+" ("+st.Reason()+")")
			continue
		}
		// A root this account cannot enter hides its contents from every other
		// unprivileged account too. For an exposure question that is an answer,
		// not a gap.
		if st.Meta != nil && st.Meta.Mode != nil {
			trav := env.Traversers(st.Meta.Mode, st.Meta.UID, st.Meta.GID)
			if trav.Determined && !trav.BeyondOwner {
				st.Detail = "scan root shielded from other unprivileged accounts: " + trav.Description
				st.OptOut = scan.ProtectionOptOut + root + " mode " + octalMode(*st.Meta.Mode) + ", readers beyond owner: none)"
				r.Add(st)
				protectedRoots = append(protectedRoots, root+" (mode "+octalMode(*st.Meta.Mode)+"; "+trav.Description+")")
				continue
			}
		}
		rootsPresent = append(rootsPresent, root)

		budget := probe.WalkBudget{MaxTime: 3 * time.Second, NetworkFSMounts: netMounts}
		if hasDeadline {
			budget.Deadline = deadline
		}
		var candidates []string
		res, obs := env.Files.Walk(root, budget, func(path string, d fs.DirEntry) {
			// Only a regular file can be key material. A symlink is counted
			// and skipped: following it would describe another inode, and
			// listing 121 CA-bundle links as "candidates" buries the answer.
			if !looksLikeKeyName(d.Name()) {
				return
			}
			if d.Type()&fs.ModeSymlink != 0 {
				symlinksSkipped++
				return
			}
			if !d.Type().IsRegular() {
				nonRegularSkipped++
				return
			}
			candidates = append(candidates, path)
		})
		obs.Detail = "bounded key-material enumeration under " + root
		walkSources = append(walkSources, obs.Source)
		if res.SkippedFSType != "" {
			skippedNetworkRoots = append(skippedNetworkRoots, root+" ("+res.SkippedFSType+")")
			boundaries = append(boundaries, root+" is on a "+res.SkippedFSType+" mount and was not walked")
			networkSkipped = true
			r.Add(obs)
			walks = append(walks, res)
			continue
		}
		if res.SkipReason != "" {
			// A root this sensor declined to enumerate is a boundary stated in
			// words, not an errno: "root is a symlink to a target writable by
			// other accounts" is what a reader needs, and ENOTREG is not.
			skippedRoots = append(skippedRoots, root+": "+res.SkipReason)
			boundaries = append(boundaries, root+" was not enumerated ("+res.SkipReason+")")
			r.Add(obs)
			walks = append(walks, res)
			continue
		}
		if res.SymlinkTarget != "" {
			followedRootSymlinks = append(followedRootSymlinks, root+" -> "+res.SymlinkTarget)
			obs.Detail += "; " + root + " is a symlink to the local, non-user-writable directory " +
				res.SymlinkTarget + ", followed once"
		}
		walks = append(walks, res)
		if !res.Complete() {
			// Each unreadable directory is re-examined: one whose own mode
			// excludes other users is protection, not a boundary.
			realBoundaries := []string{}
			for _, d := range res.UnreadableDirs {
				prot, ancestors := protectionFromDenial(env, d+"/x")
				for _, a := range ancestors {
					a.OptOut = "recorded to show what decided the protection question for " + d
					r.Add(a)
				}
				if prot.Protected {
					protectedRoots = append(protectedRoots, d+" ("+prot.Basis+")")
					continue
				}
				realBoundaries = append(realBoundaries, d+" ("+prot.Basis+")")
			}
			if len(realBoundaries) > 0 || res.BudgetExhausted != "none" || res.CrossedMounts ||
				res.UnreadableDirsCount > int64(len(res.UnreadableDirs)) {
				boundaries = append(boundaries, res.Boundary())
			} else {
				// Every unreadable subtree turned out to be shielded, so the
				// enumeration is not a prefix of a longer one: nothing beyond
				// it is reachable by another unprivileged account either.
				obs.Truncated = false
				obs.Detail += "; every subtree it could not enter is shielded from other unprivileged accounts"
			}
		}
		r.Add(obs)

		for _, p := range candidates {
			st := env.Files.Stat(p)
			hit := secretHit{Path: p, Errno: st.Reason()}
			if st.Meta != nil {
				hit.FileType = st.Meta.FileType
				hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
			}
			if hit.FileType != "regular" {
				nonRegularSkipped++
				continue
			}
			cls, cObs := classifyHeader(env.Files, p)
			hit.MagicClass = cls
			if cObs.Status != probe.StatusOK {
				// We could not read the header. That says nothing about
				// whether the file is key material and everything about who
				// can read it: the candidate stays, classified as unread, and
				// the exposure verdict is taken from its mode.
				hit.MagicClass = "unclassified (" + cObs.Reason() + ")"
				hit.Errno = cObs.Reason()
				prot, ancestors := protectionFromDenial(env, p)
				hit.Protection = &prot
				cObs.OptOut = "the content was not read; the exposure verdict for this candidate is taken from its mode, owner and group"
				recordProtection(&r, cObs, prot, ancestors)
			} else if !privateKeyClasses[cls] {
				continue // a certificate is not key material
			}
			acl, aclObs := env.Files.ReadACL(p)
			hit.ACL = &acl
			readers := env.Readers(hit.Mode, hit.UID, hit.GID)
			hit.EffectiveReaders, hit.GroupName = readers.Description, readers.GroupName
			hit.GroupMembers = int64(len(readers.GroupMember))
			// Row 43: an account model we could not resolve is an open
			// question about this candidate. Reporting it as an exposure
			// invents a reader; reporting it as safe invents an absence.
			hit.Adverse = readers.Determined && readers.BeyondOwner
			if !readers.Determined {
				undeterminedKeys = append(undeterminedKeys, p+" ("+readers.Description+")")
			}
			if acl.Determined && acl.GrantsNonOwner {
				hit.Adverse = true
				hit.EffectiveReaders += "; an ACL grants a non-owner principal read"
			}
			if !acl.Determined && aclObs.Status != probe.StatusOK {
				aclUndetermined++
				aclObs.LoadBearing = true
				r.Add(aclObs)
				boundaries = append(boundaries, p+" ACL ("+acl.Errno+")")
			}
			hits = append(hits, hit)
		}
	}

	r.Field("walks", walks)
	r.Field("scan_roots_present", rootsPresent)
	r.Field("scan_roots_absent", rootsAbsent)
	r.Field("scan_roots_protected", protectedRoots)
	r.Field("scan_roots_on_network_storage", skippedNetworkRoots)
	r.Field("root_symlink_followed", followedRootSymlinks)
	r.Field("scan_roots_not_enumerated", skippedRoots)
	r.Field("boundaries", boundaries)
	r.Field("candidates_with_an_unresolved_reader_set", undeterminedKeys)
	r.Field("symlinks_skipped", symlinksSkipped)
	r.Field("non_regular_skipped", nonRegularSkipped)
	r.Field("private_key_files", hits)
	r.Field("content_read", "at most 64 bytes per candidate, used to classify and immediately discarded")

	var exposed []string
	for _, h := range hits {
		if h.Adverse {
			exposed = append(exposed, h.Path+" ("+h.EffectiveReaders+")")
		}
	}
	// A key we FOUND is a positive observation and stands whether or not the
	// rest of the search completed.
	completenessSources := append(append([]string{}, walkSources...), "/proc/self/mountinfo")
	r.OptOut(len(exposed) > 0,
		"exposed key material was observed directly, so how completely the rest of the machine was searched does not underwrite the verdict",
		completenessSources...)

	switch {
	case len(exposed) > 0:
		// An exposed key is a positive observation. It stands whether or not
		// the rest of the enumeration finished.
		return finish(scan.Fail(scan.ReasonPolicy,
			"private key material is readable beyond its owner: "+strings.Join(exposed, "; ")))
	case len(undeterminedKeys) > 0:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"who can read "+itoa(int64(len(undeterminedKeys)))+" of the key-material candidates could not be established: "+
				strings.Join(undeterminedKeys, "; ")))
	case len(rootsPresent) == 0 && len(protectedRoots) == 0:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"this machine has none of the directories this check searches for key material, so nothing was searched"))
	case len(boundaries) > 0:
		reason := scan.ReasonEACCES
		switch {
		case networkSkipped && !anyDenied(boundaries):
			// Declining to touch storage whose server can stop answering is a
			// decision, not an exhausted budget.
			reason = scan.ReasonNotAttempted
		case aclUndetermined == 0 && !anyDenied(boundaries):
			reason = scan.ReasonBudget
		}
		return finish(scan.Unknown(reason,
			"the search could not cover everything it was pointed at: "+strings.Join(boundaries, "; ")+
				"; exposed key material there can neither be confirmed nor excluded"))
	default:
		return finish(scan.Pass(
			"each private-key-class candidate the search reached is restricted to its owner (" +
				itoa(int64(len(hits))) + " candidate(s) across " + itoa(int64(len(rootsPresent))) + " searched root(s), " +
				itoa(int64(len(protectedRoots))) + " root(s) or subtree(s) shielded by an ancestor an unprivileged account cannot traverse)"))
	}
}

// anyDenied reports whether a boundary was a permission denial rather than a
// budget. The two call for different remediation and are not collapsed.
func anyDenied(boundaries []string) bool {
	for _, b := range boundaries {
		if strings.Contains(b, "EACCES") || strings.Contains(b, "EPERM") || strings.Contains(b, "could not be read") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// CREDENTIAL_FILE_EXPOSURE
// ---------------------------------------------------------------------------

type credentialFileExposure struct{ meta }

// ruleKind is what a piece of software actually objects to. OpenSSH's
// StrictModes rejects a WRITABLE ~/.ssh/config; it does not care that the file
// is world-readable, and 0644 is the default every distribution ships. libpq
// ignores a READABLE .pgpass. Stating one rule and testing the other bits is
// how a check comes to fail a healthy machine.
type ruleKind int

const (
	kindNotReadableByOthers ruleKind = iota
	kindNotWritableByOthers
)

// text renders the rule so that the sentence in the evidence and the predicate
// in the code come from the same declaration and cannot drift apart.
func (k ruleKind) text() string {
	switch k {
	case kindNotWritableByOthers:
		return "not group- or world-writable"
	default:
		return "not group- or world-readable"
	}
}

// violated applies the rule to an object's metadata.
func (k ruleKind) violated(env *scan.Env, mode, uid, gid *int64) (bool, string) {
	if mode == nil {
		return false, "unknown (mode not readable)"
	}
	switch k {
	case kindNotWritableByOthers:
		m := *mode
		if m&0o002 != 0 {
			return true, "any local user can write it"
		}
		if m&0o020 != 0 {
			r := env.Readers(mode, uid, gid)
			if !r.Determined {
				return false, r.Description
			}
			if r.BeyondOwner {
				return true, "writable by " + r.Description
			}
			return false, "group-writable, but " + r.Description
		}
		return false, "writable by the owner only"
	default:
		// These rules are the software's own, and every one of them is
		// written against the MODE BITS: libpq refuses a 0640 .pgpass whether
		// or not the group has a member. Judging effective readers here would
		// be a looser predicate than the sentence the finding cites.
		m := *mode
		if m&0o044 != 0 {
			r := env.Readers(mode, uid, gid)
			return true, "group- or world-readable (mode " + octalMode(m) + "); " + r.Description
		}
		return false, "readable by the owner only (mode " + octalMode(m) + ")"
	}
}

// credentialRule pairs a relative path with the permission rule its own
// software documents. The rule text and the predicate are both derived from
// kind, so the sentence cannot claim one thing while the code tests another.
type credentialRule struct {
	rel    string
	kind   ruleKind
	source string
}

func (c credentialRule) rule() string { return c.kind.text() }

var homeCredentialRules = []credentialRule{
	{".pgpass", kindNotReadableByOthers, "PostgreSQL libpq ignores a .pgpass with group or world permissions"},
	{".netrc", kindNotReadableByOthers, "curl and ftp refuse a .netrc readable by others"},
	{".my.cnf", kindNotReadableByOthers, "MySQL client password file"},
	{".docker/config.json", kindNotReadableByOthers, "Docker stores registry auths base64-encoded, which is not encryption"},
	{".aws/credentials", kindNotReadableByOthers, "AWS CLI long-lived access keys"},
	{".kube/config", kindNotReadableByOthers, "kubectl client certificates and bearer tokens"},
	{".git-credentials", kindNotReadableByOthers, "git-credential-store writes cleartext credentials"},
	{".npmrc", kindNotReadableByOthers, "npm _authToken"},
	{".pypirc", kindNotReadableByOthers, "twine upload credentials"},
	// StrictModes objects to a writable config, not a readable one: 0644 is the
	// default ~/.ssh/config on every distribution.
	{".ssh/config", kindNotWritableByOthers, "OpenSSH StrictModes rejects a group- or world-writable ~/.ssh/config"},
}

var systemCredentialRules = []credentialRule{
	{"/etc/docker/config.json", kindNotReadableByOthers, "Docker registry auths"},
	{"/etc/kubernetes/admin.conf", kindNotReadableByOthers, "cluster-admin credentials"},
	{"/root/.aws/credentials", kindNotReadableByOthers, "AWS CLI credentials of root"},
}

func (c credentialFileExposure) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	passwd := env.Files.Read("/etc/passwd", probe.Large)
	passwd.LoadBearing = true
	r.Add(passwd)
	if passwd.Status != probe.StatusOK {
		return finish(scan.Unknown(passwd.Reason(),
			"/etc/passwd could not be read ("+passwd.Reason()+"), so the set of home directories to inspect is unknown"))
	}

	var candidates []struct {
		path string
		rule credentialRule
	}
	homes, skipped := credentialHomes(passwd.Value)
	for _, home := range homes {
		for _, cr := range homeCredentialRules {
			candidates = append(candidates, struct {
				path string
				rule credentialRule
			}{home + "/" + cr.rel, cr})
		}
	}
	r.Field("homes_skipped", skipped)
	for _, cr := range systemCredentialRules {
		candidates = append(candidates, struct {
			path string
			rule credentialRule
		}{cr.rel, cr})
	}

	var hits []secretHit
	unreadableHomes := []string{}
	unreadableSeen := map[string]bool{}
	var exposed []string
	undetermined := false
	protectedByAncestor := 0

	for _, cand := range candidates {
		st := env.Files.Stat(cand.path)
		if st.Status == probe.StatusENOENT {
			st.Detail = "credential file candidate; absent"
			r.Add(st)
			continue
		}
		hit := secretHit{Path: cand.path, Errno: st.Reason(), Rule: cand.rule.rule(), RuleSource: cand.rule.source}
		if st.Status != probe.StatusOK {
			// A denial is evidence about protection, not a hole in the answer:
			// if an ancestor keeps this account out, it keeps every other
			// unprivileged account out too.
			prot, ancestors := protectionFromDenial(env, cand.path)
			hit.Protection = &prot
			if prot.Protected {
				hit.EffectiveReaders = "the owner only (" + prot.Basis + ")"
				protectedByAncestor++
			} else {
				undetermined = true
				hit.EffectiveReaders = "unknown (" + st.Reason() + ")"
				if home := homeOfCandidate(cand.path, homes); home != "" && !unreadableSeen[home] {
					unreadableSeen[home] = true
					unreadableHomes = append(unreadableHomes, home)
				}
			}
			recordProtection(&r, st, prot, ancestors)
			hits = append(hits, hit)
			continue
		}
		r.Add(st)
		if st.Meta != nil {
			hit.FileType = st.Meta.FileType
			hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		acl, _ := env.Files.ReadACL(cand.path)
		hit.ACL = &acl
		violated, desc := cand.rule.kind.violated(env, hit.Mode, hit.UID, hit.GID)
		_, _, hit.GroupName, hit.GroupMembers = effectiveReaders(env, hit.Mode, hit.UID, hit.GID)
		hit.EffectiveReaders, hit.Adverse = desc, violated
		if acl.Determined && acl.GrantsNonOwner && cand.rule.kind == kindNotReadableByOthers {
			hit.Adverse = true
			hit.EffectiveReaders += "; an ACL grants a non-owner principal read"
		}
		if !acl.Determined && acl.Errno != "" && acl.Errno != "ENODATA" {
			undetermined = true
		}
		if readers := env.Readers(hit.Mode, hit.UID, hit.GID); !readers.Determined {
			undetermined = true
			hit.Adverse = false
			hit.EffectiveReaders = readers.Description
		}
		if hit.Adverse {
			exposed = append(exposed, cand.path+" is "+desc+", against its own rule ("+cand.rule.rule()+") — "+cand.rule.source)
		}
		hits = append(hits, hit)
	}

	r.Field("credential_files", hits)
	r.Field("homes_inspected", homes)
	r.Field("unreadable_homes", unreadableHomes)
	r.Field("protected_by_ancestor", int64(protectedByAncestor))
	r.Field("decoding_note", "a Docker config auths entry is base64, which is not encryption; it is never decoded")

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a credential file does not satisfy the permission rule its own software documents: "+strings.Join(exposed, "; ")))
	case undetermined:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"at least one credential path could not be inspected (denied home directory or unreadable ACL), so that account's credential exposure is unknown rather than clean"))
	default:
		return finish(scan.Pass(
			"each credential file the search reached satisfies the permission rule its own software documents (" +
				itoa(int64(len(hits))) + " inspected across " + itoa(int64(len(homes))) + " home directory/ies; " +
				itoa(int64(protectedByAncestor)) + " shielded by an ancestor an unprivileged account cannot traverse)"))
	}
}

// systemHomeDirs are the placeholder home directories distributions give to
// service accounts. They are not anybody's home, and walking them produces
// noise (and, for "/", a walk of the entire filesystem root) rather than a
// finding about a person's credentials.
var systemHomeDirs = map[string]bool{
	"/": true, "/bin": true, "/sbin": true, "/dev": true, "/dev/null": true,
	"/usr/sbin": true, "/usr/bin": true, "/var/run": true, "/run": true,
	"/nonexistent": true, "/var/empty": true, "/proc": true, "/etc": true,
	"/var/lib/empty": true, "/usr/share/empty": true,
}

// credentialHomes returns the deduplicated home directories worth inspecting:
// accounts that can actually obtain a session, plus root, and never a
// placeholder home shared by a dozen service accounts.
func credentialHomes(passwd string) (homes, skipped []string) {
	seen := map[string]bool{}
	skippedSeen := map[string]bool{}
	for _, ln := range strings.Split(passwd, "\n") {
		f := strings.Split(strings.TrimSpace(ln), ":")
		if len(f) < 7 || f[0] == "" || f[5] == "" {
			continue
		}
		// root is inspected whatever its shell says, because root's credential
		// files matter even on a system where root cannot log in.
		if shellClass(f[6]) != "login" && f[0] != "root" {
			continue
		}
		home := strings.TrimRight(f[5], "/")
		if home == "" {
			home = "/"
		}
		if systemHomeDirs[home] {
			if !skippedSeen[home] {
				skippedSeen[home] = true
				skipped = append(skipped, home+" (a placeholder home for service accounts, not a user's home)")
			}
			continue
		}
		if seen[home] {
			continue
		}
		seen[home] = true
		homes = append(homes, home)
	}
	if homes == nil {
		homes = []string{}
	}
	if skipped == nil {
		skipped = []string{}
	}
	return homes, skipped
}

// ---------------------------------------------------------------------------
// PROVISIONING_DATA_PROTECTION
// ---------------------------------------------------------------------------

type provisioningDataProtection struct{ meta }

// Provisioning artifacts fall into two classes, and conflating them produces a
// false positive on every cloud-init host.
//
//   - PAYLOAD carries what the provisioning system was told to apply: user-data,
//     vendor-data, seed files, the pickled instance object, the merged config,
//     and the sensitive companion of instance-data. cloud-init ships all of
//     these root-only. Any of them readable beyond root is the finding.
//   - PUBLIC is published readable BY DESIGN with its sensitive keys redacted:
//     instance-data.json, cloud-id, and the .cfg drop-ins, which are
//     configuration rather than credentials. These are reported as inventory.
//
// A drop-in is promoted to payload class when it declares a credential-bearing
// key. The key NAME is matched, never its value.
type provisioningClass string

const (
	classPayload provisioningClass = "payload"
	classPublic  provisioningClass = "public-by-design"
)

type provisioningPath struct {
	path  string
	class provisioningClass
}

var provisioningArtifacts = []provisioningPath{
	{"/var/lib/cloud/instance/user-data.txt", classPayload},
	{"/var/lib/cloud/instance/user-data.txt.i", classPayload},
	{"/var/lib/cloud/instance/vendor-data.txt", classPayload},
	{"/var/lib/cloud/instance/vendor-data.txt.i", classPayload},
	{"/var/lib/cloud/instance/obj.pkl", classPayload},
	{"/var/lib/cloud/seed/nocloud/user-data", classPayload},
	{"/var/lib/cloud/seed/nocloud/meta-data", classPayload},
	{"/var/lib/cloud/seed/nocloud-net/user-data", classPayload},
	{"/var/lib/cloud/seed/nocloud-net/meta-data", classPayload},
	{"/run/cloud-init/instance-data-sensitive.json", classPayload},
	{"/run/cloud-init/combined-cloud-config.json", classPayload},
	{"/root/anaconda-ks.cfg", classPayload},
	{"/usr/share/oem/config.ign", classPayload},
	{"/var/lib/ignition/user.ign", classPayload},
	{"/run/cloud-init/instance-data.json", classPublic},
	{"/run/cloud-init/cloud-id", classPublic},
	{"/etc/cloud/ds-identify.cfg", classPublic},
}

// payloadNamePrefixes promote a discovered file to payload class wherever it is
// found: instance directories are named after the instance id, so the fixed
// path set above cannot enumerate their contents in advance.
var payloadNamePrefixes = []string{"user-data", "vendor-data", "meta-data", "network-config", "obj.pkl"}

// injectionKeys are configuration key NAMES that mean a drop-in can inject
// credentials. Only names are matched; no value is ever read or emitted.
var injectionKeys = []string{"ssh_authorized_keys", "chpasswd", "ssh_pwauth", "password", "users", "runcmd"}

// declaredKeys returns the credential-bearing YAML keys a drop-in actually
// declares.
//
// A substring search over the whole file promotes a drop-in to payload because
// a COMMENT mentions the word - "ssh_pwauth is left at the default; no password
// is set here" - and then fails a public, correctly-permissioned file. Comments
// are stripped and a key is only a key at the start of a line, followed by a
// colon.
func declaredKeys(body string) []string {
	var found []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		trimmed := strings.TrimLeft(line, " \t-")
		if trimmed == "" {
			continue
		}
		key, _, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		for _, k := range injectionKeys {
			if key == k && !seen[k] {
				seen[k] = true
				found = append(found, k)
			}
		}
	}
	return found
}

type provisioningArtifactRow struct {
	Path             string            `json:"path"`
	Class            provisioningClass `json:"class"`
	FileType         string            `json:"file_type,omitempty"`
	Mode             *int64            `json:"mode,omitempty"`
	UID              *int64            `json:"uid,omitempty"`
	GID              *int64            `json:"gid,omitempty"`
	Size             *int64            `json:"size,omitempty"`
	EffectiveReaders string            `json:"effective_readers"`
	Adverse          bool              `json:"adverse"`
	InjectionKeys    []string          `json:"declares_credential_keys,omitempty"`
	Errno            string            `json:"errno,omitempty"`
	Note             string            `json:"note,omitempty"`
}

func (c provisioningDataProtection) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var rows []provisioningArtifactRow
	var exposed []string
	var denied []string
	present := false
	undetermined := false
	protectedCount := 0

	inspect := func(path string, class provisioningClass) int {
		st := env.Files.Stat(path)
		st.Detail = "provisioning artifact candidate (" + string(class) + ")"
		// Absence here is a real answer: ENOENT from a stat that resolved the
		// path IS the observation, while EACCES is a boundary.
		st.LoadBearing = true
		st.AbsenceProven = st.Status == probe.StatusENOENT
		r.Add(st)
		if st.Status == probe.StatusENOENT {
			return -1
		}
		row := provisioningArtifactRow{Path: path, Class: class}
		if st.Status != probe.StatusOK {
			row.Errno = st.Reason()
			// An artifact we were refused, behind an ancestor no unprivileged
			// account can traverse, is protected - which is the question this
			// check asks. /root at 0700 is the ordinary case on every host.
			prot, ancestors := protectionFromDenial(env, path)
			if prot.Protected {
				row.EffectiveReaders = "the owner only (" + prot.Basis + ")"
				row.Note = "not readable by this account, and the ancestor that explains it excludes every unprivileged account"
				protectedCount++
			} else {
				undetermined = true
				denied = append(denied, path+" ("+prot.Basis+")")
				row.EffectiveReaders = "undetermined"
			}
			// The stat was already recorded; replace it with the judged copy.
			r.Observations = r.Observations[:len(r.Observations)-1]
			recordProtection(&r, st, prot, ancestors)
			rows = append(rows, row)
			return len(rows) - 1
		}
		present = true
		if st.Meta != nil {
			row.FileType = st.Meta.FileType
			row.Mode, row.UID, row.GID, row.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		desc, reachable, _, _ := effectiveReaders(env, row.Mode, row.UID, row.GID)
		row.EffectiveReaders = desc
		if readers := env.Readers(row.Mode, row.UID, row.GID); !readers.Determined {
			undetermined = true
			reachable = false
			denied = append(denied, path+" ("+readers.Description+")")
		}

		switch {
		case class == classPublic:
			row.Note = "cloud-init publishes this readable by design with its sensitive keys redacted; it is inventory, not exposure"
		case row.FileType == "dir":
			// A listable directory is exposure only through a readable file
			// inside it, and those files are inspected in their own right.
			row.Note = "directory; the verdict rests on the payload files inside it, each inspected separately"
		case row.Size != nil && *row.Size == 0:
			row.Note = "empty; there is no payload to expose"
		case reachable:
			row.Adverse = true
			exposed = append(exposed, path+" is readable by "+desc)
		}
		rows = append(rows, row)
		return len(rows) - 1
	}

	for _, a := range provisioningArtifacts {
		inspect(a.path, a.class)
	}

	// Instance and seed directories are named after the instance id, so their
	// contents are classified by name rather than enumerated in advance.
	for _, dir := range []string{"/var/lib/cloud/instances", "/var/lib/cloud/seed", "/etc/cloud/cloud.cfg.d"} {
		names, obs := env.Files.ReadDirNames(dir, 256)
		obs.Detail = "provisioning directory enumeration"
		obs.LoadBearing = true
		obs.AbsenceProven = obs.Status == probe.StatusENOENT
		r.Add(obs)
		if obs.Status == probe.StatusENOENT {
			continue
		}
		if obs.Status != probe.StatusOK {
			undetermined = true
			denied = append(denied, dir+" ("+obs.Reason()+")")
			continue
		}
		present = true
		for _, n := range names {
			p := dir + "/" + n
			if dir == "/etc/cloud/cloud.cfg.d" {
				idx := inspect(p, classPublic)
				if idx < 0 {
					continue
				}
				// A drop-in that declares a credential-bearing key is payload,
				// whatever its extension says.
				body := env.Files.Read(p, probe.Small)
				if body.Status != probe.StatusOK {
					continue
				}
				found := declaredKeys(body.Value)
				if len(found) == 0 {
					continue
				}
				rows[idx].Class = classPayload
				rows[idx].InjectionKeys = found
				rows[idx].Note = "declares credential-bearing key names, so it is treated as payload rather than public configuration"
				if _, reachable, _, _ := effectiveReaders(env, rows[idx].Mode, rows[idx].UID, rows[idx].GID); reachable {
					rows[idx].Adverse = true
					exposed = append(exposed, p+" is readable by "+rows[idx].EffectiveReaders+" and declares "+strings.Join(found, ", "))
				}
				continue
			}
			// An instance or seed directory: descend one level, classify by name.
			inspect(p, classPayload)
			children, cObs := env.Files.ReadDirNames(p, 256)
			if cObs.Status != probe.StatusOK {
				continue
			}
			for _, child := range children {
				if !hasAnyPrefix(child, payloadNamePrefixes) {
					continue
				}
				inspect(p+"/"+child, classPayload)
			}
		}
	}

	// A readable instance-data.json self-redacts for non-root readers, so an
	// empty-looking field there is redaction, not absence.
	redaction := false
	datasource := ""
	if idj := env.Files.Read("/run/cloud-init/instance-data.json", probe.Large); idj.Status == probe.StatusOK {
		redaction = strings.Contains(idj.Value, "redacted") || strings.Contains(idj.Value, "REDACTED")
		datasource = cloudNameFrom(idj.Value)
	}
	if cloudID, obs := env.Files.ReadTrimmed("/run/cloud-init/cloud-id", probe.Tiny); obs.Status == probe.StatusOK && cloudID != "" {
		datasource = cloudID
	}

	r.Field("artifacts", rows)
	r.Field("redaction_observed", redaction)
	r.Field("datasource_class", firstNonEmpty(datasource, scan.UnknownString))
	r.Field("sensitive_paths_denied", denied)
	r.Field("protected_by_ancestor", int64(protectedCount))
	r.Field("classification_note", "payload artifacts (user-data, vendor-data, seeds, obj.pkl, the sensitive and combined configs) carry the verdict; instance-data.json and the .cfg drop-ins are published readable by design with their sensitive keys redacted, and are reported as inventory")
	r.Field("content_read", "key names only; no provisioning payload value is read or emitted")

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"provisioning payload that can carry injected credentials is readable beyond root: "+strings.Join(exposed, "; ")))
	case undetermined:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"part of the provisioning surface could not be inspected ("+strings.Join(denied, ", ")+
				"), so whether it exposes injected credentials is unknown"))
	case !present:
		return finish(scan.Pass(
			"this machine carries no provisioning artifact at any cloud-init, Ignition or kickstart location"))
	default:
		return finish(scan.Pass(
			"each provisioning payload artifact the search reached is restricted to root (" + itoa(int64(len(rows))) +
				" inspected, " + itoa(int64(protectedCount)) + " shielded by an ancestor an unprivileged account cannot traverse); " +
				"the readable ones are what cloud-init publishes that way by design, with their sensitive keys redacted"))
	}
}

// cloudNameFrom extracts the datasource identity from a readable
// instance-data.json. The document is parsed and only that one identifying
// field is taken from it.
func cloudNameFrom(body string) string {
	var doc struct {
		V1 struct {
			CloudName string `json:"cloud_name"`
			Platform  string `json:"platform"`
		} `json:"v1"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return ""
	}
	if doc.V1.CloudName != "" && doc.V1.CloudName != "unknown" {
		return doc.V1.CloudName
	}
	if doc.V1.Platform != "" && doc.V1.Platform != "unknown" {
		return doc.V1.Platform
	}
	return ""
}

// ---------------------------------------------------------------------------
// SYSTEM_SECRET_STORE_PROTECTION
// ---------------------------------------------------------------------------

type systemSecretStoreProtection struct{ meta }

// systemStores are the operating system's own secret stores. A directory store
// is judged by what is INSIDE it: sudo ships /etc/sudoers.d as drwxr-xr-x with
// 0440 files, and failing that layout fails every stock Debian and Ubuntu
// machine. A listable directory is not exposure; a readable secret is.
var systemStores = []struct {
	path  string
	isDir bool
}{
	{"/etc/shadow", false},
	{"/etc/gshadow", false},
	{"/etc/ssl/private", true},
	{"/etc/pki/tls/private", true},
	{"/etc/sudoers", false},
	{"/etc/sudoers.d", true},
	{"/var/lib/systemd/random-seed", false},
	{"/etc/krb5.keytab", false},
}

func (c systemSecretStoreProtection) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var hits []secretHit
	var exposed, boundaries []string
	protectedCount := 0

	// judge inspects one concrete secret file.
	judge := func(path, expect string) {
		st := env.Files.Stat(path)
		st.Detail = "system secret store (" + expect + ")"
		st.AbsenceProven = st.Status == probe.StatusENOENT
		r.Add(st)
		if st.Status == probe.StatusENOENT {
			return
		}
		hit := secretHit{Path: path, Rule: expect, RuleSource: "distribution-shipped permission class"}
		if st.Status != probe.StatusOK {
			hit.Errno = st.Reason()
			prot, ancestors := protectionFromDenial(env, path)
			hit.Protection = &prot
			if prot.Protected {
				hit.EffectiveReaders = "the owner only (" + prot.Basis + ")"
				protectedCount++
			} else {
				hit.EffectiveReaders = "undetermined (" + prot.Basis + ")"
				boundaries = append(boundaries, path+" ("+prot.Basis+")")
			}
			// The stat was recorded above; replace it with the judged copy so a
			// denial that answered the question does not also downgrade it.
			r.Observations = r.Observations[:len(r.Observations)-1]
			recordProtection(&r, st, prot, ancestors)
			hits = append(hits, hit)
			return
		}
		if st.Meta != nil {
			hit.FileType = st.Meta.FileType
			hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		acl, aclObs := env.Files.ReadACL(path)
		hit.ACL = &acl
		r.Add(aclObs)

		readers := env.Readers(hit.Mode, hit.UID, hit.GID)
		hit.EffectiveReaders, hit.GroupName = readers.Description, readers.GroupName
		hit.GroupMembers = int64(len(readers.GroupMember))
		// An undetermined reader set is an open question, not an exposure.
		hit.Adverse = readers.Determined && readers.BeyondOwner
		if hit.Mode != nil && *hit.Mode&0o002 != 0 {
			hit.Adverse = true
			hit.EffectiveReaders += "; other-writable"
		}
		if acl.Determined && acl.GrantsNonOwner {
			hit.Adverse = true
			hit.EffectiveReaders += "; an ACL grants a non-owner principal read"
		}
		if !readers.Determined {
			boundaries = append(boundaries, path+" ("+readers.Description+")")
		}
		if !acl.Determined && acl.Errno != "" && acl.Errno != "ENODATA" {
			boundaries = append(boundaries, path+" ACL ("+acl.Errno+")")
		}
		if hit.Adverse {
			exposed = append(exposed, path+" ("+hit.EffectiveReaders+")")
		}
		hits = append(hits, hit)
	}

	for _, store := range systemStores {
		if !store.isDir {
			judge(store.path, "not readable beyond its owner")
			continue
		}
		// A directory store: the verdict is about the secrets inside it.
		st := env.Files.Stat(store.path)
		st.Detail = "system secret store directory"
		st.AbsenceProven = st.Status == probe.StatusENOENT
		r.Add(st)
		if st.Status == probe.StatusENOENT {
			continue
		}
		dirHit := secretHit{Path: store.path, Rule: "its contents are not readable beyond their owner",
			RuleSource: "distribution-shipped permission class", FileType: "dir"}
		if st.Meta != nil {
			dirHit.Mode, dirHit.UID, dirHit.GID = st.Meta.Mode, st.Meta.UID, st.Meta.GID
		}
		if st.Status == probe.StatusOK && st.Meta != nil && st.Meta.Mode != nil && *st.Meta.Mode&0o002 != 0 {
			dirHit.Adverse = true
			dirHit.EffectiveReaders = "any local user can create or replace files in it (other-writable)"
			exposed = append(exposed, store.path+" is other-writable")
		} else {
			dirHit.EffectiveReaders = "judged by its contents"
		}
		hits = append(hits, dirHit)

		names, dirObs := env.Files.ReadDirNames(store.path, 512)
		dirObs.Detail = "contents of " + store.path
		dirObs.AbsenceProven = dirObs.Status == probe.StatusENOENT
		r.Add(dirObs)
		if dirObs.Status != probe.StatusOK {
			prot, ancestors := protectionFromDenial(env, store.path+"/x")
			if prot.Protected {
				protectedCount++
			} else {
				boundaries = append(boundaries, store.path+" listing ("+prot.Basis+")")
			}
			r.Observations = r.Observations[:len(r.Observations)-1]
			recordProtection(&r, dirObs, prot, ancestors)
			continue
		}
		for _, n := range names {
			judge(store.path+"/"+n, "not readable beyond its owner")
		}
	}

	r.Field("stores", hits)
	r.Field("observation_boundaries", boundaries)
	r.Field("protected_by_ancestor", int64(protectedCount))
	r.Field("directory_rule", "a directory store is judged by the secrets inside it: sudo ships /etc/sudoers.d world-listable with 0440 files, and a listable directory is not exposure")
	r.Field("acl_note", "ENODATA from system.posix_acl_access means the file has no ACL, which is a positive answer, not an unknown")

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a system secret store is reachable beyond its owner: "+strings.Join(exposed, "; ")))
	case len(boundaries) > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"the permissions of "+itoa(int64(len(boundaries)))+" system secret store(s) could not be established from this account ("+
				strings.Join(boundaries, ", ")+"); reporting that boundary is the point"))
	default:
		return finish(scan.Pass(
			"each system secret store the search reached keeps its expected restrictive permissions (" +
				itoa(int64(len(hits))) + " inspected, " + itoa(int64(protectedCount)) + " shielded by an unreadable ancestor)"))
	}
}
func homeOfCandidate(path string, homes []string) string {
	for _, h := range homes {
		if strings.HasPrefix(path, h+"/") {
			return h
		}
	}
	return ""
}
