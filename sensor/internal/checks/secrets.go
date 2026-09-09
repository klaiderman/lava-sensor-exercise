package checks

import (
	"context"
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
func classifyHeader(f probe.Files, path string) (string, probe.Observation) {
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

// effectiveReaders describes who can actually read an object, pairing the mode
// with group membership: a 0640 file whose group has no members is owner-only
// in practice, and failing it would be a false positive (L42, L43).
func effectiveReaders(env *scan.Env, mode *int64, gid *int64) (desc string, adverse bool, groupName string, members int64) {
	if mode == nil {
		return "unknown (mode not readable)", false, "", 0
	}
	m := *mode
	if gid != nil {
		for _, g := range env.Groups().Groups {
			if g.GID == *gid {
				groupName, members = g.Name, int64(len(g.Members))
				break
			}
		}
	}
	switch {
	case m&0o004 != 0:
		return "any local user (other-readable)", true, groupName, members
	case m&0o040 != 0 && members > 0:
		return "members of group " + groupName + " (" + itoa(members) + " member(s))", true, groupName, members
	case m&0o040 != 0:
		return "group " + groupName + " is empty, so this is owner-only in practice", false, groupName, members
	}
	return "the owner only", false, groupName, members
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
	incomplete := false
	deadline, hasDeadline := ctx.Deadline()

	for _, root := range keyWalkRoots {
		if !env.Files.Exists(root) {
			continue
		}
		budget := probe.WalkBudget{MaxTime: 3 * time.Second}
		if hasDeadline {
			budget.Deadline = deadline
		}
		var candidates []string
		res, obs := env.Files.Walk(root, budget, func(path string, d fs.DirEntry) {
			if looksLikeKeyName(d.Name()) {
				candidates = append(candidates, path)
			}
		})
		obs.Detail = "bounded key-material enumeration under " + root
		r.Add(obs)
		walks = append(walks, res)
		if !res.Complete() {
			incomplete = true
		}
		for _, p := range candidates {
			st := env.Files.Stat(p)
			hit := secretHit{Path: p, Errno: st.Reason()}
			if st.Meta != nil {
				hit.FileType = st.Meta.FileType
				hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
			}
			if hit.FileType != "regular" {
				// A FIFO or device at a key path is recorded and never opened.
				hit.MagicClass = "not-a-regular-file"
				hits = append(hits, hit)
				continue
			}
			cls, cObs := classifyHeader(env.Files, p)
			hit.MagicClass = cls
			if cObs.Status != probe.StatusOK {
				hit.Errno = cObs.Reason()
			}
			if !privateKeyClasses[cls] {
				continue // a certificate is not key material
			}
			acl, aclObs := env.Files.ReadACL(p)
			hit.ACL = &acl
			desc, adverse, gname, gmembers := effectiveReaders(env, hit.Mode, hit.GID)
			hit.EffectiveReaders, hit.Adverse, hit.GroupName, hit.GroupMembers = desc, adverse, gname, gmembers
			if acl.Determined && acl.GrantsNonOwner {
				hit.Adverse = true
				hit.EffectiveReaders += "; an ACL grants a non-owner principal read"
			}
			if !acl.Determined && aclObs.Status != probe.StatusOK {
				incomplete = true
			}
			hits = append(hits, hit)
		}
	}

	r.Field("walks", walks)
	r.Field("private_key_files", hits)
	r.Field("content_read", "at most 64 bytes per candidate, used to classify and immediately discarded")

	var exposed []string
	for _, h := range hits {
		if h.Adverse {
			exposed = append(exposed, h.Path+" ("+h.EffectiveReaders+")")
		}
	}
	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"private key material is readable beyond its owner: "+strings.Join(exposed, "; ")))
	case incomplete:
		return finish(scan.Unknown(scan.ReasonBudget,
			"the enumeration did not complete everywhere (budgets or denied subtrees are listed in the walk boundaries), "+
				"so the absence of further exposed key material is not proven; what was enumerated shows none"))
	default:
		return finish(scan.Pass(
			"every enumeration completed and each private-key-class file found is readable by its owner only (" +
				itoa(int64(len(hits))) + " candidate(s) classified)"))
	}
}

// ---------------------------------------------------------------------------
// CREDENTIAL_FILE_EXPOSURE
// ---------------------------------------------------------------------------

type credentialFileExposure struct{ meta }

// credentialRule pairs a relative path with the permission rule its own
// software documents, plus the citation that makes the verdict actionable.
type credentialRule struct {
	rel    string
	rule   string
	source string
}

var homeCredentialRules = []credentialRule{
	{".pgpass", "not group- or world-readable", "PostgreSQL libpq: a .pgpass with group or world permissions is ignored"},
	{".netrc", "not group- or world-readable", "curl and ftp refuse a .netrc readable by others"},
	{".docker/config.json", "not group- or world-readable", "Docker stores registry auths base64-encoded, which is not encryption"},
	{".aws/credentials", "not group- or world-readable", "AWS CLI long-lived access keys"},
	{".kube/config", "not group- or world-readable", "kubectl client certificates and bearer tokens"},
	{".git-credentials", "not group- or world-readable", "git-credential-store writes cleartext credentials"},
	{".npmrc", "not group- or world-readable", "npm _authToken"},
	{".pypirc", "not group- or world-readable", "twine upload credentials"},
	{".ssh/config", "not group- or world-writable", "OpenSSH StrictModes"},
}

var systemCredentialRules = []credentialRule{
	{"/etc/docker/config.json", "not group- or world-readable", "Docker registry auths"},
	{"/etc/kubernetes/admin.conf", "not group- or world-readable", "cluster-admin credentials"},
	{"/root/.aws/credentials", "not group- or world-readable", "AWS CLI credentials of root"},
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
	var homes []string
	for _, ln := range strings.Split(passwd.Value, "\n") {
		f := strings.Split(strings.TrimSpace(ln), ":")
		if len(f) < 7 || f[5] == "" || shellClass(f[6]) != "login" {
			continue
		}
		home := strings.TrimRight(f[5], "/")
		homes = append(homes, home)
		for _, cr := range homeCredentialRules {
			candidates = append(candidates, struct {
				path string
				rule credentialRule
			}{home + "/" + cr.rel, cr})
		}
	}
	for _, cr := range systemCredentialRules {
		candidates = append(candidates, struct {
			path string
			rule credentialRule
		}{cr.rel, cr})
	}

	var hits []secretHit
	var unreadableHomes []string
	var exposed []string
	undetermined := false

	for _, cand := range candidates {
		st := env.Files.Stat(cand.path)
		if st.Status == probe.StatusENOENT {
			continue
		}
		hit := secretHit{Path: cand.path, Errno: st.Reason(), Rule: cand.rule.rule, RuleSource: cand.rule.source}
		if st.Status != probe.StatusOK {
			// A denied stat means that user's exposure is unknown, never clean.
			undetermined = true
			hit.EffectiveReaders = "unknown (" + st.Reason() + ")"
			hits = append(hits, hit)
			if strings.HasSuffix(cand.path, "/.pgpass") || strings.Contains(cand.path, "/.aws/") {
				unreadableHomes = append(unreadableHomes, parentDir(parentDir(cand.path)))
			}
			continue
		}
		r.Add(st)
		if st.Meta != nil {
			hit.FileType = st.Meta.FileType
			hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		acl, _ := env.Files.ReadACL(cand.path)
		hit.ACL = &acl
		desc, adverse, gname, gmembers := effectiveReaders(env, hit.Mode, hit.GID)
		hit.EffectiveReaders, hit.Adverse, hit.GroupName, hit.GroupMembers = desc, adverse, gname, gmembers
		if acl.Determined && acl.GrantsNonOwner {
			hit.Adverse = true
			hit.EffectiveReaders += "; an ACL grants a non-owner principal read"
		}
		if !acl.Determined && acl.Errno != "" && acl.Errno != "ENODATA" {
			undetermined = true
		}
		if hit.Adverse {
			exposed = append(exposed, cand.path+" is readable by "+desc+" — "+cand.rule.source)
		}
		hits = append(hits, hit)
	}

	r.Field("credential_files", hits)
	r.Field("homes_inspected", homes)
	r.Field("unreadable_homes", unreadableHomes)
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
			"every credential file found satisfies the permission rule its own software documents (" +
				itoa(int64(len(hits))) + " file(s) inspected across " + itoa(int64(len(homes))) + " home directory/ies)"))
	}
}

// ---------------------------------------------------------------------------
// PROVISIONING_DATA_PROTECTION
// ---------------------------------------------------------------------------

type provisioningDataProtection struct{ meta }

var provisioningArtifacts = []string{
	"/var/lib/cloud/instance/user-data.txt",
	"/var/lib/cloud/instance/user-data.txt.i",
	"/var/lib/cloud/instance/vendor-data.txt",
	"/var/lib/cloud/instance/obj.pkl",
	"/var/lib/cloud/seed/nocloud/user-data",
	"/var/lib/cloud/seed/nocloud-net/user-data",
	"/run/cloud-init/instance-data.json",
	"/run/cloud-init/instance-data-sensitive.json",
	"/run/cloud-init/combined-cloud-config.json",
	"/etc/cloud/ds-identify.cfg",
	"/root/anaconda-ks.cfg",
	"/usr/share/oem/config.ign",
	"/var/lib/ignition/user.ign",
}

// injectionKeys are configuration key NAMES that mean a drop-in can inject
// credentials. Only names are matched; no value is ever read or emitted.
var injectionKeys = []string{"ssh_authorized_keys", "chpasswd", "password:", "ssh_pwauth"}

func (c provisioningDataProtection) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var hits []secretHit
	var exposed []string
	present := false
	undetermined := false
	var denied []string

	inspect := func(path string) {
		st := env.Files.Stat(path)
		if st.Status == probe.StatusENOENT {
			// Recorded: proven absence is only proven if the attempt is shown.
			st.Detail = "provisioning artifact candidate"
			r.Add(st)
			return
		}
		if st.Status != probe.StatusOK {
			undetermined = true
			denied = append(denied, path+" ("+st.Reason()+")")
			hits = append(hits, secretHit{Path: path, Errno: st.Reason(), EffectiveReaders: "unknown"})
			return
		}
		present = true
		r.Add(st)
		hit := secretHit{Path: path}
		if st.Meta != nil {
			hit.FileType = st.Meta.FileType
			hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		desc, adverse, gname, gmembers := effectiveReaders(env, hit.Mode, hit.GID)
		hit.EffectiveReaders, hit.Adverse, hit.GroupName, hit.GroupMembers = desc, adverse, gname, gmembers
		// An empty artifact carries nothing to expose.
		if hit.Adverse && hit.Size != nil && *hit.Size == 0 {
			hit.Adverse = false
			hit.EffectiveReaders = desc + " (but the file is empty)"
		}
		if hit.Adverse {
			exposed = append(exposed, path+" readable by "+desc)
		}
		hits = append(hits, hit)
	}

	for _, p := range provisioningArtifacts {
		inspect(p)
	}
	for _, dir := range []string{"/var/lib/cloud/instances", "/var/lib/cloud/seed", "/etc/cloud/cloud.cfg.d"} {
		names, obs := env.Files.ReadDirNames(dir, 256)
		obs.Detail = "provisioning directory enumeration"
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
			inspect(p)
			if dir == "/etc/cloud/cloud.cfg.d" {
				// Key NAMES only: the value is exactly where a password ends up.
				body := env.Files.Read(p, probe.Small)
				if body.Status != probe.StatusOK {
					continue
				}
				var found []string
				for _, k := range injectionKeys {
					if strings.Contains(strings.ToLower(body.Value), k) {
						found = append(found, strings.TrimSuffix(k, ":"))
					}
				}
				if len(found) > 0 {
					r.Field("injection_key_names_in_"+n, found)
					for i := range hits {
						if hits[i].Path == p && hits[i].Adverse {
							exposed = append(exposed, p+" is readable and declares "+strings.Join(found, ", "))
						}
					}
				}
			}
		}
	}

	// A readable instance-data.json self-redacts for non-root readers, so an
	// empty-looking field is redaction, not absence.
	redaction := false
	if idj := env.Files.Read("/run/cloud-init/instance-data.json", probe.Large); idj.Status == probe.StatusOK {
		redaction = strings.Contains(idj.Value, "redacted") || strings.Contains(idj.Value, "REDACTED")
	}
	cloudID, _ := env.Files.ReadTrimmed("/run/cloud-init/cloud-id", probe.Tiny)

	r.Field("artifacts", hits)
	r.Field("redaction_observed", redaction)
	r.Field("datasource_class", firstNonEmpty(cloudID, "unknown"))
	r.Field("sensitive_paths_denied", denied)
	r.Field("content_read", "key names only; no provisioning payload value is read or emitted")

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"provisioning data that can carry injected credentials is readable by unprivileged users: "+strings.Join(exposed, "; ")))
	case undetermined:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"part of the provisioning surface could not be inspected ("+strings.Join(denied, ", ")+
				"), so whether it exposes injected credentials is unknown"))
	case !present:
		return finish(scan.Pass(
			"no provisioning artifact exists on this machine — proven by successful listings of the cloud-init, Ignition and kickstart locations, not by their absence from a guess"))
	default:
		return finish(scan.Pass(
			"every provisioning artifact present is restricted to its owner (" + itoa(int64(len(hits))) + " inspected)"))
	}
}

// ---------------------------------------------------------------------------
// SYSTEM_SECRET_STORE_PROTECTION
// ---------------------------------------------------------------------------

type systemSecretStoreProtection struct{ meta }

// systemStores are the OS's own secret stores with the permission class each
// distribution ships them with.
var systemStores = []struct {
	path      string
	expect    string
	dirTravel bool
}{
	{"/etc/shadow", "not other-readable", false},
	{"/etc/gshadow", "not other-readable", false},
	{"/etc/ssl/private", "not other-traversable", true},
	{"/etc/pki/tls/private", "not other-traversable", true},
	{"/etc/sudoers", "not other-readable or other-writable", false},
	{"/etc/sudoers.d", "not other-readable or other-writable", true},
	{"/var/lib/systemd/random-seed", "not other-readable", false},
	{"/etc/krb5.keytab", "not other-readable", false},
}

func (c systemSecretStoreProtection) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var hits []secretHit
	var exposed, boundaries []string

	for _, store := range systemStores {
		st := env.Files.Stat(store.path)
		st.Detail = "system secret store (" + store.expect + ")"
		r.Add(st)
		if st.Status == probe.StatusENOENT {
			continue
		}
		hit := secretHit{Path: store.path, Rule: store.expect, RuleSource: "distribution-shipped permission class"}
		if st.Status != probe.StatusOK {
			// EACCES on the store itself means a parent is restrictive: the
			// store's own mode is unknown, and the boundary IS the finding.
			hit.Errno = st.Reason()
			hit.EffectiveReaders = "unknown (" + st.Reason() + " — a restrictive parent hides the store's own mode)"
			boundaries = append(boundaries, store.path+" ("+st.Reason()+")")
			hits = append(hits, hit)
			continue
		}
		if st.Meta != nil {
			hit.FileType = st.Meta.FileType
			hit.Mode, hit.UID, hit.GID, hit.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		acl, aclObs := env.Files.ReadACL(store.path)
		hit.ACL = &acl
		r.Add(aclObs)

		mode := int64(0)
		if hit.Mode != nil {
			mode = *hit.Mode
		}
		desc, adverse, gname, gmembers := effectiveReaders(env, hit.Mode, hit.GID)
		hit.GroupName, hit.GroupMembers = gname, gmembers
		if store.dirTravel {
			// For a directory the control is the traverse bit, not read.
			adverse = mode&0o001 != 0 || mode&0o004 != 0
			desc = "other-traversable"
			if !adverse {
				desc = "not traversable by other"
			}
		}
		if mode&0o002 != 0 {
			adverse = true
			desc += "; other-writable"
		}
		if acl.Determined && acl.GrantsNonOwner {
			adverse = true
			desc += "; an ACL grants a non-owner principal read"
		}
		if !acl.Determined && acl.Errno != "" {
			boundaries = append(boundaries, store.path+" ACL ("+acl.Errno+")")
		}
		hit.EffectiveReaders, hit.Adverse = desc, adverse
		if adverse {
			exposed = append(exposed, store.path+" ("+desc+")")
		}
		hits = append(hits, hit)
	}

	r.Field("stores", hits)
	r.Field("observation_boundaries", boundaries)
	r.Field("acl_note", "ENODATA from system.posix_acl_access means the file has no ACL, which is a positive answer, not an unknown")

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a system secret store is reachable beyond root: "+strings.Join(exposed, "; ")))
	case len(boundaries) > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"the permissions of "+itoa(int64(len(boundaries)))+" system secret store(s) could not be observed from this account ("+
				strings.Join(boundaries, ", ")+"); reporting that boundary is the point — it is not a pass"))
	default:
		return finish(scan.Pass(
			"every system secret store present keeps its expected restrictive permissions (" + itoa(int64(len(hits))) + " inspected)"))
	}
}
