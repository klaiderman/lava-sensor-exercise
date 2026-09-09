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
			if home := homeOfCandidate(cand.path, homes); home != "" && !unreadableSeen[home] {
				unreadableSeen[home] = true
				unreadableHomes = append(unreadableHomes, home)
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
var injectionKeys = []string{"ssh_authorized_keys", "chpasswd", "ssh_pwauth", "password"}

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

	inspect := func(path string, class provisioningClass) int {
		st := env.Files.Stat(path)
		st.Detail = "provisioning artifact candidate (" + string(class) + ")"
		r.Add(st)
		if st.Status == probe.StatusENOENT {
			return -1
		}
		row := provisioningArtifactRow{Path: path, Class: class}
		if st.Status != probe.StatusOK {
			undetermined = true
			denied = append(denied, path+" ("+st.Reason()+")")
			row.Errno = st.Reason()
			row.EffectiveReaders = "unknown"
			rows = append(rows, row)
			return len(rows) - 1
		}
		present = true
		if st.Meta != nil {
			row.FileType = st.Meta.FileType
			row.Mode, row.UID, row.GID, row.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		desc, reachable, _, _ := effectiveReaders(env, row.Mode, row.GID)
		row.EffectiveReaders = desc

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
				lower := strings.ToLower(body.Value)
				var found []string
				for _, k := range injectionKeys {
					if strings.Contains(lower, k) {
						found = append(found, k)
					}
				}
				if len(found) == 0 {
					continue
				}
				rows[idx].Class = classPayload
				rows[idx].InjectionKeys = found
				rows[idx].Note = "declares credential-bearing key names, so it is treated as payload rather than public configuration"
				if _, reachable, _, _ := effectiveReaders(env, rows[idx].Mode, rows[idx].GID); reachable {
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
			"no provisioning artifact exists on this machine - proven by successful listings of the cloud-init, Ignition and kickstart locations, not by their absence from a guess"))
	default:
		return finish(scan.Pass(
			"every provisioning payload artifact present is restricted to root (" + itoa(int64(len(rows))) +
				" artifact(s) inspected); the artifacts that are readable are the ones cloud-init publishes that way by design, with their sensitive keys redacted"))
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

// homeOfCandidate maps a candidate credential path back to the home directory
// it was generated from, so an unreadable home is named once rather than once
// per candidate file inside it.
func homeOfCandidate(path string, homes []string) string {
	for _, h := range homes {
		if strings.HasPrefix(path, h+"/") {
			return h
		}
	}
	return ""
}
