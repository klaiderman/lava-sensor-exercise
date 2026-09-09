package checks

import (
	"context"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// rootSSHDir is the conventional location of root's key material. It is a
// starting point, not an authority: where root's keys actually come from is
// what the daemon's effective authorizedkeysfile says.
const (
	rootSSHDir       = "/root/.ssh"
	rootAuthKeysPath = "/root/.ssh/authorized_keys"
)

// sshRootLoginPolicy answers: can a remote party authenticate directly as root
// over SSH, on the policy the running daemon actually loaded?
type sshRootLoginPolicy struct{ meta }

func (c sshRootLoginPolicy) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result

	// 1. The oracle: the daemon's own effective configuration.
	oracle := env.SSHD(ctx)
	oracleVal, oracleHas := oracle.Value("permitrootlogin")
	oracleOK := oracle.OK() && oracleHas

	// 2. The walker: always run, because it is the provenance source and the
	//    cross-check, not merely a fallback (LD-5).
	cfg := walkSSHDConfig(env.Files, sshdRootPath(env.Files))
	res := cfg.Resolve("permitrootlogin")

	// Evidence first, verdict after: the observation is recorded whatever the
	// verdict turns out to be.
	oracleObs := oracle.Obs
	oracleObs.LoadBearing = oracleOK
	r.Add(oracleObs)
	for i, obs := range cfg.Observations {
		// Only the root config read can be load-bearing, and only when the
		// walker is the source of the verdict. Marking a failed fallback
		// load-bearing while the oracle answered would manufacture an unknown.
		if i == 0 && !oracleOK && res.Found {
			obs.LoadBearing = true
		}
		r.Add(obs)
	}

	// 3. Reconcile. `sshd -G` prints without-password where the file says
	//    prohibit-password; folding the spellings avoids a false CONTESTED.
	normOracle := normalisePermitRootLogin(oracleVal)
	normWalker := normalisePermitRootLogin(res.EffectiveValue)

	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var effective, source string
	switch {
	case oracleOK && res.Found && normOracle != normWalker:
		r.Field("config_resolution", res)
		r.Field("oracle_value", oracleVal)
		r.Field("walker_value", res.EffectiveValue)
		r.Field("conditional_blocks", cfg.MatchBlocks)
		return finish(scan.Unknown(scan.ReasonContested, contestedDetail("permitrootlogin", oracleVal, res.EffectiveValue)))
	case oracleOK:
		effective, source = normOracle, "sshd -G (running daemon)"
	case res.Found:
		effective, source = normWalker, "configuration chain walk"
	default:
		// Nothing set it. A compiled-in default describes what a daemon would
		// do, so it is only meaningful when there is a daemon: with neither an
		// sshd binary nor a readable configuration, defaulting would invent a
		// policy for software that is not installed.
		if !sshdIsPresent(oracle, cfg) {
			r.Field("config_resolution", res)
			return finish(scan.Unknown(scan.ReasonUtilMiss, noDaemonDetail))
		}
		// A compiled-in default is only usable with a citation AND a known
		// distribution family (L19).
		osID, osIDLike := env.OSIDs()
		d, ok := defaultFor("permitrootlogin", osID, osIDLike)
		if !ok {
			r.Field("config_resolution", res)
			return finish(scan.Unknown(unresolvedReason(oracle, cfg),
				"the effective permitrootlogin could not be established: "+unresolvedDetail(oracle, cfg)))
		}
		effective = normalisePermitRootLogin(d.value)
		source = "compiled-in default"
		res.Defaulted = true
		res.DefaultSource = d.citation
		res.EffectiveValue = d.value
	}

	r.Field("config_resolution", res)
	r.Field("effective_value", effective)
	r.Field("effective_value_source", source)
	r.Field("conditional_blocks", cfg.MatchBlocks)

	// 4. A Match block scoping this keyword makes a global verdict
	//    evidence-only: the host-wide answer is contested by the conditional
	//    one (L17, F29).
	if override, ok := conflictingMatch(res, effective); ok {
		r.Field("match_override", override)
		return finish(scan.Unknown(scan.ReasonContested,
			"global permitrootlogin "+effective+" is overridden to "+override.Value+
				" for `Match "+override.MatchCriteria+"` at "+override.Path+":"+itoa(override.Line)+
				"; a host-wide verdict would be wrong in both directions"))
	}

	// 5. The verdict.
	switch effective {
	case "no":
		return finish(scan.Pass("the running policy refuses root logins over SSH outright (permitrootlogin no, per " + source + ")"))
	case "yes":
		return finish(scan.Fail(scan.ReasonPolicy,
			"the running policy permits direct root login over SSH (permitrootlogin yes, per "+source+")"))
	case "prohibit-password", "forced-commands-only":
		return c.keyBasedRootLogin(ctx, env, r, effective, source)
	default:
		r.Field("unrecognised_value", effective)
		return finish(scan.Unknown(scan.ReasonParse,
			"permitrootlogin resolved to the unrecognised value "+quote(effective)+" (per "+source+"); no verdict is derivable from it"))
	}
}

const noDaemonDetail = "no sshd binary and no sshd configuration were found, so there is no root-login policy to report; " +
	"note that the absence of an SSH listener is not the absence of remote access to the machine"

// keyPathVerdict is the per-path evidence row of the key-material question.
type keyPathVerdict struct {
	Path         string `json:"path"`
	Status       string `json:"status"`
	Errno        string `json:"errno,omitempty"`
	Size         *int64 `json:"size,omitempty"`
	Mode         *int64 `json:"mode,omitempty"`
	ProvenAbsent bool   `json:"proven_absent"`
	ParentStatus string `json:"parent_listing_status"`
}

// keyBasedRootLogin decides the prohibit-password / forced-commands-only
// branch, where password login as root is refused but key login is not.
//
// Absence proven by a successful listing is evidence, not an unknown. This
// passes only when the daemon itself told us where root's keys would come from
// — `authorizedkeysfile` expanded for root, with `authorizedkeyscommand` and
// `trustedusercakeys` both none — AND every one of those paths is proven absent
// by a successful stat of its parent directory. When any of that cannot be
// established (the usual case on an unprivileged run: /root/.ssh is EACCES),
// root key login can neither be confirmed nor excluded, and the honest answer
// is unknown (R4 B2 trap (d); L39 under-claim rule).
func (c sshRootLoginPolicy) keyBasedRootLogin(ctx context.Context, env *scan.Env, r scan.Result, effective, source string) scan.Result {
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	policyNote := "the running policy permits root login by public key (permitrootlogin " + effective + ", per " + source + ")"

	oracle := env.SSHD(ctx)
	rootHome := homeOf(env.Files, "root")
	paths, akfSource := rootAuthorizedKeyPaths(oracle, rootHome)

	akc, akcKnown := oracle.Value("authorizedkeyscommand")
	tuca, tucaKnown := oracle.Value("trustedusercakeys")

	checked := make([]keyPathVerdict, 0, len(paths))
	allProvenAbsent := true
	var undetermined probe.Observation

	for _, p := range paths {
		keyObs := env.Files.Stat(p)
		keyObs.Detail = "candidate root AuthorizedKeysFile (" + akfSource + ")"
		keyObs.LoadBearing = true
		parentObs := env.Files.Stat(parentDir(p))
		parentObs.Detail = "parent of a candidate root AuthorizedKeysFile; a successful listing is what makes absence provable"
		r.Add(parentObs, keyObs)

		v := keyPathVerdict{Path: p, Status: string(keyObs.Status), Errno: keyObs.Reason(), ParentStatus: string(parentObs.Status)}
		if keyObs.Meta != nil {
			v.Size, v.Mode = keyObs.Meta.Size, keyObs.Meta.Mode
		}
		switch {
		case keyObs.Status == probe.StatusOK && keyObs.Meta != nil && keyObs.Meta.Size != nil && *keyObs.Meta.Size > 0:
			checked = append(checked, v)
			r.Field("authorized_keys_checked", checked)
			return finish(scan.Fail(scan.ReasonPolicy,
				policyNote+" and root key material is present at "+p+" ("+itoa(*keyObs.Meta.Size)+" bytes)"))
		case keyObs.Status == probe.StatusENOENT && parentObs.Status == probe.StatusOK:
			// Absent, and the parent listing succeeded: a proven negative.
			v.ProvenAbsent = true
		case keyObs.Status == probe.StatusOK:
			// Present and empty: no key material to authenticate with.
			v.ProvenAbsent = true
		default:
			allProvenAbsent = false
			if undetermined.Status == "" {
				undetermined = keyObs
			}
		}
		checked = append(checked, v)
	}

	r.Field("authorized_keys_checked", checked)
	r.Field("authorized_keys_source", akfSource)
	r.Field("authorized_keys_command", renderDirective(akc, akcKnown))
	r.Field("trusted_user_ca_keys", renderDirective(tuca, tucaKnown))
	r.Field("root_home", rootHome)

	akcNone := akcKnown && isNoneValue(akc)
	tucaNone := tucaKnown && isNoneValue(tuca)

	switch {
	case !oracle.OK():
		// Without the daemon's own answer we do not know which paths, which
		// command or which CA it would consult, so the absence of a key at the
		// conventional path proves nothing.
		return finish(scan.Unknown(scan.ReasonUtilMiss,
			policyNote+"; the daemon did not report its effective authorizedkeysfile, authorizedkeyscommand or "+
				"trustedusercakeys, so the paths root's keys could come from are not established and key-based "+
				"root login cannot be excluded"))
	case !allProvenAbsent:
		reason := scan.ReasonEACCES
		if undetermined.Status != "" && undetermined.Reason() != "" {
			reason = undetermined.Reason()
		}
		return finish(scan.Unknown(reason,
			policyNote+" and at least one candidate AuthorizedKeysFile path could not be resolved ("+reason+
				"), so root key material can neither be confirmed nor excluded; denied is not absent"))
	case !akcNone || !tucaNone:
		what := "authorizedkeyscommand " + renderDirective(akc, akcKnown)
		if !tucaNone {
			what = "trustedusercakeys " + renderDirective(tuca, tucaKnown)
		}
		return finish(scan.Unknown(scan.ReasonPolicy,
			policyNote+"; no key file exists at any path the daemon named, but "+what+
				" can supply root keys from outside the filesystem paths we checked"))
	default:
		return finish(scan.Pass(policyNote + ", but root has no key material it could use: " + akfSource +
			" resolves to " + strings.Join(paths, ", ") + ", each proven absent by a successful listing of its parent, " +
			"authorizedkeyscommand is none and trustedusercakeys is none, so no remote party can authenticate as root over SSH"))
	}
}

// rootAuthorizedKeyPaths expands the daemon's effective authorizedkeysfile for
// root. OpenSSH resolves a relative path against the user's home directory and
// substitutes %h (home), %u (user name) and %% (a literal percent).
func rootAuthorizedKeyPaths(oracle *scan.SSHDOracle, rootHome string) (paths []string, source string) {
	if v, ok := oracle.Value("authorizedkeysfile"); ok && strings.TrimSpace(v) != "" {
		source = "sshd -G authorizedkeysfile"
		for _, tok := range splitArgs(v) {
			if isNoneValue(tok) {
				continue
			}
			paths = append(paths, expandAuthorizedKeysToken(tok, rootHome))
		}
	}
	if len(paths) == 0 {
		source = "default AuthorizedKeysFile path (the daemon did not report one)"
		paths = []string{rootHome + "/.ssh/authorized_keys"}
	}
	return paths, source
}

func expandAuthorizedKeysToken(tok, home string) string {
	var b strings.Builder
	for i := 0; i < len(tok); i++ {
		if tok[i] == '%' && i+1 < len(tok) {
			switch tok[i+1] {
			case 'h':
				b.WriteString(home)
				i++
				continue
			case 'u':
				b.WriteString("root")
				i++
				continue
			case '%':
				b.WriteByte('%')
				i++
				continue
			}
		}
		b.WriteByte(tok[i])
	}
	out := b.String()
	if !strings.HasPrefix(out, "/") {
		out = home + "/" + out
	}
	return out
}

// homeOf resolves an account's home directory from /etc/passwd. No exec, and a
// documented convention rather than a guess when the file cannot be read.
func homeOf(f probe.Files, user string) string {
	obs := f.Read("/etc/passwd", probe.Large)
	if obs.Status == probe.StatusOK {
		for _, ln := range strings.Split(obs.Value, "\n") {
			fields := strings.Split(strings.TrimSpace(ln), ":")
			if len(fields) >= 6 && fields[0] == user && fields[5] != "" {
				return strings.TrimRight(fields[5], "/")
			}
		}
	}
	if user == "root" {
		return rootHomeDefault
	}
	return "/home/" + user
}

const rootHomeDefault = "/root"

func parentDir(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "/"
}

func isNoneValue(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	return t == "" || t == "none"
}

func renderDirective(v string, known bool) string {
	if !known {
		return "unknown (not reported by the daemon)"
	}
	if strings.TrimSpace(v) == "" {
		return "none"
	}
	return v
}

// conflictingMatch returns a Match-scoped occurrence whose verdict class
// differs from the global one. A Match that is strictly more restrictive does
// not invalidate a global fail.
func conflictingMatch(res sshdResolution, global string) (sshdOccurrence, bool) {
	for _, occ := range res.ConditionalBlocks {
		if verdictClass(normalisePermitRootLogin(occ.Value)) != verdictClass(global) {
			return occ, true
		}
	}
	return sshdOccurrence{}, false
}

func verdictClass(v string) string {
	switch v {
	case "no":
		return "refused"
	case "yes":
		return "permitted"
	case "prohibit-password", "forced-commands-only":
		return "key-only"
	}
	return "unknown"
}

// sshdIsPresent reports whether there is evidence of an SSH daemon at all: a
// binary that could be executed, or a configuration chain that was read.
func sshdIsPresent(oracle *scan.SSHDOracle, cfg *sshdConfig) bool {
	if oracle.Obs.Status != probe.StatusUtilityMissing {
		return true
	}
	return cfg.Resolved
}

// unresolvedReason picks the reason that is actually actionable.
//
// A daemon that exists but did not answer inside its budget (TIMEOUT) or failed
// for its own reasons (EXECUTION_ERROR) is a stronger signal than "the config
// file is not there", so it wins; a missing binary is weaker than a denied or
// absent config chain, so the chain wins over it.
func unresolvedReason(oracle *scan.SSHDOracle, cfg *sshdConfig) string {
	switch oracle.Obs.Status {
	case probe.StatusTimeout, probe.StatusExecError:
		if r := oracle.Obs.Reason(); r != "" {
			return r
		}
	}
	if cfg.RootObs.Status != probe.StatusOK && cfg.RootObs.Status != "" {
		if r := cfg.RootObs.Reason(); r != "" {
			return r
		}
	}
	if r := oracle.Obs.Reason(); r != "" {
		return r
	}
	return scan.ReasonENOENT
}

func unresolvedDetail(oracle *scan.SSHDOracle, cfg *sshdConfig) string {
	parts := []string{"sshd -G: " + string(oracle.Obs.Status)}
	if oracle.ParseError != "" {
		parts = append(parts, "oracle parse: "+oracle.ParseError)
	}
	if cfg.RootObs.Status == probe.StatusOK {
		parts = append(parts, "the config chain was read ("+strings.Join(cfg.Files, ", ")+
			") but does not set the directive, and no compiled-in default is citable for this distribution")
	} else {
		parts = append(parts, cfg.RootPath+": "+string(cfg.RootObs.Status))
	}
	return strings.Join(parts, "; ")
}

func reasonOf(obs ...probe.Observation) string {
	for _, o := range obs {
		if o.Status != probe.StatusOK && o.Status != "" {
			if r := o.Reason(); r != "" {
				return r
			}
		}
	}
	return scan.ReasonEACCES
}

// fileMeta is the file_metadata evidence shape for a single path.
type fileMeta struct {
	Path     string `json:"path"`
	Exists   *bool  `json:"exists,omitempty"`
	FileType string `json:"file_type,omitempty"`
	Mode     *int64 `json:"mode,omitempty"`
	UID      *int64 `json:"uid,omitempty"`
	GID      *int64 `json:"gid,omitempty"`
	Size     *int64 `json:"size,omitempty"`
	Errno    string `json:"errno,omitempty"`
	Status   string `json:"status"`
}

func renderMeta(obs probe.Observation) fileMeta {
	fm := fileMeta{Path: obs.Source, Status: string(obs.Status), Errno: obs.Reason()}
	if obs.Meta != nil {
		fm.Exists = obs.Meta.Exists
		fm.FileType = obs.Meta.FileType
		fm.Mode = obs.Meta.Mode
		fm.UID = obs.Meta.UID
		fm.GID = obs.Meta.GID
		fm.Size = obs.Meta.Size
	}
	return fm
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func quote(s string) string { return `"` + s + `"` }
