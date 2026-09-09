package checks

import (
	"context"
	"strings"

	"lava.sh/sensor/internal/probe"
	"lava.sh/sensor/internal/scan"
)

// rootAuthKeysPath is the default AuthorizedKeysFile location for root. It is
// the default only: AuthorizedKeysFile can point elsewhere, which is why the
// absence of a key here never proves the absence of root key material.
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

	var effective, source string
	switch {
	case oracleOK && res.Found && normOracle != normWalker:
		r.Field("config_resolution", res)
		r.Field("oracle_value", oracleVal)
		r.Field("walker_value", res.EffectiveValue)
		r.Field("conditional_blocks", cfg.MatchBlocks)
		out := scan.Unknown(scan.ReasonContested, contestedDetail("permitrootlogin", oracleVal, res.EffectiveValue))
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
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
			out := scan.Unknown(scan.ReasonUtilMiss,
				"no sshd binary and no sshd configuration were found, so there is no root-login policy to report; "+
					"note that the absence of an SSH listener is not the absence of remote access to the machine")
			out.Observations, out.Fields = r.Observations, r.Fields
			return out
		}
		// A compiled-in default is only usable with a citation AND a known
		// distribution family (L19).
		osID, osIDLike := env.OSIDs()
		if d, ok := defaultFor("permitrootlogin", osID, osIDLike); ok {
			effective = normalisePermitRootLogin(d.value)
			source = "compiled-in default"
			res.Defaulted = true
			res.DefaultSource = d.citation
			res.EffectiveValue = d.value
		} else {
			r.Field("config_resolution", res)
			out := scan.Unknown(unresolvedReason(oracle, cfg),
				"the effective permitrootlogin could not be established: "+unresolvedDetail(oracle, cfg))
			out.Observations, out.Fields = r.Observations, r.Fields
			return out
		}
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
		out := scan.Unknown(scan.ReasonContested,
			"global permitrootlogin "+effective+" is overridden to "+override.Value+
				" for `Match "+override.MatchCriteria+"` at "+override.Path+":"+itoa(override.Line)+
				"; a host-wide verdict would be wrong in both directions")
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	// 5. The verdict.
	switch effective {
	case "no":
		out := scan.Pass("the running policy refuses root logins over SSH outright (permitrootlogin no, per " + source + ")")
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	case "yes":
		out := scan.Fail(scan.ReasonPolicy,
			"the running policy permits direct root login over SSH (permitrootlogin yes, per "+source+")")
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	case "prohibit-password", "forced-commands-only":
		return c.keyBasedRootLogin(env, r, effective, source)
	default:
		r.Field("unrecognised_value", effective)
		out := scan.Unknown(scan.ReasonParse,
			"permitrootlogin resolved to the unrecognised value "+quote(effective)+" (per "+source+"); no verdict is derivable from it")
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
}

// keyBasedRootLogin decides the prohibit-password / forced-commands-only
// branch, where password login as root is refused but key login is not.
//
// The distinction that matters: EACCES on /root/.ssh is not "no keys". On an
// unprivileged run that directory is normally 0700 root, so root key login can
// neither be confirmed nor excluded — the honest answer is unknown, and it is
// worth more than a comfortable pass (R4 B2 trap (d)).
func (c sshRootLoginPolicy) keyBasedRootLogin(env *scan.Env, r scan.Result, effective, source string) scan.Result {
	dirObs := env.Files.Stat(rootSSHDir)
	keyObs := env.Files.Stat(rootAuthKeysPath)
	dirObs.Detail = "root's ssh directory; its readability decides whether root key material is observable at all"
	keyObs.Detail = "root's default AuthorizedKeysFile"
	keyObs.LoadBearing = true
	r.Add(dirObs, keyObs)
	r.Field("root_ssh_dir", renderMeta(dirObs))
	r.Field("root_authorized_keys", renderMeta(keyObs))

	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	switch {
	case keyObs.Status == probe.StatusOK && keyObs.Meta != nil && keyObs.Meta.Size != nil && *keyObs.Meta.Size > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the running policy permits root login by public key (permitrootlogin "+effective+
				", per "+source+") and root key material is present at "+rootAuthKeysPath+
				" ("+itoa(*keyObs.Meta.Size)+" bytes)"))

	case keyObs.Status == probe.StatusOK:
		// Readable and empty: key login is currently impossible at the default
		// path, but the policy still permits it and AuthorizedKeysFile may
		// point elsewhere. Not a pass; not a fail.
		return finish(scan.Unknown(scan.ReasonENOENT,
			"the running policy permits root login by public key (permitrootlogin "+effective+
				", per "+source+"); "+rootAuthKeysPath+" is readable and empty, but AuthorizedKeysFile may name another path "+
				"and a key can be added without a policy change, so root access cannot be excluded from the policy alone"))

	case keyObs.Status == probe.StatusENOENT && dirObs.Status == probe.StatusOK:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"the running policy permits root login by public key (permitrootlogin "+effective+
				", per "+source+"); no key file exists at "+rootAuthKeysPath+" right now, proven by a successful listing of "+
				rootSSHDir+", but the policy itself still permits key-based root login"))

	default:
		// The live branch on an unprivileged run of a normally configured host.
		return finish(scan.Unknown(reasonOf(keyObs, dirObs),
			"the running policy permits root login by public key (permitrootlogin "+effective+
				", per "+source+") and "+rootSSHDir+" is not readable by this uid ("+reasonOf(keyObs, dirObs)+
				"), so root key material can neither be confirmed nor excluded; denied is not absent"))
	}
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
		parts = append(parts, "the config chain was read ("+strings.Join(cfg.Files, ", ")+") but does not set the directive, and no compiled-in default is citable for this distribution")
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
