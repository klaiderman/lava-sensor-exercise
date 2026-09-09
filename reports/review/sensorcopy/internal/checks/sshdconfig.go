package checks

import (
	"path"
	"sort"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
)

// Bounds on the config walk. An Include chain is attacker-influencable on a
// compromised host, so depth, file count and per-file bytes are all capped.
const (
	sshdMaxIncludeDepth = 8
	sshdMaxFiles        = 64
	sshdDefaultPath     = "/etc/ssh/sshd_config"
	sshdConfigDir       = "/etc/ssh"
)

// sshdOccurrence is one place a keyword was written.
type sshdOccurrence struct {
	Path          string `json:"path"`
	Line          int64  `json:"line"`
	Value         string `json:"value"`
	MatchCriteria string `json:"match_criteria,omitempty"`
}

// sshdMatchBlock records a conditional block. Its presence makes any global
// verdict evidence-only (L17, F29).
type sshdMatchBlock struct {
	Criteria string `json:"criteria"`
	Path     string `json:"path"`
	Line     int64  `json:"line"`
}

// sshdConfig is the result of walking the daemon's config chain.
//
// It is the fallback oracle and, always, the provenance source: `sshd -G`
// prints the effective value but not which file set it (LD-5).
type sshdConfig struct {
	RootPath     string
	Files        []string
	Occurrences  map[string][]sshdOccurrence
	MatchBlocks  []sshdMatchBlock
	Observations []probe.Observation
	RootObs      probe.Observation
	Resolved     bool
	Truncated    bool
	BudgetHit    string
}

// sshdResolution is the config_resolution evidence shape.
type sshdResolution struct {
	Directive         string           `json:"directive"`
	EffectiveValue    string           `json:"effective_value,omitempty"`
	WinningSource     *sshdOccurrence  `json:"winning_source,omitempty"`
	Shadowed          []sshdOccurrence `json:"shadowed_occurrences"`
	ResolutionRule    string           `json:"resolution_rule"`
	Defaulted         bool             `json:"defaulted"`
	DefaultSource     string           `json:"default_source,omitempty"`
	ConditionalBlocks []sshdOccurrence `json:"conditional_blocks"`
	FilesRead         []string         `json:"files_read"`
	Found             bool             `json:"found"`
}

// walkSSHDConfig resolves the sshd configuration chain, expanding Include at
// the position it appears in the file and glob-sorting each expansion, because
// OpenSSH takes the FIRST obtained value for a keyword: an Include at the top
// and the same Include at the bottom give opposite answers (L16, F27).
func walkSSHDConfig(f probe.Files, rootPath string) *sshdConfig {
	if rootPath == "" {
		rootPath = sshdDefaultPath
	}
	c := &sshdConfig{
		RootPath:    rootPath,
		Occurrences: map[string][]sshdOccurrence{},
		Files:       []string{},
		MatchBlocks: []sshdMatchBlock{},
	}
	seen := map[string]bool{}
	c.parseFile(f, rootPath, 0, seen, true)
	return c
}

func (c *sshdConfig) parseFile(f probe.Files, p string, depth int, seen map[string]bool, isRoot bool) {
	if depth > sshdMaxIncludeDepth {
		c.BudgetHit = "depth"
		return
	}
	if len(c.Files) >= sshdMaxFiles {
		c.BudgetHit = "files"
		return
	}
	if seen[p] {
		// An Include cycle is a config bug, not a reason to loop forever.
		return
	}
	seen[p] = true

	obs := f.Read(p, probe.Small)
	obs.Detail = "sshd config chain: " + p
	c.Observations = append(c.Observations, obs)
	if isRoot {
		c.RootObs = obs
	}
	if obs.Status != probe.StatusOK {
		return
	}
	c.Files = append(c.Files, p)
	if obs.Truncated {
		c.Truncated = true
		c.BudgetHit = "bytes"
	}
	if isRoot {
		c.Resolved = true
	}

	currentMatch := ""
	for i, raw := range strings.Split(obs.Value, "\n") {
		line := int64(i + 1)
		s := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if idx := strings.IndexByte(s, '#'); idx >= 0 {
			s = strings.TrimSpace(s[:idx])
			if s == "" {
				continue
			}
		}
		key, val := splitDirective(s)
		lk := strings.ToLower(key)
		switch lk {
		case "match":
			if strings.EqualFold(val, "all") {
				currentMatch = ""
			} else {
				currentMatch = val
				c.MatchBlocks = append(c.MatchBlocks, sshdMatchBlock{Criteria: val, Path: p, Line: line})
			}
			continue
		case "include":
			// Include expands here, in place, glob-sorted.
			for _, pattern := range splitArgs(val) {
				for _, inc := range c.expand(f, pattern) {
					c.parseFile(f, inc, depth+1, seen, false)
				}
			}
			continue
		}
		c.Occurrences[lk] = append(c.Occurrences[lk], sshdOccurrence{
			Path: p, Line: line, Value: val, MatchCriteria: currentMatch,
		})
	}
}

// expand resolves an Include pattern against the filesystem, sorted, with the
// listing bounded. Globbing is supported in the final path component only; a
// pattern with a directory glob is recorded as read but not expanded.
func (c *sshdConfig) expand(f probe.Files, pattern string) []string {
	pattern = strings.Trim(pattern, `"`)
	if !strings.HasPrefix(pattern, "/") {
		pattern = path.Join(sshdConfigDir, pattern)
	}
	dir, base := path.Split(pattern)
	dir = strings.TrimSuffix(dir, "/")
	if dir == "" {
		dir = "/"
	}
	if strings.ContainsAny(dir, "*?[") {
		return nil
	}
	if !strings.ContainsAny(base, "*?[") {
		return []string{pattern}
	}
	names, obs := f.ReadDirNames(dir, 512)
	obs.Detail = "sshd Include expansion: " + pattern
	c.Observations = append(c.Observations, obs)
	if obs.Status != probe.StatusOK {
		return nil
	}
	var out []string
	for _, n := range names {
		if ok, err := path.Match(base, n); err == nil && ok {
			out = append(out, path.Join(dir, n))
		}
	}
	sort.Strings(out)
	return out
}

func splitDirective(s string) (key, val string) {
	// sshd accepts "Keyword value" and "Keyword=value".
	if i := strings.IndexAny(s, " \t="); i >= 0 {
		return s[:i], strings.TrimSpace(strings.TrimLeft(s[i:], " \t="))
	}
	return s, ""
}

func splitArgs(s string) []string {
	var out []string
	for _, tok := range strings.Fields(s) {
		out = append(out, strings.Trim(tok, `"`))
	}
	return out
}

// Resolve applies OpenSSH's precedence rule: the first obtained value for a
// keyword wins, and every later occurrence is shadowed. Reporting the LAST
// occurrence is the classic false verdict this defends against (L16).
func (c *sshdConfig) Resolve(directive string) sshdResolution {
	lk := strings.ToLower(directive)
	r := sshdResolution{
		Directive:         lk,
		ResolutionRule:    "first-obtained-value-wins (sshd_config(5): the first obtained value for each parameter is used)",
		Shadowed:          []sshdOccurrence{},
		ConditionalBlocks: []sshdOccurrence{},
		FilesRead:         c.Files,
	}
	if r.FilesRead == nil {
		r.FilesRead = []string{}
	}
	for _, occ := range c.Occurrences[lk] {
		if occ.MatchCriteria != "" {
			r.ConditionalBlocks = append(r.ConditionalBlocks, occ)
			continue
		}
		if !r.Found {
			r.Found = true
			r.EffectiveValue = occ.Value
			winner := occ
			r.WinningSource = &winner
			continue
		}
		r.Shadowed = append(r.Shadowed, occ)
	}
	return r
}

// sshdDefault is a compiled-in default with the citation that makes it usable.
// A pass derived from an assumed default with no default_source is a bug (L19).
type sshdDefault struct {
	value    string
	citation string
}

// sshdUpstreamDefaults are OpenSSH's documented compiled-in defaults. They are
// only applied when the distro family is known, because distros patch them
// (F28 is CONTESTED, so every defaulted row carries its scope).
var sshdUpstreamDefaults = map[string]sshdDefault{
	"permitrootlogin":              {"prohibit-password", "sshd_config(5) PermitRootLogin, default prohibit-password since OpenSSH 7.0"},
	"passwordauthentication":       {"yes", "sshd_config(5) PasswordAuthentication, default yes"},
	"kbdinteractiveauthentication": {"yes", "sshd_config(5) KbdInteractiveAuthentication, default yes"},
	"pubkeyauthentication":         {"yes", "sshd_config(5) PubkeyAuthentication, default yes"},
	"permitemptypasswords":         {"no", "sshd_config(5) PermitEmptyPasswords, default no"},
	"usepam":                       {"no", "sshd_config(5) UsePAM, default no"},
}

// sshdDebianDefaults are the values Debian and Ubuntu ship patched.
var sshdDebianDefaults = map[string]sshdDefault{
	"usepam": {"yes", "Debian/Ubuntu openssh-server ships UsePAM yes in the packaged sshd_config"},
}

// defaultFor returns a citable compiled-in default for a directive.
//
// It refuses to answer when the distribution family is unknown: an assumed
// default on an unidentified system is a guess, and a guess is not a finding
// (L19, fixture usepam-absent-unknown-distro).
func defaultFor(directive, osID, osIDLike string) (sshdDefault, bool) {
	lk := strings.ToLower(directive)
	family := strings.ToLower(strings.TrimSpace(osID + " " + osIDLike))
	if strings.TrimSpace(family) == "" {
		return sshdDefault{}, false
	}
	if strings.Contains(family, "debian") || strings.Contains(family, "ubuntu") {
		if d, ok := sshdDebianDefaults[lk]; ok {
			return d, true
		}
	}
	d, ok := sshdUpstreamDefaults[lk]
	return d, ok
}

// normalisePermitRootLogin folds the two spellings of the same policy: `sshd -G`
// prints `without-password` where the config file says `prohibit-password`
// (L18). Treating them as different values is a false CONTESTED.
func normalisePermitRootLogin(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "without-password", "prohibit-password":
		return "prohibit-password"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

// sshdRootPath finds the config file the daemon actually loads. Only observed
// paths are used; the distro name never selects a path (L37).
func sshdRootPath(f probe.Files) string {
	for _, p := range []string{sshdDefaultPath, "/etc/sshd_config", "/usr/local/etc/sshd_config"} {
		if f.Exists(p) {
			return p
		}
	}
	return sshdDefaultPath
}

// contestedDetail renders a disagreement without picking a winner.
func contestedDetail(directive, oracle, walker string) string {
	return "the running daemon reports " + directive + " " + oracle +
		" while the configuration chain resolves to " + walker +
		"; both are recorded and neither is preferred"
}
