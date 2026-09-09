package scan

import (
	"context"
	"strings"
	"sync"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
)

// Check is one registered posture question. Every registered check emits
// exactly one finding per run, always (L34).
type Check interface {
	ID() string
	Category() string
	Title() string
	// Impact is the severity reported when the check does not pass. It is
	// declared here and applied centrally; a check never sets severity itself.
	Impact() string
	// Observational marks a check that inventories rather than judges. Those
	// are always reported at severity info.
	Observational() bool
	// Budget is the check's own declared time bound. The engine takes
	// min(Budget, remaining scan deadline), so a declared budget can only ever
	// shrink (see scan.Run).
	Budget() time.Duration
	Run(ctx context.Context, env *Env) Result
}

// Result is what a check returns. It carries the verdict, the closed-vocabulary
// reason, the observations behind it and any ordered evidence extras.
type Result struct {
	Status       Status
	Reason       string
	Detail       string
	Observations []probe.Observation
	Fields       []Field
}

// Add appends observations to the result.
func (r *Result) Add(obs ...probe.Observation) { r.Observations = append(r.Observations, obs...) }

// Field appends an ordered evidence extra.
func (r *Result) Field(key string, value any) { r.Fields = append(r.Fields, F(key, value)) }

// LoadBearingIf marks already-recorded observations as load-bearing when the
// verdict turns out to rest on them.
//
// Whether an observation is load-bearing depends on the branch taken, not on
// the order the observations were gathered in: a check that FOUND something
// stands on that positive observation, while a check about to say it found
// nothing stands on every listing having succeeded. Marking unconditionally
// would manufacture unknowns out of positive findings.
func (r *Result) LoadBearingIf(cond bool, sources ...string) {
	if !cond {
		return
	}
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	for i := range r.Observations {
		if len(want) == 0 || want[r.Observations[i].Source] {
			r.Observations[i].LoadBearing = true
		}
	}
}

// Pass builds a passing result.
func Pass(detail string) Result { return Result{Status: StatusPass, Detail: detail} }

// Fail builds a failing result. reason comes from the closed vocabulary.
func Fail(reason, detail string) Result {
	return Result{Status: StatusFail, Reason: reason, Detail: detail}
}

// Unknown builds an unknown result. reason comes from the closed vocabulary and
// is mandatory.
func Unknown(reason, detail string) Result {
	return Result{Status: StatusUnknown, Reason: reason, Detail: detail}
}

// Closed reason vocabulary (EVIDENCE_MODEL §7). The five failure classes stay
// five and are never collapsed (L35).
const (
	ReasonEACCES    = "EACCES"
	ReasonEPERM     = "EPERM"
	ReasonENOENT    = "ENOENT"
	ReasonEINVAL    = "EINVAL"
	ReasonTimeout   = "TIMEOUT"
	ReasonUtilMiss  = "UTILITY_MISSING"
	ReasonBudget    = "BUDGET_EXHAUSTED"
	ReasonParse     = "PARSE_ERROR"
	ReasonExecError = "EXECUTION_ERROR"
	ReasonContested = "CONTESTED"
	ReasonPolicy    = "POLICY"
	ReasonInternal  = "INTERNAL_ERROR"
	// ReasonTimestampRes means two events were observed with a timestamp too
	// coarse to order them. It is distinct from CONTESTED: nothing disagrees,
	// the instrument simply does not resolve the question.
	ReasonTimestampRes = "TIMESTAMP_RESOLUTION"
	// ReasonNotAttempted means the observation was reachable but the sensor
	// declined to make it, by design. It is distinct from EACCES (we were
	// refused) and from ENOENT (there was nothing there): the limit is the
	// sensor's own read-only contract, and saying so is the honest answer.
	ReasonNotAttempted = "NOT_ATTEMPTED"
)

// Env is the read-once shared state for a whole scan: the probe handles, a
// fixed clock, and the three observations more than one check needs. Everything
// else a check wants, it reads itself.
type Env struct {
	Files    *probe.Reader
	Runner   probe.Runner
	Now      func() time.Time
	Deadline time.Time
	EUID     int64

	// Degradations records run-level capability losses (an os.Root that would
	// not open, for instance) for the run-level scan block.
	Degradations []string

	onceSSHD   sync.Once
	sshd       *SSHDOracle
	onceMount  sync.Once
	mounts     *MountTable
	onceGroup  sync.Once
	groups     *GroupDB
	onceOS     sync.Once
	osID       string
	osIDLike   string
	onceGroups sync.Once
	selfGroups []int64
	muUnits    sync.Mutex
	units      map[string]probe.Observation
}

// SystemdShow runs `systemctl show` for one unit at most once per scan and
// caches the RAW observation. Env caches observations, never conclusions: what
// the properties mean is decided by each check that reads them.
func (e *Env) SystemdShow(ctx context.Context, unit string, props ...string) probe.Observation {
	key := unit + " " + strings.Join(props, " ")
	e.muUnits.Lock()
	if obs, ok := e.units[key]; ok {
		e.muUnits.Unlock()
		return obs
	}
	e.muUnits.Unlock()

	args := []string{"show", unit}
	for _, p := range props {
		args = append(args, "-p", p)
	}
	obs := e.Runner.Run(ctx, probe.Spec{
		Name: "systemctl", Args: args, Budget: 3 * time.Second,
		Purpose: "unit properties of " + unit,
	})
	e.muUnits.Lock()
	if e.units == nil {
		e.units = map[string]probe.Observation{}
	}
	e.units[key] = obs
	e.muUnits.Unlock()
	return obs
}

// SelfGroups returns the effective and supplementary group ids of the running
// sensor, read from /proc/self/status.
//
// This is what makes "who may open this device node" answerable without opening
// it: a node's mode, owner and group are compared against the identity we
// actually have, rather than against an assumption about it.
func (e *Env) SelfGroups() []int64 {
	e.onceGroups.Do(func() {
		e.selfGroups = []int64{}
		obs := e.Files.Read("/proc/self/status", probe.Small)
		if obs.Status != probe.StatusOK {
			return
		}
		for _, ln := range strings.Split(obs.Value, "\n") {
			rest, ok := strings.CutPrefix(ln, "Groups:")
			if !ok {
				continue
			}
			for _, f := range strings.Fields(rest) {
				e.selfGroups = append(e.selfGroups, atoi64(f))
			}
		}
	})
	return e.selfGroups
}

// OSIDs returns the os-release ID and ID_LIKE. A check that needs a documented
// compiled-in default must know the distribution family; when this returns
// empty strings the honest answer is UNKNOWN, never an assumed default (L19).
func (e *Env) OSIDs() (id, idLike string) {
	e.onceOS.Do(func() {
		obs := e.Files.Read("/etc/os-release", probe.SmallFollow)
		if obs.Status != probe.StatusOK {
			obs = e.Files.Read("/usr/lib/os-release", probe.SmallFollow)
		}
		if obs.Status != probe.StatusOK {
			return
		}
		for _, ln := range strings.Split(obs.Value, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "ID":
				e.osID = v
			case "ID_LIKE":
				e.osIDLike = v
			}
		}
	})
	return e.osID, e.osIDLike
}

// NewEnv builds the production environment.
func NewEnv(files *probe.Reader, runner probe.Runner, now func() time.Time, deadline time.Time, euid int64) *Env {
	if now == nil {
		now = time.Now
	}
	return &Env{Files: files, Runner: runner, Now: now, Deadline: deadline, EUID: euid}
}

// SSHDOracle is what sshd itself makes of the configuration on disk right now.
//
// `sshd -G` re-parses the current files with the installed binary's compiled-in
// defaults; it says nothing about the process that is listening. Whether the
// daemon loaded these files is a separate question, answered by
// SSH_POLICY_IN_FORCE, and the policy checks carry that answer as a caveat.
// It is run at most once per scan: one observation, shared (L18, L41).
type SSHDOracle struct {
	Obs        probe.Observation
	Directives map[string][]string
	Order      []string
	ParseError string
}

// Value returns the first value of a directive as the daemon reported it.
func (o *SSHDOracle) Value(key string) (string, bool) {
	if o == nil || o.Directives == nil {
		return "", false
	}
	v, ok := o.Directives[strings.ToLower(key)]
	if !ok || len(v) == 0 {
		return "", false
	}
	return v[0], true
}

// OK reports whether the oracle produced a usable directive set.
func (o *SSHDOracle) OK() bool {
	return o != nil && o.Obs.Status == probe.StatusOK && o.ParseError == "" && len(o.Directives) > 0
}

// sshdCandidates are the paths a system daemon binary is normally installed at.
// The gate is the observed presence of the binary, never the distro name (L37).
var sshdCandidates = []string{"/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd", "/usr/libexec/openssh/sshd"}

// SSHD runs `sshd -G` once per scan and caches the parsed result.
func (e *Env) SSHD(ctx context.Context) *SSHDOracle {
	e.onceSSHD.Do(func() {
		o := &SSHDOracle{Directives: map[string][]string{}}
		// Binary discovery goes through the read seam, not through PATH: a
		// capability gate must be an observation of this filesystem (L37).
		bin := ""
		for _, c := range sshdCandidates {
			st := e.Files.Stat(c)
			if st.Status == probe.StatusOK && st.Meta != nil &&
				(st.Meta.FileType == "regular" || st.Meta.FileType == "symlink") {
				bin = c
				break
			}
		}
		if bin == "" {
			o.Obs = probe.Observation{
				Source: "sshd -G", Kind: probe.KindCommandExec,
				Status: probe.StatusUtilityMissing,
				Detail: "no sshd binary at " + strings.Join(sshdCandidates, ", ") + " or on the sensor PATH",
				Meta:   &probe.Meta{Command: []string{"sshd", "-G"}},
			}
			e.sshd = o
			return
		}
		// -G, never -T: -T loads the host keys first and exits 1 unprivileged,
		// which would look like a config error (F26, L18).
		o.Obs = e.Runner.Run(ctx, probe.Spec{
			Name: bin, Args: []string{"-G"},
			Budget:  5 * time.Second,
			Purpose: "effective sshd configuration as sshd resolves it from disk now",
		})
		if o.Obs.Status == probe.StatusOK {
			parseSSHDG(o)
		}
		e.sshd = o
	})
	return e.sshd
}

// SSHDCached returns the oracle from the one run this scan already made. It is
// for callers that are downstream of SSHD(ctx) in the same check and have no
// context to hand; it never starts a process.
func (e *Env) SSHDCached() *SSHDOracle {
	if e.sshd == nil {
		return &SSHDOracle{Directives: map[string][]string{}}
	}
	return e.sshd
}

func parseSSHDG(o *SSHDOracle) {
	lines := strings.Split(o.Obs.Value, "\n")
	for _, ln := range lines {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, found := strings.Cut(ln, " ")
		if !found {
			k, v = ln, ""
		}
		k = strings.ToLower(strings.TrimSpace(k))
		if k == "" {
			continue
		}
		if _, seen := o.Directives[k]; !seen {
			o.Order = append(o.Order, k)
		}
		o.Directives[k] = append(o.Directives[k], strings.TrimSpace(v))
	}
	if len(o.Directives) == 0 {
		o.ParseError = "sshd -G produced no keyword/value lines"
	}
	if o.Obs.Truncated {
		o.ParseError = "sshd -G output hit the capture cap; the directive set is partial"
	}
}

// MountEntry is one line of /proc/self/mountinfo.
type MountEntry struct {
	MountPoint string `json:"mount_point"`
	FSType     string `json:"fstype"`
	Source     string `json:"source"`
	Options    string `json:"options"`
	SuperOpts  string `json:"super_options"`
	MajorMinor string `json:"major_minor"`
	Root       string `json:"root"`
}

// MountTable is the parsed mount table plus the observation that produced it.
type MountTable struct {
	Obs     probe.Observation
	Entries []MountEntry
}

// Mounts reads /proc/self/mountinfo once per scan.
func (e *Env) Mounts() *MountTable {
	e.onceMount.Do(func() {
		m := &MountTable{}
		m.Obs = e.Files.Read("/proc/self/mountinfo", probe.Large)
		if m.Obs.Status == probe.StatusOK {
			m.Entries = parseMountInfo(m.Obs.Value)
		}
		e.mounts = m
	})
	return e.mounts
}

// parseMountInfo splits on the literal " - " separator and indexes the tail
// from the end, because the optional propagation fields between them are
// variable in number (L31, F20).
func parseMountInfo(s string) []MountEntry {
	var out []MountEntry
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		head, tail, ok := strings.Cut(ln, " - ")
		if !ok {
			continue
		}
		hf := strings.Fields(head)
		tf := strings.Fields(tail)
		if len(hf) < 6 || len(tf) < 3 {
			continue
		}
		out = append(out, MountEntry{
			Root:       unmangle(hf[3]),
			MountPoint: unmangle(hf[4]),
			Options:    hf[5],
			MajorMinor: hf[2],
			FSType:     tf[0],
			Source:     unmangle(tf[1]),
			SuperOpts:  tf[2],
		})
	}
	return out
}

// unmangle decodes the octal escapes the kernel uses for space, tab, newline
// and backslash in mountinfo paths.
func unmangle(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			var v int
			ok := true
			for j := 1; j <= 3; j++ {
				c := s[i+j]
				if c < '0' || c > '7' {
					ok = false
					break
				}
				v = v*8 + int(c-'0')
			}
			if ok {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Group is one /etc/group record.
type Group struct {
	Name    string   `json:"name"`
	GID     int64    `json:"gid"`
	Members []string `json:"members"`
}

// GroupDB is the local group database plus the observation that produced it.
// Its caveat: nsswitch may route group lookups elsewhere, so an empty member
// list here is "empty in files", not "empty" (F73).
type GroupDB struct {
	Obs    probe.Observation
	Groups []Group
	byName map[string]Group
}

// Lookup returns a group by name.
func (g *GroupDB) Lookup(name string) (Group, bool) {
	if g == nil || g.byName == nil {
		return Group{}, false
	}
	v, ok := g.byName[name]
	return v, ok
}

// Groups reads /etc/group once per scan.
func (e *Env) Groups() *GroupDB {
	e.onceGroup.Do(func() {
		g := &GroupDB{byName: map[string]Group{}}
		g.Obs = e.Files.Read("/etc/group", probe.Large)
		if g.Obs.Status == probe.StatusOK {
			for _, ln := range strings.Split(g.Obs.Value, "\n") {
				f := strings.Split(strings.TrimSpace(ln), ":")
				if len(f) < 4 || f[0] == "" {
					continue
				}
				var members []string
				if f[3] != "" {
					members = strings.Split(f[3], ",")
				} else {
					members = []string{}
				}
				grp := Group{Name: f[0], GID: atoi64(f[2]), Members: members}
				g.Groups = append(g.Groups, grp)
				g.byName[grp.Name] = grp
			}
		}
		e.groups = g
	})
	return e.groups
}

func atoi64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	return n
}
