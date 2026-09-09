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

// OptOut records that some already-gathered observations do not underwrite the
// verdict, and WHY.
//
// Observations are load-bearing by default. Whether one underwrites the answer
// depends on the branch taken, not on the order things were gathered in: a
// check that FOUND something stands on that positive observation, while a check
// about to say it found nothing stands on every listing having succeeded. The
// reason is recorded in the evidence so the exemption is auditable rather than
// silent.
func (r *Result) OptOut(cond bool, reason string, sources ...string) {
	if !cond || reason == "" {
		return
	}
	want := map[string]bool{}
	for _, s := range sources {
		want[s] = true
	}
	for i := range r.Observations {
		if len(want) == 0 || want[r.Observations[i].Source] {
			if r.Observations[i].OptOut == "" {
				r.Observations[i].OptOut = reason
			}
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
	// ReasonNoEvidence means the check reached a verdict without a single
	// successful observation underwriting it. A conclusion with nothing behind
	// it is not a conclusion.
	ReasonNoEvidence = "NO_EVIDENCE"
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
//
// Membership of a group is NOT just field 4 of /etc/group. An account whose
// PRIMARY gid (field 4 of /etc/passwd) is the group's gid is a member of it and
// reads every file that group can read, while appearing in no member list. A
// model that counts only the explicit list reports "the group is empty, so this
// is owner-only" about a file a real account can open.
//
// Its caveat: nsswitch may route lookups elsewhere, so this is "as the local
// files describe it", not "as the system resolves it" (F73).
type GroupDB struct {
	Obs       probe.Observation
	PasswdObs probe.Observation
	Groups    []Group
	byName    map[string]Group
	byGID     map[int64]Group
}

// Determined reports whether the group model could be built at all. A database
// that could not be read is an unknown, never an empty set: treating an
// unreadable /etc/group as "every group is empty" turns a group-readable secret
// into a pass.
func (g *GroupDB) Determined() bool {
	return g != nil && g.Obs.Status == probe.StatusOK && g.PasswdObs.Status == probe.StatusOK
}

// Reason names why the group model is unavailable.
func (g *GroupDB) Reason() string {
	if g == nil {
		return ReasonInternal
	}
	if g.Obs.Status != probe.StatusOK {
		return "/etc/group " + g.Obs.Reason()
	}
	if g.PasswdObs.Status != probe.StatusOK {
		return "/etc/passwd " + g.PasswdObs.Reason()
	}
	return ""
}

// ByGID returns the group with that gid, including its effective members.
func (g *GroupDB) ByGID(gid int64) (Group, bool) {
	if g == nil || g.byGID == nil {
		return Group{}, false
	}
	v, ok := g.byGID[gid]
	return v, ok
}

// Lookup returns a group by name.
func (g *GroupDB) Lookup(name string) (Group, bool) {
	if g == nil || g.byName == nil {
		return Group{}, false
	}
	v, ok := g.byName[name]
	return v, ok
}

// Groups reads /etc/group and /etc/passwd once per scan and builds the
// EFFECTIVE membership of every group: the explicit member list plus every
// account whose primary gid is that group.
func (e *Env) Groups() *GroupDB {
	e.onceGroup.Do(func() {
		g := &GroupDB{byName: map[string]Group{}, byGID: map[int64]Group{}}
		g.Obs = e.Files.Read("/etc/group", probe.Large)
		g.PasswdObs = e.Files.Read("/etc/passwd", probe.Large)

		primary := map[int64][]string{}
		if g.PasswdObs.Status == probe.StatusOK {
			for _, ln := range strings.Split(g.PasswdObs.Value, "\n") {
				f := strings.Split(strings.TrimSpace(ln), ":")
				if len(f) < 4 || f[0] == "" {
					continue
				}
				gid := atoi64(f[3])
				primary[gid] = append(primary[gid], f[0])
			}
		}
		if g.Obs.Status == probe.StatusOK {
			for _, ln := range strings.Split(g.Obs.Value, "\n") {
				f := strings.Split(strings.TrimSpace(ln), ":")
				if len(f) < 4 || f[0] == "" {
					continue
				}
				members := []string{}
				if f[3] != "" {
					members = strings.Split(f[3], ",")
				}
				gid := atoi64(f[2])
				seen := map[string]bool{}
				for _, m := range members {
					seen[m] = true
				}
				for _, m := range primary[gid] {
					if !seen[m] {
						seen[m] = true
						members = append(members, m)
					}
				}
				grp := Group{Name: f[0], GID: gid, Members: members}
				g.Groups = append(g.Groups, grp)
				g.byName[grp.Name] = grp
				g.byGID[gid] = grp
			}
		}
		e.groups = g
	})
	return e.groups
}

// Readers is the answer to "who can read this object", from its metadata and
// the group model.
type Readers struct {
	Determined  bool     `json:"determined"`
	Reason      string   `json:"reason,omitempty"`
	OtherRead   bool     `json:"other_readable"`
	OtherWrite  bool     `json:"other_writable"`
	GroupRead   bool     `json:"group_readable"`
	GroupWrite  bool     `json:"group_writable"`
	GroupName   string   `json:"group_name,omitempty"`
	GroupMember []string `json:"group_effective_members,omitempty"`
	// BeyondOwner is true when a principal other than the owner can read it.
	BeyondOwner bool   `json:"readable_beyond_owner"`
	Description string `json:"description"`
}

// Readers answers who can read an object. It is the one place the question is
// decided, so secrets, BMC device nodes and drive nodes cannot disagree.
func (e *Env) Readers(mode, gid *int64) Readers {
	if mode == nil {
		return Readers{Description: "unknown (mode not readable)", Reason: ReasonEACCES}
	}
	m := *mode
	r := Readers{
		Determined: true,
		OtherRead:  m&0o004 != 0,
		OtherWrite: m&0o002 != 0,
		GroupRead:  m&0o040 != 0,
		GroupWrite: m&0o020 != 0,
	}
	if r.OtherRead {
		r.BeyondOwner = true
		r.Description = "any local user (other-readable)"
		return r
	}
	if !r.GroupRead {
		r.Description = "the owner only"
		return r
	}
	// Group-readable: whether that means anything depends on who is in the
	// group, and that question needs both databases.
	db := e.Groups()
	if !db.Determined() {
		r.Determined = false
		r.Reason = db.Reason()
		r.BeyondOwner = true // conservative: unknown readers are not no readers
		r.Description = "unknown: the file is group-readable and the group model is unavailable (" + db.Reason() + ")"
		return r
	}
	if gid == nil {
		r.Determined = false
		r.Reason = ReasonEACCES
		r.BeyondOwner = true
		r.Description = "unknown: the file is group-readable and its gid could not be read"
		return r
	}
	grp, ok := db.ByGID(*gid)
	if !ok {
		r.Determined = false
		r.Reason = ReasonENOENT
		r.BeyondOwner = true
		r.Description = "unknown: the file is group-readable and gid " + itoa64(*gid) + " is in neither database"
		return r
	}
	r.GroupName, r.GroupMember = grp.Name, grp.Members
	if len(grp.Members) == 0 {
		r.Description = "group " + grp.Name + " has no members by list or primary gid, so this is owner-only in practice"
		return r
	}
	r.BeyondOwner = true
	r.Description = "the " + itoa64(int64(len(grp.Members))) + " effective member(s) of group " + grp.Name +
		" (" + strings.Join(grp.Members, ", ") + ")"
	return r
}

func itoa64(n int64) string {
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
