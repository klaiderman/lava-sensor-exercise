package checks

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// ---------------------------------------------------------------------------
// SSH_AUTH_METHODS_POLICY
// ---------------------------------------------------------------------------

// sshAuthMethodsPolicy answers which authentication methods a remote party can
// actually use — as the running daemon resolved them, not as one file says.
type sshAuthMethodsPolicy struct{ meta }

// verdictDirectives are the four that decide the verdict. Everything else the
// daemon reports is operator context, explicitly marked non-contributing.
var verdictDirectives = []struct {
	name string
	want string
}{
	{"passwordauthentication", "no"},
	{"kbdinteractiveauthentication", "no"},
	{"permitemptypasswords", "no"},
	{"pubkeyauthentication", "yes"},
}

// contextDirectives are reported because an operator should see them (OPEN-1,
// folded into this check's evidence by lead resolution).
var contextDirectives = []string{
	"usepam", "maxauthtries", "logingracetime", "maxstartups", "x11forwarding",
	"allowtcpforwarding", "allowagentforwarding", "gatewayports", "permittunnel",
	"authorizedkeysfile", "authorizedkeyscommand", "trustedusercakeys", "banner",
	"allowusers", "denyusers", "allowgroups", "denygroups",
}

type directiveRow struct {
	Directive           string           `json:"directive"`
	EffectiveValue      string           `json:"effective_value"`
	Source              string           `json:"source"`
	WinningSource       *sshdOccurrence  `json:"winning_source,omitempty"`
	Shadowed            []sshdOccurrence `json:"shadowed_occurrences"`
	Defaulted           bool             `json:"defaulted"`
	DefaultSource       string           `json:"default_source,omitempty"`
	ConditionalBlocks   []sshdOccurrence `json:"conditional_blocks"`
	Satisfied           *bool            `json:"satisfied,omitempty"`
	VerdictContributing bool             `json:"verdict_contributing"`
}

func (c sshAuthMethodsPolicy) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	oracle := env.SSHD(ctx)
	cfg := walkSSHDConfig(env.Files, sshdRootPath(env.Files))

	obs := oracle.Obs
	if !oracle.OK() {
		obs.OptOut = "the daemon's own answer was not obtained; the verdict is taken from the configuration chain instead"
	}
	r.Add(obs)
	for _, o := range cfg.Observations {
		if oracle.OK() {
			o.OptOut = "the verdict comes from the daemon's own effective configuration; this file is read for provenance and cross-checking"
		}
		r.Add(o)
	}

	// PAM is recorded because kbdinteractive can serve passwords through it
	// even when passwordauthentication is no — the classic false pass.
	pam := env.Files.Stat("/etc/pam.d/sshd")
	pam.Detail = "PAM stack for sshd; its presence is why kbdinteractiveauthentication matters"
	pam.OptOut = "recorded as context for the kbdinteractive result; no verdict here rests on it"
	r.Add(pam)
	r.Field("pam_sshd", renderMeta(pam))

	bare := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	if !sshdIsPresent(oracle, cfg) {
		return bare(scan.Unknown(scan.ReasonUtilMiss, noDaemonDetail))
	}
	// Every verdict below is read out of the files on disk, so it is a claim
	// about the listening daemon only if the daemon loaded them.
	finish := func(out scan.Result) scan.Result { return applyDaemonState(ctx, env, cfg, &r, out) }

	osID, osIDLike := env.OSIDs()
	rows := make([]directiveRow, 0, len(verdictDirectives)+len(contextDirectives))
	var unresolved, contested, conditional []string
	var failed []string

	for _, d := range verdictDirectives {
		row, state := resolveDirective(oracle, cfg, d.name, osID, osIDLike)
		row.VerdictContributing = true
		switch state {
		case dirContested:
			contested = append(contested, d.name)
		case dirUnresolved:
			unresolved = append(unresolved, d.name)
		default:
			ok := strings.EqualFold(row.EffectiveValue, d.want)
			row.Satisfied = &ok
			if !ok {
				failed = append(failed, d.name+" "+row.EffectiveValue)
			}
		}
		if len(row.ConditionalBlocks) > 0 {
			conditional = append(conditional, d.name)
		}
		rows = append(rows, row)
	}
	for _, name := range contextDirectives {
		row, state := resolveDirective(oracle, cfg, name, osID, osIDLike)
		if state == dirUnresolved {
			continue
		}
		row.VerdictContributing = false
		rows = append(rows, row)
	}
	r.Field("directives", rows)

	switch {
	case len(contested) > 0:
		return finish(scan.Unknown(scan.ReasonContested,
			"the running daemon and the configuration chain disagree on "+strings.Join(contested, ", ")+
				"; both values are recorded and neither is preferred"))
	case len(conditional) > 0:
		return finish(scan.Unknown(scan.ReasonContested,
			"a Match block scopes "+strings.Join(conditional, ", ")+
				", so no host-wide statement about the accepted authentication methods is valid; the block is in evidence"))
	case len(unresolved) > 0:
		return finish(scan.Unknown(unresolvedReason(oracle, cfg),
			"the effective value of "+strings.Join(unresolved, ", ")+
				" could not be established and no citable compiled-in default applies: "+unresolvedDetail(oracle, cfg)))
	case len(failed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the running policy leaves a password-based authentication path open ("+strings.Join(failed, "; ")+
				"); note that kbdinteractiveauthentication yes reaches PAM passwords even when passwordauthentication is no"))
	default:
		return finish(scan.Pass(
			"the running policy accepts public keys only: passwordauthentication no, kbdinteractiveauthentication no, " +
				"permitemptypasswords no, pubkeyauthentication yes"))
	}
}

type dirState int

const (
	dirResolved dirState = iota
	dirContested
	dirUnresolved
)

// resolveDirective reconciles the daemon's answer with the configuration chain
// for one directive, and falls back to a cited compiled-in default only when
// the distribution family is known.
func resolveDirective(oracle *scan.SSHDOracle, cfg *sshdConfig, name, osID, osIDLike string) (directiveRow, dirState) {
	res := cfg.Resolve(name)
	row := directiveRow{
		Directive:         name,
		WinningSource:     res.WinningSource,
		Shadowed:          res.Shadowed,
		ConditionalBlocks: res.ConditionalBlocks,
	}
	oracleVal, oracleHas := oracle.Value(name)
	oracleOK := oracle.OK() && oracleHas

	if oracleOK && res.Found && !strings.EqualFold(strings.TrimSpace(oracleVal), strings.TrimSpace(res.EffectiveValue)) {
		row.EffectiveValue = oracleVal + " | " + res.EffectiveValue
		row.Source = "contested (sshd -G vs configuration chain)"
		return row, dirContested
	}
	switch {
	case oracleOK:
		row.EffectiveValue, row.Source = oracleVal, "sshd -G (effective configuration as sshd would load it from disk now)"
	case res.Found:
		row.EffectiveValue, row.Source = res.EffectiveValue, "configuration chain walk"
	default:
		d, ok := defaultFor(name, osID, osIDLike)
		if !ok {
			return row, dirUnresolved
		}
		row.EffectiveValue, row.Source = d.value, "compiled-in default"
		row.Defaulted, row.DefaultSource = true, d.citation
	}
	return row, dirResolved
}

// ---------------------------------------------------------------------------
// SSH_POLICY_IN_FORCE
// ---------------------------------------------------------------------------

// sshPolicyInForce answers whether the policy just reported is the one the
// running daemon actually loaded.
type sshPolicyInForce struct{ meta }

type configFileRow struct {
	Path   string `json:"path"`
	Status string `json:"status"`
	Errno  string `json:"errno,omitempty"`
	Mode   *int64 `json:"mode,omitempty"`
	UID    *int64 `json:"uid,omitempty"`
	Size   *int64 `json:"size,omitempty"`
}

func (c sshPolicyInForce) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	oracle := env.SSHD(ctx)
	cfg := walkSSHDConfig(env.Files, sshdRootPath(env.Files))
	r.Add(cfg.Observations...)

	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	if !sshdIsPresent(oracle, cfg) {
		return finish(scan.Unknown(scan.ReasonUtilMiss, noDaemonDetail))
	}

	files := make([]configFileRow, 0, len(cfg.Files))
	for _, p := range cfg.Files {
		st := env.Files.Stat(p)
		// Each file's metadata is load-bearing: the comparison is only as good
		// as the set of files it saw.
		st.LoadBearing = true
		r.Add(st)
		row := configFileRow{Path: p, Status: string(st.Status), Errno: st.Reason()}
		if st.Meta != nil {
			row.Mode, row.UID, row.Size = st.Meta.Mode, st.Meta.UID, st.Meta.Size
		}
		files = append(files, row)
	}
	r.Field("config_chain", files)

	state, stateObs := daemonStateOf(ctx, env, cfg)
	for _, o := range stateObs {
		o.LoadBearing = true
		r.Add(o)
	}
	r.Field("daemon_state", state)

	sock := env.SystemdShow(ctx, "ssh.socket", "ListenStream", "ActiveState")
	sock.OptOut = "socket activation is recorded as context; the verdict compares the configuration chain with the daemon's start time"
	r.Add(sock)
	sockProps := parseSystemctlShow(sock.Value)
	if sockProps["ActiveState"] == "active" {
		r.Field("socket_activation", map[string]string{
			"unit": "ssh.socket", "active_state": sockProps["ActiveState"], "listen_stream": sockProps["ListenStream"],
			"note": "the listener comes from the socket unit, so sshd_config never decides the listen address",
		})
	}
	if len(cfg.MatchBlocks) > 0 {
		r.Field("conditional_blocks", cfg.MatchBlocks)
	}

	switch state.Relation {
	case relConfigNewer:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the configuration chain changed after the daemon started: "+state.Note+
				", so the running daemon is enforcing something other than what is on disk"))
	case relDaemonNewer:
		return finish(scan.Pass(
			"the daemon started after every file in the resolved configuration chain was last modified (" + state.Note + ")"))
	case relUndecidable:
		return finish(scan.Unknown(scan.ReasonTimestampRes,
			state.Note+"; this is the normal shape of a provisioning run that rewrote the configuration and restarted the daemon, but it is not proof of one"))
	default:
		// The reason has to name the same failure the detail names: reporting
		// EINVAL while the detail says the unit properties were unreadable
		// sends a reader looking for a malformed value that does not exist.
		return finish(scan.Unknown(reasonOfFailure(stateObs, scan.ReasonEINVAL),
			"whether the running daemon loaded the configuration on disk could not be established: "+state.Note))
	}
}

// reasonOfFailure returns the reason of the first observation that did not
// succeed, so a finding's reason field always names something that actually
// happened during this run.
func reasonOfFailure(obs []probe.Observation, fallback string) string {
	for _, o := range obs {
		if o.Status != probe.StatusOK && o.Reason() != "" {
			return scan.NormalizeReason(o.Reason())
		}
	}
	return fallback
}

// serviceStartTime resolves the unit's start instant, and the resolution that
// instant is actually good to.
//
// The reconstruction is boot = now - uptime, start = boot + monotonic. uptime is
// CLOCK_BOOTTIME and now is CLOCK_REALTIME: the two diverge by however much NTP
// has slewed or stepped the wall clock since boot, which is not observable from
// a single sample and can be seconds. Claiming a fixed 100 ms floor for that
// path would be asserting an accuracy the domains do not support.
//
// So the divergence is MEASURED against the one thing that is in the same
// domain as the file times we compare with: systemd's own rendered
// ActiveEnterTimestamp. If the reconstruction lands inside the whole second
// that timestamp names, the two domains agree to better than a second here and
// now, and the resolution is the read skew we measured. If they disagree, the
// disagreement itself becomes the resolution. Either way the number is
// observed, not assumed.
func serviceStartTime(env *scan.Env, props map[string]string) (time.Time, time.Duration, string, string, bool) {
	rendered, renderedOK := parseSystemdTimestamp(props["ActiveEnterTimestamp"])

	for _, key := range []string{"ActiveEnterTimestampMonotonic", "ExecMainStartTimestampMonotonic"} {
		raw := strings.TrimSpace(props[key])
		if raw == "" || raw == "0" {
			continue
		}
		usec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || usec <= 0 {
			continue
		}
		// Bracket the wall-clock sample with two uptime reads: the spread is
		// the measured cost of not sampling both clocks at the same instant.
		readStart := time.Now()
		up1 := readUptime(env)
		now := env.Now()
		up2 := readUptime(env)
		readSkew := time.Since(readStart)
		if up1 <= 0 || up2 <= 0 {
			continue
		}
		if spread := up2 - up1; spread > readSkew {
			readSkew = spread
		}
		boot := now.Add(-up2)
		start := boot.Add(time.Duration(usec) * time.Microsecond)

		// uptime is published to 10 ms, so nothing derived from it is finer.
		resolution := 10 * time.Millisecond
		if readSkew > resolution {
			resolution = readSkew
		}
		basis := "measured: uptime granularity 10 ms, read skew " + itoa(readSkew.Milliseconds()) + " ms"
		if renderedOK {
			// Both are meant to name the same instant; the rendered one is
			// truncated to a whole second, so agreement means |diff| < 1 s.
			diff := start.Sub(rendered)
			if diff < 0 {
				diff = -diff
			}
			if diff >= time.Second {
				resolution = diff
				basis = "measured: the monotonic reconstruction and the rendered timestamp disagree by " +
					itoa(diff.Milliseconds()) + " ms, so the wall clock has moved relative to boot time since boot and " +
					"the comparison is no finer than that disagreement"
			} else {
				basis += "; cross-checked against ActiveEnterTimestamp, which agrees to within " +
					itoa(diff.Milliseconds()) + " ms, so the two clock domains have not diverged by more than a second"
			}
		} else {
			// Nothing to cross-check against: the divergence between the two
			// clock domains is unbounded from here.
			resolution = time.Second
			basis = "no rendered timestamp to cross-check the monotonic reconstruction against, so the wall-clock/boot-time divergence is unbounded and the comparison is held to one second"
		}
		return start, resolution, key + " + /proc/uptime", basis, true
	}

	if !renderedOK {
		return time.Time{}, 0, "", "", false
	}
	return rendered, time.Second, "ActiveEnterTimestamp (whole-second resolution)",
		"the only start time systemd rendered is truncated to a whole second", true
}

// readUptime returns the system's uptime, which is CLOCK_BOOTTIME.
func readUptime(env *scan.Env) time.Duration {
	obs := env.Files.Read("/proc/uptime", probe.Tiny)
	if obs.Status != probe.StatusOK {
		return 0
	}
	fields := strings.Fields(obs.Value)
	if len(fields) == 0 {
		return 0
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// sshDaemonState is the set of RAW facts about whether the daemon is running
// what is on disk. It is not a verdict: SSH_POLICY_IN_FORCE turns it into one,
// and the policy checks read the same facts to decide whether their own answer
// is still safe to state.
type sshDaemonState struct {
	SystemdBooted   bool   `json:"systemd_booted"`
	Unit            string `json:"unit,omitempty"`
	ActiveState     string `json:"active_state,omitempty"`
	StartedAt       string `json:"daemon_started_at,omitempty"`
	StartSource     string `json:"start_time_source,omitempty"`
	ResolutionMS    int64  `json:"comparison_resolution_ms"`
	ResolutionBasis string `json:"resolution_basis,omitempty"`
	NewestConfig    string `json:"newest_config_path,omitempty"`
	NewestConfigAt  string `json:"newest_config_mtime,omitempty"`
	DeltaMS         *int64 `json:"delta_ms,omitempty"`
	// Relation is one of: config-newer, daemon-newer, undecidable, unknown.
	Relation string `json:"relation"`
	Note     string `json:"note"`
}

const (
	relConfigNewer = "config-newer"
	relDaemonNewer = "daemon-newer"
	relUndecidable = "undecidable"
	relUnknown     = "unknown"
)

// daemonStateOf gathers the raw in-force facts. Every SSH check calls it; the
// systemctl observation behind it is cached once per scan by Env.
func daemonStateOf(ctx context.Context, env *scan.Env, cfg *sshdConfig) (sshDaemonState, []probe.Observation) {
	st := sshDaemonState{Relation: relUnknown}
	var obs []probe.Observation

	st.SystemdBooted = env.Files.Exists("/run/systemd/system")
	if !st.SystemdBooted {
		st.Note = "systemd is not booted, so no unit can be asked when the daemon started; whether it loaded the files on disk is unknown"
		return st, obs
	}

	const props = "ActiveEnterTimestamp ActiveEnterTimestampMonotonic ExecMainStartTimestampMonotonic ActiveState FragmentPath"
	svc := env.SystemdShow(ctx, "ssh.service", strings.Fields(props)...)
	st.Unit = "ssh.service"
	if svc.Status != probe.StatusOK || strings.TrimSpace(svc.Value) == "" {
		alt := env.SystemdShow(ctx, "sshd.service", strings.Fields(props)...)
		if alt.Status == probe.StatusOK {
			svc, st.Unit = alt, "sshd.service"
		}
	}
	obs = append(obs, svc)
	if svc.Status != probe.StatusOK {
		st.Note = "the sshd unit's properties could not be read (" + svc.Reason() + ")"
		return st, obs
	}

	p := parseSystemctlShow(svc.Value)
	st.ActiveState = p["ActiveState"]
	started, resolution, source, basis, ok := serviceStartTime(env, p)
	if !ok {
		st.Note = "the sshd unit reported no parseable start time"
		return st, obs
	}
	st.StartedAt = started.UTC().Format(time.RFC3339Nano)
	st.StartSource, st.ResolutionMS, st.ResolutionBasis = source, resolution.Milliseconds(), basis

	var newest time.Time
	for _, f := range cfg.Files {
		if mt, ok := env.Files.ModTime(f); ok && mt.After(newest) {
			newest, st.NewestConfig = mt, f
		}
	}
	if newest.IsZero() {
		st.Note = "no modification time could be read for any file in the configuration chain"
		return st, obs
	}
	st.NewestConfigAt = newest.UTC().Format(time.RFC3339Nano)
	delta := started.Sub(newest)
	ms := delta.Milliseconds()
	st.DeltaMS = &ms

	switch {
	case delta < -resolution:
		st.Relation = relConfigNewer
		st.Note = st.NewestConfig + " was modified " + itoa(-ms) + " ms after the daemon started, which is beyond the " +
			itoa(st.ResolutionMS) + " ms resolution of " + source
	case delta > resolution:
		st.Relation = relDaemonNewer
		st.Note = "every file in the configuration chain is older than the daemon's start time by more than the " +
			itoa(st.ResolutionMS) + " ms resolution of " + source
	default:
		st.Relation = relUndecidable
		st.Note = "the newest configuration file and the daemon's start time fall within the " +
			itoa(st.ResolutionMS) + " ms resolution of " + source + ", so their order cannot be established"
	}
	return st, obs
}

func parseSystemctlShow(out string) map[string]string {
	m := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if ok && k != "" {
			m[k] = v
		}
	}
	return m
}

// parseSystemdTimestamp reads systemd's default timestamp rendering, e.g.
// "Mon 2026-09-08 17:37:29 UTC".
func parseSystemdTimestamp(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "n/a" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		"Mon 2006-01-02 15:04:05 MST",
		"Mon 2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 MST",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ---------------------------------------------------------------------------
// REMOTE_LISTENING_SURFACE
// ---------------------------------------------------------------------------

// remoteListeningSurface answers what can be reached over the network, and by
// which unit — from the socket tables, never from a config file.
type remoteListeningSurface struct{ meta }

type listener struct {
	Proto       string `json:"proto"`
	LocalAddr   string `json:"local_addr"`
	Port        int64  `json:"port"`
	Scope       string `json:"scope"`
	UID         int64  `json:"uid"`
	Inode       int64  `json:"inode"`
	OwnerUnit   string `json:"owner_unit,omitempty"`
	OwnerReason string `json:"owner_reason"`
	Class       string `json:"class"`
	Recognised  bool   `json:"recognised"`
}

// remoteAccessClasses maps a port to the *class* of remote access it registers
// as. It is a classification aid for the evidence, never the gate: the verdict
// rests on whether the class is an expected remote-access path, and the class
// is always reported next to the port so a reader can disagree.
var remoteAccessClasses = map[int64]string{
	22: "ssh", 23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
	2375: "docker-api-plaintext", 2376: "docker-api-tls", 2379: "etcd-client", 2380: "etcd-peer",
	3389: "rdp", 5432: "postgresql", 5900: "vnc-rfb", 5901: "vnc-rfb", 6000: "x11",
	6379: "redis", 6443: "kubernetes-api", 8080: "http-alt", 9200: "elasticsearch",
	10250: "kubelet", 11211: "memcached", 27017: "mongodb", 51820: "wireguard",
}

// adverseClasses are remote-access paths that are not the expected SSH one.
var adverseClasses = map[string]bool{
	"telnet": true, "rexec": true, "rlogin": true, "rsh": true,
	"docker-api-plaintext": true, "docker-api-tls": true, "etcd-client": true, "etcd-peer": true,
	"rdp": true, "vnc-rfb": true, "x11": true, "redis": true, "kubernetes-api": true,
	"kubelet": true, "memcached": true, "mongodb": true, "elasticsearch": true, "wireguard": true,
}

const outboundBlindSpot = "an outbound reverse tunnel (Cloudflare Tunnel, ngrok, frp, ssh -R) creates no listener and is structurally invisible to this check"

func (c remoteListeningSurface) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	r.Field("blind_spots", []string{outboundBlindSpot})

	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	var all []listener
	var truncatedTables []string
	readAny := false
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
	} {
		obs := env.Files.Read(src.path, probe.Large)
		obs.Detail = "socket table: the only source that is identical on every distribution"
		// An absent /proc/net/tcp6 on an IPv6-less kernel is not a gap in the
		// answer the IPv4 table gives.
		if obs.Status == probe.StatusENOENT {
			obs.AbsenceProven = true
		}
		if !strings.HasPrefix(src.proto, "tcp") {
			obs.OptOut = "UDP sockets are reported for completeness; the verdict is about TCP listeners"
		}
		r.Add(obs)
		if obs.Status != probe.StatusOK {
			continue
		}
		readAny = true
		rows := parseProcNet(obs.Value, src.proto)
		if obs.Truncated {
			truncatedTables = append(truncatedTables,
				src.path+" (read "+itoa(int64(len(rows)))+" row(s) before the byte cap)")
		}
		all = append(all, rows...)
	}

	if !readAny {
		// `ss` is a cross-check, never the primary: unprivileged it degrades by
		// silent omission (exit 0, blank Process column), so a parser that
		// trusts it reports "no owner" as fact.
		ss := env.Runner.Run(ctx, probe.Spec{Name: "ss", Args: []string{"-tulnH"}, Budget: 3 * time.Second,
			Purpose: "listener cross-check (never primary: unprivileged ss omits ownership silently)"})
		r.Add(ss)
		if ss.Status != probe.StatusOK {
			return finish(scan.Unknown(reasonOf(ss),
				"the socket tables under /proc/net are unreadable and no fallback tool produced a listing, so what is listening on this machine is unknown"))
		}
		return finish(scan.Unknown(scan.ReasonEACCES,
			"the socket tables under /proc/net are unreadable; `ss` produced output but it omits ownership silently for other users' sockets, so it is recorded as a cross-check and not used as a verdict"))
	}

	// Ownership: match the socket inode to a process only where /proc/<pid>/fd
	// is readable, and say so when it is not.
	ownerScan, ownerObs := resolveSocketOwners(ctx, env)
	r.Add(ownerObs)
	r.Field("owner_attribution", ownerScan)

	var global, adverse, gaps []string
	sort.Slice(all, func(i, j int) bool {
		if all[i].Port != all[j].Port {
			return all[i].Port < all[j].Port
		}
		return all[i].Proto < all[j].Proto
	})
	for i := range all {
		l := &all[i]
		l.Class = remoteAccessClasses[l.Port]
		if l.Class == "" {
			l.Class = "unclassified"
		}
		if unit, ok := ownerScan.Owners[l.Inode]; ok {
			l.OwnerUnit, l.OwnerReason = unit, "resolved from /proc/<pid>/fd"
		} else if !ownerScan.Complete {
			l.OwnerReason = "unattributed: the ownership scan stopped early (" + ownerScan.StoppedBy + ")"
		} else {
			l.OwnerReason = "EACCES: /proc/<pid>/fd of another uid is unreadable, so the owning process is unknown"
		}
		if l.Scope != "global" {
			continue
		}
		global = append(global, l.Proto+" "+l.LocalAddr+":"+itoa(l.Port))
		switch {
		case adverseClasses[l.Class]:
			l.Recognised = true
			adverse = append(adverse, l.Proto+"/"+itoa(l.Port)+" ("+l.Class+")")
		case l.Class == "ssh":
			l.Recognised = true
		default:
			gaps = append(gaps, l.Proto+"/"+itoa(l.Port))
		}
	}
	r.Field("listeners", all)
	r.Field("truncated_tables", truncatedTables)
	r.Field("global_scope_listeners", global)
	r.Field("attribution_gaps", gaps)

	// A listener we SAW is a positive observation: a table that was cut short
	// after it still showed it.
	r.OptOut(len(adverse) > 0,
		"an adverse listener was observed directly in the rows that were read, so the completeness of the socket table does not underwrite the verdict",
		"/proc/net/tcp", "/proc/net/tcp6")

	switch {
	case len(adverse) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a remote-access path other than SSH is listening on a non-loopback address: "+strings.Join(adverse, ", ")+
				"; "+outboundBlindSpot))
	case len(truncatedTables) > 0:
		return finish(scan.Unknown(scan.ReasonBudget,
			"the socket table was cut short at its byte cap ("+strings.Join(truncatedTables, "; ")+
				"), so the listeners in the rows that were read are reported as partial evidence and a listener past the cut cannot be ruled out"))
	case len(gaps) > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"the socket tables were read completely, but "+itoa(int64(len(gaps)))+
				" non-loopback listener(s) could not be attributed to a service class or an owning unit ("+
				strings.Join(gaps, ", ")+"); the attributed rows keep their verdict and are in evidence"))
	default:
		return finish(scan.Pass(
			"every non-loopback listener is an expected remote-access path (" + strings.Join(global, ", ") +
				"); " + outboundBlindSpot))
	}
}

// parseProcNet decodes the kernel's hex socket table. TCP state 0A is LISTEN;
// UDP sockets are reported as bound rather than listening.
func parseProcNet(body, proto string) []listener {
	var out []listener
	for i, ln := range strings.Split(body, "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 10 {
			continue
		}
		if strings.HasPrefix(proto, "tcp") && f[3] != "0A" {
			continue
		}
		addrHex, portHex, ok := strings.Cut(f[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 64)
		if err != nil {
			continue
		}
		addr := decodeHexAddr(addrHex)
		uid, _ := strconv.ParseInt(f[7], 10, 64)
		inode, _ := strconv.ParseInt(f[9], 10, 64)
		out = append(out, listener{
			Proto: proto, LocalAddr: addr, Port: port, Scope: addrScope(addr),
			UID: uid, Inode: inode,
		})
	}
	return out
}

// decodeHexAddr renders the kernel's little-endian hex address. The exact text
// matters less than the scope decision, so both are reported.
func decodeHexAddr(h string) string {
	switch len(h) {
	case 8:
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
			if err != nil {
				return h
			}
			b[3-i] = byte(v)
		}
		return itoa(int64(b[0])) + "." + itoa(int64(b[1])) + "." + itoa(int64(b[2])) + "." + itoa(int64(b[3]))
	case 32:
		var parts []string
		for w := 0; w < 4; w++ {
			word := h[8*w : 8*w+8]
			var b [4]byte
			for i := 0; i < 4; i++ {
				v, err := strconv.ParseUint(word[2*i:2*i+2], 16, 8)
				if err != nil {
					return h
				}
				b[3-i] = byte(v)
			}
			parts = append(parts, hex16(b[0], b[1]), hex16(b[2], b[3]))
		}
		return strings.Join(parts, ":")
	}
	return h
}

func hex16(a, b byte) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[a>>4], digits[a&0xf], digits[b>>4], digits[b&0xf]})
}

func addrScope(addr string) string {
	switch {
	case addr == "0.0.0.0" || addr == "0000:0000:0000:0000:0000:0000:0000:0000":
		return "global"
	case strings.HasPrefix(addr, "127."):
		return "loopback"
	case addr == "0000:0000:0000:0000:0000:0000:0000:0001":
		return "loopback"
	case strings.HasPrefix(addr, "fe80:"):
		return "link"
	}
	return "global"
}

// Socket-owner attribution budget. The traversal is PIDs x file descriptors: on
// a busy machine - a container host, an app server with 2000 processes each
// holding 500 descriptors - that is millions of readlink calls. The per-check
// context deadline cannot stop a loop that never consults it, and scan.Run is
// sequential, so an unbounded loop here would blow the whole scan deadline on
// somebody else's production machine.
const (
	socketOwnerMaxPIDs     = 2048
	socketOwnerMaxSyscalls = 20000
	socketOwnerMaxTime     = 2 * time.Second
)

// socketOwnerScan is the result of the attribution pass, including the boundary
// it stopped at. Attribution that stopped early is marked incomplete, so the
// listeners it did not reach are reported as unattributed rather than as
// unowned.
type socketOwnerScan struct {
	Owners         map[int64]string
	PIDsScanned    int64  `json:"pids_scanned"`
	SyscallsIssued int64  `json:"syscalls_issued"`
	Unreadable     int64  `json:"pids_unreadable"`
	Complete       bool   `json:"complete"`
	StoppedBy      string `json:"stopped_by"`
	ElapsedMS      int64  `json:"elapsed_ms"`
}

// resolveSocketOwners maps socket inodes to process names where /proc/<pid>/fd
// can be read, under its own budget. A gap is recorded, never filled in with a
// guess.
func resolveSocketOwners(ctx context.Context, env *scan.Env) (socketOwnerScan, probe.Observation) {
	res := socketOwnerScan{Owners: map[int64]string{}, Complete: true, StoppedBy: "none"}
	start := env.Now()
	deadline := time.Now().Add(socketOwnerMaxTime)

	names, obs := env.Files.ReadDirNames("/proc", 4096)
	obs.Detail = "process table scan for socket ownership; an unreadable /proc/<pid>/fd of another uid is an attribution gap, not an absence"
	if obs.Status != probe.StatusOK {
		res.Complete, res.StoppedBy = false, "the process table could not be listed"
		return res, obs
	}

	for _, n := range names {
		if n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		// Checked per PID, so a deadline that expires mid-traversal stops it.
		if err := ctx.Err(); err != nil {
			res.Complete, res.StoppedBy = false, "the check deadline expired"
			break
		}
		if time.Now().After(deadline) {
			res.Complete, res.StoppedBy = false, "the "+socketOwnerMaxTime.String()+" attribution budget expired"
			break
		}
		if res.PIDsScanned >= socketOwnerMaxPIDs {
			res.Complete, res.StoppedBy = false, "the "+itoa(socketOwnerMaxPIDs)+"-process budget was reached"
			break
		}
		if res.SyscallsIssued >= socketOwnerMaxSyscalls {
			res.Complete, res.StoppedBy = false, "the "+itoa(socketOwnerMaxSyscalls)+"-syscall budget was reached"
			break
		}
		res.PIDsScanned++

		fds, fdObs := env.Files.ReadDirNames("/proc/"+n+"/fd", 1024)
		res.SyscallsIssued++
		if fdObs.Status != probe.StatusOK {
			res.Unreadable++
			continue
		}
		comm, _ := env.Files.ReadTrimmed("/proc/"+n+"/comm", probe.Tiny)
		res.SyscallsIssued++
		for _, fd := range fds {
			if res.SyscallsIssued >= socketOwnerMaxSyscalls {
				res.Complete, res.StoppedBy = false, "the "+itoa(socketOwnerMaxSyscalls)+"-syscall budget was reached"
				break
			}
			target, lObs := env.Files.ReadLinkBase("/proc/" + n + "/fd/" + fd)
			res.SyscallsIssued++
			if lObs.Status != probe.StatusOK || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err == nil && comm != "" {
				res.Owners[inode] = comm + " (pid " + n + ")"
			}
		}
	}
	res.ElapsedMS = env.Now().Sub(start).Milliseconds()
	if !res.Complete {
		obs.Truncated = true
		obs.Detail = "socket-owner attribution stopped early: " + res.StoppedBy +
			"; listeners it did not reach are unattributed, not unowned"
	}
	return res, obs
}

// ---------------------------------------------------------------------------
// LOGIN_AND_ESCALATION_SURFACE
// ---------------------------------------------------------------------------

// loginAndEscalationSurface answers who can obtain an interactive session and
// who has a path to root.
type loginAndEscalationSurface struct{ meta }

// rootEquivalentGroups grant a path to root by what the group can do, not by
// name policy: membership is equivalent to root on any host where the
// corresponding subsystem is installed.
var rootEquivalentGroups = []string{"docker", "lxd", "disk", "kmem", "sudo", "wheel", "adm", "systemd-journal"}

type account struct {
	Name       string `json:"name"`
	UID        int64  `json:"uid"`
	Shell      string `json:"shell"`
	ShellClass string `json:"shell_class"`
	Home       string `json:"home"`
	AuthKeys   string `json:"authorized_keys_status"`
	AuthKeyErr string `json:"authorized_keys_errno,omitempty"`
	KeyCount   *int64 `json:"authorized_keys_count,omitempty"`
}

type privilegedGroup struct {
	Group               string   `json:"group"`
	GID                 int64    `json:"gid"`
	Members             []string `json:"members"`
	EffectivelyRootOnly bool     `json:"effectively_root_only"`
	RootEquivalent      bool     `json:"root_equivalent"`
}

func (c loginAndEscalationSurface) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	passwd := env.Files.Read("/etc/passwd", probe.Large)
	passwd.LoadBearing = true
	passwd.Detail = "account inventory; the file is primary because it needs no tool"
	r.Add(passwd)
	groups := env.Groups()
	r.Add(groups.Obs)

	nsswitch := env.Files.Read("/etc/nsswitch.conf", probe.Small)
	r.Add(nsswitch)
	backends := nsswitchBackends(nsswitch.Value)
	r.Field("nsswitch_backends", backends)

	if passwd.Status != probe.StatusOK {
		return finish(scan.Unknown(passwd.Reason(),
			"/etc/passwd could not be read ("+passwd.Reason()+"), so the account inventory is not established"))
	}

	var accounts []account
	var boundaries []fileMeta
	var unreadableHomes []string
	for _, ln := range strings.Split(passwd.Value, "\n") {
		f := strings.Split(strings.TrimSpace(ln), ":")
		if len(f) < 7 || f[0] == "" {
			continue
		}
		uid, _ := strconv.ParseInt(f[2], 10, 64)
		a := account{Name: f[0], UID: uid, Shell: f[6], Home: f[5], ShellClass: shellClass(f[6])}
		if a.ShellClass == "login" {
			ak := a.Home + "/.ssh/authorized_keys"
			st := env.Files.Stat(ak)
			a.AuthKeys, a.AuthKeyErr = string(st.Status), st.Reason()
			if st.Status == probe.StatusOK {
				// A line count, never a key body.
				if body := env.Files.Read(ak, probe.Small); body.Status == probe.StatusOK {
					n := int64(0)
					for _, kl := range strings.Split(body.Value, "\n") {
						if s := strings.TrimSpace(kl); s != "" && !strings.HasPrefix(s, "#") {
							n++
						}
					}
					a.KeyCount = &n
				}
			} else if st.Status == probe.StatusEACCES {
				unreadableHomes = append(unreadableHomes, a.Home)
			}
		}
		accounts = append(accounts, a)
	}
	r.Field("accounts", accounts)
	r.Field("unreadable_homes", unreadableHomes)

	var privs []privilegedGroup
	var adverse []string
	for _, name := range rootEquivalentGroups {
		g, ok := groups.Lookup(name)
		if !ok {
			continue
		}
		pg := privilegedGroup{Group: g.Name, GID: g.GID, Members: g.Members, RootEquivalent: true}
		// An empty privileged group makes group-mode objects root-only in
		// practice, which is a stronger statement than absence (L43).
		pg.EffectivelyRootOnly = len(g.Members) == 0
		privs = append(privs, pg)
		if name == "docker" || name == "lxd" || name == "disk" || name == "kmem" {
			for _, m := range g.Members {
				if !isSystemAccount(accounts, m) {
					adverse = append(adverse, m+" in "+name)
				}
			}
		}
	}
	r.Field("privileged_groups", privs)

	// Our own password state only. `passwd -S` reports the caller unprivileged;
	// generalising it to other accounts would be a false claim (F33).
	self := env.Runner.Run(ctx, probe.Spec{Name: "passwd", Args: []string{"-S"}, Budget: 3 * time.Second,
		Purpose: "password state of the calling account only"})
	self.Detail = "passwd -S reports the caller only; it is never generalised to other accounts"
	self.OptOut = "the password state of the calling account is context; the verdict is about accounts, groups and policy files"
	r.Add(self)
	r.Field("password_state_self", strings.TrimSpace(self.Value))

	for _, p := range []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", rootSSHDir, rootAuthKeysPath} {
		st := env.Files.Stat(p)
		r.Add(st)
		boundaries = append(boundaries, renderMeta(st))
	}
	r.Field("policy_boundaries", boundaries)

	shadow := env.Files.Read("/etc/shadow", probe.Large)
	sudoers := env.Files.Read("/etc/sudoers", probe.Small)
	var open []string
	if shadow.Status == probe.StatusOK {
		for _, ln := range strings.Split(shadow.Value, "\n") {
			f := strings.Split(strings.TrimSpace(ln), ":")
			if len(f) >= 2 && f[1] == "" && shellClassOf(accounts, f[0]) == "login" {
				open = append(open, f[0])
			}
		}
	}

	if len(adverse) > 0 {
		return finish(scan.Fail(scan.ReasonPolicy,
			"a non-system account holds root-equivalent group membership: "+strings.Join(adverse, ", ")+
				"; membership of docker, lxd, disk or kmem is a direct path to root regardless of sudo policy"))
	}
	if len(open) > 0 {
		return finish(scan.Fail(scan.ReasonPolicy,
			"an account with a login shell has an empty password field in a readable /etc/shadow: "+strings.Join(open, ", ")))
	}

	var unknowns []string
	if shadow.Status != probe.StatusOK {
		unknowns = append(unknowns, "the password state of other accounts (/etc/shadow "+shadow.Reason()+
			") — unreadable is not 'no password set'")
	}
	if sudoers.Status != probe.StatusOK {
		unknowns = append(unknowns, "the sudo policy behind group membership (/etc/sudoers "+sudoers.Reason()+")")
	}
	if len(unreadableHomes) > 0 {
		unknowns = append(unknowns, "key material in "+strings.Join(unreadableHomes, ", ")+" (EACCES)")
	}
	for _, b := range backends {
		if b != "files" && b != "systemd" && b != "compat" && b != "" {
			unknowns = append(unknowns, "accounts served by the "+b+" nsswitch backend, which this sensor cannot query")
		}
	}
	if len(unknowns) > 0 {
		return finish(scan.Unknown(scan.ReasonEACCES,
			"the enumerable part is complete and in evidence, but this account cannot establish: "+strings.Join(unknowns, "; ")))
	}
	return finish(scan.Pass(
		"every account with a login shell and every privileged group was enumerated, and no non-system account holds root-equivalent group membership"))
}

func shellClass(sh string) string {
	switch {
	case strings.HasSuffix(sh, "/nologin"):
		return "nologin"
	case strings.HasSuffix(sh, "/false"):
		return "false"
	case strings.TrimSpace(sh) == "":
		return "unset"
	}
	return "login"
}

func shellClassOf(accounts []account, name string) string {
	for _, a := range accounts {
		if a.Name == name {
			return a.ShellClass
		}
	}
	return "unknown"
}

func isSystemAccount(accounts []account, name string) bool {
	for _, a := range accounts {
		if a.Name == name {
			return a.UID < 1000 || a.ShellClass != "login"
		}
	}
	return false
}

func nsswitchBackends(body string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(body, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "passwd:") && !strings.HasPrefix(ln, "group:") {
			continue
		}
		_, rest, _ := strings.Cut(ln, ":")
		for _, tok := range strings.Fields(rest) {
			if strings.HasPrefix(tok, "[") {
				continue
			}
			if !seen[tok] {
				seen[tok] = true
				out = append(out, tok)
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// ---------------------------------------------------------------------------
// HOST_FIREWALL_STATE
// ---------------------------------------------------------------------------

// hostFirewallState answers whether anything is filtering inbound traffic, and
// whether this account can see what it does.
type hostFirewallState struct{ meta }

type firewallSubsystem struct {
	Name            string            `json:"name"`
	Unit            string            `json:"unit"`
	IsActive        string            `json:"is_active"`
	IsActiveRC      *int64            `json:"is_active_rc,omitempty"`
	ConfigPath      string            `json:"config_path,omitempty"`
	ConfigValues    map[string]string `json:"config_values,omitempty"`
	RulesetReadable bool              `json:"ruleset_readable"`
	Errno           string            `json:"errno,omitempty"`
	StderrExcerpt   string            `json:"stderr_excerpt,omitempty"`
}

func (c hostFirewallState) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	systemd := env.Files.Exists("/run/systemd/system")
	r.Field("systemd_booted", systemd)
	r.Field("unit_state_note", "a unit being active means the unit ran, not that any rule is loaded: ufw.service is a oneshot that exits early when ufw.conf says ENABLED=no")

	// disableKey names, per implementation, the configuration value that means
	// "installed but switched off". Reading it is the only way to tell a
	// firewall that is running from one that merely has a running unit.
	candidates := []struct {
		name, unit, config, disableKey, disabledValue string
	}{
		{"ufw", "ufw", "/etc/ufw/ufw.conf", "ENABLED", "no"},
		{"firewalld", "firewalld", "/etc/firewalld/firewalld.conf", "", ""},
		{"nftables", "nftables", "/etc/nftables.conf", "", ""},
		{"iptables", "iptables", "", "", ""},
		{"netfilter-persistent", "netfilter-persistent", "", "", ""},
	}
	var subsystems []firewallSubsystem
	anyActive := false
	var disabledByConfig []string

	for _, cand := range candidates {
		sub := firewallSubsystem{Name: cand.name, Unit: cand.unit, IsActive: "unknown", ConfigValues: map[string]string{}}
		if systemd {
			obs := env.Runner.Run(ctx, probe.Spec{Name: "systemctl", Args: []string{"is-active", cand.unit},
				Budget: 3 * time.Second, Purpose: "firewall unit state"})
			r.Add(obs)
			sub.IsActive = strings.TrimSpace(obs.Value)
			sub.IsActiveRC = obs.ExitCode
			if sub.IsActive == "" {
				sub.IsActive = string(obs.Status)
			}
			if sub.IsActive == "active" {
				anyActive = true
			}
		}
		if cand.config != "" {
			cfg := env.Files.Read(cand.config, probe.Small)
			r.Add(cfg)
			if cfg.Status == probe.StatusOK {
				sub.ConfigPath = cand.config
				for k, v := range parseKeyValue(cfg.Value) {
					sub.ConfigValues[k] = v
				}
			} else {
				sub.Errno = cfg.Reason()
			}
		}
		if cand.disableKey != "" && sub.IsActive == "active" {
			if v, ok := sub.ConfigValues[cand.disableKey]; ok && strings.EqualFold(v, cand.disabledValue) {
				disabledByConfig = append(disabledByConfig,
					cand.name+" ("+cand.config+" says "+cand.disableKey+"="+v+", while the "+cand.unit+" unit reports active)")
			}
		}
		subsystems = append(subsystems, sub)
	}
	// /etc/default/ufw carries the default policies and is world-readable even
	// where the rule files are not: a partial answer that is reported rather
	// than discarded.
	if def := env.Files.Read("/etc/default/ufw", probe.Small); def.Status == probe.StatusOK {
		r.Add(def)
		kv := parseKeyValue(def.Value)
		for i := range subsystems {
			if subsystems[i].Name == "ufw" {
				for k, v := range kv {
					subsystems[i].ConfigValues[k] = v
				}
			}
		}
	}
	// The rule files' own permissions are the boundary the registry cites.
	var ruleFileModes []fileMeta
	for _, p := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/before.rules"} {
		st := env.Files.Stat(p)
		if st.Status == probe.StatusENOENT {
			continue
		}
		r.Add(st)
		ruleFileModes = append(ruleFileModes, renderMeta(st))
	}
	r.Field("rule_file_modes", ruleFileModes)

	// The effective ruleset. A missing nft says nothing about whether nftables
	// rules exist, because iptables here is usually the nf_tables variant.
	rulesetReadable := false
	rulesetLines := 0
	rulesetErr := ""
	rulesetSource := ""
	for _, attempt := range []struct {
		name string
		args []string
	}{
		{"nft", []string{"list", "ruleset"}},
		{"iptables", []string{"-S"}},
		{"iptables-nft", []string{"-S"}},
	} {
		obs := env.Runner.Run(ctx, probe.Spec{Name: attempt.name, Args: attempt.args, Budget: 3 * time.Second,
			Purpose: "effective packet-filter ruleset"})
		r.Add(obs)
		if obs.Status == probe.StatusOK {
			rulesetReadable = true
			rulesetSource = attempt.name + " " + strings.Join(attempt.args, " ")
			if body := strings.TrimSpace(obs.Value); body != "" {
				rulesetLines = len(strings.Split(body, "\n"))
			}
			break
		}
		if obs.Status != probe.StatusUtilityMissing && rulesetErr == "" {
			rulesetErr = obs.Reason()
		}
		if obs.Meta != nil && obs.Meta.StderrExcerpt != "" {
			for i := range subsystems {
				if subsystems[i].Name == attempt.name ||
					(attempt.name == "iptables-nft" && subsystems[i].Name == "iptables") {
					subsystems[i].StderrExcerpt = obs.Meta.StderrExcerpt
				}
			}
		}
	}
	for i := range subsystems {
		subsystems[i].RulesetReadable = rulesetReadable
	}
	r.Field("subsystems", subsystems)
	r.Field("ruleset_lines", int64(rulesetLines))
	if rulesetSource != "" {
		r.Field("default_policy_source", rulesetSource)
	}

	if mods := env.Files.Read("/proc/modules", probe.Large); mods.Status == probe.StatusOK {
		var present []string
		for _, m := range []string{"nf_tables", "ip_tables", "iptable_filter", "nft_chain_nat"} {
			if strings.Contains(mods.Value, m+" ") {
				present = append(present, m)
			}
		}
		r.Field("netfilter_modules_loaded", present)
		r.Field("netfilter_modules_note", "a loaded module is a capability signal, not evidence that any rule is loaded")
	}
	r.Field("global_scope_listener_present", hasGlobalListener(env))

	// A firewall switched off in its own readable configuration is a positive
	// observation; the ruleset tool's absence does not soften it.
	if len(disabledByConfig) > 0 {
		r.OptOut(true,
			"the subsystem's own configuration was read and says it is disabled; that is a direct observation, and nothing else here underwrites the verdict")
		// The configuration read that carries the verdict stays load-bearing.
		for i := range r.Observations {
			if strings.HasSuffix(r.Observations[i].Source, "/ufw.conf") ||
				strings.HasSuffix(r.Observations[i].Source, "/firewalld.conf") ||
				strings.HasSuffix(r.Observations[i].Source, "/nftables.conf") {
				r.Observations[i].OptOut = ""
			}
		}
	}

	switch {
	case len(disabledByConfig) > 0:
		// The implementation is installed and its own configuration says it is
		// off. That is a readable fact, and it outranks the unit's state.
		return finish(scan.Fail(scan.ReasonPolicy,
			"a host firewall is installed but switched off in its own configuration: "+strings.Join(disabledByConfig, "; ")+
				" — the unit running is not the same as rules being loaded"))
	case rulesetReadable && rulesetLines > 0:
		return finish(scan.Pass("the effective packet-filter ruleset is readable from " + rulesetSource + " and carries " +
			itoa(int64(rulesetLines)) + " rule line(s)"))
	case rulesetReadable:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the effective packet-filter ruleset was read from "+rulesetSource+" and is empty: nothing is filtering inbound traffic"))
	case rulesetErr != "":
		return finish(scan.Unknown(rulesetErr,
			"the effective packet-filter ruleset is not readable by this account ("+rulesetErr+
				"), so whether this host is filtered is unknown; the readable configuration and unit states are in evidence, "+
				"and a ruleset this account may not read is never reported as a ruleset that does not exist"))
	case anyActive:
		return finish(scan.Unknown(scan.ReasonUtilMiss,
			"a filtering unit reports active but this account has no tool that can print the effective ruleset, "+
				"so what it loaded is unknown; a unit's state does not establish that rules exist"))
	default:
		// Rules can be loaded by something outside any candidate unit: an
		// iptables-restore ExecStartPre, rc.local, a config-management run, a
		// provider's own unit. Not finding a unit we know about is not finding
		// that the host is unfiltered.
		return finish(scan.Unknown(scan.ReasonUtilMiss,
			"no filtering implementation this sensor recognises reported active, and this account has no tool that can "+
				"print the effective ruleset; rules loaded by a mechanism outside the candidate list would be invisible "+
				"here, so whether this host is filtered is unknown"))
	}
}

func hasGlobalListener(env *scan.Env) bool {
	for _, src := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		obs := env.Files.Read(src.path, probe.Large)
		if obs.Status != probe.StatusOK {
			continue
		}
		for _, l := range parseProcNet(obs.Value, src.proto) {
			if l.Scope == "global" {
				return true
			}
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// applyDaemonState attaches the raw in-force facts to a policy check's evidence
// and decides whether the policy verdict is still safe to state.
//
// A policy verdict read out of the files on disk is a claim about the daemon
// only if the daemon loaded those files. Where the chain is provably newer than
// the daemon, it did not, and the verdict is downgraded. Where the order cannot
// be established, the verdict stands and the caveat rides with it: the caveat
// observation is deliberately NOT load-bearing, because an undecidable ordering
// is not a failed observation and turning every SSH finding on every
// provisioned host into an unknown would be its own kind of dishonesty.
func applyDaemonState(ctx context.Context, env *scan.Env, cfg *sshdConfig, r *scan.Result, out scan.Result) scan.Result {
	state, obs := daemonStateOf(ctx, env, cfg)
	for _, o := range obs {
		r.Add(o)
	}
	r.Field("daemon_state", state)

	switch state.Relation {
	case relConfigNewer:
		out = scan.Unknown(scan.ReasonContested,
			"the configuration this verdict was read from is newer than the running daemon ("+state.Note+
				"), so it describes what sshd would load if restarted, not what the listening daemon is enforcing")
	case relUndecidable, relUnknown:
		note := probe.Observation{
			Source: "in-force caveat (" + state.Relation + ")",
			Kind:   probe.KindFileMetadata,
			Status: probe.StatusOK,
			Value:  state.Relation,
			Detail: "this verdict is read from the configuration on disk; whether the listening daemon loaded it is " +
				state.Relation + " (" + state.Note + "). See SSH_POLICY_IN_FORCE.",
		}
		r.Add(note)
		out.Detail += " [in-force caveat: " + state.Note + "; see SSH_POLICY_IN_FORCE]"
	}
	out.Observations, out.Fields = r.Observations, r.Fields
	return out
}
