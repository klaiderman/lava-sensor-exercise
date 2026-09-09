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
	obs.LoadBearing = oracle.OK()
	r.Add(obs)
	r.Add(cfg.Observations...)

	// PAM is recorded because kbdinteractive can serve passwords through it
	// even when passwordauthentication is no — the classic false pass.
	pam := env.Files.Stat("/etc/pam.d/sshd")
	pam.Detail = "PAM stack for sshd; its presence is why kbdinteractiveauthentication matters"
	r.Add(pam)
	r.Field("pam_sshd", renderMeta(pam))

	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	if !sshdIsPresent(oracle, cfg) {
		return finish(scan.Unknown(scan.ReasonUtilMiss, noDaemonDetail))
	}

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
		row.EffectiveValue, row.Source = oracleVal, "sshd -G (running daemon)"
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
	var newest time.Time
	var newestPath string
	for _, p := range cfg.Files {
		st := env.Files.Stat(p)
		row := configFileRow{Path: p, Status: string(st.Status), Errno: st.Reason()}
		if st.Meta != nil {
			row.Mode, row.UID, row.Size = st.Meta.Mode, st.Meta.UID, st.Meta.Size
		}
		if mt, ok := statModTime(env.Files, p); ok && mt.After(newest) {
			newest, newestPath = mt, p
		}
		files = append(files, row)
	}
	r.Field("config_chain", files)
	if !newest.IsZero() {
		r.Field("newest_config_mtime", newest.UTC().Format(time.RFC3339))
		r.Field("newest_config_path", newestPath)
	}

	// The daemon's start time. systemd is a capability, gated on the documented
	// sd_booted(3) test rather than on the presence of the systemctl binary.
	systemd := env.Files.Exists("/run/systemd/system")
	r.Field("systemd_booted", systemd)
	if !systemd {
		return finish(scan.Unknown(scan.ReasonEINVAL,
			"systemd is not booted, so the daemon's start time is not obtainable from a unit; "+
				"the configuration chain was resolved and is in evidence, but whether the running daemon loaded it is unknown"))
	}

	svc := env.Runner.Run(ctx, probe.Spec{
		Name: "systemctl", Args: []string{"show", "ssh.service", "-p", "ActiveEnterTimestamp", "-p", "ActiveEnterTimestampMonotonic", "-p", "ExecMainStartTimestampMonotonic", "-p", "ActiveState", "-p", "FragmentPath"},
		Budget: 3 * time.Second, Purpose: "sshd service start time",
	})
	if svc.Status != probe.StatusOK || strings.TrimSpace(svc.Value) == "" {
		alt := env.Runner.Run(ctx, probe.Spec{
			Name: "systemctl", Args: []string{"show", "sshd.service", "-p", "ActiveEnterTimestamp", "-p", "ActiveEnterTimestampMonotonic", "-p", "ExecMainStartTimestampMonotonic", "-p", "ActiveState", "-p", "FragmentPath"},
			Budget: 3 * time.Second, Purpose: "sshd service start time (rpm-family unit name)",
		})
		if alt.Status == probe.StatusOK {
			svc = alt
		}
	}
	svc.LoadBearing = true
	r.Add(svc)

	sock := env.Runner.Run(ctx, probe.Spec{
		Name: "systemctl", Args: []string{"show", "ssh.socket", "-p", "ListenStream", "-p", "ActiveState"},
		Budget: 3 * time.Second, Purpose: "socket activation state",
	})
	r.Add(sock)
	sockProps := parseSystemctlShow(sock.Value)
	if sockProps["ActiveState"] == "active" {
		r.Field("socket_activation", map[string]string{
			"unit": "ssh.socket", "active_state": sockProps["ActiveState"], "listen_stream": sockProps["ListenStream"],
			"note": "the listener comes from the socket unit, so sshd_config never decides the listen address",
		})
	}

	props := parseSystemctlShow(svc.Value)
	r.Field("service_state", props)
	if svc.Status != probe.StatusOK {
		return finish(scan.Unknown(svc.Reason(),
			"the sshd unit's start time could not be read ("+svc.Reason()+"), so whether the on-disk configuration is the one in force is unknown"))
	}
	started, resolution, tsSource, ok := serviceStartTime(env, props)
	if !ok {
		return finish(scan.Unknown(scan.ReasonParse,
			"the sshd unit reported an unparseable ActiveEnterTimestamp "+quote(props["ActiveEnterTimestamp"])+
				", so the configuration-versus-runtime comparison could not be made"))
	}
	r.Field("service_active_enter", started.UTC().Format(time.RFC3339Nano))
	r.Field("service_start_source", tsSource)
	r.Field("comparison_resolution_ms", resolution.Milliseconds())

	if newest.IsZero() {
		return finish(scan.Unknown(scan.ReasonEACCES,
			"no modification time could be read for any file in the configuration chain, so it cannot be compared with the daemon's start time"))
	}
	delta := started.Sub(newest)
	r.Field("delta_seconds", int64(delta.Seconds()))
	r.Field("delta_ms", delta.Milliseconds())

	if len(cfg.MatchBlocks) > 0 {
		r.Field("conditional_blocks", cfg.MatchBlocks)
	}

	// Two events cannot be ordered more finely than the coarser of the two
	// timestamps that describe them. Provisioning that rewrites the config and
	// restarts the daemon lands both inside the same second, and calling that
	// drift asserts an ordering the evidence does not carry.
	switch {
	case delta < -resolution:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the configuration chain changed after the daemon started ("+newestPath+" was modified "+
				itoa(-delta.Milliseconds())+" ms after the unit's start time, read from "+tsSource+
				"), so the running daemon is enforcing something other than what is on disk"))
	case delta > resolution:
		return finish(scan.Pass(
			"every file in the resolved configuration chain is older than the daemon's start time by more than the " +
				itoa(resolution.Milliseconds()) + " ms resolution of " + tsSource + ", so what is on disk is what is loaded"))
	default:
		return finish(scan.Unknown(scan.ReasonTimestampRes,
			"the newest configuration file ("+newestPath+") and the daemon's start time fall within the "+
				itoa(resolution.Milliseconds())+" ms resolution of "+tsSource+
				", so their order cannot be established; this is the normal shape of a provisioning run that rewrote the configuration and restarted the daemon, but it is not proof of one"))
	}
}

// serviceStartTime resolves the unit's start instant as precisely as the system
// will report it, and returns the resolution that instant is good to.
//
// systemd's rendered timestamps are whole seconds. Its *Monotonic properties
// are microseconds since boot, so pairing one with /proc/uptime and the current
// time recovers sub-second precision; that reconstruction inherits the error of
// the uptime read, which is what the returned resolution accounts for.
func serviceStartTime(env *scan.Env, props map[string]string) (time.Time, time.Duration, string, bool) {
	for _, key := range []string{"ActiveEnterTimestampMonotonic", "ExecMainStartTimestampMonotonic"} {
		raw := strings.TrimSpace(props[key])
		if raw == "" || raw == "0" {
			continue
		}
		usec, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || usec <= 0 {
			continue
		}
		upObs := env.Files.Read("/proc/uptime", probe.Tiny)
		if upObs.Status != probe.StatusOK {
			continue
		}
		fields := strings.Fields(upObs.Value)
		if len(fields) == 0 {
			continue
		}
		secs, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			continue
		}
		now := env.Now()
		boot := now.Add(-time.Duration(secs * float64(time.Second)))
		// /proc/uptime is published to 10 ms, and the read and the clock sample
		// are not simultaneous; 100 ms is the honest floor for this path.
		return boot.Add(time.Duration(usec) * time.Microsecond), 100 * time.Millisecond,
			key + " + /proc/uptime", true
	}
	t, ok := parseSystemdTimestamp(props["ActiveEnterTimestamp"])
	if !ok {
		return time.Time{}, 0, "", false
	}
	return t, time.Second, "ActiveEnterTimestamp (whole-second resolution)", true
}

func statModTime(f probe.Files, p string) (time.Time, bool) {
	// Modification times come from the same stat the metadata does; probe keeps
	// only what evidence needs, so this re-stats through the same seam.
	if r, ok := f.(*probe.Reader); ok {
		return r.ModTime(p)
	}
	return time.Time{}, false
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
	readAny := false
	for _, src := range []struct{ path, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
	} {
		obs := env.Files.Read(src.path, probe.Large)
		obs.Detail = "socket table: the only source that is identical on every distribution"
		// Load-bearing only where it succeeded: an absent /proc/net/tcp6 on an
		// IPv6-less kernel must not downgrade a verdict the IPv4 table supports.
		obs.LoadBearing = obs.Status == probe.StatusOK && strings.HasPrefix(src.proto, "tcp")
		r.Add(obs)
		if obs.Status != probe.StatusOK {
			continue
		}
		readAny = true
		all = append(all, parseProcNet(obs.Value, src.proto)...)
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
	inodeOwners, ownerObs := resolveSocketOwners(env)
	r.Add(ownerObs)

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
		if unit, ok := inodeOwners[l.Inode]; ok {
			l.OwnerUnit, l.OwnerReason = unit, "resolved from /proc/<pid>/fd"
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
	r.Field("global_scope_listeners", global)
	r.Field("attribution_gaps", gaps)

	switch {
	case len(adverse) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a remote-access path other than SSH is listening on a non-loopback address: "+strings.Join(adverse, ", ")+
				"; "+outboundBlindSpot))
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

// resolveSocketOwners maps socket inodes to process names where /proc/<pid>/fd
// can be read. A gap is recorded, never filled in with a guess.
func resolveSocketOwners(env *scan.Env) (map[int64]string, probe.Observation) {
	owners := map[int64]string{}
	names, obs := env.Files.ReadDirNames("/proc", 4096)
	obs.Detail = "process table scan for socket ownership; unreadable /proc/<pid>/fd of another uid is an attribution gap, not an absence"
	if obs.Status != probe.StatusOK {
		return owners, obs
	}
	scanned := 0
	for _, n := range names {
		if n == "" || n[0] < '0' || n[0] > '9' {
			continue
		}
		if scanned++; scanned > 4096 {
			break
		}
		fds, fdObs := env.Files.ReadDirNames("/proc/"+n+"/fd", 1024)
		if fdObs.Status != probe.StatusOK {
			continue
		}
		comm, _ := env.Files.ReadTrimmed("/proc/"+n+"/comm", probe.Tiny)
		for _, fd := range fds {
			target, lObs := env.Files.ReadLinkBase("/proc/" + n + "/fd/" + fd)
			if lObs.Status != probe.StatusOK || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err == nil && comm != "" {
				owners[inode] = comm + " (pid " + n + ")"
			}
		}
	}
	return owners, obs
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

	candidates := []struct{ name, unit, config string }{
		{"ufw", "ufw", "/etc/ufw/ufw.conf"},
		{"firewalld", "firewalld", "/etc/firewalld/firewalld.conf"},
		{"nftables", "nftables", "/etc/nftables.conf"},
		{"iptables", "iptables", ""},
		{"netfilter-persistent", "netfilter-persistent", ""},
	}
	var subsystems []firewallSubsystem
	anyActive := false
	for _, cand := range candidates {
		s := firewallSubsystem{Name: cand.name, Unit: cand.unit, IsActive: "unknown", ConfigValues: map[string]string{}}
		if systemd {
			obs := env.Runner.Run(ctx, probe.Spec{Name: "systemctl", Args: []string{"is-active", cand.unit},
				Budget: 3 * time.Second, Purpose: "firewall unit state"})
			r.Add(obs)
			s.IsActive = strings.TrimSpace(obs.Value)
			s.IsActiveRC = obs.ExitCode
			if s.IsActive == "" {
				s.IsActive = string(obs.Status)
			}
			if s.IsActive == "active" {
				anyActive = true
			}
		}
		if cand.config != "" {
			cfg := env.Files.Read(cand.config, probe.Small)
			r.Add(cfg)
			if cfg.Status == probe.StatusOK {
				s.ConfigPath = cand.config
				for k, v := range parseKeyValue(cfg.Value) {
					s.ConfigValues[k] = v
				}
			} else {
				s.Errno = cfg.Reason()
			}
		}
		subsystems = append(subsystems, s)
	}
	// /etc/default/ufw carries the default policies and is world-readable even
	// when the rule files are not: a partial answer that must be reported
	// rather than discarded.
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

	// The ruleset itself. nft absence says nothing about whether nftables rules
	// exist, because iptables here is usually the nf_tables variant (L39).
	rulesetReadable := false
	var rulesetErr string
	var defaultPolicySource string
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
		if obs.Status == probe.StatusOK && strings.TrimSpace(obs.Value) != "" {
			rulesetReadable = true
			defaultPolicySource = attempt.name + " " + strings.Join(attempt.args, " ")
			r.Field("ruleset_lines", int64(len(strings.Split(strings.TrimSpace(obs.Value), "\n"))))
			break
		}
		if obs.Status != probe.StatusUtilityMissing {
			rulesetErr = obs.Reason()
			if obs.Meta != nil && obs.Meta.StderrExcerpt != "" {
				for i := range subsystems {
					if subsystems[i].Name == attempt.name || (attempt.name == "iptables-nft" && subsystems[i].Name == "iptables") {
						subsystems[i].StderrExcerpt = obs.Meta.StderrExcerpt
					}
				}
			}
		}
	}
	for i := range subsystems {
		subsystems[i].RulesetReadable = rulesetReadable
	}
	r.Field("subsystems", subsystems)
	if defaultPolicySource != "" {
		r.Field("default_policy_source", defaultPolicySource)
	}

	// Module presence is a capability signal only, never "rules exist".
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

	globalListeners := hasGlobalListener(env)
	r.Field("global_scope_listener_present", globalListeners)

	switch {
	case rulesetReadable:
		return finish(scan.Pass("a packet filter is active and its effective ruleset is readable from " + defaultPolicySource))
	case anyActive:
		return finish(scan.Unknown(firstNonEmpty(rulesetErr, scan.ReasonEACCES),
			"a filtering subsystem is enabled but its effective ruleset is not readable by this account ("+
				firstNonEmpty(rulesetErr, scan.ReasonEACCES)+"); the readable configuration defaults are in evidence, "+
				"and 'no rules readable' is never reported as 'no rules'"))
	case !systemd:
		return finish(scan.Unknown(scan.ReasonEINVAL,
			"systemd is not booted, so no unit can be asked whether a filtering subsystem is enabled, and no ruleset was readable"))
	case globalListeners:
		return finish(scan.Fail(scan.ReasonPolicy,
			"every candidate filtering subsystem reported inactive and no ruleset was readable, while at least one listener is bound to a non-loopback address: the machine is reachable and unfiltered"))
	default:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"no filtering subsystem is enabled and no ruleset was readable; with no non-loopback listener observed, this is recorded rather than judged"))
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
