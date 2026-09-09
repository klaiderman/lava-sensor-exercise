package checks

import (
	"context"
	"strconv"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// BOOT_CHAIN asks whether this machine's own boot path can be trusted. Every
// check here decodes a kernel-supplied table as data, and an absent capability
// is reported as not-applicable rather than as a failure (L46).

const (
	efiGlobalGUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
	efivarsDir    = "/sys/firmware/efi/efivars"
)

// readEFIVarBool decodes a one-byte UEFI boolean variable.
//
// An efivars file begins with a 4-byte little-endian attribute mask; the value
// starts at index 4. Reading byte 0 instead inverts the answer on some
// platforms, so the prefix and the value byte are reported separately for a
// reviewer to check the arithmetic.
func readEFIVarBool(env *scan.Env, name string) (value byte, attrHex string, obs probe.Observation, ok bool) {
	path := efivarsDir + "/" + name + "-" + efiGlobalGUID
	obs = env.Files.Read(path, probe.Tiny)
	obs.LoadBearing = true
	if obs.Status != probe.StatusOK {
		return 0, "", obs, false
	}
	if len(obs.Value) < 5 {
		obs.Status = probe.StatusUnsupported
		obs.Errno = "EINVAL"
		obs.Detail = "efivar shorter than the 4-byte attribute prefix plus one value byte"
		return 0, "", obs, false
	}
	b := []byte(obs.Value)
	const digits = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b[:4] {
		sb.WriteByte(digits[x>>4])
		sb.WriteByte(digits[x&0xf])
	}
	return b[4], sb.String(), obs, true
}

// efiPresent reports whether this is an EFI platform at all. Absent efivars is
// "not applicable", never "Secure Boot disabled".
func efiPresent(env *scan.Env) bool { return env.Files.Exists("/sys/firmware/efi") }

// ---------------------------------------------------------------------------
// SECURE_BOOT_ENABLED
// ---------------------------------------------------------------------------

type secureBootEnabled struct{ meta }

func (c secureBootEnabled) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	present := efiPresent(env)
	r.Field("efi_present", present)

	val, attr, obs, ok := readEFIVarBool(env, "SecureBoot")
	r.Add(obs)
	if ok {
		r.Field("file_read", map[string]any{
			"path": obs.Source, "bytes_read": obs.Bytes,
			"attribute_prefix_hex": attr, "value_byte": int64(val),
		})
	}

	// mokutil is a cross-check only: its absence must never turn a readable
	// efivar into an unknown.
	if !ok {
		mok := env.Runner.Run(ctx, probe.Spec{Name: "mokutil", Args: []string{"--sb-state"}, Budget: 3000000000,
			Purpose: "Secure Boot state cross-check"})
		r.Add(mok)
		if mok.Status == probe.StatusOK {
			out := strings.ToLower(mok.Value)
			r.Field("applicable", true)
			switch {
			case strings.Contains(out, "secureboot enabled"):
				return finish(scan.Pass("mokutil reports Secure Boot enabled (the efivar itself was not readable: " + obs.Reason() + ")"))
			case strings.Contains(out, "secureboot disabled"):
				return finish(scan.Fail(scan.ReasonPolicy,
					"mokutil reports Secure Boot disabled, so the firmware does not verify the boot loader or kernel signatures (the efivar itself was not readable: "+obs.Reason()+")"))
			}
		}
	}

	switch {
	case ok && val == 1:
		r.Field("applicable", true)
		return finish(scan.Pass("the SecureBoot UEFI variable reads 1 at byte 4 (after the 4-byte attribute prefix " + attr + "), so the firmware verifies boot loader and kernel signatures"))
	case ok:
		r.Field("applicable", true)
		return finish(scan.Fail(scan.ReasonPolicy,
			"the SecureBoot UEFI variable reads "+itoa(int64(val))+" at byte 4 (attribute prefix "+attr+
				"), so the firmware does not verify the signature of the boot loader or the kernel"))
	case !present:
		r.Field("applicable", false)
		return finish(scan.Unknown(scan.ReasonENOENT,
			"this platform exposes no EFI firmware interface, so Secure Boot is not applicable here; an absent efivars tree is not a disabled Secure Boot"))
	default:
		r.Field("applicable", true)
		return finish(scan.Unknown(obs.Reason(),
			"the SecureBoot UEFI variable could not be read ("+obs.Reason()+
				"), so whether the firmware verifies boot signatures is unknown"))
	}
}

// ---------------------------------------------------------------------------
// UEFI_PLATFORM_SETUP_MODE
// ---------------------------------------------------------------------------

type uefiPlatformSetupMode struct{ meta }

func (c uefiPlatformSetupMode) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	present := efiPresent(env)
	r.Field("efi_present", present)

	// The presence of the key variables corroborates the mode. Existence only:
	// their contents are never parsed.
	var keyVars []string
	if names, obs := env.Files.ReadDirNames(efivarsDir, 2048); obs.Status == probe.StatusOK {
		r.Add(obs)
		for _, n := range names {
			for _, k := range []string{"PK-", "KEK-", "db-", "dbx-"} {
				if strings.HasPrefix(n, k) {
					keyVars = append(keyVars, n)
				}
			}
		}
	}
	r.Field("key_variables_present", keyVars)

	val, attr, obs, ok := readEFIVarBool(env, "SetupMode")
	r.Add(obs)
	if ok {
		r.Field("file_read", map[string]any{
			"path": obs.Source, "bytes_read": obs.Bytes,
			"attribute_prefix_hex": attr, "value_byte": int64(val),
		})
	}

	switch {
	case ok && val == 0:
		r.Field("applicable", true)
		return finish(scan.Pass("the SetupMode UEFI variable reads 0 at byte 4 (attribute prefix " + attr +
			"), so a Platform Key is enrolled and the firmware is in User Mode"))
	case ok:
		r.Field("applicable", true)
		return finish(scan.Fail(scan.ReasonPolicy,
			"the SetupMode UEFI variable reads "+itoa(int64(val))+" at byte 4 (attribute prefix "+attr+
				"): no Platform Key is enrolled, so anyone with firmware access — including whoever held this machine before us, and anyone reaching the management controller's virtual media or BIOS console — can enrol their own Secure Boot keys and produce a machine that appears to boot securely"))
	case !present:
		r.Field("applicable", false)
		return finish(scan.Unknown(scan.ReasonENOENT,
			"this platform exposes no EFI firmware interface, so platform Setup Mode is not applicable here"))
	default:
		r.Field("applicable", true)
		return finish(scan.Unknown(obs.Reason(),
			"the SetupMode UEFI variable could not be read ("+obs.Reason()+
				"), so whether a Platform Key is enrolled is unknown; mokutil does not report Setup Mode on all versions and its silence is not a negative"))
	}
}

// ---------------------------------------------------------------------------
// KERNEL_LOCKDOWN_MODE
// ---------------------------------------------------------------------------

type kernelLockdownMode struct{ meta }

func (c kernelLockdownMode) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	securityfs := env.Files.Exists("/sys/kernel/security")
	r.Field("securityfs_mounted", securityfs)
	if lsm, obs := env.Files.ReadTrimmed("/sys/kernel/security/lsm", probe.Tiny); obs.Status == probe.StatusOK {
		r.Add(obs)
		r.Field("lsm_list", strings.Split(lsm, ","))
	}
	if cmdline, obs := env.Files.ReadTrimmed("/proc/cmdline", probe.Small); obs.Status == probe.StatusOK {
		for _, tok := range strings.Fields(cmdline) {
			if strings.HasPrefix(tok, "lockdown=") {
				r.Field("cmdline_lockdown_param", map[string]string{
					"value": strings.TrimPrefix(tok, "lockdown="),
					"note":  "a kernel command line parameter is configured intent, not the effective state",
				})
			}
		}
	}

	obs := env.Files.Read("/sys/kernel/security/lockdown", probe.Tiny)
	obs.LoadBearing = true
	r.Add(obs)

	// The three ways this can be unavailable are three different reasons, and
	// they are not collapsed: securityfs unmounted, file absent, read denied.
	if obs.Status != probe.StatusOK {
		switch {
		case !securityfs:
			r.Field("applicable", false)
			return finish(scan.Unknown(scan.ReasonEINVAL,
				"securityfs is not mounted at /sys/kernel/security, so the kernel lockdown state is not observable here"))
		case obs.Status == probe.StatusENOENT:
			r.Field("applicable", false)
			return finish(scan.Unknown(scan.ReasonENOENT,
				"securityfs is mounted but exposes no lockdown attribute, so the Lockdown LSM is not built into this kernel and the control does not exist to be evaluated"))
		default:
			r.Field("applicable", true)
			return finish(scan.Unknown(obs.Reason(),
				"the lockdown attribute exists but could not be read ("+obs.Reason()+"), so the effective lockdown mode is unknown"))
		}
	}

	// The value is an option list with the active one in brackets; parsing the
	// list instead of the bracketed selection is the classic misread.
	selected := ""
	var offered []string
	for _, tok := range strings.Fields(obs.Value) {
		offered = append(offered, strings.Trim(tok, "[]"))
		if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
			selected = strings.Trim(tok, "[]")
		}
	}
	r.Field("file_read", map[string]any{"path": obs.Source, "value": strings.TrimSpace(obs.Value),
		"options_offered": offered, "selected": selected})

	switch selected {
	case "integrity", "confidentiality":
		return finish(scan.Pass("kernel lockdown is active in " + selected +
			" mode, so a privileged user cannot modify or read the running kernel through kexec, /dev/mem or unsigned module loading"))
	case "none":
		return finish(scan.Fail(scan.ReasonPolicy,
			"kernel lockdown is [none], so a privileged user can modify or read the running kernel (kexec, /dev/mem, unsigned module loading); lockdown is independent of Secure Boot and neither implies the other"))
	case "":
		return finish(scan.Unknown(scan.ReasonParse,
			"the lockdown attribute was read but no option is marked selected, so the effective mode is not derivable from it"))
	default:
		return finish(scan.Unknown(scan.ReasonParse,
			"the lockdown attribute reports the unrecognised mode "+quote(selected)+", so no verdict is derivable from it"))
	}
}

// ---------------------------------------------------------------------------
// UNSIGNED_OR_OUT_OF_TREE_MODULES
// ---------------------------------------------------------------------------

type unsignedOrOutOfTreeModules struct{ meta }

// taintBits is the kernel's taint table, decoded as data. All bits are named so
// the number in the evidence is something a reader can act on.
var taintBits = []struct {
	bit     uint
	letter  string
	meaning string
}{
	{0, "P", "proprietary module loaded"},
	{1, "F", "module force-loaded"},
	{2, "S", "kernel running on an out-of-specification system"},
	{3, "R", "module force-unloaded"},
	{4, "M", "processor reported a machine check exception"},
	{5, "B", "bad page referenced or unexpected page flags"},
	{6, "U", "taint requested by userspace"},
	{7, "D", "kernel died recently (OOPS or BUG)"},
	{8, "A", "ACPI table overridden by user"},
	{9, "W", "kernel issued a warning"},
	{10, "C", "staging driver loaded"},
	{11, "I", "workaround for a firmware bug applied"},
	{12, "O", "out-of-tree module loaded"},
	{13, "E", "unsigned module loaded"},
	{14, "L", "soft lockup occurred"},
	{15, "K", "kernel live-patched"},
	{16, "X", "auxiliary taint defined by the distribution"},
	{17, "T", "kernel built with struct randomisation plugin"},
	{18, "N", "in-kernel test module loaded"},
}

type taintedModule struct {
	Name         string `json:"name"`
	TaintLetters string `json:"taint_letters"`
	Path         string `json:"path"`
}

func (c unsignedOrOutOfTreeModules) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	obs := env.Files.Read("/proc/sys/kernel/tainted", probe.Tiny)
	obs.LoadBearing = true
	r.Add(obs)
	if obs.Status != probe.StatusOK {
		return finish(scan.Unknown(obs.Reason(),
			"/proc/sys/kernel/tainted could not be read ("+obs.Reason()+
				"), so whether unsigned or out-of-tree code is running in the kernel is unknown"))
	}
	mask, err := strconv.ParseUint(strings.TrimSpace(obs.Value), 10, 64)
	if err != nil {
		return finish(scan.Unknown(scan.ReasonParse,
			"/proc/sys/kernel/tainted did not parse as an integer, so the taint state is not derivable from it"))
	}

	type decodedBit struct {
		Bit     uint   `json:"bit"`
		Letter  string `json:"letter"`
		Meaning string `json:"meaning"`
		Set     bool   `json:"set"`
	}
	decoded := make([]decodedBit, 0, len(taintBits))
	outOfTree, unsigned := false, false
	for _, tb := range taintBits {
		set := mask&(1<<tb.bit) != 0
		decoded = append(decoded, decodedBit{tb.bit, tb.letter, tb.meaning, set})
		if set && tb.bit == 12 {
			outOfTree = true
		}
		if set && tb.bit == 13 {
			unsigned = true
		}
	}
	r.Field("file_read", map[string]any{"path": "/proc/sys/kernel/tainted", "value": mask, "decoded_bits": decoded})

	// Per-module attribution. /sys/module also contains built-in modules, so
	// the per-module taint file is the discriminator, not mere presence.
	var tainting []taintedModule
	names, modObs := env.Files.ReadDirNames("/sys/module", 4096)
	r.Add(modObs)
	attributionGap := modObs.Status != probe.StatusOK
	for _, n := range names {
		p := "/sys/module/" + n + "/taint"
		v, o := env.Files.ReadTrimmed(p, probe.Tiny)
		if o.Status != probe.StatusOK || strings.TrimSpace(v) == "" {
			continue
		}
		tainting = append(tainting, taintedModule{Name: n, TaintLetters: v, Path: p})
	}
	r.Field("tainting_modules", tainting)
	r.Field("modules_total", int64(len(names)))
	if attributionGap {
		r.Field("attribution_gap", "/sys/module could not be enumerated ("+modObs.Reason()+"), so which modules taint the kernel is unknown while the taint bits themselves are known")
	}

	// Enforcement is recorded, never inferred: taint E records an unsigned
	// module even on a kernel that does not enforce signatures.
	sigEnforce, seObs := env.Files.ReadTrimmed("/sys/module/module/parameters/sig_enforce", probe.Tiny)
	r.Field("sig_enforce", map[string]string{"value": firstNonEmpty(sigEnforce, "unknown"), "errno": seObs.Reason()})
	var configRows []map[string]string
	if kernel, o := env.Files.ReadTrimmed("/proc/sys/kernel/osrelease", probe.Tiny); o.Status == probe.StatusOK {
		cfgPath := "/boot/config-" + kernel
		if cfg := env.Files.Read(cfgPath, probe.Large); cfg.Status == probe.StatusOK {
			r.Add(cfg)
			for _, ln := range strings.Split(cfg.Value, "\n") {
				for _, key := range []string{"CONFIG_MODULE_SIG_FORCE", "CONFIG_MODULE_SIG_ALL", "CONFIG_MODULE_SIG="} {
					if strings.HasPrefix(ln, key) {
						configRows = append(configRows, map[string]string{"key": strings.TrimSuffix(key, "="), "line": strings.TrimSpace(ln), "source_path": cfgPath})
					}
				}
			}
		}
	}
	r.Field("config_module_sig", configRows)
	r.Field("enforcement_note", "taint bit E records that an unsigned module was loaded, even on a kernel that does not enforce module signatures; enforcement is read separately and never inferred from taint")
	if md, o := env.Files.ReadTrimmed("/proc/sys/kernel/modules_disabled", probe.Tiny); o.Status == probe.StatusOK {
		r.Field("modules_disabled", md)
	}

	if !outOfTree && !unsigned {
		return finish(scan.Pass(
			"the kernel taint mask has neither bit 12 (out-of-tree) nor bit 13 (unsigned) set, so no out-of-tree or unsigned module is loaded"))
	}
	var which []string
	if outOfTree {
		which = append(which, "bit 12 O (out-of-tree module loaded)")
	}
	if unsigned {
		which = append(which, "bit 13 E (unsigned module loaded)")
	}
	detail := "the kernel taint mask has " + strings.Join(which, " and ") + " set"
	if len(tainting) > 0 {
		var named []string
		for _, m := range tainting {
			named = append(named, m.Name+" ("+m.TaintLetters+")")
		}
		detail += ", attributed to " + strings.Join(named, ", ")
	} else if attributionGap {
		detail += ", but /sys/module could not be enumerated, so which module is responsible is unknown"
	} else {
		detail += ", but no currently loaded module reports a per-module taint, so the tainting module has since been unloaded"
	}
	return finish(scan.Fail(scan.ReasonPolicy, detail))
}

// ---------------------------------------------------------------------------
// TPM_PRESENCE
// ---------------------------------------------------------------------------

type tpmPresence struct{ meta }

func (c tpmPresence) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	// Presence is the finding; usage is not. On a machine whose Secure Boot is
	// off, a present TPM measures nothing that is verified.
	r.Field("measured_boot_state", "unknown: the PCR values and the measured-boot event log are root-only, and a denial there is not evidence that measured boot is unused")

	names, obs := env.Files.ReadDirNames("/sys/class/tpm", 64)
	obs.LoadBearing = true
	r.Add(obs)

	var nodes []fileMeta
	for _, p := range []string{"/dev/tpm0", "/dev/tpmrm0"} {
		st := env.Files.Stat(p)
		st.Detail = "TPM device node metadata; the node is never opened"
		if st.Status != probe.StatusENOENT {
			r.Add(st)
		}
		nodes = append(nodes, renderMeta(st))
	}
	r.Field("device_nodes", nodes)
	if log := env.Files.Stat("/sys/kernel/security/tpm0/binary_bios_measurements"); log.Status != probe.StatusENOENT {
		r.Add(log)
		r.Field("event_log", renderMeta(log))
	}

	switch obs.Status {
	case probe.StatusENOENT:
		r.Field("tpm_present", false)
		return finish(scan.Unknown(scan.ReasonEINVAL,
			"this kernel or namespace exposes no TPM subsystem at /sys/class/tpm, so whether the machine has a hardware root of trust is not observable here"))
	case probe.StatusOK:
	default:
		return finish(scan.Unknown(obs.Reason(),
			"/sys/class/tpm could not be listed ("+obs.Reason()+"), so TPM presence is unknown"))
	}

	if len(names) == 0 {
		r.Field("tpm_present", false)
		return finish(scan.Pass(
			"no TPM is present: /sys/class/tpm was listed successfully and is empty, which is a proven negative rather than an absence of evidence"))
	}
	dev := names[0]
	version, vObs := env.Files.ReadTrimmed("/sys/class/tpm/"+dev+"/tpm_version_major", probe.Tiny)
	r.Add(vObs)
	desc, _ := env.Files.ReadTrimmed("/sys/class/tpm/"+dev+"/device/description", probe.Tiny)
	firmwareID, _ := env.Files.ReadLinkBase("/sys/class/tpm/" + dev + "/device")
	r.Field("tpm_present", true)
	r.Field("tpm_version", firstNonEmpty(version, "unknown"))
	r.Field("tpm_device", map[string]string{"name": dev, "description": desc, "firmware_id": firmwareID})

	if version == "" {
		return finish(scan.Pass("a TPM device is present at /sys/class/tpm/" + dev +
			" but its major version attribute was not readable; presence is the finding, and use of it is a separate question this sensor cannot answer unprivileged"))
	}
	return finish(scan.Pass("a TPM " + version + " device is present at /sys/class/tpm/" + dev +
		"; presence is not use — whether anything measures or seals to it is root-only and reported as unknown in the evidence"))
}

// ---------------------------------------------------------------------------
// BOOT_ARTIFACT_READABILITY
// ---------------------------------------------------------------------------

type bootArtifactReadability struct{ meta }

func (c bootArtifactReadability) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("initramfs_not_opened", true)
	r.Field("scope_note", "the initramfs is never opened; extracting it to look for embedded provisioning material would be unbounded and outside read-only intent. Mode and size are the finding")

	names, obs := env.Files.ReadDirNames("/boot", 1024)
	obs.LoadBearing = true
	r.Add(obs)
	if obs.Status != probe.StatusOK {
		return finish(scan.Unknown(obs.Reason(),
			"/boot could not be listed ("+obs.Reason()+"), so who can read the kernel, initramfs and boot loader configuration is unknown"))
	}
	runningKernel, _ := env.Files.ReadTrimmed("/proc/sys/kernel/osrelease", probe.Tiny)

	type artifact struct {
		Path                 string `json:"path"`
		Mode                 *int64 `json:"mode,omitempty"`
		UID                  *int64 `json:"uid,omitempty"`
		GID                  *int64 `json:"gid,omitempty"`
		Size                 *int64 `json:"size,omitempty"`
		MatchesRunningKernel bool   `json:"matches_running_kernel"`
		OtherReadable        bool   `json:"other_readable"`
		Errno                string `json:"errno,omitempty"`
	}
	var artifacts []artifact
	var exposed []string
	runningInitramfsSeen := false

	for _, n := range names {
		if !hasAnyPrefix(n, []string{"vmlinuz", "initrd.img", "initramfs", "System.map", "config-"}) {
			continue
		}
		p := "/boot/" + n
		st := env.Files.Stat(p)
		a := artifact{Path: p, Errno: st.Reason()}
		if st.Meta != nil {
			a.Mode, a.UID, a.GID, a.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		a.MatchesRunningKernel = runningKernel != "" && strings.Contains(n, runningKernel)
		if a.MatchesRunningKernel && strings.HasPrefix(n, "initr") {
			runningInitramfsSeen = true
		}
		if a.Mode != nil && *a.Mode&0o004 != 0 {
			a.OtherReadable = true
			// The live initramfs matters most: provider images routinely inject
			// provisioning material into it.
			weight := "a stale artifact"
			if a.MatchesRunningKernel {
				weight = "the artifact the running kernel booted from"
			}
			if strings.HasPrefix(n, "vmlinuz") || strings.HasPrefix(n, "config-") || strings.HasPrefix(n, "System.map") {
				// A kernel image and its config carry no injected secrets; they
				// are recorded but do not carry the verdict.
				a.OtherReadable = true
			} else {
				exposed = append(exposed, p+" ("+weight+")")
			}
		}
		artifacts = append(artifacts, a)
	}
	for _, p := range []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/loader/entries"} {
		st := env.Files.Stat(p)
		if st.Status == probe.StatusENOENT {
			continue
		}
		r.Add(st)
		a := artifact{Path: p, Errno: st.Reason()}
		if st.Meta != nil {
			a.Mode, a.UID, a.GID, a.Size = st.Meta.Mode, st.Meta.UID, st.Meta.GID, st.Meta.Size
		}
		if a.Mode != nil && *a.Mode&0o004 != 0 {
			a.OtherReadable = true
			exposed = append(exposed, p)
		}
		artifacts = append(artifacts, a)
	}
	r.Field("artifacts", artifacts)

	// The ESP is vfat: it has no owners, so the control is the mount mask, not
	// a file permission.
	mounts := env.Mounts()
	r.Add(mounts.Obs)
	espWorldReadable := false
	espKnown := false
	for _, m := range mounts.Entries {
		if m.FSType != "vfat" && m.FSType != "msdos" {
			continue
		}
		espKnown = true
		opts := m.Options + "," + m.SuperOpts
		fmask := optionValue(opts, "fmask")
		dmask := optionValue(opts, "dmask")
		umask := optionValue(opts, "umask")
		world := !maskBlocksOther(fmask) && !maskBlocksOther(umask)
		if world {
			espWorldReadable = true
		}
		r.Field("esp", map[string]any{
			"mountpoint": m.MountPoint, "fstype": m.FSType, "options": opts,
			"fmask": fmask, "dmask": dmask, "umask": umask,
			"world_readable": world,
			"note":           "vfat has no owners, so the mount mask is the control, not a file permission",
		})
	}
	if espWorldReadable {
		exposed = append(exposed, "the EFI system partition is mounted without a mask that blocks other")
	}

	switch {
	case len(exposed) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"boot artifacts are readable by any local user: "+strings.Join(exposed, "; ")+
				" — bare-metal provider images routinely inject provisioning material into the initramfs"))
	case runningKernel != "" && !runningInitramfsSeen:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"/boot was listed successfully but contains no initramfs matching the running kernel "+runningKernel+
				", so the permissions of the image this machine actually booted from are not established"))
	case !espKnown && mounts.Obs.Status != probe.StatusOK:
		return finish(scan.Unknown(mounts.Obs.Reason(),
			"the mount table could not be read, so whether the EFI system partition is mounted with a world-readable mask is unknown"))
	default:
		return finish(scan.Pass(
			"every boot artifact in /boot that could carry injected provisioning material is restricted from other users (" +
				itoa(int64(len(artifacts))) + " inspected)"))
	}
}

func optionValue(opts, key string) string {
	for _, tok := range strings.Split(opts, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(tok), "="); ok && k == key {
			return v
		}
	}
	return ""
}

// maskBlocksOther reports whether a vfat mask denies the read bit to other.
func maskBlocksOther(mask string) bool {
	if mask == "" {
		return false
	}
	v, err := strconv.ParseInt(strings.TrimPrefix(mask, "0"), 8, 64)
	if err != nil {
		return false
	}
	return v&0o004 != 0
}

// ---------------------------------------------------------------------------
// BOOT_KERNEL_DRIFT
// ---------------------------------------------------------------------------

type bootKernelDrift struct{ meta }

func (c bootKernelDrift) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	running, runObs := env.Files.ReadTrimmed("/proc/sys/kernel/osrelease", probe.Tiny)
	runObs.LoadBearing = true
	r.Add(runObs)
	r.Field("running_kernel", firstNonEmpty(running, "unknown"))

	bootNames, bootObs := env.Files.ReadDirNames("/boot", 1024)
	r.Add(bootObs)
	modNames, modObs := env.Files.ReadDirNames("/lib/modules", 256)
	if modObs.Status != probe.StatusOK {
		modNames, modObs = env.Files.ReadDirNames("/usr/lib/modules", 256)
	}
	r.Add(modObs)

	installed := map[string]bool{}
	var fromBoot, fromModules []string
	for _, n := range bootNames {
		if v, ok := strings.CutPrefix(n, "vmlinuz-"); ok && v != "" {
			installed[v] = true
			fromBoot = append(fromBoot, v)
		}
	}
	for _, n := range modNames {
		if n != "" {
			installed[n] = true
			fromModules = append(fromModules, n)
		}
	}
	var all []string
	for v := range installed {
		all = append(all, v)
	}
	sortStrings(all)
	r.Field("installed_kernels", all)
	r.Field("installed_from_boot", fromBoot)
	r.Field("installed_from_modules", fromModules)
	r.Field("boot_listing_status", string(bootObs.Status))
	r.Field("modules_listing_status", string(modObs.Status))

	// The reboot-required marker is corroboration only: its absence is not
	// evidence that no reboot is pending.
	marker := env.Files.Stat("/var/run/reboot-required")
	if marker.Status == probe.StatusENOENT {
		marker = env.Files.Stat("/run/reboot-required")
	}
	r.Field("reboot_required_marker", map[string]any{
		"present": marker.Status == probe.StatusOK,
		"path":    marker.Source,
		"note":    "the absence of this marker is not evidence that no reboot is pending; it is a distribution convention, not a kernel fact",
	})
	if def, obs := env.Files.ReadLinkBase("/boot/vmlinuz"); obs.Status == probe.StatusOK {
		r.Field("boot_default_symlink", strings.TrimPrefix(def, "vmlinuz-"))
	}

	switch {
	case runObs.Status != probe.StatusOK:
		return finish(scan.Unknown(runObs.Reason(),
			"the running kernel version could not be read ("+runObs.Reason()+"), so drift against the installed kernels cannot be evaluated"))
	case len(all) == 0:
		return finish(scan.Unknown(reasonOf(bootObs, modObs),
			"no installed kernel could be enumerated from /boot or the module directories ("+
				string(bootObs.Status)+" / "+string(modObs.Status)+"), so whether the running kernel is the newest installed one is unknown"))
	}

	newest := all[0]
	for _, v := range all {
		if compareKernelVersions(v, newest) > 0 {
			newest = v
		}
	}
	r.Field("newest_installed_kernel", newest)

	if newest == running {
		return finish(scan.Pass("the running kernel " + running +
			" is the newest kernel installed on this machine, so no reboot is pending to pick up a newer one"))
	}
	if compareKernelVersions(newest, running) <= 0 {
		return finish(scan.Pass("the running kernel " + running +
			" is at least as new as every installed kernel (newest installed: " + newest + ")"))
	}
	return finish(scan.Fail(scan.ReasonPolicy,
		"the running kernel is "+running+" while "+newest+
			" is installed: the machine is running an older kernel than the one it would boot, so any fix in the newer kernel is not in effect until it reboots"))
}

// compareKernelVersions orders two kernel release strings by their numeric
// components, falling back to a lexicographic comparison of the remainder.
func compareKernelVersions(a, b string) int {
	an, ar := splitKernelVersion(a)
	bn, br := splitKernelVersion(b)
	for i := 0; i < len(an) || i < len(bn); i++ {
		var x, y int64
		if i < len(an) {
			x = an[i]
		}
		if i < len(bn) {
			y = bn[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return strings.Compare(ar, br)
}

func splitKernelVersion(v string) ([]int64, string) {
	var nums []int64
	i := 0
	for i < len(v) {
		if v[i] < '0' || v[i] > '9' {
			if len(nums) > 0 && v[i] != '.' && v[i] != '-' {
				break
			}
			i++
			continue
		}
		j := i
		for j < len(v) && v[j] >= '0' && v[j] <= '9' {
			j++
		}
		n, _ := strconv.ParseInt(v[i:j], 10, 64)
		nums = append(nums, n)
		i = j
		if len(nums) >= 4 {
			break
		}
	}
	return nums, v[i:]
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
