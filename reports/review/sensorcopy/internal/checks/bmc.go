package checks

import (
	"context"
	"strconv"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// The sensor never issues an IPMI command and never opens /dev/ipmi* — not even
// O_RDONLY|O_NONBLOCK. Everything in this file is sysfs, /proc and lstat
// (LD-3). The BMC's own identity attributes are read under an out-of-band
// deadline because that read drives a live KCS transaction that no context can
// cancel once issued (L40).

const neverIssuedCommand = "no IPMI command was issued and no BMC device node was opened"

// ---------------------------------------------------------------------------
// BMC_INBAND_INTERFACE_PRESENT
// ---------------------------------------------------------------------------

type bmcInbandInterfacePresent struct{ meta }

func (c bmcInbandInterfacePresent) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	dmiEntries, dmiObs := env.Files.ReadDirNames("/sys/firmware/dmi/entries", 1024)
	dmiObs.Detail = "SMBIOS entry directory; the directory names are the only unprivileged signal, the attributes inside are 0400"
	r.Add(dmiObs)
	acpi, acpiObs := env.Files.ReadDirNames("/sys/bus/acpi/devices", 4096)
	r.Add(acpiObs)
	platform, platObs := env.Files.ReadDirNames("/sys/devices/platform", 1024)
	r.Add(platObs)

	var evidence []string
	var type38 []string
	for _, n := range dmiEntries {
		if strings.HasPrefix(n, "38-") {
			type38 = append(type38, n)
			evidence = append(evidence, "SMBIOS type 38 entry /sys/firmware/dmi/entries/"+n)
		}
	}
	for _, n := range acpi {
		if strings.HasPrefix(n, "IPI0001") {
			evidence = append(evidence, "ACPI device /sys/bus/acpi/devices/"+n)
		}
	}
	for _, n := range platform {
		if strings.HasPrefix(n, "dmi-ipmi-si") || strings.HasPrefix(n, "ipmi_si") || strings.HasPrefix(n, "ipmi_bmc") {
			evidence = append(evidence, "platform device /sys/devices/platform/"+n)
		}
	}

	// One attribute read is attempted so the denial is recorded rather than
	// implied: we never claim to have decoded type-38 fields.
	var attrReads []fileMeta
	if len(type38) > 0 {
		for _, attr := range []string{"type", "raw"} {
			p := "/sys/firmware/dmi/entries/" + type38[0] + "/" + attr
			obs := env.Files.Read(p, probe.Tiny)
			obs.Detail = "SMBIOS entry attribute; kernel ships these 0400"
			r.Add(obs)
			attrReads = append(attrReads, fileMeta{Path: p, Status: string(obs.Status), Errno: obs.Reason()})
		}
	}
	r.Field("entries_observed", evidence)
	r.Field("attribute_reads", attrReads)
	r.Field("decoded_fields", nil)
	r.Field("decode_blocked_by", "EACCES on SMBIOS entry attributes (kernel ships them 0400); base address, IRQ and interface type stay unknown")
	r.Field("interface_declared", len(evidence) > 0)
	r.Field("never_issued_ipmi_command", true)

	listingsOK := dmiObs.Status == probe.StatusOK || acpiObs.Status == probe.StatusOK || platObs.Status == probe.StatusOK
	switch {
	case len(evidence) > 0:
		return finish(scan.Pass("firmware declares an in-band management-controller interface: " + strings.Join(evidence, "; ") +
			" — declared, which is not the same as usable"))
	case dmiObs.Status == probe.StatusENOENT && acpiObs.Status == probe.StatusENOENT:
		return finish(scan.Unknown(scan.ReasonEINVAL,
			"neither SMBIOS entries nor ACPI devices are exposed by this kernel or namespace, so whether the platform declares a management-controller interface cannot be determined — this is not evidence that there is no BMC"))
	case !listingsOK:
		return finish(scan.Unknown(reasonOf(dmiObs, acpiObs, platObs),
			"the firmware and device listings could not be read, so a management-controller declaration can neither be found nor ruled out"))
	default:
		return finish(scan.Pass(
			"no management-controller interface is declared: the SMBIOS entry directory, the ACPI device list and the platform device list were all enumerated successfully and none contains one"))
	}
}

// ---------------------------------------------------------------------------
// BMC_RESPONDS_IN_BAND
// ---------------------------------------------------------------------------

type bmcRespondsInBand struct{ meta }

// The manufacturer id is reported as the raw sysfs value and as the decimal
// IANA Private Enterprise Number it decodes to. It is deliberately NOT mapped
// to a vendor name: a name table is a second thing to keep correct, and the
// number is the citable fact an operator can look up.

type bmcAttribute struct {
	Path      string `json:"path"`
	Value     string `json:"value,omitempty"`
	BytesRead int64  `json:"bytes_read"`
	ElapsedMS int64  `json:"elapsed_ms"`
	Errno     string `json:"errno,omitempty"`
	Status    string `json:"status"`
}

func (c bmcRespondsInBand) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("never_issued_ipmi_command", true)
	r.Field("deadline_ms", probe.BMCOOBDeadline.Milliseconds())

	platform, platObs := env.Files.ReadDirNames("/sys/devices/platform", 1024)
	r.Add(platObs)
	var bmcDirs []string
	for _, n := range platform {
		if strings.HasPrefix(n, "ipmi_bmc.") {
			bmcDirs = append(bmcDirs, "/sys/devices/platform/"+n)
		}
	}
	r.Field("bmc_sysfs_dirs", bmcDirs)

	// A loaded ipmi_si is not proof of a responding BMC. Only a populated
	// identity attribute is.
	var modules []string
	if mods := env.Files.Read("/proc/modules", probe.Large); mods.Status == probe.StatusOK {
		for _, m := range []string{"ipmi_si", "ipmi_devintf", "ipmi_msghandler", "ipmi_ssif", "acpi_ipmi"} {
			if strings.Contains(mods.Value, m+" ") {
				modules = append(modules, m)
			}
		}
	}
	r.Field("ipmi_modules_loaded", modules)
	r.Field("module_note", "a loaded ipmi_si is a capability signal; only a populated identity attribute proves the controller answered")

	if len(bmcDirs) == 0 {
		classPresent := env.Files.Exists("/sys/class/ipmi/ipmi0")
		r.Field("ipmi_class_device_present", classPresent)
		if len(modules) > 0 || classPresent {
			return finish(scan.Unknown(scan.ReasonENOENT,
				"the IPMI driver stack is loaded but no /sys/devices/platform/ipmi_bmc.* directory exists, so the interface is present while the controller has not been identified — that is 'declared but not usable', not 'no BMC'"))
		}
		return finish(scan.Unknown(scan.ReasonENOENT,
			"no /sys/devices/platform/ipmi_bmc.* directory exists and no IPMI driver is loaded, so whether a management controller would answer over the in-band interface is unknown"))
	}

	base := bmcDirs[0]
	attrs := []string{"ipmi_version", "firmware_revision", "manufacturer_id", "product_id", "device_id", "guid"}
	rows := make([]bmcAttribute, 0, len(attrs))
	values := map[string]string{}
	timedOut := false
	answered := false
	for _, a := range attrs {
		p := base + "/" + a
		// Out-of-band deadline: this read is a live KCS transaction that cannot
		// be cancelled, so it runs in its own goroutine under a timer and is
		// abandoned on overrun rather than waited on (L40).
		obs := env.Files.ReadOOB(p, probe.Tiny, probe.BMCOOBDeadline)
		obs.Detail = "BMC identity attribute read under an out-of-band deadline; a successful read is itself proof the controller answered"
		r.Add(obs)
		row := bmcAttribute{Path: p, BytesRead: obs.Bytes, ElapsedMS: obs.Elapsed.Milliseconds(),
			Errno: obs.Reason(), Status: string(obs.Status)}
		if obs.Status == probe.StatusOK {
			row.Value = strings.TrimSpace(obs.Value)
			values[a] = row.Value
			answered = true
		}
		if obs.Status == probe.StatusTimeout {
			timedOut = true
		}
		rows = append(rows, row)
	}
	r.Field("attributes", rows)

	if mid, ok := values["manufacturer_id"]; ok {
		raw := strings.TrimSpace(mid)
		n, err := strconv.ParseInt(strings.TrimPrefix(raw, "0x"), 16, 64)
		if err != nil {
			n, err = strconv.ParseInt(raw, 10, 64)
		}
		row := map[string]any{"raw": raw,
			"note": "the value is an IANA Private Enterprise Number; it is reported as observed rather than mapped to a vendor name"}
		if err == nil {
			row["iana_pen_decimal"] = n
		}
		r.Field("manufacturer_id", row)
	}

	switch {
	case answered:
		return finish(scan.Pass("the management controller answered over the in-band interface: " + base +
			" returned " + itoa(int64(len(values))) + " identity attribute(s) within the out-of-band deadline; " + neverIssuedCommand))
	case timedOut:
		return finish(scan.Unknown(scan.ReasonTimeout,
			"every BMC identity attribute read exceeded its "+probe.BMCOOBDeadline.String()+
				" out-of-band deadline; the reads were abandoned rather than waited on and no cached value is presented as fresh"))
	default:
		return finish(scan.Unknown(reasonOf(probe.Observation{Status: probe.StatusEACCES, Errno: rows[0].Errno}),
			"the BMC identity directory exists but no attribute could be read ("+rows[0].Errno+
				"), so whether the controller answers in band is unknown"))
	}
}

// ---------------------------------------------------------------------------
// BMC_DEVICE_NODE_ACCESS
// ---------------------------------------------------------------------------

type bmcDeviceNodeAccess struct{ meta }

// ipmiNodes are checked in all three spellings because ipmitool itself confuses
// their errnos and reports EACCES as ENOENT (F46).
var ipmiNodes = []string{"/dev/ipmi0", "/dev/ipmi/0", "/dev/ipmidev/0"}

type deviceNode struct {
	Path             string     `json:"path"`
	Exists           bool       `json:"exists"`
	FileType         string     `json:"file_type,omitempty"`
	Mode             *int64     `json:"mode,omitempty"`
	UID              *int64     `json:"uid,omitempty"`
	GID              *int64     `json:"gid,omitempty"`
	GroupName        string     `json:"group_name,omitempty"`
	GroupMembers     int64      `json:"group_member_count"`
	AccessPermitted  string     `json:"access_permitted"`
	ACL              *probe.ACL `json:"acl,omitempty"`
	Errno            string     `json:"errno,omitempty"`
	RestrictionBasis string     `json:"restriction_basis,omitempty"`
}

func (c bmcDeviceNodeAccess) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("node_opened", false)
	r.Field("never_issued_ipmi_command", true)

	var nodes []deviceNode
	found := false
	adverse := []string{}
	undetermined := []string{}

	for _, p := range ipmiNodes {
		st := env.Files.Stat(p)
		st.Detail = "BMC device node metadata; the node is never opened, not even O_RDONLY|O_NONBLOCK"
		r.Add(st)
		n := deviceNode{Path: p, Errno: st.Reason()}
		if st.Status != probe.StatusOK {
			if st.Status != probe.StatusENOENT {
				undetermined = append(undetermined, p+" ("+st.Reason()+")")
			}
			n.AccessPermitted = "unknown"
			nodes = append(nodes, n)
			continue
		}
		found = true
		n.Exists = true
		if st.Meta != nil {
			n.FileType = st.Meta.FileType
			n.Mode, n.UID, n.GID = st.Meta.Mode, st.Meta.UID, st.Meta.GID
		}
		acl, aclObs := env.Files.ReadACL(p)
		n.ACL = &acl
		r.Add(aclObs)

		mode := int64(0)
		if n.Mode != nil {
			mode = *n.Mode
		}
		if n.GID != nil {
			for _, g := range env.Groups().Groups {
				if g.GID == *n.GID {
					n.GroupName, n.GroupMembers = g.Name, int64(len(g.Members))
					break
				}
			}
		}
		switch {
		case mode&0o006 != 0:
			n.AccessPermitted = "any local user"
			adverse = append(adverse, p+" is other-accessible (mode "+octal(mode)+")")
		case mode&0o060 != 0 && n.GroupMembers > 0:
			n.AccessPermitted = "members of group " + n.GroupName
			adverse = append(adverse, p+" is accessible to the "+itoa(n.GroupMembers)+" member(s) of group "+n.GroupName)
		case acl.Determined && acl.GrantsNonOwner:
			n.AccessPermitted = "a named ACL principal"
			adverse = append(adverse, p+" has an ACL granting a non-owner principal access")
		case !acl.Determined && acl.Errno != "" && acl.Errno != "ENODATA":
			n.AccessPermitted = "unknown (ACL " + acl.Errno + ")"
			undetermined = append(undetermined, p+" ACL ("+acl.Errno+")")
		default:
			n.AccessPermitted = "root only"
			// The precise statement: this is the devtmpfs default mode, not a
			// capability check inside the driver's open path.
			n.RestrictionBasis = "restricted by file mode only; ipmi_devintf's open path performs no capability check, so the mode is the whole control"
		}
		nodes = append(nodes, n)
	}
	r.Field("device_nodes", nodes)

	// Anything that could relax the kernel default.
	var relaxing []string
	for _, dir := range []string{"/etc/udev/rules.d", "/lib/udev/rules.d", "/usr/lib/udev/rules.d", "/etc/modprobe.d"} {
		names, obs := env.Files.ReadDirNames(dir, 512)
		if obs.Status != probe.StatusOK {
			continue
		}
		for _, n := range names {
			if !strings.Contains(strings.ToLower(n), "ipmi") {
				continue
			}
			body := env.Files.Read(dir+"/"+n, probe.Small)
			if body.Status == probe.StatusOK {
				relaxing = append(relaxing, dir+"/"+n)
			}
		}
	}
	r.Field("udev_or_modprobe_rules_matching_ipmi", relaxing)

	switch {
	case !found:
		interfaceDeclared := env.Files.Exists("/sys/class/ipmi/ipmi0")
		r.Field("ipmi_class_device_present", interfaceDeclared)
		if interfaceDeclared {
			return finish(scan.Unknown(scan.ReasonENOENT,
				"an IPMI interface is present but no /dev/ipmi* node exists in any of its three spellings, which means ipmi_devintf is not loaded — not that there is no BMC"))
		}
		return finish(scan.Pass(
			"no in-band BMC device node exists in any of its three spellings, proven by successful stats of each path, so no local user has an in-band path to a management controller"))
	case len(adverse) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"an unprivileged local principal can open the BMC device node: "+strings.Join(adverse, "; ")+
				" — that is an out-of-band-equivalent compromise path from a local account"))
	case len(undetermined) > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"who may open the BMC device node could not be fully established ("+strings.Join(undetermined, ", ")+")"))
	default:
		return finish(scan.Pass(
			"the BMC device node is reachable by root only, and the restriction is the devtmpfs file mode rather than a capability check in the driver's open path"))
	}
}

func octal(m int64) string {
	if m == 0 {
		return "0"
	}
	var b []byte
	for m > 0 {
		b = append([]byte{byte('0' + m%8)}, b...)
		m /= 8
	}
	return "0" + string(b)
}

// ---------------------------------------------------------------------------
// BMC_CLIENT_TOOLING_INVENTORY
// ---------------------------------------------------------------------------

type bmcClientToolingInventory struct{ meta }

var bmcToolNames = []string{
	"ipmitool", "ipmiutil", "ipmievd", "openipmish", "freeipmi-config",
	"bmc-info", "ipmi-sensors", "ipmi-chassis", "ipmi-config", "ipmi-locate", "ipmiconsole",
}

// pathDirs are scanned regardless of the caller's PATH: an unprivileged PATH
// often omits the sbin directories, which would produce a false "not installed".
var pathDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin"}

type toolRow struct {
	Name         string `json:"name"`
	Found        bool   `json:"found"`
	ResolvedPath string `json:"resolved_path,omitempty"`
	Mode         *int64 `json:"mode,omitempty"`
	UID          *int64 `json:"uid,omitempty"`
	GID          *int64 `json:"gid,omitempty"`
}

func (c bmcClientToolingInventory) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("executed", false)

	var scanned, unreadable []string
	for _, d := range pathDirs {
		st := env.Files.Stat(d)
		st.Detail = "binary search path directory; scanned regardless of the caller's PATH, which often omits the sbin directories"
		r.Add(st)
		switch st.Status {
		case probe.StatusOK:
			scanned = append(scanned, d)
		case probe.StatusENOENT:
		default:
			unreadable = append(unreadable, d+" ("+st.Reason()+")")
		}
	}
	r.Field("path_dirs_scanned", scanned)
	r.Field("path_dirs_unreadable", unreadable)

	rows := make([]toolRow, 0, len(bmcToolNames))
	var installed []string
	for _, name := range bmcToolNames {
		row := toolRow{Name: name}
		for _, d := range scanned {
			p := d + "/" + name
			st := env.Files.Stat(p)
			if st.Status != probe.StatusOK {
				continue
			}
			row.Found, row.ResolvedPath = true, p
			if st.Meta != nil {
				row.Mode, row.UID, row.GID = st.Meta.Mode, st.Meta.UID, st.Meta.GID
			}
			installed = append(installed, name)
			break
		}
		rows = append(rows, row)
	}
	r.Field("tools", rows)
	r.Field("inventory_note", "the absence of a client tool says nothing about whether a management controller exists or answers; it never sets another check to unknown")

	if len(scanned) == 0 {
		return finish(scan.Unknown(scan.ReasonEACCES,
			"no directory in the standard binary search path could be listed ("+strings.Join(unreadable, ", ")+
				"), so which IPMI client tooling is installed is unknown"))
	}
	if len(installed) == 0 {
		return finish(scan.Pass("no IPMI client tooling is installed — every candidate was resolved to not-found across " +
			itoa(int64(len(scanned))) + " binary directories, and none was executed"))
	}
	return finish(scan.Pass("IPMI client tooling is installed: " + strings.Join(installed, ", ") +
		" — inventory only; none was executed, and whether it could reach the controller is decided by BMC_DEVICE_NODE_ACCESS"))
}

// ---------------------------------------------------------------------------
// BMC_HOST_INTERFACE_EXPOSURE
// ---------------------------------------------------------------------------

type bmcHostInterfaceExposure struct{ meta }

// usbNetDrivers are the drivers a USB network gadget binds to. A USB NIC is not
// automatically a BMC NIC: the classification also needs a firmware declaration
// or a management-controller descriptor, and the basis is always recorded.
var usbNetDrivers = map[string]bool{"rndis_host": true, "cdc_ether": true, "cdc_ncm": true, "usbnet": true, "cdc_subset": true}

// managementDescriptorHints are substrings that identify a management
// controller's own USB gadget. Never a vendor id literal (L37).
var managementDescriptorHints = []string{"aspeed", "rndis/ethernet gadget", "bmc", "management", "ipmi", "ilo", "idrac", "emulex pilot"}

type netInterface struct {
	Name                string   `json:"ifname"`
	Driver              string   `json:"driver,omitempty"`
	Operstate           string   `json:"operstate,omitempty"`
	Carrier             string   `json:"carrier,omitempty"`
	HasAddress          bool     `json:"has_address"`
	USBManufacturer     string   `json:"usb_manufacturer,omitempty"`
	USBProduct          string   `json:"usb_product,omitempty"`
	ClassifiedAsBMC     bool     `json:"classified_as_bmc"`
	ClassificationBasis []string `json:"classification_basis"`
	SpeedErrno          string   `json:"speed_errno,omitempty"`
}

const oobBlindSpot = "out-of-band LAN exposure is unknown by construction: the dedicated BMC network port is not visible to this operating system"

func (c bmcHostInterfaceExposure) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("oob_lan_exposure", oobBlindSpot)

	entries, dmiObs := env.Files.ReadDirNames("/sys/firmware/dmi/entries", 1024)
	r.Add(dmiObs)
	type42 := false
	for _, n := range entries {
		if strings.HasPrefix(n, "42-") {
			type42 = true
		}
	}
	r.Field("smbios_type42_present", type42)

	names, netObs := env.Files.ReadDirNames("/sys/class/net", 512)
	netObs.Detail = "network interface enumeration for a host-to-controller path"
	r.Add(netObs)
	if netObs.Status != probe.StatusOK {
		return finish(scan.Unknown(netObs.Reason(),
			"the network interface list could not be read ("+netObs.Reason()+
				"), so whether a management-controller host interface exists is unknown; "+oobBlindSpot))
	}

	var ifaces []netInterface
	var live, latent []string
	undetermined := false
	for _, n := range names {
		if n == "lo" {
			continue
		}
		base := "/sys/class/net/" + n
		iface := netInterface{Name: n, ClassificationBasis: []string{}}
		iface.Driver, _ = env.Files.ReadLinkBase(base + "/device/driver")
		iface.Operstate, _ = env.Files.ReadTrimmed(base+"/operstate", probe.Tiny)
		iface.Carrier, _ = env.Files.ReadTrimmed(base+"/carrier", probe.Tiny)
		if addr, obs := env.Files.ReadTrimmed(base+"/address", probe.Tiny); obs.Status == probe.StatusOK && addr != "" && addr != "00:00:00:00:00:00" {
			iface.HasAddress = true
		}
		// Reading speed on a down link returns EINVAL. That is normal and is
		// recorded as unsupported, never as a failure.
		if _, obs := env.Files.ReadTrimmed(base+"/speed", probe.Tiny); obs.Status != probe.StatusOK {
			iface.SpeedErrno = obs.Reason()
		}

		if !usbNetDrivers[iface.Driver] {
			ifaces = append(ifaces, iface)
			continue
		}
		iface.ClassificationBasis = append(iface.ClassificationBasis, "USB network gadget driver "+iface.Driver)
		// Walk up the USB parent chain for descriptor strings.
		for _, rel := range []string{"/device/..", "/device/../..", "/device/../../.."} {
			man, mObs := env.Files.ReadTrimmed(base+rel+"/manufacturer", probe.Tiny)
			prod, pObs := env.Files.ReadTrimmed(base+rel+"/product", probe.Tiny)
			if mObs.Status == probe.StatusOK && iface.USBManufacturer == "" {
				iface.USBManufacturer = man
			}
			if pObs.Status == probe.StatusOK && iface.USBProduct == "" {
				iface.USBProduct = prod
			}
		}
		descriptor := strings.ToLower(iface.USBManufacturer + " " + iface.USBProduct)
		for _, hint := range managementDescriptorHints {
			if strings.Contains(descriptor, hint) {
				iface.ClassificationBasis = append(iface.ClassificationBasis, "USB descriptor matches a management-controller class pattern ("+hint+")")
			}
		}
		if type42 {
			iface.ClassificationBasis = append(iface.ClassificationBasis, "firmware declares an SMBIOS type 42 management-controller host interface")
		}
		iface.ClassifiedAsBMC = len(iface.ClassificationBasis) > 1
		if iface.ClassifiedAsBMC {
			switch {
			case iface.Operstate == "up" && iface.HasAddress:
				live = append(live, n)
			case iface.Operstate == "" && iface.Carrier == "":
				undetermined = true
			default:
				latent = append(latent, n+" (operstate "+firstNonEmpty(iface.Operstate, "unknown")+")")
			}
		}
		ifaces = append(ifaces, iface)
	}
	r.Field("interfaces", ifaces)

	switch {
	case len(live) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a management-controller host interface is up with an address configured ("+strings.Join(live, ", ")+
				"): there is a live network path from this operating system to the controller. "+oobBlindSpot))
	case len(latent) > 0:
		return finish(scan.Pass(
			"a management-controller host interface is present but down (" + strings.Join(latent, ", ") +
				"); down is its current state, not a control — anyone with the capability to bring it up gets a network path to the controller. " + oobBlindSpot))
	case undetermined:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"a management-controller host interface was classified but neither its operstate nor its carrier could be read, so whether it is usable is unknown. "+oobBlindSpot))
	case type42 && dmiObs.Status == probe.StatusOK:
		return finish(scan.Unknown(scan.ReasonENOENT,
			"firmware declares an SMBIOS type 42 management-controller host interface but no matching network interface is enumerated, so whether a second path to the controller exists is unknown. "+oobBlindSpot))
	default:
		return finish(scan.Pass(
			"no management-controller host interface is observable: the SMBIOS entry list and the network interface list were both enumerated and neither contains one. " + oobBlindSpot))
	}
}
