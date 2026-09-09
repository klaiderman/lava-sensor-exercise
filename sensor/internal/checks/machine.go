// Package checks holds the machine-description collectors and the registered
// posture checks. Nothing in here constructs an exec.Cmd or opens a file
// directly: every observation goes through internal/probe.
package checks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// hostIDLabel keys the host_id derivation. /etc/machine-id is declared
// confidential by machine-id(5), so the raw value is never emitted; a keyed
// derivation is stable across runs and useless to an attacker (LD-4, L32).
const hostIDLabel = "lava-sensor-host-id"

const hostIDCaveat = "stable across reboots; regenerated on re-image; clone-vulnerable"

// dmiDir is the parsed DMI object directory. The raw SMBIOS tables next to it
// are root-only and are never a sole dependency (L02).
const dmiDir = "/sys/class/dmi/id"

// CollectMachine builds part one of the output: describe the machine.
//
// Every field carries a *_source; an undeterminable string is the literal
// "unknown" and an undeterminable integer is 0 with an entry in unknowns. No
// field is ever "" and no value is ever a guess (B6, AM-5).
func CollectMachine(ctx context.Context, env *scan.Env) scan.Machine {
	m := scan.Machine{
		Unknowns:        scan.Unknowns{},
		OwnerCandidates: []scan.OwnerCandidate{},
		AssetTags:       []scan.AssetTag{},
		Storage:         []scan.StorageDevice{},
		OtherBlockDevs:  []scan.StorageDevice{},
	}
	// Execution context is established before hardware inventory, because a
	// container sees the host's /sys and DMI and every field below would
	// otherwise be silently misattributed (L45, F85).
	collectExecutionContext(ctx, env, &m)
	collectIdentity(env, &m)
	collectDMI(env, &m)
	collectOS(env, &m)
	collectCPU(env, &m)
	collectMemory(env, &m)
	collectStorage(env, &m)
	collectOwner(env, &m)
	return m
}

func collectExecutionContext(ctx context.Context, env *scan.Env, m *scan.Machine) {
	f := env.Files
	if f.Exists("/.dockerenv") {
		m.ExecutionContext, m.ExecContextSrc = "container:docker", "/.dockerenv"
		m.DescribesHostKrn = true
		return
	}
	if f.Exists("/run/.containerenv") {
		m.ExecutionContext, m.ExecContextSrc = "container:podman", "/run/.containerenv"
		m.DescribesHostKrn = true
		return
	}
	if cg := f.Read("/proc/1/cgroup", probe.Small); cg.Status == probe.StatusOK {
		for _, marker := range []string{"docker", "lxc", "kubepods", "containerd", "libpod"} {
			if strings.Contains(cg.Value, "/"+marker) {
				m.ExecutionContext = "container:" + marker
				m.ExecContextSrc = "/proc/1/cgroup"
				m.DescribesHostKrn = true
				return
			}
		}
	}
	// systemd-detect-virt has inverted polarity: exit 0 means virtualisation
	// was DETECTED. A missing utility is UNKNOWN, never "bare metal" (F53).
	obs := env.Runner.Run(ctx, probe.Spec{
		Name: "systemd-detect-virt", Budget: 2 * time.Second,
		Purpose: "execution context cross-check",
	})
	switch {
	case obs.Status == probe.StatusOK:
		id := strings.TrimSpace(obs.Value)
		if id == "" || id == "none" {
			m.ExecutionContext, m.ExecContextSrc = "bare-metal", "systemd-detect-virt (exit 0, none)"
		} else {
			m.ExecutionContext, m.ExecContextSrc = "vm:"+id, "systemd-detect-virt"
		}
	case obs.Status == probe.StatusExecError && obs.ExitCode != nil && *obs.ExitCode == 1:
		// Exit 1 with "none" is the documented "no virtualisation" answer.
		m.ExecutionContext, m.ExecContextSrc = "bare-metal", "systemd-detect-virt (exit 1, none)"
	case obs.Status == probe.StatusUtilityMissing:
		m.ExecutionContext = scan.UnknownString
		m.ExecContextSrc = "none (systemd-detect-virt not installed)"
		m.Unknowns.Add("execution_context", scan.ReasonUtilMiss, "/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "systemd-detect-virt")
	default:
		m.ExecutionContext = scan.UnknownString
		m.ExecContextSrc = "none (systemd-detect-virt " + string(obs.Status) + ")"
		m.Unknowns.Add("execution_context", obs.Reason(), "/.dockerenv", "/run/.containerenv", "/proc/1/cgroup", "systemd-detect-virt")
	}
}

func collectIdentity(env *scan.Env, m *scan.Machine) {
	f := env.Files

	// hostname: one bounded read, no exec. hostnamectl is systemd-only.
	hn, hnObs := f.ReadTrimmed("/proc/sys/kernel/hostname", probe.Tiny)
	hn2, hnObs2 := "", probe.Observation{}
	if hnObs.Status != probe.StatusOK || hn == "" {
		hn2, hnObs2 = f.ReadTrimmed("/etc/hostname", probe.Tiny)
	}
	switch {
	case hnObs.Status == probe.StatusOK && hn != "":
		m.Hostname, m.HostnameSource = hn, "/proc/sys/kernel/hostname"
	case hnObs2.Status == probe.StatusOK && hn2 != "":
		m.Hostname, m.HostnameSource = hn2, "/etc/hostname"
	default:
		// An empty hostname file is unknown, not the empty string (B6).
		m.Hostname, m.HostnameSource = scan.UnknownString, "none"
		m.Unknowns.Add("hostname", firstReason(hnObs, hnObs2), "/proc/sys/kernel/hostname", "/etc/hostname")
	}

	// host_id: keyed derivation over the first source that yields bytes.
	type src struct {
		path  string
		label string
		pol   probe.Policy
	}
	chain := []src{
		{dmiDir + "/product_uuid", "product-uuid", probe.Tiny},
		{"/etc/machine-id", "machine-id", probe.Tiny},
	}
	tried := []string{}
	for _, s := range chain {
		tried = append(tried, s.path)
		v, obs := f.ReadTrimmed(s.path, s.pol)
		if obs.Status == probe.StatusOK && v != "" {
			m.HostID = keyedID(v)
			m.HostIDSource = s.label + " (keyed hash)"
			m.HostIDCaveat = hostIDCaveat
			return
		}
	}
	// Last resort: stable hardware identifiers. Never random, never
	// time-derived — an id that changes per run is not an id (B1a).
	if seed, used := hardwareSeed(env); seed != "" {
		m.HostID = keyedID(seed)
		m.HostIDSource = "hardware-ids (keyed hash)"
		m.HostIDCaveat = "derived from " + used + "; survives re-image, changes if the hardware changes"
		return
	}
	m.HostID, m.HostIDSource = scan.UnknownString, "none"
	m.Unknowns.Add("host_id", scan.ReasonENOENT, append(tried, "/sys/block/*/wwid", "/sys/class/net/*/address")...)
}

func keyedID(msg string) string {
	mac := hmac.New(sha256.New, []byte(hostIDLabel))
	mac.Write([]byte(strings.TrimSpace(msg)))
	return hex.EncodeToString(mac.Sum(nil))
}

// hardwareSeed builds a stable seed from hardware identifiers: NVMe/SCSI wwids
// and permanent NIC MACs. A MAC is only used when addr_assign_type says it is
// permanent, because a generated MAC changes on every boot.
func hardwareSeed(env *scan.Env) (seed, used string) {
	f := env.Files
	var parts, usedPaths []string
	names, _ := f.ReadDirNames("/sys/block", 512)
	for _, n := range names {
		if v, obs := f.ReadTrimmed("/sys/block/"+n+"/wwid", probe.Tiny); obs.Status == probe.StatusOK && v != "" {
			parts = append(parts, "wwid:"+v)
			usedPaths = append(usedPaths, "/sys/block/"+n+"/wwid")
		}
	}
	nets, _ := f.ReadDirNames("/sys/class/net", 256)
	for _, n := range nets {
		if n == "lo" {
			continue
		}
		at, obs := f.ReadTrimmed("/sys/class/net/"+n+"/addr_assign_type", probe.Tiny)
		if obs.Status != probe.StatusOK || at != "0" {
			continue
		}
		if mac, obs := f.ReadTrimmed("/sys/class/net/"+n+"/address", probe.Tiny); obs.Status == probe.StatusOK && mac != "" && mac != "00:00:00:00:00:00" {
			parts = append(parts, "mac:"+mac)
			usedPaths = append(usedPaths, "/sys/class/net/"+n+"/address")
		}
	}
	if len(parts) == 0 {
		return "", ""
	}
	return strings.Join(parts, "|"), strings.Join(usedPaths, ", ")
}

// placeholderClasses are vendor filler values. Detection is by pattern class,
// never by literal match, because every vendor spells its filler differently
// (L01, F5).
func isPlaceholder(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	if t == "" {
		return true
	}
	for _, p := range []string{
		"to be filled by o.e.m", "to be filled by oem", "default string",
		"not specified", "not available", "system asset tag", "chassis asset tag",
		"base board asset tag", "board asset tag", "asset-1234567890", "unknown",
		"none", "n/a", "na", "null", "family", "sku", "system sku number",
		"system version", "system manufacturer", "system product name",
		"0123456789", "1234567890", "empty",
	} {
		if t == p || strings.HasPrefix(t, p) {
			return true
		}
	}
	allZero := true
	for _, c := range t {
		if c != '0' && c != '-' && c != '.' && c != ' ' {
			allZero = false
			break
		}
	}
	return allZero
}

func collectDMI(env *scan.Env, m *scan.Machine) {
	f := env.Files
	read := func(attr string) (string, probe.Observation) {
		return f.ReadTrimmed(dmiDir+"/"+attr, probe.Tiny)
	}

	dirObs := f.Stat(dmiDir)
	// ENOENT on the directory means there is no DMI platform at all (aarch64,
	// most containers). EACCES on an attribute means restricted. They are
	// different findings and the wording must differ (L33).
	dmiPresent := dirObs.Status == probe.StatusOK

	vendor, vObs := read("sys_vendor")
	model, mObs := read("product_name")
	switch {
	case vObs.Status == probe.StatusOK && !isPlaceholder(vendor):
		m.Vendor, m.VendorSource = vendor, dmiDir+"/sys_vendor"
	default:
		if bv, obs := read("board_vendor"); obs.Status == probe.StatusOK && !isPlaceholder(bv) {
			m.Vendor, m.VendorSource = bv, dmiDir+"/board_vendor"
		} else if dt, obs := f.ReadTrimmed("/proc/device-tree/model", probe.Tiny); obs.Status == probe.StatusOK && dt != "" {
			m.Vendor, m.VendorSource = strings.TrimRight(dt, "\x00"), "/proc/device-tree/model"
		} else {
			m.Vendor, m.VendorSource = scan.UnknownString, "none"
			m.Unknowns.Add("vendor", dmiReason(dmiPresent, vObs), dmiDir+"/sys_vendor", dmiDir+"/board_vendor", "/proc/device-tree/model")
		}
	}
	switch {
	case mObs.Status == probe.StatusOK && !isPlaceholder(model):
		m.Model, m.ModelSource = model, dmiDir+"/product_name"
	default:
		if bn, obs := read("board_name"); obs.Status == probe.StatusOK && !isPlaceholder(bn) {
			m.Model, m.ModelSource = bn, dmiDir+"/board_name"
		} else if dt, obs := f.ReadTrimmed("/proc/device-tree/model", probe.Tiny); obs.Status == probe.StatusOK && dt != "" {
			m.Model, m.ModelSource = strings.TrimRight(dt, "\x00"), "/proc/device-tree/model"
		} else {
			m.Model, m.ModelSource = scan.UnknownString, "none"
			m.Unknowns.Add("model", dmiReason(dmiPresent, mObs), dmiDir+"/product_name", dmiDir+"/board_name", "/proc/device-tree/model")
		}
	}

	fw := scan.Firmware{Source: dmiDir}
	for _, fld := range []struct {
		attr string
		dst  *string
	}{
		{"board_vendor", &fw.BoardVendor},
		{"board_name", &fw.BoardName},
		{"board_version", &fw.BoardVersion},
		{"bios_vendor", &fw.BIOSVendor},
		{"bios_version", &fw.BIOSVersion},
		{"bios_date", &fw.BIOSDate},
		{"chassis_type", &fw.ChassisType},
		{"product_sku", &fw.ProductSKU},
		{"product_family", &fw.ProductFamly},
	} {
		if v, obs := read(fld.attr); obs.Status == probe.StatusOK && v != "" {
			*fld.dst = v
		}
	}
	if !dmiPresent {
		fw.Source = "none (" + dirObs.Reason() + " on " + dmiDir + ")"
	}
	m.Firmware = fw

	// Asset tags are reported as observed, with whether they are placeholders.
	// Naming a placeholder as the owner is the trap this defends against.
	for _, attr := range []string{"chassis_asset_tag", "board_asset_tag", "product_sku", "product_family", "product_serial", "board_serial", "chassis_serial", "product_uuid"} {
		v, obs := read(attr)
		tag := scan.AssetTag{Field: attr, Source: dmiDir + "/" + attr}
		if obs.Status == probe.StatusOK {
			ph := isPlaceholder(v)
			tag.Value, tag.Placeholder = v, &ph
			if v == "" {
				tag.Value = scan.UnknownString
			}
		} else {
			// Unread: no placeholder claim is made either way.
			tag.Value = scan.UnknownString
			tag.Errno = obs.Reason()
		}
		m.AssetTags = append(m.AssetTags, tag)
	}
}

func dmiReason(present bool, obs probe.Observation) string {
	if !present {
		return scan.ReasonENOENT
	}
	if r := obs.Reason(); r != "" {
		return r
	}
	return scan.ReasonParse
}

func collectOS(env *scan.Env, m *scan.Machine) {
	f := env.Files
	o := scan.OS{Name: scan.UnknownString, Version: scan.UnknownString, Kernel: scan.UnknownString}

	// /etc/os-release is a symlink into /usr/lib on Ubuntu. It is followed
	// deliberately; its st_size (the link length) is never used as a read cap.
	obs := f.Read("/etc/os-release", probe.SmallFollow)
	src := "/etc/os-release"
	if obs.Status != probe.StatusOK {
		obs = f.Read("/usr/lib/os-release", probe.SmallFollow)
		src = "/usr/lib/os-release"
	}
	if obs.Status == probe.StatusOK {
		kv := parseKeyValue(obs.Value)
		o.Source = src
		if v := kv["NAME"]; v != "" {
			o.Name = v
		}
		if v := kv["VERSION_ID"]; v != "" {
			o.Version = v
		} else {
			// VERSION_ID may legitimately be absent from a well-formed file;
			// it is never inferred from ID (F54).
			m.Unknowns.Add("os.version", scan.ReasonENOENT, src+":VERSION_ID")
		}
		o.VersionPretty = kv["PRETTY_NAME"]
		o.ID = kv["ID"]
		o.IDLike = kv["ID_LIKE"]
	} else {
		o.Source = "none"
		m.Unknowns.Add("os.name", obs.Reason(), "/etc/os-release", "/usr/lib/os-release")
	}

	if v, kObs := f.ReadTrimmed("/proc/sys/kernel/osrelease", probe.Tiny); kObs.Status == probe.StatusOK && v != "" {
		o.Kernel, o.KernelSource = v, "/proc/sys/kernel/osrelease"
	} else {
		o.KernelSource = "none"
		m.Unknowns.Add("os.kernel", kObs.Reason(), "/proc/sys/kernel/osrelease")
	}
	if sObs := f.Stat("/boot/vmlinuz"); sObs.Status == probe.StatusOK && sObs.Meta != nil && sObs.Meta.SymlinkTarget != "" {
		o.KernelBootDefault = strings.TrimPrefix(sObs.Meta.SymlinkTarget, "vmlinuz-")
	}
	m.OS = o
}

func parseKeyValue(s string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}

const maxCPUs = 4096

func collectCPU(env *scan.Env, m *scan.Machine) {
	f := env.Files
	c := scan.CPU{Model: scan.UnknownString, CoresBasis: scan.UnknownString}

	info := f.Read("/proc/cpuinfo", probe.Large)
	var cpuinfoPairs map[string]bool
	if info.Status == probe.StatusOK {
		c.Source = "/proc/cpuinfo"
		model, vendor, pairs, logical := parseCPUInfo(info.Value)
		if model != "" {
			c.Model = model
		}
		c.Vendor = vendor
		c.LogicalCPUs = logical
		cpuinfoPairs = pairs
	} else {
		c.Source = "none"
		m.Unknowns.Add("cpu.model", info.Reason(), "/proc/cpuinfo")
	}

	// Physical cores = distinct (physical_package_id, core_id) pairs.
	topo := map[string]bool{}
	sockets := map[string]bool{}
	names, dirObs := f.ReadDirNames("/sys/devices/system/cpu", maxCPUs)
	if dirObs.Status == probe.StatusOK {
		for _, n := range names {
			if !strings.HasPrefix(n, "cpu") || len(n) < 4 || n[3] < '0' || n[3] > '9' {
				continue
			}
			core, o1 := f.ReadTrimmed("/sys/devices/system/cpu/"+n+"/topology/core_id", probe.Tiny)
			pkg, o2 := f.ReadTrimmed("/sys/devices/system/cpu/"+n+"/topology/physical_package_id", probe.Tiny)
			if o1.Status == probe.StatusOK && o2.Status == probe.StatusOK {
				topo[pkg+":"+core] = true
				sockets[pkg] = true
			}
		}
	}
	switch {
	case len(topo) > 0:
		c.Cores = int64(len(topo))
		c.Sockets = int64(len(sockets))
		c.CoresBasis = "sysfs-topology"
	case len(cpuinfoPairs) > 0:
		c.Cores = int64(len(cpuinfoPairs))
		c.CoresBasis = "cpuinfo-topology"
		pkgs := map[string]bool{}
		for k := range cpuinfoPairs {
			pkgs[strings.SplitN(k, ":", 2)[0]] = true
		}
		c.Sockets = int64(len(pkgs))
	case c.LogicalCPUs > 0:
		c.Cores = c.LogicalCPUs
		c.CoresBasis = "logical (topology unavailable)"
		c.Sockets = 0
	default:
		c.Cores = 0
		c.CoresBasis = scan.UnknownString
		m.Unknowns.Add("cpu.cores", dirObs.Reason(), "/sys/devices/system/cpu/cpu*/topology", "/proc/cpuinfo")
	}
	if c.Cores > 0 && c.LogicalCPUs > 0 {
		c.ThreadsPerCore = c.LogicalCPUs / c.Cores
	}
	m.CPU = c
}

func parseCPUInfo(s string) (model, vendor string, pairs map[string]bool, logical int64) {
	pairs = map[string]bool{}
	var phys, core string
	flush := func() {
		if phys != "" && core != "" {
			pairs[phys+":"+core] = true
		}
		phys, core = "", ""
	}
	for _, ln := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			if strings.TrimSpace(ln) == "" {
				flush()
			}
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		switch k {
		case "processor":
			logical++
		case "model name", "Model name":
			if model == "" {
				model = v
			}
		case "vendor_id", "CPU implementer":
			if vendor == "" {
				vendor = v
			}
		case "physical id":
			phys = v
		case "core id":
			core = v
		}
	}
	flush()
	return model, vendor, pairs, logical
}

func collectMemory(env *scan.Env, m *scan.Machine) {
	f := env.Files
	obs := f.Read("/proc/meminfo", probe.Small)
	if obs.Status != probe.StatusOK {
		m.MemoryBytes, m.MemorySource = 0, "none"
		m.Unknowns.Add("memory_bytes", obs.Reason(), "/proc/meminfo:MemTotal")
		return
	}
	for _, ln := range strings.Split(obs.Value, "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		kb := parseKB(v)
		switch strings.TrimSpace(k) {
		case "MemTotal":
			m.MemoryBytes = kb * 1024
			m.MemorySource = "/proc/meminfo:MemTotal"
		case "SwapTotal":
			m.SwapTotalBytes = kb * 1024
		}
	}
	if m.MemoryBytes == 0 {
		// DMI installed capacity needs root and memory-block arithmetic
		// differs materially from MemTotal; neither is substituted (F62, F63).
		m.MemorySource = "none"
		m.Unknowns.Add("memory_bytes", scan.ReasonParse, "/proc/meminfo:MemTotal")
	}
}

func parseKB(v string) int64 {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return 0
	}
	n, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// sectorBytes is the fixed unit of /sys/block/<d>/size. It is 512 regardless of
// logical_block_size: multiplying by 4096 on a 4Kn drive over-reports 8x
// (L28, F55).
const sectorBytes = 512

var excludedBlockPrefixes = []string{"loop", "ram", "zram"}

func collectStorage(env *scan.Env, m *scan.Machine) {
	f := env.Files
	names, dirObs := f.ReadDirNames("/sys/block", 1024)
	if dirObs.Status != probe.StatusOK {
		m.StorageSource = "none"
		m.Unknowns.Add("storage", dirObs.Reason(), "/sys/block")
		return
	}
	m.StorageSource = "/sys/block"
	mounts := env.Mounts()

	var physical, aggregate, excluded []scan.StorageDevice
	for _, n := range names {
		if hasAnyPrefix(n, excludedBlockPrefixes) {
			excluded = append(excluded, scan.StorageDevice{
				Device: n, Model: scan.UnknownString, DevicePath: "/dev/" + n,
				Class: "virtual", ModelSource: "n/a", SizeSource: "n/a",
				Partitions: []scan.Partition{}, Holders: []string{}, Slaves: []string{},
			})
			continue
		}
		d := describeBlockDevice(f, mounts, n)
		switch {
		case strings.HasPrefix(n, "dm-") || strings.HasPrefix(n, "md"):
			d.Class = "aggregate"
			aggregate = append(aggregate, d)
		default:
			d.Class = "physical"
			physical = append(physical, d)
		}
	}
	// dm/md aggregates are excluded from storage[] only when a physical disk
	// exists; when they are all there is, listing nothing would be a silent
	// omission (T-S5, D3).
	if len(physical) > 0 {
		m.Storage = physical
		m.OtherBlockDevs = append(aggregate, excluded...)
	} else {
		m.Storage = append(physical, aggregate...)
		m.OtherBlockDevs = excluded
	}
	if m.Storage == nil {
		m.Storage = []scan.StorageDevice{}
	}
	if m.OtherBlockDevs == nil {
		m.OtherBlockDevs = []scan.StorageDevice{}
	}
	if len(m.Storage) == 0 {
		m.Unknowns.Add("storage", scan.ReasonENOENT, "/sys/block")
	}
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// describeBlockDevice reads one whole disk from sysfs and the udev database.
// The device node itself is never opened: the whole storage category depends on
// that (L13, L29).
func describeBlockDevice(f *probe.Reader, mounts *scan.MountTable, n string) scan.StorageDevice {
	base := "/sys/block/" + n
	d := scan.StorageDevice{
		Device: n, DevicePath: "/dev/" + n, Model: scan.UnknownString,
		Partitions: []scan.Partition{}, Holders: []string{}, Slaves: []string{},
	}

	if v, obs := f.ReadTrimmed(base+"/size", probe.Tiny); obs.Status == probe.StatusOK {
		if sectors, err := strconv.ParseInt(v, 10, 64); err == nil {
			d.SizeBytes = sectors * sectorBytes
			d.SizeSource = base + "/size x 512"
		} else {
			d.SizeSource = "none (" + scan.ReasonParse + ")"
		}
	} else {
		d.SizeSource = "none (" + obs.Reason() + ")"
	}

	majmin, _ := f.ReadTrimmed(base+"/dev", probe.Tiny)
	udev := readUdevRecord(f, majmin)

	switch {
	case readInto(f, base+"/device/model", &d.Model):
		d.ModelSource = base + "/device/model"
	case strings.HasPrefix(n, "nvme") && readInto(f, "/sys/class/nvme/"+nvmeController(n)+"/model", &d.Model):
		d.ModelSource = "/sys/class/nvme/" + nvmeController(n) + "/model"
	case udev["ID_MODEL"] != "":
		d.Model, d.ModelSource = udev["ID_MODEL"], "/run/udev/data/b"+majmin+":ID_MODEL"
	default:
		d.Model, d.ModelSource = scan.UnknownString, "none"
	}

	// Typed facts get typed JSON: a rotational flag is a boolean, not "1".
	d.Rotational = readBool(f, base+"/queue/rotational")
	d.Removable = readBool(f, base+"/removable")
	readInto(f, base+"/wwid", &d.WWID)
	readInto(f, base+"/device/firmware_rev", &d.FirmwareRev)
	readInto(f, base+"/device/state", &d.State)
	readInto(f, base+"/queue/write_cache", &d.WriteCache)
	if v, obs := f.ReadTrimmed(base+"/queue/scheduler", probe.Tiny); obs.Status == probe.StatusOK {
		d.Scheduler = activeScheduler(v)
	}
	d.LogicalBlockSize = readInt(f, base+"/queue/logical_block_size")
	d.PhysicalBlockSize = readInt(f, base+"/queue/physical_block_size")
	if t := transportOf(f, base); t != "" {
		d.Transport = t
	}
	if fs := udev["ID_FS_TYPE"]; fs != "" {
		d.Filesystem, d.FilesystemSource = fs, "udev-db-at-last-uevent"
	}

	if hs, obs := f.ReadDirNames(base+"/holders", 256); obs.Status == probe.StatusOK {
		d.Holders = hs
	}
	if sl, obs := f.ReadDirNames(base+"/slaves", 256); obs.Status == probe.StatusOK {
		d.Slaves = sl
	}

	if ents, obs := f.ReadDirNames(base, 1024); obs.Status == probe.StatusOK {
		for _, e := range ents {
			if !strings.HasPrefix(e, n) || e == n {
				continue
			}
			if !f.Exists(base + "/" + e + "/partition") {
				continue
			}
			p := scan.Partition{Name: e}
			if v, o := f.ReadTrimmed(base+"/"+e+"/size", probe.Tiny); o.Status == probe.StatusOK {
				if sectors, err := strconv.ParseInt(v, 10, 64); err == nil {
					p.SizeBytes = sectors * sectorBytes
				}
			}
			pmm, _ := f.ReadTrimmed(base+"/"+e+"/dev", probe.Tiny)
			prec := readUdevRecord(f, pmm)
			p.FSTypeUdev = prec["ID_FS_TYPE"]
			p.Mountpoint = mountpointFor(mounts, pmm)
			d.Partitions = append(d.Partitions, p)
		}
	}
	return d
}

// nvmeController strips the namespace suffix from an NVMe block device name:
// nvme0n1 -> nvme0. Searching forward for "n" finds the one in "nvme", so the
// cut is made at the LAST "n" that is followed only by digits.
func nvmeController(n string) string {
	for i := len(n) - 1; i > 0; i-- {
		if n[i] != 'n' {
			continue
		}
		rest := n[i+1:]
		if rest == "" {
			return n
		}
		allDigits := true
		for _, c := range rest {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && n[i-1] >= '0' && n[i-1] <= '9' {
			return n[:i]
		}
		return n
	}
	return n
}

func readInto(f *probe.Reader, path string, dst *string) bool {
	v, obs := f.ReadTrimmed(path, probe.Tiny)
	if obs.Status == probe.StatusOK && v != "" {
		*dst = v
		return true
	}
	return false
}

// readBool reads a sysfs 0/1 flag. A missing or unparseable flag is nil, never
// a defaulted false.
func readBool(f *probe.Reader, path string) *bool {
	v, obs := f.ReadTrimmed(path, probe.Tiny)
	if obs.Status != probe.StatusOK {
		return nil
	}
	switch v {
	case "0":
		b := false
		return &b
	case "1":
		b := true
		return &b
	}
	return nil
}

func readInt(f *probe.Reader, path string) int64 {
	v, obs := f.ReadTrimmed(path, probe.Tiny)
	if obs.Status != probe.StatusOK {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func activeScheduler(v string) string {
	for _, tok := range strings.Fields(v) {
		if strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]") {
			return strings.Trim(tok, "[]")
		}
	}
	return strings.TrimSpace(v)
}

// transportOf reads the bus a device sits on from the subsystem symlink rather
// than guessing from the kernel name (L37).
func transportOf(f *probe.Reader, base string) string {
	for _, rel := range []string{"/device/subsystem", "/device/device/subsystem"} {
		if t, obs := f.ReadLinkBase(base + rel); obs.Status == probe.StatusOK && t != "" {
			return t
		}
	}
	return ""
}

// readUdevRecord reads /run/udev/data/b<major>:<minor>. The udev database
// answers identity and filesystem type without opening the device; an empty
// field means "not recorded at the last uevent", never "no filesystem" (L29).
func readUdevRecord(f *probe.Reader, majmin string) map[string]string {
	out := map[string]string{}
	if majmin == "" {
		return out
	}
	obs := f.Read("/run/udev/data/b"+majmin, probe.Small)
	if obs.Status != probe.StatusOK {
		return out
	}
	for _, ln := range strings.Split(obs.Value, "\n") {
		if !strings.HasPrefix(ln, "E:") {
			continue
		}
		k, v, ok := strings.Cut(ln[2:], "=")
		if ok {
			out[k] = v
		}
	}
	return out
}

func mountpointFor(mounts *scan.MountTable, majmin string) string {
	if mounts == nil || majmin == "" {
		return ""
	}
	for _, e := range mounts.Entries {
		if e.MajorMinor == majmin {
			return e.MountPoint
		}
	}
	return ""
}

func collectOwner(env *scan.Env, m *scan.Machine) {
	f := env.Files
	m.Owner = scan.UnknownString

	// The only sources that could legitimately name an owner.
	if obs := f.Read("/etc/machine-info", probe.Small); obs.Status == probe.StatusOK {
		kv := parseKeyValue(obs.Value)
		for _, k := range []string{"DEPLOYMENT", "LOCATION"} {
			if val := kv[k]; val != "" && !isPlaceholder(val) {
				m.Owner, m.OwnerSource = val, "/etc/machine-info:"+k
				return
			}
		}
	}
	for _, t := range m.AssetTags {
		if !usableTag(t) {
			continue
		}
		if t.Field == "chassis_asset_tag" || t.Field == "board_asset_tag" {
			m.Owner, m.OwnerSource = t.Value, t.Source
			return
		}
	}

	m.OwnerSource = "none (all sources placeholder, absent or denied)"
	// Candidates are evidence, never promoted: inferring a customer from a
	// hostname pattern or a drop-in filename is a guess (LD-4 trap).
	if v, obs := f.ReadTrimmed("/run/cloud-init/cloud-id", probe.Tiny); obs.Status == probe.StatusOK && v != "" {
		m.OwnerCandidates = append(m.OwnerCandidates, scan.OwnerCandidate{
			Value: v, Source: "/run/cloud-init/cloud-id", Confidence: "provider, not tenant",
		})
	}
	if names, obs := f.ReadDirNames("/etc/ssh/sshd_config.d", 128); obs.Status == probe.StatusOK {
		for _, n := range names {
			m.OwnerCandidates = append(m.OwnerCandidates, scan.OwnerCandidate{
				Value: n, Source: "/etc/ssh/sshd_config.d/ (drop-in filename)", Confidence: "weak; provisioning provenance only",
			})
		}
	}
	for _, t := range m.AssetTags {
		if usableTag(t) && (t.Field == "product_sku" || t.Field == "product_family") {
			m.OwnerCandidates = append(m.OwnerCandidates, scan.OwnerCandidate{
				Value: t.Value, Source: t.Source, Confidence: "vendor metadata, not ownership",
			})
		}
	}
	m.Unknowns.Add("owner", ownerUnknownReason(m), "/etc/machine-info", dmiDir+"/chassis_asset_tag", dmiDir+"/board_asset_tag", "/run/cloud-init/cloud-id")
}

// firstReason returns the reason of the first observation that actually failed,
// so an unknown never cites a probe that was never attempted.
func firstReason(obs ...probe.Observation) string {
	for _, o := range obs {
		if o.Status != "" && o.Status != probe.StatusOK {
			return o.Reason()
		}
	}
	return scan.ReasonParse
}

// usableTag reports whether an asset tag was read AND carries a real value.
func usableTag(t scan.AssetTag) bool {
	return t.Errno == "" && t.Value != scan.UnknownString && t.Placeholder != nil && !*t.Placeholder
}

// ownerUnknownReason distinguishes the two ways owner ends up unknown: every
// source was denied, or every source was absent or a vendor placeholder. They
// call for different remediation, so they are not collapsed (L03, L33).
func ownerUnknownReason(m *scan.Machine) string {
	for _, t := range m.AssetTags {
		if t.Errno == scan.ReasonEACCES || t.Errno == scan.ReasonEPERM {
			return t.Errno
		}
	}
	for _, t := range m.AssetTags {
		if t.Placeholder != nil && *t.Placeholder {
			return "PLACEHOLDER_ONLY"
		}
	}
	return scan.ReasonENOENT
}
