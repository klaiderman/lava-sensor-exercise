package checks

import (
	"context"
	"strconv"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
	"lava-sensor-exercise/sensor/internal/scan"
)

// STORAGE_POSTURE is about data-at-rest and decommissioning hygiene on rented
// hardware. No check in this file ever opens a block device: what is on a disk
// is deliberately out of scope, and saying so is part of the answer.

// ---------------------------------------------------------------------------
// DISK_ENCRYPTION_AT_REST
// ---------------------------------------------------------------------------

type diskEncryptionAtRest struct{ meta }

type dmDevice struct {
	Name     string `json:"name"`
	SysfsDir string `json:"sysfs_path"`
	DMName   string `json:"dm_name,omitempty"`
	DMUUID   string `json:"dm_uuid,omitempty"`
	Crypt    bool   `json:"crypt"`
	Errno    string `json:"errno,omitempty"`
}

type blindSpot struct {
	Mechanism  string `json:"mechanism"`
	WhyUnknown string `json:"why_unknown"`
	Evidence   string `json:"evidence_path_or_errno"`
}

func (c diskEncryptionAtRest) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	// The verdict is scoped to dm-crypt/LUKS. "No dm mapping" is not "the disks
	// are unencrypted" (L30) and the wording never says otherwise.
	r.Field("scope", "dm-crypt/LUKS as visible to the kernel's device-mapper layer")

	blockNames, blockObs := env.Files.ReadDirNames("/sys/block", 1024)
	blockObs.LoadBearing = true
	r.Add(blockObs)
	mapperNames, mapperObs := env.Files.ReadDirNames("/dev/mapper", 512)
	r.Add(mapperObs)
	mounts := env.Mounts()
	r.Add(mounts.Obs)

	var dms []dmDevice
	cryptFound := false
	uuidUnreadable := false
	for _, n := range blockNames {
		if !strings.HasPrefix(n, "dm-") {
			continue
		}
		d := dmDevice{Name: n, SysfsDir: "/sys/block/" + n + "/dm"}
		uuid, uObs := env.Files.ReadTrimmed("/sys/block/"+n+"/dm/uuid", probe.Tiny)
		name, _ := env.Files.ReadTrimmed("/sys/block/"+n+"/dm/name", probe.Tiny)
		d.DMUUID, d.DMName = uuid, name
		if uObs.Status != probe.StatusOK {
			d.Errno = uObs.Reason()
			uuidUnreadable = true
		}
		// cryptsetup's own convention: the mapping's uuid is CRYPT-<type>-...
		if strings.HasPrefix(uuid, "CRYPT-") {
			d.Crypt, cryptFound = true, true
		}
		dms = append(dms, d)
	}
	r.Field("dm_devices", dms)
	r.Field("dm_devices_found", int64(len(dms)))
	r.Field("dev_mapper_entries", mapperNames)

	// The backing chain of every real mount.
	type mountChain struct {
		Mountpoint string   `json:"mountpoint"`
		Source     string   `json:"source"`
		FSType     string   `json:"fstype"`
		Backing    []string `json:"backing_devices"`
		Encrypted  bool     `json:"encrypted_by_dm_crypt"`
	}
	var chains []mountChain
	rootEncrypted := false
	for _, m := range mounts.Entries {
		if !isRealFilesystem(m.FSType) {
			continue
		}
		backing := backingDevices(env, m.MajorMinor)
		mc := mountChain{Mountpoint: m.MountPoint, Source: m.Source, FSType: m.FSType, Backing: backing}
		for _, b := range backing {
			for _, d := range dms {
				if d.Name == b && d.Crypt {
					mc.Encrypted = true
				}
			}
		}
		if m.MountPoint == "/" {
			rootEncrypted = mc.Encrypted
		}
		chains = append(chains, mc)
	}
	r.Field("mount_chain", chains)

	// Named blind spots, each with its own reason: an unknown that is not named
	// is indistinguishable from a claim.
	spots := []blindSpot{
		{"self-encrypting drive / TCG Opal",
			"every IOC_OPAL_* ioctl is gated on CAP_SYS_ADMIN and the kernel exposes no Opal state in sysfs; the drive model string cannot substitute, because vendors ship SED and non-SED SKUs under the same base part number",
			"no sysfs attribute exists to read"},
		{"filesystem-level encryption (ext4 fscrypt)",
			"whether a filesystem uses fscrypt is recorded in its superblock, which needs root or dumpe2fs to read; kernel support for the feature is not use of it",
			"/sys/fs/ext4/features/encryption (support only)"},
		{"ZFS and btrfs native encryption",
			"reported only where such a filesystem is mounted; the property lives in the pool or subvolume metadata",
			"/proc/self/mountinfo fstype"},
	}
	if fe := env.Files.Stat("/sys/fs/ext4/features/encryption"); fe.Status == probe.StatusOK {
		r.Field("ext4_fscrypt_kernel_support", true)
	}
	r.Field("blind_spots", spots)
	if ct := env.Files.Stat("/etc/crypttab"); ct.Status == probe.StatusOK {
		r.Add(ct)
		r.Field("crypttab_present", true)
	}

	switch {
	case blockObs.Status != probe.StatusOK || mounts.Obs.Status != probe.StatusOK:
		return finish(scan.Unknown(reasonOf(blockObs, mounts.Obs),
			"the block device list or the mount table could not be read, so the backing chain of the mounted filesystems is unresolved and dm-crypt use can neither be confirmed nor ruled out"))
	case uuidUnreadable:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"a device-mapper mapping exists whose dm/uuid could not be read, so whether it is a dm-crypt mapping is unknown"))
	case rootEncrypted:
		return finish(scan.Pass(
			"the root filesystem's backing chain reaches a device-mapper mapping whose dm/uuid carries the CRYPT- prefix, so dm-crypt/LUKS is in use for it"))
	case cryptFound:
		return finish(scan.Fail(scan.ReasonPolicy,
			"dm-crypt/LUKS mappings exist on this machine but the root filesystem's backing chain does not pass through one, so the root filesystem is not protected by block-level encryption the kernel can see"))
	default:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the device-mapper and block device listings both completed and contain no CRYPT- mapping, so dm-crypt/LUKS is provably not in use for any mounted filesystem; this statement is scoped to dm-crypt/LUKS and does not assert that the media is unencrypted — the named blind spots in the evidence say what remains unknown"))
	}
}

func isRealFilesystem(fstype string) bool {
	switch fstype {
	case "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2", "securityfs",
		"pstore", "bpf", "configfs", "debugfs", "tracefs", "fusectl", "mqueue", "hugetlbfs",
		"binfmt_misc", "autofs", "efivarfs", "ramfs", "rpc_pipefs", "nsfs", "overlay", "squashfs",
		"9p", "drvfs", "none":
		return false
	}
	return true
}

// backingDevices walks from a mount's major:minor down to the physical devices
// underneath it, through slaves/ links.
func backingDevices(env *scan.Env, majmin string) []string {
	name := blockNameFor(env, majmin)
	if name == "" {
		return []string{}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(string, int)
	walk = func(n string, depth int) {
		if depth > 8 || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
		slaves, obs := env.Files.ReadDirNames("/sys/block/"+n+"/slaves", 64)
		if obs.Status != probe.StatusOK {
			// A partition's parent is its containing directory, not a slave.
			if parent := wholeDiskOf(env, n); parent != "" && parent != n {
				walk(parent, depth+1)
			}
			return
		}
		for _, s := range slaves {
			walk(s, depth+1)
		}
	}
	walk(name, 0)
	return out
}

// blockNameFor resolves a major:minor to a kernel block device name, including
// partitions, without opening anything.
func blockNameFor(env *scan.Env, majmin string) string {
	names, obs := env.Files.ReadDirNames("/sys/block", 1024)
	if obs.Status != probe.StatusOK {
		return ""
	}
	for _, n := range names {
		if v, o := env.Files.ReadTrimmed("/sys/block/"+n+"/dev", probe.Tiny); o.Status == probe.StatusOK && v == majmin {
			return n
		}
		parts, po := env.Files.ReadDirNames("/sys/block/"+n, 1024)
		if po.Status != probe.StatusOK {
			continue
		}
		for _, p := range parts {
			if !strings.HasPrefix(p, n) || p == n {
				continue
			}
			if v, o := env.Files.ReadTrimmed("/sys/block/"+n+"/"+p+"/dev", probe.Tiny); o.Status == probe.StatusOK && v == majmin {
				return p
			}
		}
	}
	return ""
}

func wholeDiskOf(env *scan.Env, part string) string {
	names, obs := env.Files.ReadDirNames("/sys/block", 1024)
	if obs.Status != probe.StatusOK {
		return ""
	}
	for _, n := range names {
		if n != part && strings.HasPrefix(part, n) {
			return n
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// ROOT_FILESYSTEM_REDUNDANCY
// ---------------------------------------------------------------------------

type rootFilesystemRedundancy struct{ meta }

type mdArray struct {
	Name      string `json:"name"`
	Level     string `json:"level,omitempty"`
	Degraded  string `json:"degraded,omitempty"`
	RaidDisks string `json:"raid_disks,omitempty"`
	Errno     string `json:"errno,omitempty"`
}

var redundantLevels = map[string]bool{"raid1": true, "raid5": true, "raid6": true, "raid10": true}

func (c rootFilesystemRedundancy) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}

	mounts := env.Mounts()
	mounts.Obs.LoadBearing = true
	r.Add(mounts.Obs)
	var rootMM, rootFS, rootSrc string
	for _, m := range mounts.Entries {
		if m.MountPoint == "/" {
			rootMM, rootFS, rootSrc = m.MajorMinor, m.FSType, m.Source
		}
	}
	if rootMM == "" {
		return finish(scan.Unknown(scan.ReasonParse,
			"the root filesystem could not be located in the mount table, so its backing chain is unresolved"))
	}
	backing := backingDevices(env, rootMM)
	r.Field("root_mount", map[string]string{"source": rootSrc, "fstype": rootFS, "major_minor": rootMM})
	r.Field("backing_devices", backing)

	// md arrays. /proc/mdstat always lists the compiled-in personalities, so a
	// populated Personalities: line is not an array (T-S2).
	mdstat := env.Files.Read("/proc/mdstat", probe.Small)
	r.Add(mdstat)
	blockNames, blockObs := env.Files.ReadDirNames("/sys/block", 1024)
	r.Add(blockObs)
	var arrays []mdArray
	for _, n := range blockNames {
		if !strings.HasPrefix(n, "md") {
			continue
		}
		a := mdArray{Name: n}
		a.Level, _ = env.Files.ReadTrimmed("/sys/block/"+n+"/md/level", probe.Tiny)
		a.Degraded, _ = env.Files.ReadTrimmed("/sys/block/"+n+"/md/degraded", probe.Tiny)
		a.RaidDisks, _ = env.Files.ReadTrimmed("/sys/block/"+n+"/md/raid_disks", probe.Tiny)
		arrays = append(arrays, a)
	}
	r.Field("md_arrays", arrays)
	if mdstat.Status == probe.StatusOK {
		r.Field("mdstat_excerpt", excerptLines(mdstat.Value, 12))
		r.Field("mdstat_note", "/proc/mdstat always lists the compiled-in personalities; a populated Personalities: line is not an array")
	}

	// A hardware RAID controller presents one logical device and its health
	// needs a vendor CLI. Gate on the PCI class, never on a controller name.
	var raidControllers []string
	if devs, obs := env.Files.ReadDirNames("/sys/bus/pci/devices", 1024); obs.Status == probe.StatusOK {
		for _, d := range devs {
			cls, o := env.Files.ReadTrimmed("/sys/bus/pci/devices/"+d+"/class", probe.Tiny)
			if o.Status != probe.StatusOK {
				continue
			}
			if strings.HasPrefix(strings.ToLower(cls), "0x0104") {
				drv, _ := env.Files.ReadLinkBase("/sys/bus/pci/devices/" + d + "/driver")
				raidControllers = append(raidControllers, d+" (class "+cls+", driver "+firstNonEmpty(drv, "none")+")")
			}
		}
	}
	r.Field("pci_raid_controllers", raidControllers)

	// Redundancy layer, decided from the backing chain.
	layer := "none"
	degraded := false
	for _, b := range backing {
		switch {
		case strings.HasPrefix(b, "md"):
			for _, a := range arrays {
				if a.Name == b && redundantLevels[a.Level] {
					layer = "md/" + a.Level
					degraded = a.Degraded != "" && a.Degraded != "0"
				}
			}
		case strings.HasPrefix(b, "dm-"):
			if uuid, o := env.Files.ReadTrimmed("/sys/block/"+b+"/dm/uuid", probe.Tiny); o.Status == probe.StatusOK && strings.HasPrefix(uuid, "DM-RAID-") {
				layer = "dm-raid"
			}
		}
	}
	if rootFS == "btrfs" {
		if devs, obs := env.Files.ReadDirNames("/sys/fs/btrfs", 64); obs.Status == probe.StatusOK && len(devs) > 0 {
			r.Field("btrfs_filesystems", devs)
		}
		if layer == "none" {
			return finish(scan.Unknown(scan.ReasonUtilMiss,
				"the root filesystem is btrfs, whose redundancy profile lives in filesystem metadata that this sensor does not read, so whether it survives a device loss is unknown"))
		}
	}
	if rootFS == "zfs" && layer == "none" {
		return finish(scan.Unknown(scan.ReasonUtilMiss,
			"the root filesystem is ZFS, whose vdev layout is not exposed in sysfs, so whether it survives a device loss is unknown"))
	}
	r.Field("redundancy_layer", layer)

	// Idle devices that could provide redundancy make the finding actionable.
	var spares []string
	for _, n := range blockNames {
		if hasAnyPrefix(n, excludedBlockPrefixes) || strings.HasPrefix(n, "dm-") || strings.HasPrefix(n, "md") {
			continue
		}
		if !deviceInUse(env, n, mounts) {
			spares = append(spares, n)
		}
	}
	r.Field("idle_devices_present", spares)

	// Count distinct whole disks: a partition and its containing disk are one
	// device, and counting both would hide a single-device root.
	disks := map[string]bool{}
	for _, b := range backing {
		if strings.HasPrefix(b, "dm-") || strings.HasPrefix(b, "md") {
			continue
		}
		if whole := wholeDiskOf(env, b); whole != "" {
			disks[whole] = true
		} else {
			disks[b] = true
		}
	}
	physical := len(disks)
	r.Field("distinct_backing_disks", len(disks))

	switch {
	case len(raidControllers) > 0 && layer == "none":
		return finish(scan.Unknown(scan.ReasonUtilMiss,
			"a PCI RAID controller (class 0104) is present, so the root filesystem's single logical device may be backed by hardware redundancy this operating system cannot see; a vendor CLI would be needed to establish it"))
	case degraded:
		return finish(scan.Fail(scan.ReasonPolicy,
			"the root filesystem sits on a "+layer+" array that is currently degraded, so it may not survive another device loss"))
	case layer != "none":
		return finish(scan.Pass("the root filesystem's backing chain passes through a " + layer +
			" layer reporting zero degraded members, so it survives the loss of a single device"))
	case blockObs.Status != probe.StatusOK || mdstat.Status != probe.StatusOK:
		return finish(scan.Unknown(reasonOf(blockObs, mdstat),
			"the redundancy enumerations did not all complete, so a single-device root cannot be asserted"))
	case physical <= 1:
		msg := "the root filesystem resolves to a single physical device (" + strings.Join(backing, " -> ") +
			") and every redundancy enumeration completed without finding an md array, a dm-raid target or a multi-device pool, so the loss of that device loses the root filesystem"
		if len(spares) > 0 {
			msg += "; " + itoa(int64(len(spares))) + " attached device(s) (" + strings.Join(spares, ", ") +
				") are idle and could provide redundancy. A single-device root may be a deliberate rebuild-on-failure choice"
		}
		return finish(scan.Fail(scan.ReasonPolicy, msg))
	default:
		return finish(scan.Unknown(scan.ReasonParse,
			"the root filesystem's backing chain resolved to "+itoa(int64(physical))+
				" devices without an identifiable redundancy layer, so whether it survives a device loss is unresolved"))
	}
}

func excerptLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// ---------------------------------------------------------------------------
// UNUSED_ATTACHED_BLOCK_DEVICES
// ---------------------------------------------------------------------------

type unusedAttachedBlockDevices struct{ meta }

type blockDeviceUse struct {
	Name               string   `json:"name"`
	SizeBytes          int64    `json:"size_bytes"`
	Partitions         []string `json:"partitions"`
	Holders            []string `json:"holders"`
	Slaves             []string `json:"slaves"`
	Mountpoints        []string `json:"mountpoints"`
	UdevFSType         string   `json:"udev_fstype"`
	UdevRecordPath     string   `json:"udev_record_path"`
	UdevRecordReadable bool     `json:"udev_record_readable"`
	InSwap             bool     `json:"in_swap"`
	InUse              bool     `json:"in_use"`
	InUseBasis         []string `json:"in_use_basis"`
}

const remanenceStatement = "unknown by design — the sensor does not open the device to find out what is on it"

func (c unusedAttachedBlockDevices) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("device_not_opened", true)
	r.Field("remanence", remanenceStatement)
	r.Field("udev_caveat", "fstype comes from the udev database as recorded at the last uevent, not from a read of the disk; a filesystem created afterwards would be invisible")

	names, blockObs := env.Files.ReadDirNames("/sys/block", 1024)
	blockObs.LoadBearing = true
	r.Add(blockObs)
	if blockObs.Status != probe.StatusOK {
		return finish(scan.Unknown(blockObs.Reason(),
			"/sys/block could not be listed ("+blockObs.Reason()+"), so which block devices are attached is unknown"))
	}
	mounts := env.Mounts()
	r.Add(mounts.Obs)
	swaps := env.Files.Read("/proc/swaps", probe.Small)
	r.Add(swaps)

	var devices []blockDeviceUse
	var idle []string
	udevUnreadable := false

	for _, n := range names {
		if hasAnyPrefix(n, excludedBlockPrefixes) {
			continue
		}
		d := blockDeviceUse{Name: n, Partitions: []string{}, Holders: []string{}, Slaves: []string{},
			Mountpoints: []string{}, InUseBasis: []string{}}
		if v, o := env.Files.ReadTrimmed("/sys/block/"+n+"/size", probe.Tiny); o.Status == probe.StatusOK {
			if sectors, err := strconv.ParseInt(v, 10, 64); err == nil {
				d.SizeBytes = sectors * sectorBytes
			}
		}
		if ents, o := env.Files.ReadDirNames("/sys/block/"+n, 1024); o.Status == probe.StatusOK {
			for _, e := range ents {
				if e != n && strings.HasPrefix(e, n) && env.Files.Exists("/sys/block/"+n+"/"+e+"/partition") {
					d.Partitions = append(d.Partitions, e)
				}
			}
		}
		if hs, o := env.Files.ReadDirNames("/sys/block/"+n+"/holders", 64); o.Status == probe.StatusOK {
			d.Holders = hs
		}
		if sl, o := env.Files.ReadDirNames("/sys/block/"+n+"/slaves", 64); o.Status == probe.StatusOK {
			d.Slaves = sl
		}
		majmin, _ := env.Files.ReadTrimmed("/sys/block/"+n+"/dev", probe.Tiny)
		d.UdevRecordPath = "/run/udev/data/b" + majmin
		udevObs := env.Files.Read(d.UdevRecordPath, probe.Small)
		if udevObs.Status == probe.StatusOK {
			d.UdevRecordReadable = true
			for _, ln := range strings.Split(udevObs.Value, "\n") {
				if k, v, ok := strings.Cut(strings.TrimPrefix(ln, "E:"), "="); ok && k == "ID_FS_TYPE" {
					d.UdevFSType = v
				}
			}
		} else if udevObs.Status != probe.StatusENOENT {
			udevUnreadable = true
		}
		for _, m := range mounts.Entries {
			if m.MajorMinor == majmin || strings.Contains(m.Source, "/"+n) {
				d.Mountpoints = append(d.Mountpoints, m.MountPoint)
			}
		}
		if swaps.Status == probe.StatusOK && strings.Contains(swaps.Value, "/"+n) {
			d.InSwap = true
		}

		if len(d.Partitions) > 0 {
			d.InUseBasis = append(d.InUseBasis, "has "+itoa(int64(len(d.Partitions)))+" partition(s)")
		}
		if len(d.Holders) > 0 {
			d.InUseBasis = append(d.InUseBasis, "has holders")
		}
		if len(d.Mountpoints) > 0 {
			d.InUseBasis = append(d.InUseBasis, "is mounted")
		}
		if d.InSwap {
			d.InUseBasis = append(d.InUseBasis, "is a swap device")
		}
		if d.UdevFSType != "" {
			d.InUseBasis = append(d.InUseBasis, "udev recorded filesystem type "+d.UdevFSType)
		}
		d.InUse = len(d.InUseBasis) > 0
		if !d.InUse {
			idle = append(idle, n)
		}
		devices = append(devices, d)
	}
	r.Field("devices", devices)

	switch {
	case mounts.Obs.Status != probe.StatusOK || swaps.Status != probe.StatusOK:
		return finish(scan.Unknown(reasonOf(mounts.Obs, swaps),
			"the mount table or the swap list could not be read, so whether every attached device is accounted for is unknown"))
	case udevUnreadable && len(idle) > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"a device has no partition, holder, mount or swap entry, but its udev record could not be read, so whether it carries a filesystem signature is an open question"))
	case len(idle) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"attached but unaccounted for: "+strings.Join(idle, ", ")+
				" — no partition table and no filesystem signature known to udev, no holder, no mount and no swap entry. "+
				"Whether prior-tenant data remains on it is "+remanenceStatement))
	default:
		return finish(scan.Pass(
			"every attached physical block device is accounted for by a partition, a mount, a holder relationship, a swap entry or a udev filesystem signature (" +
				itoa(int64(len(devices))) + " device(s))"))
	}
}

func deviceInUse(env *scan.Env, n string, mounts *scan.MountTable) bool {
	if ents, o := env.Files.ReadDirNames("/sys/block/"+n, 1024); o.Status == probe.StatusOK {
		for _, e := range ents {
			if e != n && strings.HasPrefix(e, n) && env.Files.Exists("/sys/block/"+n+"/"+e+"/partition") {
				return true
			}
		}
	}
	if hs, o := env.Files.ReadDirNames("/sys/block/"+n+"/holders", 64); o.Status == probe.StatusOK && len(hs) > 0 {
		return true
	}
	majmin, _ := env.Files.ReadTrimmed("/sys/block/"+n+"/dev", probe.Tiny)
	for _, m := range mounts.Entries {
		if m.MajorMinor == majmin {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// MEDIA_HEALTH_VISIBILITY
// ---------------------------------------------------------------------------

type mediaHealthVisibility struct{ meta }

type healthSignal struct {
	Path  string `json:"path"`
	Value string `json:"value,omitempty"`
	Errno string `json:"errno,omitempty"`
	Clean *bool  `json:"clean,omitempty"`
}

func (c mediaHealthVisibility) Run(ctx context.Context, env *scan.Env) scan.Result {
	var r scan.Result
	finish := func(out scan.Result) scan.Result {
		out.Observations, out.Fields = r.Observations, r.Fields
		return out
	}
	r.Field("capability_required", "CAP_SYS_ADMIN on the NVMe or SCSI character device for SMART; the NVMe admin passthrough is gated by a capability check, not by group membership")
	r.Field("remediation_note", "obtaining SMART here requires CAP_SYS_ADMIN — adding the account to the disk group would not grant it, and recommending that would be a wrong instruction")

	var signals []healthSignal
	var adverse []string
	readableCount := 0

	// ext4 error counters.
	if devs, obs := env.Files.ReadDirNames("/sys/fs/ext4", 64); obs.Status == probe.StatusOK {
		r.Add(obs)
		for _, d := range devs {
			if d == "features" {
				continue
			}
			for _, attr := range []string{"errors_count", "first_error_time", "lifetime_write_kbytes"} {
				p := "/sys/fs/ext4/" + d + "/" + attr
				v, o := env.Files.ReadTrimmed(p, probe.Tiny)
				s := healthSignal{Path: p, Value: v, Errno: o.Reason()}
				if o.Status == probe.StatusOK && attr == "errors_count" {
					readableCount++
					clean := v == "0"
					s.Clean = &clean
					if !clean {
						adverse = append(adverse, "ext4 on "+d+" has recorded "+v+" filesystem error(s)")
					}
				}
				signals = append(signals, s)
			}
		}
	}

	// Device state and md degradation.
	names, blockObs := env.Files.ReadDirNames("/sys/block", 1024)
	r.Add(blockObs)
	for _, n := range names {
		if hasAnyPrefix(n, excludedBlockPrefixes) {
			continue
		}
		if strings.HasPrefix(n, "md") {
			p := "/sys/block/" + n + "/md/degraded"
			v, o := env.Files.ReadTrimmed(p, probe.Tiny)
			s := healthSignal{Path: p, Value: v, Errno: o.Reason()}
			if o.Status == probe.StatusOK {
				readableCount++
				clean := v == "0"
				s.Clean = &clean
				if !clean {
					adverse = append(adverse, "md array "+n+" reports "+v+" degraded member(s)")
				}
			}
			signals = append(signals, s)
			continue
		}
		p := "/sys/block/" + n + "/device/state"
		v, o := env.Files.ReadTrimmed(p, probe.Tiny)
		if o.Status != probe.StatusOK {
			continue
		}
		readableCount++
		clean := v == "live" || v == "running"
		signals = append(signals, healthSignal{Path: p, Value: v, Clean: &clean})
		if !clean {
			adverse = append(adverse, "device "+n+" reports state "+v)
		}
	}
	r.Field("readable_signals", signals)

	// SMART, behind sysfs. Both tools are fallbacks and both are expected to be
	// denied or absent; the errno is the evidence.
	smartObtained := false
	var smartAttempts []string
	for _, n := range names {
		if !strings.HasPrefix(n, "nvme") && !strings.HasPrefix(n, "sd") {
			continue
		}
		obs := env.Runner.Run(ctx, probe.Spec{Name: "smartctl", Args: []string{"-H", "-j", "/dev/" + n},
			Budget: 3000000000, Purpose: "drive health (JSON only; a tool that rejects -j yields unknown, never positional parsing)"})
		r.Add(obs)
		smartAttempts = append(smartAttempts, "smartctl -H -j /dev/"+n+" -> "+string(obs.Status)+" "+obs.Reason())
		if obs.Status == probe.StatusOK && strings.Contains(obs.Value, "{") {
			smartObtained = true
			if strings.Contains(obs.Value, `"passed":false`) {
				adverse = append(adverse, "SMART health self-assessment failed for /dev/"+n)
			}
			break
		}
		if strings.HasPrefix(n, "nvme") {
			nobs := env.Runner.Run(ctx, probe.Spec{Name: "nvme", Args: []string{"smart-log", "/dev/" + n},
				Budget: 3000000000, Purpose: "NVMe health (expected to be denied without CAP_SYS_ADMIN; the errno is the evidence)"})
			r.Add(nobs)
			smartAttempts = append(smartAttempts, "nvme smart-log /dev/"+n+" -> "+string(nobs.Status)+" "+nobs.Reason())
			if nobs.Status == probe.StatusOK {
				smartObtained = true
				break
			}
		}
		break
	}
	r.Field("smart_attempts", smartAttempts)
	r.Field("smart_obtained", smartObtained)

	switch {
	case len(adverse) > 0:
		return finish(scan.Fail(scan.ReasonPolicy,
			"a readable health signal reports a problem: "+strings.Join(adverse, "; ")))
	case smartObtained:
		return finish(scan.Pass("drive health telemetry is readable by this account and reports no failure"))
	case readableCount > 0:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"SMART telemetry is not obtainable by this account ("+strings.Join(smartAttempts, "; ")+
				"), so media health itself is unknown; the "+itoa(int64(readableCount))+
				" readable adjacent signals are in evidence and are all clean, but a filesystem error counter is not media health"))
	default:
		return finish(scan.Unknown(scan.ReasonEACCES,
			"no health signal was readable at all: SMART needs a capability this account does not have, and no filesystem or device-state counter could be read"))
	}
}
