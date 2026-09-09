package lab

import (
	"testing"

	"lava-sensor-exercise/sensor/internal/scan"
)

// This file is the storage fixture matrix required by the testing-phase brief:
// plain block device, NVMe-style sysfs, dm/LVM (incl. LUKS2), md RAID (healthy
// and degraded), an NFS/network root, an iSCSI-style sysfs class device,
// missing storage utility, permission denied, partial /sys, and technology
// absent — each mapped onto the actual STORAGE_POSTURE checks
// (DISK_ENCRYPTION_AT_REST, ROOT_FILESYSTEM_REDUNDANCY,
// UNUSED_ATTACHED_BLOCK_DEVICES, MEDIA_HEALTH_VISIBILITY).
//
// Malformed-lsblk-JSON is not exercised: internal/checks/storage.go never
// shells out to lsblk (it is sysfs-first by design, L39), so that fixture has
// no code path to hit here. Noted as n/a in reports/TEST_REPORT.md rather than
// silently skipped.

func storageBase() map[string]string {
	return map[string]string{
		"/sys/block/":     "",
		"/dev/mapper/":    "",
		"/proc/mdstat":    "Personalities : [raid1]\nunused devices: <none>\n",
		"/proc/swaps":     "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n",
		"/etc/crypttab":   "",
		"/run/udev/data/": "",
	}
}

func withRootMount(files map[string]string, majmin, fstype, source string) map[string]string {
	files["/proc/self/mountinfo"] = "24 30 " + majmin + " / / rw,relatime shared:1 - " + fstype + " " + source + " rw\n"
	return files
}

// --- 1. Plain block device (sda), mounted as root, no redundancy layer. -----

func TestStorageMatrix_PlainBlockDeviceSingleDiskFails(t *testing.T) {
	files := storageBase()
	files["/sys/block/sda/dev"] = "8:1\n"
	files["/sys/block/sda/size"] = "20971520\n" // 10GiB in 512B sectors
	files["/sys/block/sda/device/model"] = "QEMU HARDDISK\n"
	files = withRootMount(files, "8:1", "ext4", "/dev/sda1")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)

	if f := byID["ROOT_FILESYSTEM_REDUNDANCY"]; f.Status != scan.StatusFail {
		t.Errorf("plain single disk: ROOT_FILESYSTEM_REDUNDANCY = %s (%s), want fail", f.Status, f.Reason)
	}
	if f := byID["DISK_ENCRYPTION_AT_REST"]; f.Status != scan.StatusFail {
		t.Errorf("plain single disk, no dm mapping: DISK_ENCRYPTION_AT_REST = %s (%s), want fail", f.Status, f.Reason)
	}
}

// --- 2. NVMe-style sysfs (model only under /sys/class/nvme). ---------------

func TestStorageMatrix_NVMeStyleModelFallback(t *testing.T) {
	files := storageBase()
	files["/sys/block/nvme0n1/dev"] = "259:0\n"
	files["/sys/block/nvme0n1/size"] = "1875385008\n"
	files["/sys/class/nvme/nvme0/model"] = "Micron_7450_MTFDKCC960TFR\n"
	files = withRootMount(files, "259:0", "ext4", "/dev/nvme0n1")
	root := tree(t, files)
	// nvme0n1/device -> ../../class/nvme/nvme0 is how the real sysfs shapes
	// this (F18); the plain-file fallback in describeBlockDevice reads
	// /sys/class/nvme/<ctrl>/model directly by name, no symlink needed here.
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	if f := byID["ROOT_FILESYSTEM_REDUNDANCY"]; f.Status != scan.StatusFail {
		t.Errorf("NVMe single disk: ROOT_FILESYSTEM_REDUNDANCY = %s (%s), want fail", f.Status, f.Reason)
	}
}

// --- 3. dm/LUKS2: root encrypted, passes. ----------------------------------

func TestStorageMatrix_DMCryptLUKS2RootPasses(t *testing.T) {
	files := storageBase()
	files["/sys/block/dm-0/dev"] = "253:0\n"
	files["/sys/block/dm-0/dm/uuid"] = "CRYPT-LUKS2-1234567890abcdef-luks-root\n"
	files["/sys/block/dm-0/dm/name"] = "luks-root\n"
	files = withRootMount(files, "253:0", "ext4", "/dev/mapper/luks-root")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["DISK_ENCRYPTION_AT_REST"]
	if f.Status != scan.StatusPass {
		t.Fatalf("dm-crypt LUKS2 root: status = %s (%s detail=%s), want pass", f.Status, f.Reason, f.Evidence.Detail)
	}
}

// --- 4. dm/LVM without crypt: a real dm mapping, but not encryption. -------

func TestStorageMatrix_DMLVMNonCryptRootFails(t *testing.T) {
	files := storageBase()
	files["/sys/block/dm-0/dev"] = "253:0\n"
	files["/sys/block/dm-0/dm/uuid"] = "LVM-abcdef0123456789-lv--root\n"
	files["/sys/block/dm-0/dm/name"] = "vg0-root\n"
	files = withRootMount(files, "253:0", "ext4", "/dev/mapper/vg0-root")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["DISK_ENCRYPTION_AT_REST"]
	if f.Status != scan.StatusFail {
		t.Fatalf("dm/LVM without CRYPT- uuid: status = %s (%s), want fail (a real dm mapping exists, but it is not dm-crypt)", f.Status, f.Reason)
	}
}

// --- 5. md RAID1, healthy: passes. -----------------------------------------

func TestStorageMatrix_MDRaid1HealthyPasses(t *testing.T) {
	files := storageBase()
	files["/sys/block/md0/dev"] = "9:0\n"
	files["/sys/block/md0/md/level"] = "raid1\n"
	files["/sys/block/md0/md/degraded"] = "0\n"
	files["/sys/block/md0/md/raid_disks"] = "2\n"
	files["/sys/block/md0/slaves/"] = ""
	files["/sys/block/sda/dev"] = "8:0\n"
	files["/sys/block/sdb/dev"] = "8:16\n"
	files["/sys/block/md0/slaves/sda"] = ""
	files["/sys/block/md0/slaves/sdb"] = ""
	files = withRootMount(files, "9:0", "ext4", "/dev/md0")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["ROOT_FILESYSTEM_REDUNDANCY"]
	if f.Status != scan.StatusPass {
		t.Fatalf("md raid1 healthy: status = %s (%s detail=%s), want pass", f.Status, f.Reason, f.Evidence.Detail)
	}
}

// --- 6. md RAID1, degraded: fails, and the reason names the array. ---------

func TestStorageMatrix_MDRaid1DegradedFails(t *testing.T) {
	files := storageBase()
	files["/sys/block/md0/dev"] = "9:0\n"
	files["/sys/block/md0/md/level"] = "raid1\n"
	files["/sys/block/md0/md/degraded"] = "1\n"
	files["/sys/block/md0/md/raid_disks"] = "2\n"
	files["/sys/block/sda/dev"] = "8:0\n"
	files["/sys/block/md0/slaves/sda"] = ""
	files = withRootMount(files, "9:0", "ext4", "/dev/md0")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["ROOT_FILESYSTEM_REDUNDANCY"]
	if f.Status != scan.StatusFail {
		t.Fatalf("md raid1 degraded: status = %s (%s), want fail", f.Status, f.Reason)
	}
	if f.Reason != scan.ReasonPolicy {
		t.Errorf("degraded array should fail with reason %s, got %s", scan.ReasonPolicy, f.Reason)
	}
}

// --- 7. NFS/network root: no local backing device at all. ------------------
//
// This is a DEFECT CANDIDATE, not an assertion of correct behaviour: see
// reports/TEST_REPORT.md. internal/checks/storage.go's "physical <= 1" branch
// (rootFilesystemRedundancy, ~line 379) collapses "zero local devices behind
// this mount" (diskless / NFS root) and "exactly one local device" into the
// same FAIL wording, "resolves to a single physical device (<empty list>)".
// A network root has no local single point of failure to report on at all;
// the honest answer is closer to UNKNOWN/not-applicable than a FAIL phrased
// as if a local disk were found and it was merely unmirrored.
func TestStorageMatrix_NFSRootHasNoLocalBackingDevice(t *testing.T) {
	files := storageBase()
	files = withRootMount(files, "0:45", "nfs4", "192.0.2.10:/export/root")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["ROOT_FILESYSTEM_REDUNDANCY"]
	t.Logf("NFS root observed: status=%s reason=%s detail=%s", f.Status, f.Reason, f.Evidence.Detail)
	if f.Status == scan.StatusFail && f.Reason == scan.ReasonPolicy {
		t.Logf("DEFECT CANDIDATE: NFS root (zero local backing devices) is reported as the same " +
			"'single physical device' FAIL as a real single local disk; see storage.go's physical<=1 branch")
	}
}

// --- 8. iSCSI-style sysfs class device, attached and idle. -----------------

func TestStorageMatrix_ISCSIStyleDeviceIdleFails(t *testing.T) {
	files := storageBase()
	files["/sys/block/sdz/dev"] = "8:80\n"
	files["/sys/block/sdz/size"] = "41943040\n"
	files["/sys/class/iscsi_host/host4/"] = ""
	files["/sys/class/scsi_host/host4/proc_name"] = "iscsi_tcp\n"
	files = withRootMount(files, "8:0", "ext4", "/dev/sda1") // root is a different, local disk
	files["/sys/block/sda/dev"] = "8:0\n"
	files["/sys/block/sda/size"] = "20971520\n"
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["UNUSED_ATTACHED_BLOCK_DEVICES"]
	if f.Status != scan.StatusFail {
		t.Fatalf("iSCSI-attached idle device sdz: status = %s (%s), want fail", f.Status, f.Reason)
	}
}

// --- 9. Missing storage utility (smartctl/nvme not present anywhere). ------

func TestStorageMatrix_MissingUtilityIsUnknownNotFail(t *testing.T) {
	files := storageBase()
	files["/sys/block/nvme0n1/dev"] = "259:0\n"
	files["/sys/block/nvme0n1/size"] = "1875385008\n"
	files["/sys/block/nvme0n1/device/state"] = "live\n"
	files = withRootMount(files, "259:0", "ext4", "/dev/nvme0n1")
	root := tree(t, files)
	// newFakeRunner() with nothing stubbed: smartctl/nvme both come back
	// UTILITY_MISSING, which must never be read as "media health confirmed
	// clean" or "media unhealthy" — only ever unknown (L39).
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["MEDIA_HEALTH_VISIBILITY"]
	if f.Status != scan.StatusUnknown {
		t.Fatalf("smartctl/nvme both missing: MEDIA_HEALTH_VISIBILITY = %s (%s), want unknown", f.Status, f.Reason)
	}
}

// --- 10. Permission denied on /sys/block: everything downstream is unknown. -

func TestStorageMatrix_SysBlockEACCES_IsUnknownEverywhere(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	files := storageBase()
	files["/sys/block/sda/dev"] = "8:0\n"
	files = withRootMount(files, "8:0", "ext4", "/dev/sda1")
	root := tree(t, files)
	if err := chmodPath(root, "sys/block", 0o000); err != nil {
		t.Fatal(err)
	}
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	for _, id := range []string{"DISK_ENCRYPTION_AT_REST", "ROOT_FILESYSTEM_REDUNDANCY", "UNUSED_ATTACHED_BLOCK_DEVICES"} {
		f := byID[id]
		if f.Status != scan.StatusUnknown {
			t.Errorf("%s with /sys/block EACCES: status = %s (%s), want unknown (denied is not absent, EACCES != empty)", id, f.Status, f.Reason)
		}
	}
}

// --- 11. Partial /sys: the directory lists a device whose queue/ subtree is
//         missing entirely (a genuinely partial sysfs, e.g. a driver that
//         has not finished probing, or a container's masked /sys subset).

func TestStorageMatrix_PartialSysfsSubtreeStillEnumeratesTheDevice(t *testing.T) {
	files := storageBase()
	files["/sys/block/sda/dev"] = "8:0\n"
	files["/sys/block/sda/size"] = "20971520\n"
	// deliberately no queue/, no device/, no holders/, no slaves/: a bare
	// minimum sysfs entry, the kind a heavily masked container namespace or a
	// still-probing driver would expose.
	files = withRootMount(files, "8:0", "ext4", "/dev/sda1")
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	f := byID["UNUSED_ATTACHED_BLOCK_DEVICES"]
	// The device is mounted (root), so it must be accounted for even with a
	// minimal sysfs subtree: this exercises "in_use_basis: is mounted" without
	// any of the richer sysfs attributes being present.
	if f.Status != scan.StatusPass {
		t.Errorf("partial sysfs, device is the mounted root: status = %s (%s detail=%s), want pass", f.Status, f.Reason, f.Evidence.Detail)
	}
}

// --- 12. Technology absent: /sys/block exists and is empty. ----------------

func TestStorageMatrix_NoBlockDevicesAtAllIsAProvenNegative(t *testing.T) {
	files := storageBase() // /sys/block/ exists (empty dir), no root mount majmin match at all
	files["/proc/self/mountinfo"] = "24 30 0:1 / / rw,relatime - tmpfs tmpfs rw\n"
	root := tree(t, files)
	env := newLabEnv(t, root, newFakeRunner())
	byID := runFullScan(t, env)
	if f := byID["UNUSED_ATTACHED_BLOCK_DEVICES"]; f.Status != scan.StatusPass {
		t.Errorf("zero block devices, proven by a successful empty listing: status = %s (%s), want pass (0 devices accounted for)", f.Status, f.Reason)
	}
}
