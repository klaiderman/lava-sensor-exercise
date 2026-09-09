package checks

import (
	"context"
	"strings"
	"testing"

	"lava-sensor-exercise/sensor/internal/scan"
)

// TestMachineProfileA covers the host-shaped profile: DMI present, NVMe, real
// topology, an os-release reached through a symlink.
func TestMachineProfileA(t *testing.T) {
	env := newTestEnv(t, buildProfile(t, "profileA"), nil)
	m := CollectMachine(context.Background(), env)

	if m.Vendor != "Supermicro" {
		t.Errorf("vendor = %q, want Supermicro", m.Vendor)
	}
	// The vendor's stray space is part of the value; normalising it would be
	// inventing data.
	if m.Model != "AS -3015MR-H10TNR" {
		t.Errorf("model = %q, want %q", m.Model, "AS -3015MR-H10TNR")
	}
	if m.Hostname != "f4-metal-small-chi-1" {
		t.Errorf("hostname = %q", m.Hostname)
	}
	if m.OS.Name != "Ubuntu" || m.OS.Version != "24.04" || m.OS.Kernel != "6.8.0-139-generic" {
		t.Errorf("os = %+v", m.OS)
	}
	if m.OS.Source != "/etc/os-release" {
		t.Errorf("os source = %q; the symlink at /etc/os-release must be followed deliberately", m.OS.Source)
	}
	if m.CPU.Model != "AMD EPYC 4484PX 12-Core Processor" {
		t.Errorf("cpu model = %q", m.CPU.Model)
	}
	// Four logical CPUs over two (package, core) pairs: two physical cores.
	if m.CPU.Cores != 2 || m.CPU.LogicalCPUs != 4 || m.CPU.ThreadsPerCore != 2 {
		t.Errorf("cpu = %+v, want cores 2 / logical 4 / threads 2", m.CPU)
	}
	if m.CPU.CoresBasis != "sysfs-topology" {
		t.Errorf("cores_basis = %q, want sysfs-topology", m.CPU.CoresBasis)
	}
	if want := int64(97938032) * 1024; m.MemoryBytes != want {
		t.Errorf("memory_bytes = %d, want %d", m.MemoryBytes, want)
	}

	if len(m.Storage) != 2 {
		t.Fatalf("storage has %d entries, want 2 (nvme0n1, nvme1n1); loop0 belongs in other_block_devices", len(m.Storage))
	}
	d := m.Storage[0]
	if d.Device != "nvme0n1" {
		t.Errorf("storage[0].device = %q", d.Device)
	}
	// L28/F55: sectors are always 512 bytes, never logical_block_size.
	if want := int64(1875385008) * 512; d.SizeBytes != want {
		t.Errorf("size_bytes = %d, want %d (sectors x 512, not x logical_block_size)", d.SizeBytes, want)
	}
	if d.Model != "Micron_7450_MTFDKCC960TFR" {
		t.Errorf("model = %q (reached through the device symlink)", d.Model)
	}
	if d.Transport != "nvme" {
		t.Errorf("transport = %q, want nvme (read from the subsystem link, not the kernel name)", d.Transport)
	}
	if len(d.Partitions) != 2 {
		t.Errorf("partitions = %+v, want 2", d.Partitions)
	} else if d.Partitions[1].Mountpoint != "/" {
		t.Errorf("nvme0n1p2 mountpoint = %q, want / (from mountinfo major:minor)", d.Partitions[1].Mountpoint)
	}
	foundLoop := false
	for _, o := range m.OtherBlockDevs {
		if o.Device == "loop0" {
			foundLoop = true
		}
	}
	if !foundLoop {
		t.Errorf("loop0 must be reported separately, not silently dropped")
	}

	// host_id is a keyed derivation, stable across runs, and the raw
	// machine-id never appears anywhere in the machine block.
	if len(m.HostID) != 64 {
		t.Errorf("host_id = %q, want a 64-hex digest", m.HostID)
	}
	if m.HostIDSource != "machine-id (keyed hash)" {
		t.Errorf("host_id_source = %q", m.HostIDSource)
	}
	again := CollectMachine(context.Background(), newTestEnv(t, buildProfile(t, "profileA"), nil))
	if again.HostID != m.HostID {
		t.Errorf("host_id is not stable across runs: %q vs %q", m.HostID, again.HostID)
	}

	// owner is unknown by construction here: every candidate is a vendor
	// placeholder. Naming one of them as the owner would be a guess.
	if m.Owner != scan.UnknownString {
		t.Errorf("owner = %q, want the explicit unknown; all asset tags are placeholders", m.Owner)
	}
	if len(m.OwnerCandidates) == 0 {
		t.Errorf("owner candidates must still be reported as evidence")
	}
	for _, tag := range m.AssetTags {
		if tag.Field != "chassis_asset_tag" {
			continue
		}
		if tag.Placeholder == nil {
			t.Fatalf("chassis_asset_tag was read; it must carry a placeholder verdict")
		}
		if !*tag.Placeholder {
			t.Errorf("%q must be detected as a vendor placeholder", tag.Value)
		}
	}
}

// TestMachineProfileB covers a generic minimal VM: no DMI at all, a virtio disk
// with no model, a flat CPU topology and no machine-id.
func TestMachineProfileB(t *testing.T) {
	env := newTestEnv(t, buildProfile(t, "profileB"), nil)
	m := CollectMachine(context.Background(), env)

	if m.Vendor != scan.UnknownString || m.Model != scan.UnknownString {
		t.Errorf("vendor/model = %q/%q, want the explicit unknown on a machine with no DMI", m.Vendor, m.Model)
	}
	// ENOENT (no DMI platform) and EACCES (restricted DMI) are different
	// findings and the wording must differ (L33).
	for _, u := range m.Unknowns {
		if u.Field == "vendor" && u.Reason != scan.ReasonENOENT {
			t.Errorf("vendor unknown reason = %q, want ENOENT when there is no DMI directory", u.Reason)
		}
	}
	if m.OS.Name != "Alpine Linux" {
		t.Errorf("os.name = %q", m.OS.Name)
	}
	if len(m.Storage) != 1 || m.Storage[0].Device != "vda" {
		t.Fatalf("storage = %+v, want one vda", m.Storage)
	}
	if m.Storage[0].Model != scan.UnknownString {
		t.Errorf("virtio model = %q, want the explicit unknown; the device must still be listed", m.Storage[0].Model)
	}
	if want := int64(41943040) * 512; m.Storage[0].SizeBytes != want {
		t.Errorf("size = %d, want %d", m.Storage[0].SizeBytes, want)
	}
	// No machine-id and no product_uuid: the keyed hardware-id fallback is the
	// only honest source, and it must not be random.
	if m.HostIDSource != "hardware-ids (keyed hash)" {
		t.Errorf("host_id_source = %q, want the hardware-id fallback", m.HostIDSource)
	}
	again := CollectMachine(context.Background(), newTestEnv(t, buildProfile(t, "profileB"), nil))
	if again.HostID != m.HostID {
		t.Errorf("hardware-derived host_id is not stable: %q vs %q", m.HostID, again.HostID)
	}
	// Flat topology: physical == logical, and the basis must say so.
	if m.CPU.CoresBasis == "sysfs-topology" {
		t.Errorf("cores_basis = %q, but this fixture has no sysfs topology", m.CPU.CoresBasis)
	}
}

// TestMachineProfileC covers a restricted/containerised profile.
func TestMachineProfileC(t *testing.T) {
	env := newTestEnv(t, buildProfile(t, "profileC"), nil)
	m := CollectMachine(context.Background(), env)

	if m.ExecutionContext != "container:docker" {
		t.Errorf("execution_context = %q, want container:docker", m.ExecutionContext)
	}
	if !m.DescribesHostKrn {
		t.Errorf("a containerised run must annotate that /sys-derived fields describe the host kernel")
	}
	// /sys is absent entirely here: storage must be an empty array WITH an
	// unknowns entry, never a bare empty array that reads as "no disks".
	if len(m.Storage) != 0 {
		t.Errorf("storage = %+v, want empty", m.Storage)
	}
	if !m.Unknowns.Has("storage") {
		t.Errorf("an empty storage array needs a matching unknowns entry")
	}
}

// TestNoEmptyStringsInMachine enforces B6 across every profile: an
// undeterminable string is the literal "unknown", never "".
func TestNoEmptyStringsInMachine(t *testing.T) {
	for _, p := range []string{"profileA", "profileB", "profileC"} {
		t.Run(p, func(t *testing.T) {
			m := CollectMachine(context.Background(), newTestEnv(t, buildProfile(t, p), nil))
			required := map[string]string{
				"host_id": m.HostID, "hostname": m.Hostname, "owner": m.Owner,
				"vendor": m.Vendor, "model": m.Model,
				"os.name": m.OS.Name, "os.version": m.OS.Version, "os.kernel": m.OS.Kernel,
				"cpu.model":      m.CPU.Model,
				"host_id_source": m.HostIDSource, "hostname_source": m.HostnameSource,
				"owner_source": m.OwnerSource, "vendor_source": m.VendorSource,
				"model_source": m.ModelSource, "execution_context": m.ExecutionContext,
			}
			for k, v := range required {
				if strings.TrimSpace(v) == "" {
					t.Errorf("%s is the empty string; it must be the literal %q with a *_source", k, scan.UnknownString)
				}
			}
			for _, d := range m.Storage {
				if d.Device == "" || d.Model == "" {
					t.Errorf("storage entry %+v has an empty required field", d)
				}
			}
			// AM-5: an integer 0 is only legal alongside an unknowns entry.
			if m.MemoryBytes == 0 && !m.Unknowns.Has("memory_bytes") {
				t.Errorf("memory_bytes is 0 without an unknowns entry")
			}
			if m.CPU.Cores == 0 && !m.Unknowns.Has("cpu.cores") {
				t.Errorf("cpu.cores is 0 without an unknowns entry")
			}
		})
	}
}

// TestDMIDeniedIsNotAbsent covers L01/L33: a 0000 attribute is reported as
// denied, with the attribute still listed. Mode bits only mean something on a
// real unix as a non-root uid.
func TestDMIDeniedIsNotAbsent(t *testing.T) {
	requireLinux(t)
	skipIfRoot(t)
	m := CollectMachine(context.Background(), newTestEnv(t, buildProfile(t, "profileA"), nil))
	found := false
	for _, tag := range m.AssetTags {
		if tag.Field != "product_serial" {
			continue
		}
		found = true
		if tag.Errno != "EACCES" {
			t.Errorf("product_serial errno = %q, want EACCES; denied is not absent", tag.Errno)
		}
		if tag.Value != scan.UnknownString {
			t.Errorf("a denied attribute must not carry a value, got %q", tag.Value)
		}
		if tag.Placeholder != nil {
			t.Errorf("an unread attribute must make no placeholder claim, got %v", *tag.Placeholder)
		}
	}
	if !found {
		t.Errorf("product_serial must still appear in the asset tag list when it is denied")
	}
	// The rest of DMI is still read: a denial on one attribute never blanks
	// the others (the under-claim guard).
	if m.Vendor != "Supermicro" {
		t.Errorf("vendor = %q; one denied attribute must not suppress the readable ones", m.Vendor)
	}
}

func TestPlaceholderDetection(t *testing.T) {
	for _, v := range []string{
		"", "To be filled by O.E.M.", "to be filled by oem", "Default string",
		"Not Specified", "Chassis Asset Tag", "System Asset Tag", "0123456789",
		"0000000000", "unknown", "None", "Family",
	} {
		if !isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"Supermicro", "acme-rack-14", "CHI-0042"} {
		if isPlaceholder(v) {
			t.Errorf("isPlaceholder(%q) = true, want false", v)
		}
	}
}
