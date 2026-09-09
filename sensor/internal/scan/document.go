// Package scan holds the output contract, the check interface, the engine loop
// and the single place where a raw check Result becomes a reported Finding.
package scan

import (
	"bytes"
	"encoding/json"
	"sort"
)

// SchemaVersion is the literal value the brief's output contract specifies.
const SchemaVersion = "1"

// Status is the reported verdict of a check.
type Status string

// The three statuses. There is never a fourth, and an unset verdict never
// defaults to pass (L34).
const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

// Severity levels permitted by the output contract.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Document is the whole findings.json. Struct order is the output order:
// encoding/json preserves declaration order for structs, which is half of why
// the artifact is byte-stable between runs (L47, R5-F30).
type Document struct {
	SchemaVersion string    `json:"schema_version"`
	CollectedAt   string    `json:"collected_at"`
	SensorVersion string    `json:"sensor_version,omitempty"`
	Machine       Machine   `json:"machine"`
	Findings      []Finding `json:"findings"`
	Scan          ScanMeta  `json:"scan"`
}

// ScanMeta is a run-level extra. Run-level errors live here and never inside
// the findings array (L34).
type ScanMeta struct {
	StartedAt      string   `json:"started_at"`
	DurationMS     int64    `json:"duration_ms"`
	DeadlineMS     int64    `json:"deadline_ms"`
	ChecksRun      int64    `json:"checks_run"`
	BudgetCut      bool     `json:"budget_cut"`
	BudgetCutCount int64    `json:"budget_cut_count"`
	EUID           int64    `json:"euid"`
	Degradations   []string `json:"degradations"`
	SelfCheck      string   `json:"self_check"`
	SelfCheckFails []string `json:"self_check_failures,omitempty"`
}

// Finding is one registered check's single result for this run.
type Finding struct {
	Category    string   `json:"category"`
	CheckID     string   `json:"check_id"`
	Status      Status   `json:"status"`
	Severity    string   `json:"severity"`
	Title       string   `json:"title"`
	Reason      string   `json:"reason,omitempty"`
	Evidence    Evidence `json:"evidence"`
	CollectedAt string   `json:"collected_at"`
	Impact      string   `json:"impact"`
	DurationMS  int64    `json:"duration_ms"`
	// EntailmentViolation is set when a check wrote a completeness claim its
	// own observations did not support. The finding is downgraded, and this
	// flag makes the fact auditable from the artifact alone.
	EntailmentViolation bool `json:"entailment_violation,omitempty"`
}

// Field is one ordered extra key in an evidence object. Insertion order is the
// output order, so evidence stays deterministic without using a map.
type Field struct {
	Key   string
	Value any
}

// F builds an evidence field.
func F(key string, value any) Field { return Field{Key: key, Value: value} }

// Evidence is what someone needs in order to act on the finding, and to re-run
// the observation by hand and get the same bytes. It records the observation,
// never the conclusion (EVIDENCE_MODEL, D2).
type Evidence struct {
	Detail       string
	Observations []ObsEvidence
	Fields       []Field
}

// MarshalJSON emits detail, then observations, then the ordered extras.
func (e Evidence) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	first := true
	write := func(k string, v any) error {
		b, err := marshalDeterministic(v)
		if err != nil {
			return err
		}
		if !first {
			buf.WriteByte(',')
		}
		first = false
		kb, err := marshalDeterministic(k)
		if err != nil {
			return err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(b)
		return nil
	}
	if e.Detail != "" {
		if err := write("detail", e.Detail); err != nil {
			return nil, err
		}
	}
	obs := e.Observations
	if obs == nil {
		obs = []ObsEvidence{}
	}
	if err := write("observations", obs); err != nil {
		return nil, err
	}
	seen := map[string]bool{"detail": true, "observations": true}
	for _, f := range e.Fields {
		if seen[f.Key] {
			continue
		}
		seen[f.Key] = true
		if err := write(f.Key, f.Value); err != nil {
			return nil, err
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// ObsEvidence is the shape every probe.Observation is rendered into by the one
// shared evidence builder in finalize.go.
type ObsEvidence struct {
	Source          string   `json:"source"`
	ObservationType string   `json:"observation_type,omitempty"`
	Status          string   `json:"status"`
	Reason          string   `json:"reason,omitempty"`
	Value           string   `json:"value,omitempty"`
	ValueTruncated  bool     `json:"value_truncated_in_evidence,omitempty"`
	Errno           string   `json:"errno,omitempty"`
	ExitCode        *int64   `json:"exit_code,omitempty"`
	Signal          string   `json:"signal,omitempty"`
	TimedOut        bool     `json:"timed_out,omitempty"`
	Truncated       bool     `json:"truncated,omitempty"`
	Bytes           int64    `json:"bytes,omitempty"`
	DurationMS      int64    `json:"duration_ms"`
	LoadBearing     bool     `json:"load_bearing,omitempty"`
	AbsenceProven   bool     `json:"absence_proven,omitempty"`
	Detail          string   `json:"detail,omitempty"`
	Command         []string `json:"command,omitempty"`
	BinaryPath      string   `json:"binary_resolved_path,omitempty"`
	StdoutBytes     int64    `json:"stdout_bytes,omitempty"`
	StderrBytes     int64    `json:"stderr_bytes,omitempty"`
	StderrExcerpt   string   `json:"stderr_excerpt,omitempty"`
	WaitDelay       bool     `json:"wait_delay_expired,omitempty"`
	Exists          *bool    `json:"exists,omitempty"`
	FileType        string   `json:"file_type,omitempty"`
	Mode            *int64   `json:"mode,omitempty"`
	UID             *int64   `json:"uid,omitempty"`
	GID             *int64   `json:"gid,omitempty"`
	Size            *int64   `json:"size,omitempty"`
	SymlinkTarget   string   `json:"symlink_target,omitempty"`
	ResolvedPath    string   `json:"resolved_path,omitempty"`
	Root            string   `json:"root,omitempty"`
	EntriesScanned  int64    `json:"entries_scanned,omitempty"`
	BudgetExhausted string   `json:"budget_exhausted,omitempty"`
	CrossedMounts   bool     `json:"crossed_mounts,omitempty"`
	UnreadableDirs  []string `json:"unreadable_dirs,omitempty"`
	DirsPruned      []string `json:"dirs_pruned,omitempty"`
}

// Machine is part one of the output: describe the machine.
//
// Every field carries a sibling *_source. Unknown strings are the literal
// "unknown"; unknown integers are 0 together with an entry in Unknowns. No
// field is ever the empty string or a guess (B6, AM-5).
type Machine struct {
	HostID           string           `json:"host_id"`
	HostIDSource     string           `json:"host_id_source"`
	HostIDCaveat     string           `json:"host_id_caveat,omitempty"`
	Hostname         string           `json:"hostname"`
	HostnameSource   string           `json:"hostname_source"`
	Owner            string           `json:"owner"`
	OwnerSource      string           `json:"owner_source"`
	OwnerCandidates  []OwnerCandidate `json:"owner_candidates"`
	AssetTags        []AssetTag       `json:"asset_tags"`
	Vendor           string           `json:"vendor"`
	VendorSource     string           `json:"vendor_source"`
	Model            string           `json:"model"`
	ModelSource      string           `json:"model_source"`
	OS               OS               `json:"os"`
	CPU              CPU              `json:"cpu"`
	MemoryBytes      int64            `json:"memory_bytes"`
	MemorySource     string           `json:"memory_source"`
	SwapTotalBytes   int64            `json:"swap_total_bytes"`
	Storage          []StorageDevice  `json:"storage"`
	StorageSource    string           `json:"storage_source"`
	OtherBlockDevs   []StorageDevice  `json:"other_block_devices"`
	Firmware         Firmware         `json:"firmware"`
	ExecutionContext string           `json:"execution_context"`
	ExecContextSrc   string           `json:"execution_context_source"`
	DescribesHostKrn bool             `json:"describes_host_kernel,omitempty"`
	Unknowns         Unknowns         `json:"unknowns"`
}

// OS is the userland/kernel pair. In a container these are two different
// systems and must not be presented as one (L45).
type OS struct {
	Name              string `json:"name"`
	Version           string `json:"version"`
	Kernel            string `json:"kernel"`
	VersionPretty     string `json:"version_pretty,omitempty"`
	ID                string `json:"id,omitempty"`
	IDLike            string `json:"id_like,omitempty"`
	Source            string `json:"source"`
	KernelSource      string `json:"kernel_source"`
	KernelBootDefault string `json:"kernel_boot_default,omitempty"`
}

// CPU carries the required model/cores plus the basis the core count rests on.
type CPU struct {
	Model          string `json:"model"`
	Cores          int64  `json:"cores"`
	LogicalCPUs    int64  `json:"logical_cpus"`
	Sockets        int64  `json:"sockets"`
	ThreadsPerCore int64  `json:"threads_per_core"`
	CoresBasis     string `json:"cores_basis"`
	Vendor         string `json:"cpu_vendor,omitempty"`
	Source         string `json:"source"`
}

// StorageDevice is one whole block device. The device node is never opened.
type StorageDevice struct {
	Device            string      `json:"device"`
	Model             string      `json:"model"`
	SizeBytes         int64       `json:"size_bytes"`
	DevicePath        string      `json:"device_path"`
	ModelSource       string      `json:"model_source"`
	SizeSource        string      `json:"size_source"`
	Transport         string      `json:"transport,omitempty"`
	Rotational        *bool       `json:"rotational,omitempty"`
	Removable         *bool       `json:"removable,omitempty"`
	LogicalBlockSize  int64       `json:"logical_block_size,omitempty"`
	PhysicalBlockSize int64       `json:"physical_block_size,omitempty"`
	WWID              string      `json:"wwid,omitempty"`
	FirmwareRev       string      `json:"firmware_rev,omitempty"`
	Scheduler         string      `json:"scheduler,omitempty"`
	WriteCache        string      `json:"write_cache,omitempty"`
	State             string      `json:"state,omitempty"`
	Filesystem        string      `json:"filesystem,omitempty"`
	FilesystemSource  string      `json:"filesystem_source,omitempty"`
	Partitions        []Partition `json:"partitions"`
	Holders           []string    `json:"holders"`
	Slaves            []string    `json:"slaves"`
	Class             string      `json:"class,omitempty"`
}

// Partition is one partition of a whole disk, from sysfs plus the udev database.
type Partition struct {
	Name       string `json:"name"`
	SizeBytes  int64  `json:"size_bytes"`
	FSTypeUdev string `json:"fstype_udev,omitempty"`
	Mountpoint string `json:"mountpoint,omitempty"`
}

// Firmware carries the DMI extras. These are firmware-settable values: they
// identify, they do not attest.
type Firmware struct {
	BoardVendor  string `json:"board_vendor,omitempty"`
	BoardName    string `json:"board_name,omitempty"`
	BoardVersion string `json:"board_version,omitempty"`
	BIOSVendor   string `json:"bios_vendor,omitempty"`
	BIOSVersion  string `json:"bios_version,omitempty"`
	BIOSDate     string `json:"bios_date,omitempty"`
	ChassisType  string `json:"chassis_type,omitempty"`
	ProductSKU   string `json:"product_sku,omitempty"`
	ProductFamly string `json:"product_family,omitempty"`
	Source       string `json:"source"`
}

// OwnerCandidate is evidence about who the machine might belong to. It is never
// promoted to owner: inferring a customer from a hostname pattern is a guess.
type OwnerCandidate struct {
	Value      string `json:"value"`
	Source     string `json:"source"`
	Confidence string `json:"confidence"`
}

// AssetTag is a DMI tag as observed, with whether it is a vendor placeholder.
// Placeholder is a pointer because "we could not read this tag" and "we read it
// and it is not a placeholder" are different facts.
type AssetTag struct {
	Field       string `json:"field"`
	Value       string `json:"value"`
	Placeholder *bool  `json:"placeholder,omitempty"`
	Source      string `json:"source"`
	Errno       string `json:"errno,omitempty"`
}

// UnknownEntry says why one machine field could not be determined and what was
// tried. An integer 0 is only legal alongside one of these (AM-5).
type UnknownEntry struct {
	Field        string   `json:"-"`
	Reason       string   `json:"reason"`
	SourcesTried []string `json:"sources_tried"`
}

// Unknowns marshals as a JSON object keyed by field name, sorted for
// determinism.
type Unknowns []UnknownEntry

// Add records an unknown field once.
func (u *Unknowns) Add(field, reason string, sources ...string) {
	for _, e := range *u {
		if e.Field == field {
			return
		}
	}
	if sources == nil {
		sources = []string{}
	}
	*u = append(*u, UnknownEntry{Field: field, Reason: reason, SourcesTried: sources})
}

// Has reports whether a field was recorded as unknown.
func (u Unknowns) Has(field string) bool {
	for _, e := range u {
		if e.Field == field {
			return true
		}
	}
	return false
}

// MarshalJSON renders the list as an object with sorted keys.
func (u Unknowns) MarshalJSON() ([]byte, error) {
	entries := append([]UnknownEntry(nil), u...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Field < entries[j].Field })
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := marshalDeterministic(e.Field)
		if err != nil {
			return nil, err
		}
		v, err := marshalDeterministic(struct {
			Reason       string   `json:"reason"`
			SourcesTried []string `json:"sources_tried"`
		}{e.Reason, e.SourcesTried})
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalDeterministic encodes a value with HTML escaping disabled and without
// the trailing newline json.Encoder appends.
func marshalDeterministic(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// UnknownString is the literal every undeterminable string field carries.
const UnknownString = "unknown"
