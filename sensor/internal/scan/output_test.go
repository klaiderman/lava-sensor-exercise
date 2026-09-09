package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func minimalDoc() *Document {
	return &Document{
		SchemaVersion: SchemaVersion,
		CollectedAt:   "2026-09-09T12:00:00Z",
		SensorVersion: "test",
		Machine: Machine{
			HostID: "abc", HostIDSource: "s", Hostname: "h", HostnameSource: "s",
			Owner: UnknownString, OwnerSource: "none", OwnerCandidates: []OwnerCandidate{}, AssetTags: []AssetTag{},
			Vendor: "v", VendorSource: "s", Model: "m", ModelSource: "s",
			OS:          OS{Name: "n", Version: "1", Kernel: "k", Source: "s", KernelSource: "s"},
			CPU:         CPU{Model: "c", Cores: 4, Source: "s", CoresBasis: "sysfs-topology"},
			MemoryBytes: 1024, MemorySource: "s",
			Storage:        []StorageDevice{{Device: "sda", Model: "m", SizeBytes: 512, Partitions: []Partition{}, Holders: []string{}, Slaves: []string{}}},
			OtherBlockDevs: []StorageDevice{},
			Unknowns:       Unknowns{},
		},
		Findings: []Finding{{
			Category: "TEST_CATEGORY", CheckID: "A_CHECK", Status: StatusPass, Severity: SeverityInfo,
			Title: "t", Evidence: Evidence{Detail: "d"}, CollectedAt: "2026-09-09T12:00:00Z", Impact: SeverityLow,
		}},
		Scan: ScanMeta{StartedAt: "2026-09-09T12:00:00Z", Degradations: []string{}, SelfCheck: "pass"},
	}
}

func TestSelfCheckAcceptsAValidDocument(t *testing.T) {
	b, err := Encode(minimalDoc())
	if err != nil {
		t.Fatal(err)
	}
	if fails := SelfCheck(b); len(fails) != 0 {
		t.Fatalf("self-check rejected a valid document: %v", fails)
	}
}

func TestSelfCheckCatchesEachContractViolation(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Document)
		pointer string
	}{
		{"missing reason on fail", func(d *Document) {
			d.Findings[0].Status = StatusFail
			d.Findings[0].Reason = ""
		}, "/findings/0/reason"},
		{"missing reason on unknown", func(d *Document) {
			d.Findings[0].Status = StatusUnknown
			d.Findings[0].Reason = ""
		}, "/findings/0/reason"},
		{"bad status", func(d *Document) { d.Findings[0].Status = "maybe" }, "/findings/0/status"},
		{"bad severity", func(d *Document) { d.Findings[0].Severity = "catastrophic" }, "/findings/0/severity"},
		{"lowercase category", func(d *Document) { d.Findings[0].Category = "lower" }, "/findings/0/category"},
		{"empty title", func(d *Document) { d.Findings[0].Title = "" }, "/findings/0/title"},
		{"bad timestamp", func(d *Document) { d.Findings[0].CollectedAt = "yesterday" }, "/findings/0/collected_at"},
		{"empty machine string", func(d *Document) { d.Machine.Vendor = "" }, "/machine/vendor"},
		{"zero memory without an unknowns entry", func(d *Document) { d.Machine.MemoryBytes = 0 }, "/machine/memory_bytes"},
		{"empty storage model", func(d *Document) { d.Machine.Storage[0].Model = "" }, "/machine/storage/0/model"},
		{"wrong schema version", func(d *Document) { d.SchemaVersion = "2" }, "/schema_version"},
		{"duplicate check_id", func(d *Document) {
			d.Findings = append(d.Findings, d.Findings[0])
		}, "/findings/1/check_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := minimalDoc()
			tc.mutate(doc)
			b, err := Encode(doc)
			if err != nil {
				t.Fatal(err)
			}
			fails := SelfCheck(b)
			found := false
			for _, f := range fails {
				if strings.HasPrefix(f, tc.pointer+":") {
					found = true
				}
			}
			if !found {
				t.Errorf("self-check missed %s; failures were %v", tc.pointer, fails)
			}
		})
	}
}

// A zero integer is legal only together with an unknowns entry naming the field.
func TestZeroIntegerNeedsAnUnknownsEntry(t *testing.T) {
	doc := minimalDoc()
	doc.Machine.MemoryBytes = 0
	doc.Machine.Unknowns.Add("memory_bytes", ReasonEACCES, "/proc/meminfo:MemTotal")
	b, _ := Encode(doc)
	if fails := SelfCheck(b); len(fails) != 0 {
		t.Errorf("a marked zero must be accepted: %v", fails)
	}
}

// Two encodings of the same document are byte-identical: struct order, sorted
// unknown keys, insertion-ordered evidence extras and pre-formatted timestamps.
func TestEncodingIsDeterministic(t *testing.T) {
	doc := minimalDoc()
	doc.Machine.Unknowns.Add("z_field", "ENOENT", "a", "b")
	doc.Machine.Unknowns.Add("a_field", "EACCES", "c")
	doc.Findings[0].Evidence.Fields = []Field{F("zeta", 1), F("alpha", "two"), F("nested", map[string]string{"b": "2", "a": "1"})}

	first, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := Encode(doc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("encoding is not deterministic on iteration %d", i)
		}
	}
	// Evidence extras keep insertion order; unknowns are key-sorted.
	s := string(first)
	if strings.Index(s, `"zeta"`) > strings.Index(s, `"alpha"`) {
		t.Errorf("evidence extras must keep insertion order")
	}
	if strings.Index(s, `"a_field"`) > strings.Index(s, `"z_field"`) {
		t.Errorf("unknowns must be key-sorted")
	}
}

// HTML escaping is off so config text stays literal in the artifact.
func TestEncodingDoesNotEscapeHTML(t *testing.T) {
	doc := minimalDoc()
	doc.Findings[0].Evidence.Detail = `AllowUsers a<b>c & d`
	b, err := Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `a<b>c & d`) {
		t.Errorf("angle brackets and ampersands must survive verbatim:\n%s", b)
	}
}

func TestUnknownsMarshalAsAnObject(t *testing.T) {
	var u Unknowns
	u.Add("b", "ENOENT", "x")
	u.Add("a", "EACCES", "y")
	u.Add("a", "IGNORED", "z") // a field is recorded once
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]struct {
		Reason       string   `json:"reason"`
		SourcesTried []string `json:"sources_tried"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unknowns is not a JSON object: %v (%s)", err, b)
	}
	if len(m) != 2 || m["a"].Reason != "EACCES" || len(m["a"].SourcesTried) != 1 {
		t.Errorf("unknowns = %s", b)
	}
}

func TestEvidenceAlwaysHasAnObservationsArray(t *testing.T) {
	b, err := json.Marshal(Evidence{})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"observations":[]}` {
		t.Errorf("empty evidence = %s, want an explicit empty observations array", b)
	}
}
