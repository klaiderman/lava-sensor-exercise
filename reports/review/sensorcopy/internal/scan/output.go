package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Encode renders the document deterministically: struct field order, HTML
// escaping off so config text stays literal, two-space indent, one trailing
// newline. Two runs against the same inputs differ only in timestamps (L47).
func Encode(doc *Document) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Write writes the artifact. The document is fully rendered in memory first, so
// a failure never leaves a half-written file, and nothing but the --out path is
// ever created (Invariant 1: read-only outside the output file).
func Write(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

var (
	upperSnake = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	statusEnum = map[string]bool{"pass": true, "fail": true, "unknown": true}
	sevEnum    = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}
)

// SelfCheck mirrors task/derived/finding.schema.json in stdlib, so the shipped
// binary carries no schema machinery yet still refuses to lie about its own
// output. It returns the JSON pointers that failed.
//
// The full JSON Schema 2020-12 validation runs in tests and at the release
// gate; this is the runtime floor (LD-6, L48).
func SelfCheck(b []byte) []string {
	var root any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return []string{"/: document is not valid JSON: " + err.Error()}
	}
	var fails []string
	add := func(ptr, msg string) { fails = append(fails, ptr+": "+msg) }

	doc, ok := root.(map[string]any)
	if !ok {
		return []string{"/: document is not a JSON object"}
	}
	if v, ok := doc["schema_version"].(string); !ok || v != SchemaVersion {
		add("/schema_version", `must be the string "1"`)
	}
	requireRFC3339(doc, "collected_at", "/collected_at", add)

	machine, ok := doc["machine"].(map[string]any)
	if !ok {
		add("/machine", "missing or not an object")
	} else {
		for _, k := range []string{"host_id", "hostname", "owner", "vendor", "model"} {
			v, ok := machine[k].(string)
			switch {
			case !ok:
				add("/machine/"+k, "missing or not a string")
			case v == "":
				add("/machine/"+k, `is the empty string; an undeterminable value must be the literal "unknown"`)
			}
		}
		if osObj, ok := machine["os"].(map[string]any); !ok {
			add("/machine/os", "missing or not an object")
		} else {
			for _, k := range []string{"name", "version", "kernel"} {
				if v, ok := osObj[k].(string); !ok || v == "" {
					add("/machine/os/"+k, "missing, not a string, or empty")
				}
			}
		}
		if cpu, ok := machine["cpu"].(map[string]any); !ok {
			add("/machine/cpu", "missing or not an object")
		} else {
			if v, ok := cpu["model"].(string); !ok || v == "" {
				add("/machine/cpu/model", "missing, not a string, or empty")
			}
			requireInteger(cpu, "cores", "/machine/cpu/cores", add)
		}
		requireInteger(machine, "memory_bytes", "/machine/memory_bytes", add)
		storage, ok := machine["storage"].([]any)
		if !ok {
			add("/machine/storage", "missing or not an array")
		}
		for i, it := range storage {
			ptr := fmt.Sprintf("/machine/storage/%d", i)
			d, ok := it.(map[string]any)
			if !ok {
				add(ptr, "not an object")
				continue
			}
			for _, k := range []string{"device", "model"} {
				if v, ok := d[k].(string); !ok || v == "" {
					add(ptr+"/"+k, "missing, not a string, or empty")
				}
			}
			requireInteger(d, "size_bytes", ptr+"/size_bytes", add)
		}
		// AM-5: an integer 0 is only legal alongside an unknowns entry.
		unknowns, _ := machine["unknowns"].(map[string]any)
		if n, ok := machine["memory_bytes"].(json.Number); ok && n.String() == "0" {
			if _, marked := unknowns["memory_bytes"]; !marked {
				add("/machine/memory_bytes", "is 0 without a matching /machine/unknowns entry")
			}
		}
	}

	findings, ok := doc["findings"].([]any)
	if !ok {
		add("/findings", "missing or not an array")
	}
	seen := map[string]bool{}
	for i, it := range findings {
		ptr := fmt.Sprintf("/findings/%d", i)
		f, ok := it.(map[string]any)
		if !ok {
			add(ptr, "not an object")
			continue
		}
		cat, _ := f["category"].(string)
		if !upperSnake.MatchString(cat) {
			add(ptr+"/category", "missing or not UPPER_SNAKE_CASE")
		}
		id, _ := f["check_id"].(string)
		if id == "" {
			add(ptr+"/check_id", "missing or empty")
		} else if seen[id] {
			add(ptr+"/check_id", "duplicate check_id "+id)
		}
		seen[id] = true
		status, _ := f["status"].(string)
		if !statusEnum[status] {
			add(ptr+"/status", "must be one of pass, fail, unknown")
		}
		if sev, _ := f["severity"].(string); !sevEnum[sev] {
			add(ptr+"/severity", "must be one of critical, high, medium, low, info")
		}
		if t, ok := f["title"].(string); !ok || t == "" {
			add(ptr+"/title", "missing or empty")
		}
		if _, ok := f["evidence"].(map[string]any); !ok {
			add(ptr+"/evidence", "missing or not an object")
		}
		requireRFC3339(f, "collected_at", ptr+"/collected_at", add)
		if status == "fail" || status == "unknown" {
			if r, ok := f["reason"].(string); !ok || strings.TrimSpace(r) == "" {
				add(ptr+"/reason", "required when status is fail or unknown")
			}
		}
	}
	return fails
}

func requireInteger(obj map[string]any, key, ptr string, add func(string, string)) {
	n, ok := obj[key].(json.Number)
	if !ok {
		add(ptr, "missing or not a number")
		return
	}
	if strings.ContainsAny(n.String(), ".eE") {
		add(ptr, "must be an integer, got "+n.String())
	}
}

func requireRFC3339(obj map[string]any, key, ptr string, add func(string, string)) {
	v, ok := obj[key].(string)
	if !ok {
		add(ptr, "missing or not a string")
		return
	}
	if _, err := time.Parse(time.RFC3339, v); err != nil {
		add(ptr, "not an RFC 3339 timestamp: "+v)
	}
}
