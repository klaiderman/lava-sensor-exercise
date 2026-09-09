package main

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func devNullFile(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestExitCodeContract(t *testing.T) {
	null := devNullFile(t)
	out := filepath.Join(t.TempDir(), "findings.json")

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"version", []string{"--version"}, exitOK},
		{"no subcommand", []string{"--out", out}, exitFatal},
		{"unknown subcommand", []string{"inspect", "--out", out}, exitFatal},
		{"missing --out", []string{"scan"}, exitFatal},
		{"non-positive timeout", []string{"scan", "--out", out, "--timeout", "0s"}, exitFatal},
		{"unwritable output", []string{"scan", "--out", filepath.Join(t.TempDir(), "no", "such", "dir", "f.json")}, exitFatal},
		{"unexpected extra argument", []string{"scan", "--out", out, "extra"}, exitFatal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args, null, null); got != tc.want {
				t.Errorf("exit = %d, want %d", got, tc.want)
			}
		})
	}
}

// A successful scan writes the file and exits 0, whatever the findings say: a
// finding's verdict never becomes an exit code.
func TestScanWritesAValidArtifactAndExitsZero(t *testing.T) {
	null := devNullFile(t)
	out := filepath.Join(t.TempDir(), "findings.json")
	if code := run([]string{"scan", "--out", out, "--timeout", "30s"}, null, null); code != exitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SchemaVersion string `json:"schema_version"`
		Findings      []struct {
			CheckID  string `json:"check_id"`
			Status   string `json:"status"`
			Severity string `json:"severity"`
			Reason   string `json:"reason"`
		} `json:"findings"`
		Scan struct {
			SelfCheck string `json:"self_check"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("artifact is not valid JSON: %v", err)
	}
	if doc.SchemaVersion != "1" {
		t.Errorf("schema_version = %q", doc.SchemaVersion)
	}
	if doc.Scan.SelfCheck != "pass" {
		t.Errorf("self_check = %q on a live run", doc.Scan.SelfCheck)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range doc.Findings {
		if f.Status != "pass" && f.Reason == "" {
			t.Errorf("%s: %s without a reason", f.CheckID, f.Status)
		}
	}
	// The artifact is the only thing written.
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "findings.json" {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("the output directory contains %v; only the --out file may be written", names)
	}
}

// L49: the shipped binary has zero third-party dependencies. This walks the
// production sources rather than shelling out to the toolchain, so it also
// holds when the tests run on a machine without a Go installation.
func TestShippedBinaryHasNoThirdPartyImports(t *testing.T) {
	const modulePrefix = "lava-sensor-exercise/sensor/"
	fset := token.NewFileSet()
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return nil
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if strings.HasPrefix(path, modulePrefix) {
				continue
			}
			// A standard-library path has no dot in its first element.
			first, _, _ := strings.Cut(path, "/")
			if strings.Contains(first, ".") {
				t.Errorf("%s imports the third-party package %q; the shipped binary carries no runtime dependencies", p, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
