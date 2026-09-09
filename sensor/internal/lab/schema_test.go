package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"lava-sensor-exercise/sensor/internal/checks"
	"lava-sensor-exercise/sensor/internal/scan"
)

// authoritativeSchemaPath is task/derived/finding.schema.json, the ONLY schema
// source of truth (CLAUDE.md). This file never reconstructs the schema or
// maintains a second copy; it reads the one in the repository directly.
const authoritativeSchemaPath = "../../../task/derived/finding.schema.json"

func compileAuthoritativeSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(authoritativeSchemaPath)
	if err != nil {
		t.Fatalf("authoritative schema not readable at %s: %v", authoritativeSchemaPath, err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat() // format is a constraint here (date-time on collected_at), not decoration.
	if err := c.AddResource("finding.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("finding.schema.json")
	if err != nil {
		t.Fatalf("compiling task/derived/finding.schema.json: %v", err)
	}
	return sch
}

// buildLabDocument runs the real pipeline (machine collection + the full
// registered roster + the deterministic encoder) independently of
// internal/checks/document_test.go's buildDocument, against one of the
// author's fixture profiles.
func buildLabDocument(t *testing.T, profile string, runner *fakeRunner) (*scan.Document, []byte) {
	t.Helper()
	root := buildAuthorProfile(t, profile)
	env := newLabEnv(t, root, runner)
	roster := checks.All()
	if err := scan.ValidateRoster(roster); err != nil {
		t.Fatalf("roster: %v", err)
	}
	findings, cut := scan.Run(context.Background(), roster, env)
	doc := &scan.Document{
		SchemaVersion: scan.SchemaVersion,
		CollectedAt:   env.Now().UTC().Format(time.RFC3339),
		SensorVersion: "test-lab",
		Machine:       checks.CollectMachine(context.Background(), env),
		Findings:      findings,
		Scan: scan.ScanMeta{
			StartedAt: env.Now().UTC().Format(time.RFC3339), DeadlineMS: 60000,
			ChecksRun: int64(len(roster)), BudgetCut: cut > 0, BudgetCutCount: cut,
			EUID: 1000, Degradations: []string{}, SelfCheck: "pass",
		},
	}
	b, err := scan.Encode(doc)
	if err != nil {
		t.Fatal(err)
	}
	return doc, b
}

func sshdRunnerFor(profile string) *fakeRunner {
	switch profile {
	case "profileA":
		return profileARunner()
	case "profileC":
		return newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("no"))
	default:
		return newFakeRunner()
	}
}

// TestSchema_AllProfilesValidateIndependently is an independent re-run of the
// schema validation the author already performs in
// internal/checks/document_test.go: same authoritative schema, same
// santhosh-tekuri/jsonschema/v6 library, format assertion on, but its own
// document construction and its own compiled schema instance, so a mistake in
// one does not mask a mistake in the other.
func TestSchema_AllProfilesValidateIndependently(t *testing.T) {
	sch := compileAuthoritativeSchema(t)
	for _, profile := range []string{"profileA", "profileB", "profileC"} {
		t.Run(profile, func(t *testing.T) {
			_, body := buildLabDocument(t, profile, sshdRunnerFor(profile))
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("produced document is not valid JSON: %v", err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Fatalf("schema validation failed:\n%v", err)
			}
			if fails := scan.SelfCheck(body); len(fails) != 0 {
				t.Errorf("the binary's own runtime self-check disagrees with the schema validator: %v", fails)
			}
		})
	}
}

// TestSchema_CheckIDUniquenessAndRFC3339Everywhere walks the raw JSON (not the
// typed struct, so a future field the struct does not know about cannot hide
// a violation) and checks: every check_id is unique, collected_at parses as
// RFC 3339 at both the document level and on every finding.
func TestSchema_CheckIDUniquenessAndRFC3339Everywhere(t *testing.T) {
	for _, profile := range []string{"profileA", "profileB", "profileC"} {
		t.Run(profile, func(t *testing.T) {
			_, body := buildLabDocument(t, profile, sshdRunnerFor(profile))
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			topLevel, _ := doc["collected_at"].(string)
			if _, err := time.Parse(time.RFC3339, topLevel); err != nil {
				t.Errorf("document collected_at %q does not parse as RFC 3339: %v", topLevel, err)
			}
			findings, _ := doc["findings"].([]any)
			seen := map[string]bool{}
			for i, it := range findings {
				f, _ := it.(map[string]any)
				id, _ := f["check_id"].(string)
				if id == "" {
					t.Errorf("findings[%d]: empty or missing check_id", i)
					continue
				}
				if seen[id] {
					t.Errorf("findings[%d]: duplicate check_id %q", i, id)
				}
				seen[id] = true
				ca, _ := f["collected_at"].(string)
				if _, err := time.Parse(time.RFC3339, ca); err != nil {
					t.Errorf("findings[%d] (%s): collected_at %q does not parse as RFC 3339: %v", i, id, ca, err)
				}
			}
			if len(findings) == 0 {
				t.Errorf("no findings at all in %s output", profile)
			}
		})
	}
}

// TestSchema_NoEmptyStringInMachine walks machine.* generically (any nested
// object/array), flagging a literal "" anywhere: undeterminable values must be
// the literal "unknown", never the empty string (B6).
func TestSchema_NoEmptyStringInMachine(t *testing.T) {
	for _, profile := range []string{"profileA", "profileB", "profileC"} {
		t.Run(profile, func(t *testing.T) {
			_, body := buildLabDocument(t, profile, sshdRunnerFor(profile))
			var doc map[string]any
			if err := json.Unmarshal(body, &doc); err != nil {
				t.Fatal(err)
			}
			machine, ok := doc["machine"]
			if !ok {
				t.Fatal("no machine object")
			}
			var walk func(path string, v any)
			walk = func(path string, v any) {
				switch vv := v.(type) {
				case string:
					if vv == "" {
						t.Errorf("%s is the empty string; must be the literal \"unknown\" or omitted", path)
					}
				case map[string]any:
					for k, sub := range vv {
						walk(path+"."+k, sub)
					}
				case []any:
					for i, sub := range vv {
						walk(fmt.Sprintf("%s[%d]", path, i), sub)
					}
				}
			}
			walk("machine", machine)
		})
	}
}

// TestSchema_NoSecretShapedStrings is an independent secret-shape sweep
// (separate regex set, separate document construction) from
// internal/checks/document_test.go's TestNoSecretValuesInOutput: PEM armor,
// common API-key prefixes (sk-, AKIA), Slack tokens, and JWT-shaped strings.
func TestSchema_NoSecretShapedStrings(t *testing.T) {
	markers := []string{
		"-----BEGIN ", "-----END ", "PRIVATE KEY", "AKIA", "sk-", "xoxb-", "xoxp-",
		"ghp_", "glpat-",
	}
	jwtShape := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}`)
	for _, profile := range []string{"profileA", "profileB", "profileC"} {
		t.Run(profile, func(t *testing.T) {
			_, body := buildLabDocument(t, profile, sshdRunnerFor(profile))
			s := string(body)
			for _, m := range markers {
				if bytesContains(s, m) {
					t.Errorf("output contains secret-shaped marker %q", m)
				}
			}
			if jwtShape.MatchString(s) {
				t.Errorf("output contains a JWT-shaped string")
			}
		})
	}
}

func bytesContains(s, sub string) bool { return len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub)) }

// TestSchema_DeterministicAcrossTwoRuns rebuilds the same profile twice with
// the same fixed clock and asserts the two artifacts differ only in the
// explicitly volatile duration/elapsed/entries_scanned fields.
var volatileField = regexp.MustCompile(`"(duration_ms|elapsed_ms|entries_scanned)": *[0-9]+`)

func TestSchema_DeterministicAcrossTwoRuns(t *testing.T) {
	root := buildAuthorProfile(t, "profileA")
	build := func() []byte {
		env := newLabEnv(t, root, profileARunner())
		roster := checks.All()
		findings, _ := scan.Run(context.Background(), roster, env)
		doc := &scan.Document{
			SchemaVersion: scan.SchemaVersion, CollectedAt: env.Now().UTC().Format(time.RFC3339),
			Machine: checks.CollectMachine(context.Background(), env), Findings: findings,
			Scan: scan.ScanMeta{StartedAt: env.Now().UTC().Format(time.RFC3339), Degradations: []string{}, SelfCheck: "pass"},
		}
		b, err := scan.Encode(doc)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first, second := build(), build()
	a := volatileField.ReplaceAll(first, []byte(`"$1": 0`))
	c := volatileField.ReplaceAll(second, []byte(`"$1": 0`))
	if !bytes.Equal(a, c) {
		t.Errorf("two runs over the same fixture with a fixed clock differ outside duration/elapsed/entries_scanned fields")
	}
}
