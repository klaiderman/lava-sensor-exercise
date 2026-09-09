package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"lava-sensor-exercise/sensor/internal/scan"
)

// schemaPaths are, in order, the copy that ships with the sensor and the
// authoritative derived schema in the repository. The two are asserted
// byte-identical below so the copy can never drift.
const (
	shippedSchema       = "../../testdata/finding.schema.json"
	authoritativeSchema = "../../../task/derived/finding.schema.json"
)

func compiledSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	f, err := os.Open(shippedSchema)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		t.Fatalf("schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	// Format assertion on: date-time is a constraint here, not an annotation.
	c.AssertFormat()
	if err := c.AddResource("finding.schema.json", doc); err != nil {
		t.Fatal(err)
	}
	sch, err := c.Compile("finding.schema.json")
	if err != nil {
		t.Fatalf("compiling the schema: %v", err)
	}
	return sch
}

// The shipped copy of the schema must be byte-identical to the derived one, so
// there is never a second, quietly divergent contract.
func TestShippedSchemaMatchesTheAuthoritativeOne(t *testing.T) {
	authoritative, err := os.ReadFile(authoritativeSchema)
	if err != nil {
		t.Skipf("authoritative schema not present in this checkout: %v", err)
	}
	shipped, err := os.ReadFile(shippedSchema)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(authoritative, shipped) {
		t.Errorf("%s has drifted from %s; the sensor must validate against one contract only",
			shippedSchema, authoritativeSchema)
	}
}

// buildDocument runs the full pipeline the binary runs: machine collection, the
// whole roster through the engine, and the deterministic writer.
func buildDocument(t *testing.T, profile string, runner *fakeRunner) (*scan.Document, []byte) {
	t.Helper()
	return buildDocumentAt(t, buildProfile(t, profile), runner)
}

// buildDocumentAt runs the pipeline over an already-materialised fixture tree,
// which is what makes a determinism comparison meaningful: a rebuilt tree has
// fresh modification times, and the sensor is right to report them.
func buildDocumentAt(t *testing.T, root string, runner *fakeRunner) (*scan.Document, []byte) {
	t.Helper()
	env := newTestEnv(t, root, runner)
	roster := All()
	if err := scan.ValidateRoster(roster); err != nil {
		t.Fatalf("roster: %v", err)
	}
	findings, cut := scan.Run(context.Background(), roster, env)
	doc := &scan.Document{
		SchemaVersion: scan.SchemaVersion,
		CollectedAt:   env.Now().UTC().Format(time.RFC3339),
		SensorVersion: "test",
		Machine:       CollectMachine(context.Background(), env),
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

// The produced artifact validates against the derived schema on every profile,
// including the ones where almost everything is unknown.
func TestDocumentValidatesAgainstSchema(t *testing.T) {
	sch := compiledSchema(t)
	for _, profile := range []string{"profileA", "profileB", "profileC"} {
		t.Run(profile, func(t *testing.T) {
			runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password"))
			_, body := buildDocument(t, profile, runner)

			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
			if err != nil {
				t.Fatalf("produced document is not valid JSON: %v", err)
			}
			if err := sch.Validate(inst); err != nil {
				t.Fatalf("schema validation failed:\n%v\n\ndocument:\n%s", err, body)
			}
			// The binary's own stdlib self-check must agree with the validator.
			if fails := scan.SelfCheck(body); len(fails) != 0 {
				t.Errorf("runtime self-check disagrees with the schema: %v", fails)
			}
		})
	}
}

// Nothing that looks like key material, a token or a machine-id may appear in
// the artifact. This greps the produced bytes rather than trusting review.
func TestNoSecretValuesInOutput(t *testing.T) {
	runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password"))
	_, body := buildDocument(t, "profileA", runner)
	s := string(body)

	for _, marker := range []string{
		"-----BEGIN", "PRIVATE KEY", "ssh-rsa ", "ssh-ed25519 ",
		"AKIA", "sk-", "xoxb-", "-----END",
	} {
		if strings.Contains(s, marker) {
			t.Errorf("the artifact contains %q", marker)
		}
	}
	// A JWT-shaped string.
	if regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.`).MatchString(s) {
		t.Errorf("the artifact contains a JWT-shaped string")
	}
	// Long base64/hex runs that are not the host_id digest.
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	hostID, _ := doc["machine"].(map[string]any)["host_id"].(string)
	for _, m := range regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`).FindAllString(s, -1) {
		if m != hostID {
			t.Errorf("unexplained long opaque run in the artifact: %q", m)
		}
	}

	// machine-id(5) declares the id confidential: only its keyed derivation
	// may be emitted (L32).
	raw, err := os.ReadFile(filepath.Join("testdata", "profileA", "etc", "machine-id"))
	if err != nil {
		t.Fatal(err)
	}
	if id := strings.TrimSpace(string(raw)); id != "" && strings.Contains(s, id) {
		t.Errorf("the raw /etc/machine-id appears verbatim in the artifact")
	}
}

// durationField matches the only genuinely volatile values in the artifact:
// measured elapsed times. Everything else must be byte-stable between runs.
var durationField = regexp.MustCompile(`"(duration_ms|elapsed_ms|entries_scanned)": *[0-9]+`)

// Two runs over the same fixture with a fixed clock differ only in measured
// durations: key order, field order, findings order and every value are stable.
func TestTwoRunsDifferOnlyInMeasuredDurations(t *testing.T) {
	root := buildProfile(t, "profileA")
	mk := func() []byte {
		runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password"))
		_, body := buildDocumentAt(t, root, runner)
		return body
	}
	first, second := mk(), mk()
	if bytes.Equal(first, second) {
		return
	}
	normalise := func(b []byte) []byte { return durationField.ReplaceAll(b, []byte(`"$1": 0`)) }
	a, c := normalise(first), normalise(second)
	if !bytes.Equal(a, c) {
		for i := 0; i < len(a) && i < len(c); i++ {
			if a[i] != c[i] {
				lo := i - 120
				if lo < 0 {
					lo = 0
				}
				hi := i + 120
				if hi > len(a) {
					hi = len(a)
				}
				t.Fatalf("two runs over the same fixture differ outside measured durations, near byte %d:\n%s\n---\n%s", i, a[lo:hi], c[lo:hi])
			}
		}
		t.Fatalf("two runs differ in length outside measured durations: %d vs %d", len(a), len(c))
	}
}

// Every finding carries evidence that names an actual observation, not a
// restatement of the title.
func TestEveryFindingHasActionableEvidence(t *testing.T) {
	runner := newFakeRunner().ok("/usr/sbin/sshd -G", sshdGOutput("without-password"))
	doc, _ := buildDocument(t, "profileA", runner)
	for _, f := range doc.Findings {
		if len(f.Evidence.Observations) == 0 {
			t.Errorf("%s: no observations in evidence", f.CheckID)
			continue
		}
		if f.Evidence.Detail == f.Title {
			t.Errorf("%s: the detail merely restates the title", f.CheckID)
		}
		for _, o := range f.Evidence.Observations {
			if o.Source == "" || o.Status == "" {
				t.Errorf("%s: an observation without a source or status: %+v", f.CheckID, o)
			}
		}
	}
}

// Running as root must not change what the sensor does. Nothing in the tree may
// branch on the effective uid.
func TestNoBehaviourBranchesOnPrivilege(t *testing.T) {
	err := filepath.WalkDir("../..", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		src := string(b)
		for _, pat := range []string{"Geteuid() == 0", "Getuid() == 0", "EUID == 0", "IsRoot()"} {
			if strings.Contains(src, pat) {
				t.Errorf("%s branches on privilege (%s); the sensor must be read-only and bounded whoever runs it", p, pat)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// No hostname, vendor or customer string may appear in check logic: every
// branch is gated on an observation, never on identity (L37).
func TestNoIdentityGatingInCheckLogic(t *testing.T) {
	banned := []string{"Supermicro", "latitude", "Latitude", "f4-metal", "Micron", "EPYC", "Ubuntu\"", "chi-1"}
	err := filepath.WalkDir(".", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, s := range banned {
			if strings.Contains(string(b), s) {
				t.Errorf("%s contains the identity string %q; gate on capabilities, never on identity", p, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
