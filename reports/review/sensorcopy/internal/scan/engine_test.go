package scan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lava-sensor-exercise/sensor/internal/probe"
)

// stubCheck lets the engine be tested without any host access at all.
type stubCheck struct {
	id, category, title, impact string
	observational               bool
	fn                          func(context.Context, *Env) Result
}

func (c stubCheck) ID() string          { return c.id }
func (c stubCheck) Category() string    { return c.category }
func (c stubCheck) Title() string       { return c.title }
func (c stubCheck) Impact() string      { return c.impact }
func (c stubCheck) Observational() bool { return c.observational }
func (c stubCheck) Run(ctx context.Context, env *Env) Result {
	return c.fn(ctx, env)
}

func newStub(id string, impact string, fn func(context.Context, *Env) Result) stubCheck {
	return stubCheck{id: id, category: "TEST_CATEGORY", title: "stub " + id, impact: impact, fn: fn}
}

func testEnv() *Env {
	fixed := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	return NewEnv(nil, nil, func() time.Time { return fixed }, time.Time{}, 1000)
}

// A panicking check produces exactly one unknown finding with the panic in
// evidence, and every other check is unaffected.
func TestPanicIsolation(t *testing.T) {
	roster := []Check{
		newStub("PANICS", SeverityHigh, func(context.Context, *Env) Result { panic("boom in a check") }),
		newStub("SURVIVES", SeverityLow, func(context.Context, *Env) Result { return Pass("fine") }),
	}
	findings, _ := Run(context.Background(), roster, testEnv())
	if len(findings) != 2 {
		t.Fatalf("len(findings) = %d, want 2", len(findings))
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.CheckID] = f
	}
	p := byID["PANICS"]
	if p.Status != StatusUnknown {
		t.Errorf("panicking check status = %s, want unknown", p.Status)
	}
	if p.Reason != ReasonInternal || p.Evidence.Detail != "internal error" {
		t.Errorf("reason/detail = %q/%q, want the internal-error pair", p.Reason, p.Evidence.Detail)
	}
	if p.Severity != SeverityHigh {
		t.Errorf("severity = %s, want the declared impact", p.Severity)
	}
	b, _ := json.Marshal(p.Evidence)
	if !strings.Contains(string(b), "boom in a check") {
		t.Errorf("the panic value belongs in evidence: %s", b)
	}
	if byID["SURVIVES"].Status != StatusPass {
		t.Errorf("an unrelated check was affected by the panic")
	}
}

// When the scan deadline is already gone, every not-yet-run check still emits a
// finding saying so. A cut is visible in the artifact, never silent.
func TestScanDeadlineCutStillEmitsEveryFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	roster := []Check{
		newStub("A", SeverityHigh, func(context.Context, *Env) Result { return Pass("never runs") }),
		newStub("B", SeverityLow, func(context.Context, *Env) Result { return Pass("never runs") }),
	}
	findings, cut := Run(ctx, roster, testEnv())
	if len(findings) != len(roster) || cut != int64(len(roster)) {
		t.Fatalf("findings %d, cut %d, want %d/%d", len(findings), cut, len(roster), len(roster))
	}
	for _, f := range findings {
		if f.Status != StatusUnknown || f.Reason != ReasonBudget {
			t.Errorf("%s: %s/%s, want unknown/BUDGET_EXHAUSTED", f.CheckID, f.Status, f.Reason)
		}
	}
}

// LD-2: severity is the declared impact on fail and unknown, info on pass, and
// always info for an observational check. It is applied centrally.
func TestSeverityRule(t *testing.T) {
	cases := []struct {
		name          string
		result        Result
		impact        string
		observational bool
		want          string
	}{
		{"pass is info", Pass("ok"), SeverityCritical, false, SeverityInfo},
		{"fail takes the impact", Fail(ReasonPolicy, "bad"), SeverityHigh, false, SeverityHigh},
		{"unknown takes the impact too", Unknown(ReasonEACCES, "denied"), SeverityHigh, false, SeverityHigh},
		{"observational is always info", Fail(ReasonPolicy, "bad"), SeverityHigh, true, SeverityInfo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := stubCheck{id: "X", category: "C", title: "t", impact: tc.impact, observational: tc.observational,
				fn: func(context.Context, *Env) Result { return tc.result }}
			findings, _ := Run(context.Background(), []Check{c}, testEnv())
			if findings[0].Severity != tc.want {
				t.Errorf("severity = %s, want %s", findings[0].Severity, tc.want)
			}
		})
	}
}

// A pass or fail whose load-bearing observation did not succeed is downgraded
// centrally: a non-OK observation can never underwrite a verdict.
func TestLoadBearingDowngrade(t *testing.T) {
	denied := probe.Observation{
		Source: "/etc/thing", Kind: probe.KindFileRead,
		Status: probe.StatusEACCES, Errno: "EACCES", LoadBearing: true,
	}
	c := newStub("DOWNGRADE", SeverityMedium, func(context.Context, *Env) Result {
		r := Pass("claims everything is fine")
		r.Add(denied)
		return r
	})
	f, _ := Run(context.Background(), []Check{c}, testEnv())
	if f[0].Status != StatusUnknown {
		t.Fatalf("status = %s, want unknown", f[0].Status)
	}
	if f[0].Reason != "EACCES" {
		t.Errorf("reason = %q, want EACCES", f[0].Reason)
	}
	if !strings.Contains(f[0].Evidence.Detail, "downgraded from pass") {
		t.Errorf("the downgrade must be stated: %q", f[0].Evidence.Detail)
	}

	// A truncated read is a prefix, and a prefix never supports a pass either.
	trunc := probe.Observation{Source: "/etc/big", Status: probe.StatusOK, Truncated: true, LoadBearing: true}
	c2 := newStub("TRUNC", SeverityMedium, func(context.Context, *Env) Result {
		r := Pass("read the whole thing, honest")
		r.Add(trunc)
		return r
	})
	f2, _ := Run(context.Background(), []Check{c2}, testEnv())
	if f2[0].Status != StatusUnknown || f2[0].Reason != ReasonBudget {
		t.Errorf("truncated: %s/%s, want unknown/BUDGET_EXHAUSTED", f2[0].Status, f2[0].Reason)
	}

	// A failed observation that is NOT load-bearing must not downgrade
	// anything: over-claiming unknown is a bug too (L36).
	notBearing := denied
	notBearing.LoadBearing = false
	c3 := newStub("KEEPS", SeverityMedium, func(context.Context, *Env) Result {
		r := Pass("the verdict rests on something else")
		r.Add(notBearing)
		return r
	})
	f3, _ := Run(context.Background(), []Check{c3}, testEnv())
	if f3[0].Status != StatusPass {
		t.Errorf("status = %s; a non-load-bearing failure must not manufacture an unknown", f3[0].Status)
	}
}

// A fail or unknown always carries a reason, even when a check forgets one.
func TestReasonIsAlwaysPresentOnNonPass(t *testing.T) {
	c := newStub("SLOPPY", SeverityLow, func(context.Context, *Env) Result {
		return Result{Status: StatusFail}
	})
	f, _ := Run(context.Background(), []Check{c}, testEnv())
	if f[0].Reason == "" {
		t.Errorf("a fail with no reason reached the output")
	}
}

// Findings are sorted by (category, check_id) regardless of roster order.
func TestFindingsAreSorted(t *testing.T) {
	mk := func(cat, id string) Check {
		return stubCheck{id: id, category: cat, title: "t", impact: SeverityLow,
			fn: func(context.Context, *Env) Result { return Pass("ok") }}
	}
	roster := []Check{mk("ZED", "B"), mk("ALPHA", "Z"), mk("ALPHA", "A")}
	findings, _ := Run(context.Background(), roster, testEnv())
	got := make([]string, len(findings))
	for i, f := range findings {
		got[i] = f.Category + "/" + f.CheckID
	}
	want := []string{"ALPHA/A", "ALPHA/Z", "ZED/B"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestValidateRosterRejectsDuplicatesAndBadIDs(t *testing.T) {
	ok := func(id, cat, impact string) Check {
		return stubCheck{id: id, category: cat, title: "t", impact: impact,
			fn: func(context.Context, *Env) Result { return Pass("") }}
	}
	if err := ValidateRoster([]Check{ok("A_B", "CAT", SeverityLow), ok("A_B", "CAT", SeverityLow)}); err == nil {
		t.Errorf("a duplicate check_id must fail fast: it would silently drop a finding")
	}
	if err := ValidateRoster([]Check{ok("lower_case", "CAT", SeverityLow)}); err == nil {
		t.Errorf("a non-UPPER_SNAKE_CASE check_id must be rejected")
	}
	if err := ValidateRoster([]Check{ok("A", "lower", SeverityLow)}); err == nil {
		t.Errorf("a non-UPPER_SNAKE_CASE category must be rejected")
	}
	if err := ValidateRoster([]Check{ok("A", "CAT", "catastrophic")}); err == nil {
		t.Errorf("an impact outside the severity enum must be rejected")
	}
	if err := ValidateRoster([]Check{ok("A", "CAT", SeverityLow)}); err != nil {
		t.Errorf("a valid roster was rejected: %v", err)
	}
}

func TestMountInfoParsingWithPropagationFields(t *testing.T) {
	// The optional propagation fields are variable in number, so the tail must
	// be indexed from the " - " separator, not from a fixed offset (L31).
	in := "36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:2 propagate_from:3 - ext3 /dev/root rw,errors=continue\n" +
		"37 36 0:33 / /space/with\\040space rw - tmpfs tmpfs rw\n"
	got := parseMountInfo(in)
	if len(got) != 2 {
		t.Fatalf("parsed %d entries, want 2", len(got))
	}
	if got[0].FSType != "ext3" || got[0].Source != "/dev/root" || got[0].MountPoint != "/mnt2" || got[0].MajorMinor != "98:0" {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[1].MountPoint != "/space/with space" {
		t.Errorf("octal escapes must be decoded, got %q", got[1].MountPoint)
	}
}

func TestSSHDGParsing(t *testing.T) {
	o := &SSHDOracle{Directives: map[string][]string{}, Obs: probe.Observation{
		Status: probe.StatusOK,
		Value:  "port 22\npermitrootlogin without-password\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:22\n",
	}}
	parseSSHDG(o)
	if v, ok := o.Value("PermitRootLogin"); !ok || v != "without-password" {
		t.Errorf("value = %q ok = %v", v, ok)
	}
	if len(o.Directives["listenaddress"]) != 2 {
		t.Errorf("repeated directives must all be kept: %v", o.Directives["listenaddress"])
	}
	if !o.OK() {
		t.Errorf("a well-formed oracle run must be usable")
	}

	// Truncated output means the directive set is partial, so it is not usable
	// as an oracle at all.
	trunc := &SSHDOracle{Directives: map[string][]string{}, Obs: probe.Observation{
		Status: probe.StatusOK, Truncated: true, Value: "port 22\n",
	}}
	parseSSHDG(trunc)
	if trunc.OK() {
		t.Errorf("a truncated oracle run must not be treated as authoritative")
	}
}
