package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"lava-sensor-exercise/sensor/internal/probe"
)

// Evidence must entail the verdict.
//
// The failure this file exists to stop is not a typo in one check: it is a
// whole class. A check gathers observations, some of which failed, and then
// writes a sentence asserting that everything was seen — "enumerated
// successfully", "proven by a successful listing", "every enumeration
// completed". The structured evidence sitting next to that sentence contradicts
// it. A reader who trusts the sentence is wrong; a reader who trusts the
// evidence must distrust the sensor. That is worse than reporting nothing.
//
// So the link between the two is made mechanical here rather than left to each
// check's prose: the completeness statement is GENERATED from the observations,
// a claim of completeness that the observations do not support downgrades the
// finding, and TestEvidenceEntailsVerdict fails the build on any violation.

// Completeness is the generated account of what was and was not observed. It is
// attached to every finding's evidence.
type Completeness struct {
	ObservationsTotal int64    `json:"observations_total"`
	ObservationsOK    int64    `json:"observations_ok"`
	LoadBearingTotal  int64    `json:"load_bearing_total"`
	LoadBearingOK     int64    `json:"load_bearing_ok"`
	NotOK             []string `json:"not_ok"`
	// ExcusedEnumerationDenials names searches that were refused and then
	// opted out of the verdict. They are listed separately because a check can
	// excuse an observation but cannot excuse a hole in its own search.
	ExcusedEnumerationDenials []string `json:"excused_enumeration_denials,omitempty"`
	// AbsenceProvable is true only when every load-bearing observation
	// succeeded in full AND no enumeration was refused. It is the precondition
	// for any sentence that says something was not found.
	AbsenceProvable bool   `json:"absence_provable"`
	Statement       string `json:"statement"`
}

// ProtectionOptOut is the prefix of the one opt-out that an absence claim may
// rest on: a directory this account could not enter, which nobody beyond its
// owner can enter either. That is an ANSWER to "who can reach what is inside",
// not a gap in the search for it, and it is generated centrally rather than
// written by a check. Every other excuse for a refused search leaves the
// absence unprovable.
const ProtectionOptOut = "protection (ancestor "

// absenceProse matches any sentence that asserts an enumeration finished or
// that something is not there.
//
// The first version of this gate was a list of fixed phrases, which a check
// could walk straight past by wording its claim differently: "no exposed key
// material was found anywhere on this machine" matched nothing and shipped as a
// pass. Completeness and absence sentences are now GENERATED, and any
// check-authored detail that makes one is rejected on sight.
var absenceProse = regexp.MustCompile(`(?i)\b(enumerat\w*|proven|provably|absent|none found|nothing (?:was )?found|` +
	`no [a-z ]{0,30}(?:found|exists|present)|did not find|not found|` +
	`0 candidates?|zero candidates?|no candidates?|every [a-z ]{0,30}(?:covered|walked|searched|scanned|checked|completed|succeeded)|` +
	`all [a-z ]{0,30}(?:covered|completed))\b`)

// completenessClaims are the original fixed phrases, kept so the regexp has a
// readable specification next to it and so AuditEntailment can name what it saw.
var completenessClaims = []string{
	"enumerated successfully",
	"were all enumerated",
	"were both enumerated",
	"every enumeration completed",
	"the enumeration completed",
	"every redundancy enumeration completed",
	"completed without finding",
	"proven by a successful listing",
	"proven by successful listing",
	"proven by successful stats",
	"proven by a successful stat",
	"was listed successfully",
	"listed successfully",
	"proven absent",
	"a proven negative",
	"provably not in use",
	"every candidate was resolved",
	"resolved to not-found across",
	"listings both completed",
	"all three listings",
}

// claimsCompleteness reports the completeness or absence claim a detail makes.
func claimsCompleteness(detail string) (string, bool) {
	// The engine's own annotations are generated and exempt.
	if i := strings.Index(detail, " [engine: "); i >= 0 {
		detail = detail[:i]
	}
	if i := strings.Index(detail, " [downgraded from "); i >= 0 {
		detail = detail[:i]
	}
	d := strings.ToLower(detail)
	for _, c := range completenessClaims {
		if strings.Contains(d, c) {
			return c, true
		}
	}
	if m := absenceProse.FindString(detail); m != "" {
		return m, true
	}
	return "", false
}

// bearing reports whether an observation underwrites the verdict. Everything
// does, unless the check recorded a reason why not.
func bearing(o probe.Observation) bool { return o.OptOut == "" }

// clean reports whether an observation answered its question in full.
//
// A truncated read is a prefix, not a value, so it is not clean even at status
// OK. An ENOENT the check marked AbsenceProven is clean: the path resolved and
// nothing was there, which is exactly the observation an absence claim needs.
func clean(o probe.Observation) bool {
	if o.Truncated {
		return false
	}
	return o.Status == probe.StatusOK ||
		(o.Status == probe.StatusENOENT && o.AbsenceProven)
}

// completenessOf builds the generated account. Absence is provable only from
// load-bearing observations that all succeeded: a check with no load-bearing
// observation has not shown that it looked anywhere, so it may not say that it
// looked everywhere.
func completenessOf(obs []probe.Observation) Completeness {
	c := Completeness{NotOK: []string{}}
	for _, o := range obs {
		c.ObservationsTotal++
		if clean(o) {
			c.ObservationsOK++
		}
		if excusedEnumerationDenial(o) {
			c.ExcusedEnumerationDenials = append(c.ExcusedEnumerationDenials,
				o.Source+" ("+notOKLabel(o)+", excused: "+o.OptOut+")")
		}
		if bearing(o) {
			c.LoadBearingTotal++
			if clean(o) {
				c.LoadBearingOK++
			} else {
				c.NotOK = append(c.NotOK, o.Source+" ("+notOKLabel(o)+")")
			}
		}
	}
	sort.Strings(c.NotOK)
	sort.Strings(c.ExcusedEnumerationDenials)
	c.AbsenceProvable = c.LoadBearingTotal > 0 && c.LoadBearingOK == c.LoadBearingTotal &&
		len(c.ExcusedEnumerationDenials) == 0
	c.Statement = completenessStatement(c)
	return c
}

// excusedEnumerationDenial reports a search that did not complete and was then
// opted out of the verdict by the check that ran it. Opting an observation out
// is legitimate - it is how a check says "this is context, not the answer" -
// but a directory listing or walk that was REFUSED is not context: it is the
// part of the machine the check did not see, and no wording can make an
// absence provable across it.
func excusedEnumerationDenial(o probe.Observation) bool {
	if o.OptOut == "" || clean(o) || o.AbsenceProven {
		return false
	}
	if o.Kind != probe.KindDirWalk {
		return false
	}
	return !strings.HasPrefix(o.OptOut, ProtectionOptOut)
}

func notOKLabel(o probe.Observation) string {
	if o.Status == probe.StatusOK && o.Truncated {
		return "OK but truncated"
	}
	if r := o.Reason(); r != "" {
		return r
	}
	return string(o.Status)
}

// completenessStatement is the sentence a check is no longer allowed to write
// for itself.
func completenessStatement(c Completeness) string {
	switch {
	case c.LoadBearingTotal == 0:
		return fmt.Sprintf("%d of %d observations succeeded; no observation was marked load-bearing, so nothing here proves an absence",
			c.ObservationsOK, c.ObservationsTotal)
	case len(c.ExcusedEnumerationDenials) > 0:
		return fmt.Sprintf("%d of %d load-bearing observations succeeded, but %d search(es) were refused and then excused: %s — an absence is not provable across a search that did not run",
			c.LoadBearingOK, c.LoadBearingTotal, len(c.ExcusedEnumerationDenials),
			strings.Join(c.ExcusedEnumerationDenials, ", "))
	case c.AbsenceProvable:
		return fmt.Sprintf("%d of %d load-bearing observations succeeded, so an absence found by them is evidence",
			c.LoadBearingOK, c.LoadBearingTotal)
	default:
		sample := c.NotOK
		if len(sample) > 6 {
			sample = append(append([]string{}, sample[:6]...),
				fmt.Sprintf("and %d more", len(c.NotOK)-6))
		}
		return fmt.Sprintf("%d of %d load-bearing observations succeeded; not observed: %s — an absence is not provable from this",
			c.LoadBearingOK, c.LoadBearingTotal, strings.Join(sample, ", "))
	}
}

// AuditEntailment re-checks a produced findings document from the outside, so
// the same rule can be pointed at an artifact from a container or from the real
// host rather than only at an in-process run. It returns one line per
// violation.
func AuditEntailment(body []byte) []string {
	var doc struct {
		Findings []struct {
			CheckID  string `json:"check_id"`
			Status   string `json:"status"`
			Evidence struct {
				Detail       string       `json:"detail"`
				Completeness Completeness `json:"completeness"`
				Observations []struct {
					Source        string `json:"source"`
					Status        string `json:"status"`
					Truncated     bool   `json:"truncated"`
					LoadBearing   bool   `json:"load_bearing"`
					OptOut        string `json:"not_load_bearing_because"`
					AbsenceProven bool   `json:"absence_proven"`
				} `json:"observations"`
			} `json:"evidence"`
			EntailmentViolation bool `json:"entailment_violation"`
		} `json:"findings"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&doc); err != nil {
		return []string{"document is not a findings artifact: " + err.Error()}
	}
	var out []string
	for _, f := range doc.Findings {
		lbTotal, lbOK := 0, 0
		var notOK []string
		for _, o := range f.Evidence.Observations {
			if o.OptOut != "" {
				continue
			}
			lbTotal++
			if !o.Truncated && (o.Status == "OK" || (o.Status == "ENOENT" && o.AbsenceProven)) {
				lbOK++
			} else {
				notOK = append(notOK, o.Source+" ("+o.Status+")")
			}
		}
		provable := lbTotal > 0 && lbOK == lbTotal

		if f.EntailmentViolation {
			out = append(out, f.CheckID+": the engine recorded an entailment violation")
		}
		if (f.Status == "pass" || f.Status == "fail") && lbTotal == 0 {
			out = append(out, f.CheckID+": status "+f.Status+" with no load-bearing observation behind it")
		}
		if f.Status == "pass" && lbTotal > 0 && lbOK != lbTotal {
			out = append(out, f.CheckID+": status pass while load-bearing observations failed: "+strings.Join(notOK, ", "))
		}
		if phrase, claims := claimsCompleteness(f.Evidence.Detail); claims && !provable {
			out = append(out, f.CheckID+": the detail claims "+quoteStr(phrase)+
				" while "+itoaInt(lbTotal-lbOK)+" load-bearing observation(s) did not succeed")
		}
		if f.Evidence.Completeness.Statement == "" {
			out = append(out, f.CheckID+": no generated completeness statement in evidence")
		}
	}
	return out
}

func quoteStr(s string) string { return `"` + s + `"` }

func itoaInt(n int) string { return fmt.Sprintf("%d", n) }
