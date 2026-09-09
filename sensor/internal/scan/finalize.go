package scan

import (
	"strings"
	"time"

	"lava.sh/sensor/internal/probe"
)

// evidenceValueCap bounds how much of an observed value reaches the artifact.
// The full value is available to the check; evidence carries a bounded excerpt.
const evidenceValueCap = 512

// finalize turns a raw check Result into the reported Finding. It is the only
// place a severity is assigned and the only place a verdict can be downgraded,
// which is what makes both rules auditable in one screen.
//
// Order matters and is fixed:
//
//	(a) a pass/fail resting on a load-bearing observation that is not clean is
//	    downgraded to unknown with a generated reason (L07, L39);
//	(b) the severity rule LD-2 is applied;
//	(c) the evidence object is built from the observations by one function.
func finalize(c Check, r Result, env *Env, start time.Time, elapsed time.Duration) Finding {
	// (a) load-bearing downgrade.
	if r.Status == StatusPass || r.Status == StatusFail {
		if bad, ok := firstUnclean(r.Observations); ok {
			reason := bad.Reason()
			if reason == "" {
				reason = ReasonParse
			}
			if bad.Truncated && bad.Status == probe.StatusOK {
				reason = ReasonBudget
			}
			r.Detail = downgradeDetail(r.Status, bad)
			r.Status = StatusUnknown
			r.Reason = reason
		}
	}

	// A fail or an unknown without a reason is a bug; make it visible rather
	// than emitting a schema-invalid finding.
	if r.Status != StatusPass && strings.TrimSpace(r.Reason) == "" {
		r.Reason = ReasonInternal
		if r.Detail == "" {
			r.Detail = "check returned " + string(r.Status) + " without a reason"
		}
	}
	if r.Status == StatusPass {
		r.Reason = ""
	}

	// (b) severity rule LD-2, applied centrally, never by a check.
	severity := SeverityInfo
	if !c.Observational() && r.Status != StatusPass {
		severity = c.Impact()
	}

	return Finding{
		Category:    c.Category(),
		CheckID:     c.ID(),
		Status:      r.Status,
		Severity:    severity,
		Title:       c.Title(),
		Reason:      r.Reason,
		Evidence:    buildEvidence(r), // (c)
		CollectedAt: rfc3339(start),
		Impact:      c.Impact(),
		DurationMS:  elapsed.Milliseconds(),
	}
}

// firstUnclean returns the first load-bearing observation that did not fully
// succeed. A truncated read counts: a value that hit its cap is a prefix, and a
// prefix never supports a pass (L05, L12).
func firstUnclean(obs []probe.Observation) (probe.Observation, bool) {
	for _, o := range obs {
		if !o.LoadBearing {
			continue
		}
		if o.Status != probe.StatusOK || o.Truncated {
			return o, true
		}
	}
	return probe.Observation{}, false
}

func downgradeDetail(was Status, bad probe.Observation) string {
	what := "a load-bearing observation did not succeed"
	if bad.Truncated && bad.Status == probe.StatusOK {
		what = "a load-bearing observation hit its byte cap and is a prefix"
	}
	return "downgraded from " + string(was) + ": " + what + " (" + bad.Source + ": " + string(bad.Status) + ")"
}

// buildEvidence is the one shared function that renders observations into the
// evidence object. Every check's evidence goes through it, so source, status,
// errno, exit code, signal, timeout and truncation are reported the same way
// everywhere.
func buildEvidence(r Result) Evidence {
	ev := Evidence{Detail: r.Detail, Fields: r.Fields}
	ev.Observations = make([]ObsEvidence, 0, len(r.Observations))
	for _, o := range r.Observations {
		ev.Observations = append(ev.Observations, renderObservation(o))
	}
	return ev
}

func renderObservation(o probe.Observation) ObsEvidence {
	e := ObsEvidence{
		Source:          o.Source,
		ObservationType: o.Kind,
		Status:          string(o.Status),
		Reason:          o.Reason(),
		Errno:           o.Errno,
		ExitCode:        o.ExitCode,
		Signal:          o.Signal,
		Truncated:       o.Truncated,
		Bytes:           o.Bytes,
		DurationMS:      o.Elapsed.Milliseconds(),
		LoadBearing:     o.LoadBearing,
		Detail:          o.Detail,
	}
	if v := strings.TrimRight(o.Value, "\n"); v != "" {
		if len(v) > evidenceValueCap {
			e.Value = v[:evidenceValueCap]
			e.ValueTruncated = true
		} else {
			e.Value = v
		}
	}
	if m := o.Meta; m != nil {
		e.Command = m.Command
		e.BinaryPath = m.BinaryResolvedPath
		e.TimedOut = m.TimedOut
		e.StdoutBytes = m.StdoutBytes
		e.StderrBytes = m.StderrBytes
		e.StderrExcerpt = m.StderrExcerpt
		e.WaitDelay = m.WaitDelayExpired
		e.Exists = m.Exists
		e.FileType = m.FileType
		e.Mode = m.Mode
		e.UID = m.UID
		e.GID = m.GID
		e.Size = m.Size
		e.SymlinkTarget = m.SymlinkTarget
		e.ResolvedPath = m.ResolvedPath
		e.Root = m.Root
		e.EntriesScanned = m.EntriesScanned
		e.CrossedMounts = m.CrossedMounts
		e.UnreadableDirs = m.UnreadableDirs
		e.DirsPruned = m.DirsPruned
		if m.BudgetExhausted != "" && m.BudgetExhausted != "none" {
			e.BudgetExhausted = m.BudgetExhausted
		}
	}
	return e
}

// rfc3339 formats a timestamp explicitly rather than letting time.Time marshal
// itself: RFC3339Nano trims trailing zeros and the field width would vary
// between runs (R5-F32).
func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
