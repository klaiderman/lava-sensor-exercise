package scan

import (
	"context"
	"fmt"
	"regexp"
	"runtime/debug"
	"sort"
	"time"
)

// DefaultCheckBudget bounds one check that does not declare its own budget.
const DefaultCheckBudget = 8 * time.Second

// DefaultScanDeadline bounds the whole scan. It bounds scheduling and output,
// never a stuck read: the output is written without waiting on an abandoned
// goroutine (L14, F17).
const DefaultScanDeadline = 60 * time.Second

var checkIDPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
var categoryPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ValidateRoster asserts the registry is well formed. It is called at startup
// and fails fast: a duplicate check_id would silently drop a finding.
func ValidateRoster(checks []Check) error {
	seen := map[string]bool{}
	for _, c := range checks {
		id := c.ID()
		if !checkIDPattern.MatchString(id) {
			return fmt.Errorf("check id %q is not UPPER_SNAKE_CASE", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate check id %q in the registry", id)
		}
		seen[id] = true
		if !categoryPattern.MatchString(c.Category()) {
			return fmt.Errorf("check %s: category %q is not UPPER_SNAKE_CASE", id, c.Category())
		}
		switch c.Impact() {
		case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		default:
			return fmt.Errorf("check %s: impact %q is not a severity value", id, c.Impact())
		}
		if c.Title() == "" {
			return fmt.Errorf("check %s: empty title", id)
		}
	}
	return nil
}

// Run executes the whole roster and returns exactly one finding per registered
// check, in (category, check_id) order.
//
// A check that panics, times out, or never gets to run because the scan
// deadline expired still produces its finding: silent omission is the one
// failure mode this loop exists to prevent (L34, D3).
func Run(ctx context.Context, checks []Check, env *Env) ([]Finding, int64) {
	findings := make([]Finding, 0, len(checks))
	var cut int64
	for _, c := range checks {
		f, skipped := runOne(ctx, c, env)
		if skipped {
			cut++
		}
		findings = append(findings, f)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		return findings[i].CheckID < findings[j].CheckID
	})
	return findings, cut
}

func runOne(parent context.Context, c Check, env *Env) (f Finding, budgetCut bool) {
	start := env.Now()

	if parent.Err() != nil {
		r := Unknown(ReasonBudget, "scan deadline exhausted before this check ran")
		r.Field("scan_deadline_ms", env.Deadline.Sub(start).Milliseconds())
		r.Field("elapsed_ms", int64(0))
		return finalize(c, r, env, start, 0), true
	}

	budget := DefaultCheckBudget
	if b, ok := c.(Budgeted); ok && b.Budget() > 0 {
		budget = b.Budget()
	}
	if !env.Deadline.IsZero() {
		if remaining := env.Deadline.Sub(start); remaining < budget {
			budget = remaining
		}
	}

	var res Result
	func() {
		// The result is defaulted to unknown before the deferred recover runs,
		// so a panic still yields a complete, schema-valid finding.
		res = Unknown(ReasonInternal, "internal error")
		defer func() {
			if p := recover(); p != nil {
				res = Unknown(ReasonInternal, "internal error")
				res.Field("panic", fmt.Sprintf("%T: %v", p, p))
				res.Field("stack_head", headOfStack(2048))
			}
		}()
		ctx, cancel := context.WithTimeout(parent, budget)
		defer cancel()
		res = c.Run(ctx, env)
	}()

	elapsed := env.Now().Sub(start)
	return finalize(c, res, env, start, elapsed), false
}

func headOfStack(n int) string {
	b := debug.Stack()
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
