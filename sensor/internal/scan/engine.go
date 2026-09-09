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

// abandonGrace is the slack between a check's own deadline and the point the
// engine stops waiting for it. A check that honours its context returns inside
// this window; one that cannot is abandoned.
const abandonGrace = 250 * time.Millisecond

// DefaultScanDeadline bounds the whole scan. It bounds scheduling and output,
// never a stuck read: the output is written without waiting on an abandoned
// goroutine (L14, F17).
const DefaultScanDeadline = 60 * time.Second

// upperSnake is the identifier shape the output contract requires of both
// check ids and categories. One regexp, compiled once for the package.
var upperSnake = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ValidateRoster asserts the registry is well formed. It is called at startup
// and fails fast: a duplicate check_id would silently drop a finding.
func ValidateRoster(checks []Check) error {
	seen := map[string]bool{}
	for _, c := range checks {
		id := c.ID()
		if !upperSnake.MatchString(id) {
			return fmt.Errorf("check id %q is not UPPER_SNAKE_CASE", id)
		}
		if seen[id] {
			return fmt.Errorf("duplicate check id %q in the registry", id)
		}
		seen[id] = true
		if !upperSnake.MatchString(c.Category()) {
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

	// Budget arithmetic, stated once: the declared per-check budgets sum to far
	// more than the scan deadline, and the loop is sequential. The scan
	// deadline therefore dominates - a check gets min(its declared budget, the
	// time left) - so a slow early check cannot silently starve a later one:
	// it runs out of remaining time and every check after it emits its own
	// finding with reason BUDGET_EXHAUSTED rather than being dropped.
	budget := c.Budget()
	if budget <= 0 {
		budget = DefaultCheckBudget
	}
	if !env.Deadline.IsZero() {
		if remaining := env.Deadline.Sub(start); remaining < budget {
			budget = remaining
		}
	}

	// The check runs in its own goroutine and is ABANDONED on overrun.
	//
	// A context deadline only helps a check that consults it. A D-state read of
	// a hung NFS home returns to nobody: no cancellation, no close, no timeout
	// gets control back. Calling c.Run inline means one such check takes the
	// whole scan with it and the artifact is never written at all. So the
	// result arrives on a buffered channel the abandoned goroutine can always
	// finish sending to, the engine stops waiting at the deadline, and the scan
	// carries on with the honest answer for that check.
	done := make(chan Result, 1)
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	go func() {
		res := Unknown(ReasonInternal, "internal error")
		defer func() {
			if p := recover(); p != nil {
				res = Unknown(ReasonInternal, "internal error")
				res.Field("panic", fmt.Sprintf("%T: %v", p, p))
				res.Field("stack_head", headOfStack(2048))
			}
			done <- res
		}()
		res = c.Run(ctx, env)
	}()

	// The wall clock, not env.Now: a fixed test clock must not disable the
	// abandonment, and the abandonment must not depend on the check.
	timer := time.NewTimer(budget + abandonGrace)
	defer timer.Stop()

	var res Result
	select {
	case res = <-done:
	case <-timer.C:
		res = Unknown(ReasonTimeout,
			"the check did not return within its "+budget.String()+" budget and was abandoned; "+
				"it may be blocked in a syscall that cannot be interrupted, so the goroutine is left running rather than waited on and the scan continues")
		res.Field("abandoned", true)
		res.Field("budget_ms", budget.Milliseconds())
	}

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
