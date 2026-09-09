package probe

import (
	"time"
)

// BMCOOBDeadline is the out-of-band budget for one BMC sysfs attribute. Sized
// from the host's healthy path (1-2 ms) with a large safety factor, never from
// the KCS worst case of seconds per retry (L40, F44).
const BMCOOBDeadline = 400 * time.Millisecond

// ReadOOB performs a bounded read under a deadline that does not depend on the
// read being interruptible.
//
// A read of a device-adjacent sysfs attribute drives a live bus transaction and
// cannot be cancelled once issued: no context, no SetReadDeadline and no close
// will return control. So the read runs in its own goroutine with a timer, and
// on overrun the caller gets UNKNOWN/TIMEOUT while the goroutine is abandoned —
// never waited on, never joined at scan end (L14, L40, F17).
//
// The result channel is buffered so the abandoned goroutine can always finish
// its send and exit; nothing leaks but the one blocked read itself.
func (r *Reader) ReadOOB(p string, pol Policy, deadline time.Duration) Observation {
	if deadline <= 0 {
		deadline = BMCOOBDeadline
	}
	done := make(chan Observation, 1)
	start := time.Now()
	go func() { done <- r.Read(p, pol) }()

	timer := time.NewTimer(deadline)
	defer timer.Stop()
	select {
	case obs := <-done:
		return obs
	case <-timer.C:
		return Observation{
			Source:  p,
			Kind:    KindFileRead,
			Status:  StatusTimeout,
			Elapsed: time.Since(start),
			Detail:  "read did not return within its " + deadline.String() + " out-of-band budget; the read was abandoned, not cancelled",
		}
	}
}
