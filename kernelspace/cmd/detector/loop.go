package main

import (
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

// grace is how long the loop waits after a window ends before closing it.
//
// XDP stamps a packet when it starts processing it. A packet stamped just
// before a boundary may still be updating the maps on another CPU when the
// boundary passes, so closing the window right on the boundary could read
// its slot a moment before the last packets land. The grace period only
// adds to the detection delay.
const grace = 10 * time.Millisecond

// idlePoll bounds how long the loop sleeps at once, so that progress is
// printed even when a window is long overdue.
const idlePoll = time.Second

// loop closes windows as time passes. It holds no packets: the kernel
// counts them, and the loop only wakes up after each window has ended.
type loop struct {
	agg *window.Aggregator

	// clock is CLOCK_TAI, the clock XDP picks a packet's window by.
	clock func() time.Time

	// wait sleeps for d and reports whether it slept the whole time; it
	// returns false early when the run is interrupted.
	wait func(d time.Duration) bool

	// tick is called on every wake-up for progress reporting.
	tick func()
}

// run closes windows until it is interrupted or end, a CLOCK_TAI time, is
// reached. A zero end means no time limit.
func (l *loop) run(end time.Time) (string, error) {
	if err := l.agg.Tick(); err != nil {
		return report.EndError, err
	}

	for {
		now := l.clock()

		if !end.IsZero() && !now.Before(end) {
			return report.EndDurationReached, nil
		}

		wake, _ := l.agg.Deadline()
		wake = wake.Add(grace)

		if !end.IsZero() && end.Before(wake) {
			wake = end
		}

		d := wake.Sub(now)
		if d > idlePoll {
			d = idlePoll
		}

		if d > 0 && !l.wait(d) {
			return report.EndInterrupted, nil
		}

		if err := l.agg.Tick(); err != nil {
			return report.EndError, err
		}

		l.tick()
	}
}
