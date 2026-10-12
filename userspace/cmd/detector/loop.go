package main

import (
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

// liveGrace is how long a quiet window is held open after it ends before
// it is closed on the clock.
//
// The kernel timestamps a packet when the driver hands it over, slightly
// before it is queued on the socket. Without a grace period, a packet
// stamped just before a boundary could still be on its way to the socket
// when the read deadline fires, and would then arrive after its window
// had closed. The grace period adds to the detection delay of quiet
// windows only; a window followed by traffic closes on the first packet
// past its end.
const liveGrace = 10 * time.Millisecond

// idlePoll bounds how long a live read waits when no window is due, so
// that an interrupt is noticed even before the first packet arrives.
const idlePoll = time.Second

// checkEvery is how many packets pass between checks of the stop flag
// and the progress clock; checking every packet would cost more than the
// rest of the loop.
const checkEvery = 1 << 16

// liveSource is a source that can be woken by a deadline.
type liveSource interface {
	capture.Source
	SetDeadline(time.Time) error
}

// loop holds what both read loops share.
type loop struct {
	agg  *window.Aggregator
	stop *atomic.Bool

	// failed reports an error from writing results, which ends the run.
	failed func() error

	// tick is called periodically for progress reporting.
	tick func()
}

// trace reads a trace replay to the end.
func (l *loop) trace(src capture.Source) (string, error) {
	for n := 0; ; n++ {
		if n%checkEvery == 0 {
			if l.stop.Load() {
				return report.EndInterrupted, nil
			}

			l.tick()
		}

		p, err := src.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return report.EndSourceEnded, nil
			}
			return report.EndError, err
		}

		l.agg.Observe(p)

		if err := l.failed(); err != nil {
			return report.EndError, err
		}
	}
}

// live reads a live capture until it is interrupted or end is reached.
// A zero end means no time limit. clock is the wall clock, replaceable in
// tests.
//
// Windows are closed by packets when traffic flows, and by the read
// deadline when it does not: the deadline is set to the end of the
// current window plus liveGrace, and when it passes with no packet the
// aggregator is advanced to the current time.
func (l *loop) live(src liveSource, end time.Time, clock func() time.Time) (string, error) {
	var deadline time.Time

	for n := 0; ; n++ {
		if l.stop.Load() {
			return report.EndInterrupted, nil
		}

		if n%checkEvery == 0 {
			l.tick()
		}

		// Changing the deadline costs a timer update, so it is only done
		// when the deadline actually moves, about twice per second.
		if d := l.deadline(end, clock); !d.Equal(deadline) {
			if err := src.SetDeadline(d); err != nil {
				return report.EndError, err
			}
			deadline = d
		}

		p, err := src.Next()

		switch {
		case err == nil:
			if !end.IsZero() && !p.Timestamp.Before(end) {
				return report.EndDurationReached, nil
			}

			l.agg.Observe(p)

		case errors.Is(err, capture.ErrTimeout):
			now := clock()

			if !end.IsZero() && !now.Before(end) {
				return report.EndDurationReached, nil
			}

			l.agg.Advance(now.Add(-liveGrace))
			l.tick()

		case errors.Is(err, capture.ErrClosed):
			return report.EndInterrupted, nil

		default:
			return report.EndError, err
		}

		if err := l.failed(); err != nil {
			return report.EndError, err
		}
	}
}

// deadline returns when the next live read should give up.
func (l *loop) deadline(end time.Time, clock func() time.Time) time.Time {
	d, ok := l.agg.Deadline()
	if ok {
		d = d.Add(liveGrace)
	} else {
		d = clock().Add(idlePoll)
	}

	if !end.IsZero() && end.Before(d) {
		d = end
	}

	return d
}
