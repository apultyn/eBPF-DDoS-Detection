package main

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

const length = epoch.DefaultLength

// t0 lies on a window boundary.
var t0 = time.Unix(1_700_000_000, 0)

var src = flow.MustParse("192.0.2.1")

// fakeLive simulates a live socket on a simulated clock. Packets arrive
// at scripted times; a read returns the next packet if it arrives before
// the deadline, and otherwise moves the clock to the deadline and times
// out. Once the clock reaches closeAt the source behaves as if Ctrl-C
// had closed it.
type fakeLive struct {
	arrivals []time.Time
	next     int

	now      time.Time
	deadline time.Time
	closeAt  time.Time

	deadlineCalls int
}

func (f *fakeLive) clock() time.Time { return f.now }

func (f *fakeLive) SetDeadline(t time.Time) error {
	f.deadline = t
	f.deadlineCalls++
	return nil
}

func (f *fakeLive) Next() (capture.Packet, error) {
	if f.next < len(f.arrivals) {
		at := f.arrivals[f.next]

		if f.deadline.IsZero() || at.Before(f.deadline) {
			f.now = at
			f.next++
			return capture.Packet{Src: src, Timestamp: at, Length: 100}, nil
		}
	}

	if !f.closeAt.IsZero() && !f.deadline.Before(f.closeAt) {
		f.now = f.closeAt
		return capture.Packet{}, capture.ErrClosed
	}

	if f.deadline.IsZero() {
		return capture.Packet{}, capture.ErrClosed
	}

	f.now = f.deadline

	return capture.Packet{}, capture.ErrTimeout
}

func (f *fakeLive) Stats() capture.Stats { return capture.Stats{} }
func (f *fakeLive) Close() error         { return nil }

// closing records when each window was closed on the simulated clock.
type closing struct {
	epoch   epoch.Epoch
	at      time.Time
	packets uint64
	skipped int64
}

func newLoop(t *testing.T, f *fakeLive, cfg window.Config) (*loop, *[]closing) {
	t.Helper()

	// The simulated clock starts at t0, as a real one would be near the
	// first packet.
	if f.now.IsZero() {
		f.now = t0
	}

	var closed []closing

	agg, err := window.NewAggregator(cfg, func(c window.Closed) {
		closed = append(closed, closing{c.Window.Epoch, f.now, c.Window.Packets, c.Window.SkippedBefore})
	})
	if err != nil {
		t.Fatal(err)
	}

	l := &loop{
		agg:    agg,
		stop:   &atomic.Bool{},
		failed: func() error { return nil },
		tick:   func() {},
	}

	return l, &closed
}

func liveConfig() window.Config {
	cfg := window.DefaultConfig()
	cfg.MaxEmpty = window.LiveMaxEmpty

	return cfg
}

// every returns arrival times from from to to (exclusive) at the given
// spacing, as offsets from t0.
func every(from, to, step time.Duration) []time.Time {
	var out []time.Time
	for d := from; d < to; d += step {
		out = append(out, t0.Add(d))
	}
	return out
}

func TestLive_ClosesQuietWindowsOnTime(t *testing.T) {
	f := &fakeLive{
		arrivals: every(0, 400*time.Millisecond, 10*time.Millisecond),
		closeAt:  t0.Add(3*length + length/2),
	}

	l, closed := newLoop(t, f, liveConfig())

	reason, err := l.live(f, time.Time{}, f.clock)
	if err != nil || reason != report.EndInterrupted {
		t.Fatalf("live = %q, %v; want interrupted", reason, err)
	}

	// Traffic only in window 0; windows 0, 1 and 2 have ended before the
	// source closes in the middle of window 3.
	if len(*closed) != 3 {
		t.Fatalf("closed %d windows, want 3", len(*closed))
	}

	for i, c := range *closed {
		end := t0.Add(time.Duration(i+1) * length)

		// With no packet after it, a window closes on the deadline: its
		// end plus the grace period, not earlier and not later.
		if want := end.Add(liveGrace); !c.at.Equal(want) {
			t.Errorf("window %d closed at %v, want %v", i, c.at.Sub(t0), want.Sub(t0))
		}

		if c.skipped != 0 {
			t.Errorf("window %d: live capture jumped over %d epochs", i, c.skipped)
		}
	}

	if (*closed)[0].packets != 40 || (*closed)[1].packets != 0 {
		t.Errorf("packets = %d, %d; want 40, 0", (*closed)[0].packets, (*closed)[1].packets)
	}
}

func TestLive_TrafficClosesWindowsWithoutWaiting(t *testing.T) {
	f := &fakeLive{
		arrivals: every(0, 2*time.Second, 5*time.Millisecond),
		closeAt:  t0.Add(2 * time.Second),
	}

	l, closed := newLoop(t, f, liveConfig())
	l.live(f, time.Time{}, f.clock)

	// Each window closes on the first packet of the next one, without the
	// grace period.
	for i, c := range (*closed)[:3] {
		if want := t0.Add(time.Duration(i+1) * length); !c.at.Equal(want) {
			t.Errorf("window %d closed at %v, want %v", i, c.at.Sub(t0), want.Sub(t0))
		}
	}

	// About two deadline changes per second of capture, not one per packet.
	if f.deadlineCalls > 10 {
		t.Errorf("deadline set %d times for 400 packets", f.deadlineCalls)
	}
}

func TestLive_DurationEndsRun(t *testing.T) {
	tests := []struct {
		name     string
		arrivals []time.Time
	}{
		{"with traffic", every(0, 5*time.Second, 10*time.Millisecond)},
		{"in silence", every(0, 100*time.Millisecond, 10*time.Millisecond)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeLive{arrivals: tt.arrivals}
			l, closed := newLoop(t, f, liveConfig())

			end := t0.Add(2 * time.Second)

			reason, err := l.live(f, end, f.clock)
			if err != nil || reason != report.EndDurationReached {
				t.Fatalf("live = %q, %v; want duration_reached", reason, err)
			}

			if f.now.After(end) {
				t.Errorf("run ended at %v, after the duration", f.now.Sub(t0))
			}

			// Windows ending at or before 1.5 s are closed; the one ending at
			// 2 s is the incomplete last window.
			if len(*closed) != 3 {
				t.Errorf("closed %d windows, want 3", len(*closed))
			}
		})
	}
}

func TestLive_StopFlagEndsRun(t *testing.T) {
	f := &fakeLive{arrivals: every(0, time.Second, 10*time.Millisecond)}
	l, _ := newLoop(t, f, liveConfig())

	l.stop.Store(true)

	if reason, _ := l.live(f, time.Time{}, f.clock); reason != report.EndInterrupted {
		t.Errorf("reason = %q, want interrupted", reason)
	}
}

func TestLive_WaitsBeforeFirstPacket(t *testing.T) {
	// Nothing arrives for 3.2 s. Reads must still time out regularly so
	// an interrupt is noticed, but no window exists to close yet.
	f := &fakeLive{
		arrivals: every(3200*time.Millisecond, 3300*time.Millisecond, 10*time.Millisecond),
		closeAt:  t0.Add(4 * time.Second),
	}

	l, closed := newLoop(t, f, liveConfig())
	l.live(f, time.Time{}, f.clock)

	if len(*closed) == 0 || (*closed)[0].epoch != epoch.Of(t0.Add(3200*time.Millisecond), length) {
		t.Errorf("first window = %+v, want the one the first packet fell in", *closed)
	}

	if f.deadlineCalls < 3 {
		t.Errorf("deadline set %d times while idle, want a poll about every %v", f.deadlineCalls, idlePoll)
	}
}

// sliceSource replays fixed packets and then ends, like a trace file.
type sliceSource struct {
	packets []capture.Packet
}

func (s *sliceSource) Next() (capture.Packet, error) {
	if len(s.packets) == 0 {
		return capture.Packet{}, io.EOF
	}

	p := s.packets[0]
	s.packets = s.packets[1:]

	return p, nil
}

func (s *sliceSource) Stats() capture.Stats { return capture.Stats{} }
func (s *sliceSource) Close() error         { return nil }

func TestTrace_EndReasons(t *testing.T) {
	packets := []capture.Packet{
		{Src: src, Timestamp: t0},
		{Src: src, Timestamp: t0.Add(length)},
	}

	l, closed := newLoop(t, &fakeLive{}, window.DefaultConfig())

	if reason, err := l.trace(&sliceSource{packets}); err != nil || reason != report.EndSourceEnded {
		t.Errorf("trace = %q, %v; want source_ended", reason, err)
	}
	if len(*closed) != 1 {
		t.Errorf("closed %d windows, want 1", len(*closed))
	}

	l, _ = newLoop(t, &fakeLive{}, window.DefaultConfig())
	l.stop.Store(true)

	if reason, _ := l.trace(&sliceSource{packets}); reason != report.EndInterrupted {
		t.Errorf("reason = %q, want interrupted", reason)
	}
}
