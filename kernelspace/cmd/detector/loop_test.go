package main

import (
	"errors"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window/memsource"
)

const length = epoch.DefaultLength

// first is the epoch the simulated run starts in.
const first epoch.Epoch = 5_000_001

// fakeClock is a simulated CLOCK_TAI. wait advances it instead of
// sleeping, and reports an interrupt once it reaches interruptAt.
type fakeClock struct {
	now         time.Time
	interruptAt time.Time
	waits       []time.Duration
}

func (f *fakeClock) clock() time.Time { return f.now }

func (f *fakeClock) wait(d time.Duration) bool {
	f.waits = append(f.waits, d)

	if !f.interruptAt.IsZero() && !f.now.Add(d).Before(f.interruptAt) {
		f.now = f.interruptAt
		return false
	}

	f.now = f.now.Add(d)

	return true
}

// closing records when each window was closed on the simulated clock.
type closing struct {
	epoch epoch.Epoch
	at    time.Time
}

type testRun struct {
	f      *fakeClock
	src    *memsource.Source
	agg    *window.Aggregator
	l      *loop
	closed []closing

	// onClose, if set, runs inside the callback, e.g. to make the
	// evaluation slow.
	onClose func()
}

// newTestRun starts the simulated clock a third of the way into first.
func newTestRun(t *testing.T) *testRun {
	t.Helper()

	r := &testRun{
		f:   &fakeClock{now: first.Start(length).Add(length / 3)},
		src: memsource.New(),
	}

	var err error

	r.agg, err = window.NewAggregator(window.DefaultConfig(), r.src, r.f.clock, func(c window.Closed) error {
		r.closed = append(r.closed, closing{c.Window.Epoch, r.f.now})
		if r.onClose != nil {
			r.onClose()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	r.l = &loop{agg: r.agg, clock: r.f.clock, wait: r.f.wait, tick: func() {}}

	return r
}

func TestLoop_ClosesEachWindowAfterTheGracePeriod(t *testing.T) {
	r := newTestRun(t)
	r.f.interruptAt = (first + 4).Start(length).Add(length / 2)

	reason, err := r.l.run(time.Time{})
	if err != nil || reason != report.EndInterrupted {
		t.Fatalf("run = %q, %v; want interrupted", reason, err)
	}

	// The start window is discarded; first+1 .. first+3 have ended before
	// the interrupt in the middle of first+4.
	if len(r.closed) != 3 {
		t.Fatalf("closed %+v, want epochs %d to %d", r.closed, first+1, first+3)
	}

	for i, c := range r.closed {
		e := first + 1 + epoch.Epoch(i)

		if c.epoch != e {
			t.Errorf("window %d: epoch %d, want %d", i, c.epoch, e)
		}

		// Not earlier, so the last packets have landed, and not later, so
		// detection is not delayed.
		if want := e.End(length).Add(grace); !c.at.Equal(want) {
			t.Errorf("epoch %d closed %v after its end, want %v", e, c.at.Sub(e.End(length)), grace)
		}
	}

	if st := r.agg.Stats(); st.Discarded != 1 || st.Jumps != 0 {
		t.Errorf("Stats = %+v, want only the start window discarded", st)
	}
}

func TestLoop_DurationEndsRun(t *testing.T) {
	r := newTestRun(t)
	end := r.f.now.Add(2 * time.Second)

	reason, err := r.l.run(end)
	if err != nil || reason != report.EndDurationReached {
		t.Fatalf("run = %q, %v; want duration_reached", reason, err)
	}

	if r.f.now.After(end) {
		t.Errorf("run ended %v after the duration", r.f.now.Sub(end))
	}

	// Every window that ended before end was closed.
	for _, c := range r.closed {
		if c.epoch.End(length).After(end) {
			t.Errorf("epoch %d closed although it ends after the run", c.epoch)
		}
	}
	if last := r.closed[len(r.closed)-1].epoch; last.End(length).Add(length).Before(end) {
		t.Errorf("last closed epoch %d; a later one also ended before the run did", last)
	}
}

func TestLoop_InterruptBeforeFirstDeadline(t *testing.T) {
	r := newTestRun(t)
	r.f.interruptAt = r.f.now.Add(time.Millisecond)

	if reason, _ := r.l.run(time.Time{}); reason != report.EndInterrupted {
		t.Errorf("reason = %q, want interrupted", reason)
	}
	if len(r.closed) != 0 {
		t.Errorf("closed %+v before any window ended", r.closed)
	}
}

func TestLoop_NeverSleepsLongerThanIdlePoll(t *testing.T) {
	r := newTestRun(t)
	r.f.interruptAt = r.f.now.Add(5 * time.Second)

	r.l.run(time.Time{})

	for _, d := range r.f.waits {
		if d > idlePoll || d <= 0 {
			t.Fatalf("waited %v; want 0 < wait <= %v", d, idlePoll)
		}
	}
}

// An evaluation slower than a window makes the loop wake up late. The
// aggregator then discards the window whose slot was cleared too late,
// and the loop carries on on time afterwards.
func TestLoop_RecoversFromASlowEvaluation(t *testing.T) {
	r := newTestRun(t)
	r.f.interruptAt = (first + 10).Start(length).Add(length / 2)

	slowed := false
	r.onClose = func() {
		if !slowed {
			slowed = true
			r.f.now = r.f.now.Add(length + length/2)
		}
	}

	if reason, err := r.l.run(time.Time{}); err != nil || reason != report.EndInterrupted {
		t.Fatalf("run = %q, %v; want interrupted", reason, err)
	}

	st := r.agg.Stats()
	if st.Discarded != 2 || st.Jumps != 0 {
		t.Errorf("Stats = %+v, want the start window and one late window discarded, no jump", st)
	}

	last := r.closed[len(r.closed)-1]
	if want := last.epoch.End(length).Add(grace); !last.at.Equal(want) {
		t.Errorf("after recovering, epoch %d closed at +%v, want on time", last.epoch, last.at.Sub(last.epoch.End(length)))
	}
}

func TestLoop_MapErrorEndsRun(t *testing.T) {
	r := newTestRun(t)

	boom := errors.New("map read failed")
	r.onClose = func() { r.src.Err = boom }

	reason, err := r.l.run(time.Time{})
	if reason != report.EndError || !errors.Is(err, boom) {
		t.Errorf("run = %q, %v; want error %v", reason, err, boom)
	}
}
