package window

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window/memsource"
)

var (
	ipA = flow.MustParse("10.0.0.1")
	ipB = flow.MustParse("10.0.0.2")
	ipC = flow.MustParse("2001:db8::1")
)

const length = epoch.DefaultLength

// first is the epoch the tests start in. It is not a multiple of the slot
// count, so a test that confused epochs with slots would fail.
const first epoch.Epoch = 1_000_001

// at returns a time inside epoch e: offset into it, which must be less
// than one window.
func at(e epoch.Epoch, offset time.Duration) time.Time {
	return e.Start(length).Add(offset)
}

func slotOf(e epoch.Epoch) int {
	return int(e) & (heavykeeper.Slots - 1)
}

// closedWindow is a copy of what the callback saw, since the windows
// themselves are recycled.
type closedWindow struct {
	epoch      epoch.Epoch
	slot       int
	skipped    int64
	packets    uint64
	bytes      uint64
	candidates []heavykeeper.TopKEntry
	prev       epoch.Epoch // -1 when there was no Prev
	countA     uint64
	prevCountA uint64
}

type recorder struct {
	closed []closedWindow
	err    error

	// during, if set, runs inside the callback, e.g. to make it slow.
	during func()
}

func (r *recorder) onClose(c Closed) error {
	w := c.Window

	cw := closedWindow{
		epoch:      w.Epoch,
		slot:       w.Slot(),
		skipped:    w.SkippedBefore,
		packets:    w.Packets,
		bytes:      w.Bytes,
		candidates: w.Candidates(),
		prev:       -1,
	}

	var err error
	if cw.countA, err = w.Count(ipA); err != nil {
		return err
	}

	if c.Prev != nil {
		cw.prev = c.Prev.Epoch
		if cw.prevCountA, err = c.Prev.Count(ipA); err != nil {
			return err
		}
	}

	r.closed = append(r.closed, cw)

	if r.during != nil {
		r.during()
	}

	return r.err
}

// fakeTAI is a simulated CLOCK_TAI that only moves when a test sets it.
type fakeTAI struct {
	now time.Time
}

func (c *fakeTAI) read() time.Time { return c.now }

// tick moves the clock to now and ticks a, the way the live loop wakes up
// at now.
func (c *fakeTAI) tick(a *Aggregator, now time.Time) error {
	c.now = now
	return a.Tick()
}

func newTestAggregator(t *testing.T) (*Aggregator, *memsource.Source, *recorder, *fakeTAI) {
	t.Helper()

	src := memsource.New()
	r := &recorder{}
	clk := &fakeTAI{}

	a, err := NewAggregator(DefaultConfig(), src, clk.read, r.onClose)
	if err != nil {
		t.Fatal(err)
	}

	return a, src, r, clk
}

// run plays the kernel and the detector loop together: for each epoch it
// adds that epoch's traffic to its slot, then ticks just past its end, the
// way the live loop wakes up after each deadline.
func run(t *testing.T, a *Aggregator, clk *fakeTAI, src *memsource.Source, from, to epoch.Epoch, traffic func(e epoch.Epoch, slot int)) {
	t.Helper()

	for e := from; e <= to; e++ {
		traffic(e, slotOf(e))

		if err := clk.tick(a, at(e+1, time.Millisecond)); err != nil {
			t.Fatalf("Tick after epoch %d: %v", e, err)
		}
	}
}

func TestTick_FirstWindowIsDiscarded(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, length/2)); err != nil {
		t.Fatal(err)
	}

	// Starting clears every slot.
	if want := []int{0, 1, 2, 3}; !slices.Equal(src.Resets, want) {
		t.Errorf("Resets after start = %v, want %v", src.Resets, want)
	}

	// The kernel was already counting the first window before the
	// aggregator started, so its slot does not hold all of it.
	src.Add(slotOf(first), ipA, 7, 700)

	if err := clk.tick(a, at(first+1, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if len(r.closed) != 0 {
		t.Fatalf("first window was evaluated: %+v", r.closed)
	}
	if st := a.Stats(); st.Discarded != 1 || st.Closed != 0 {
		t.Errorf("Stats = %+v, want 1 discarded and none closed", st)
	}
}

func TestTick_ReadsEachWindowFromItsSlot(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	// Each epoch e gets 10*(e-first) packets from ipA, so every window
	// has a distinct count that can only come from its own slot.
	run(t, a, clk, src, first, first+6, func(e epoch.Epoch, slot int) {
		n := uint32(10 * (e - first))
		if n > 0 {
			src.Add(slot, ipA, n, uint64(n)*100)
		}
		src.Add(slot, ipB, 1, 60)
	})

	if len(r.closed) != 6 {
		t.Fatalf("%d windows closed, want 6 (all but the first)", len(r.closed))
	}

	for i, c := range r.closed {
		e := first + 1 + epoch.Epoch(i)
		wantA := uint64(10 * (e - first))

		if c.epoch != e || c.slot != slotOf(e) {
			t.Errorf("window %d: epoch %d slot %d, want epoch %d slot %d", i, c.epoch, c.slot, e, slotOf(e))
		}
		if c.packets != wantA+1 || c.bytes != wantA*100+60 {
			t.Errorf("epoch %d: totals %d packets %d bytes, want %d, %d", e, c.packets, c.bytes, wantA+1, wantA*100+60)
		}
		if c.countA != wantA {
			t.Errorf("epoch %d: Count(ipA) = %d, want %d", e, c.countA, wantA)
		}
		if len(c.candidates) == 0 || c.candidates[0].Item != ipA {
			t.Errorf("epoch %d: candidates %v, want ipA first", e, c.candidates)
		}
	}
}

func TestTick_PrevOnlyForAdjacentCleanWindows(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	run(t, a, clk, src, first, first+3, func(e epoch.Epoch, slot int) {
		src.Add(slot, ipA, uint32(e-first+1), 0)
	})

	// The first evaluated window's predecessor is the discarded start
	// window, so it has no Prev; every later one is combined with the
	// window before it, read from that window's own slot.
	if r.closed[0].prev != -1 {
		t.Errorf("epoch %d combined with the discarded start window", r.closed[0].epoch)
	}

	for _, c := range r.closed[1:] {
		if c.prev != c.epoch-1 {
			t.Errorf("epoch %d: Prev = %d, want %d", c.epoch, c.prev, c.epoch-1)
		}
		if want := uint64(c.epoch - 1 - first + 1); c.prevCountA != want {
			t.Errorf("epoch %d: Prev.Count(ipA) = %d, want %d", c.epoch, c.prevCountA, want)
		}
	}
}

// The core safety property: closing window e clears slot e+2 and never a
// slot that is still being read (e, e-1) or written by the kernel (e+1).
func TestTick_ClearsTheSlotTwoAhead(t *testing.T) {
	a, src, _, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	for e := first; e < first+8; e++ {
		before := len(src.Resets)

		if err := clk.tick(a, at(e+1, time.Millisecond)); err != nil {
			t.Fatal(err)
		}

		got := src.Resets[before:]
		if want := []int{slotOf(e + 2)}; !slices.Equal(got, want) {
			t.Fatalf("closing epoch %d reset slots %v, want %v", e, got, want)
		}
	}
}

func TestTick_CandidatesCappedAtK(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	run(t, a, clk, src, first, first+1, func(e epoch.Epoch, slot int) {
		for i := 0; i < heavykeeper.K; i++ {
			src.Add(slot, flow.FromIPv4([]byte{10, 2, 0, byte(i)}), uint32(i+1), 0)
		}
	})

	if got, want := len(r.closed[0].candidates), DefaultConfig().K; got != want {
		t.Errorf("%d candidates, want %d", got, want)
	}
}

// Falling one window behind: the kernel is already in e+2 when e closes,
// so e+2's slot is cleared too late and e+2 must be discarded, and e+3
// may not be combined with it.
func TestTick_SlightlyBehindDiscardsTheUnclearedWindow(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	// Close the start window on time, so the aggregator is current up to
	// e, then miss e's deadline.
	e := first + 1
	run(t, a, clk, src, first, e-1, func(epoch.Epoch, int) {})

	src.Add(slotOf(e), ipA, 5, 0)
	src.Add(slotOf(e+1), ipA, 6, 0)

	// Wake up late, already inside e+2.
	if err := clk.tick(a, at(e+2, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	src.Add(slotOf(e+2), ipA, 7, 0)
	if err := clk.tick(a, at(e+3, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	src.Add(slotOf(e+3), ipA, 8, 0)
	if err := clk.tick(a, at(e+4, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	var epochs []epoch.Epoch
	for _, c := range r.closed {
		epochs = append(epochs, c.epoch)
	}

	// e and e+1 are intact; e+2 is not.
	if slices.Contains(epochs, e+2) {
		t.Errorf("epoch %d was evaluated although its slot was cleared too late; closed %v", e+2, epochs)
	}
	for _, want := range []epoch.Epoch{e, e + 1, e + 3} {
		if !slices.Contains(epochs, want) {
			t.Errorf("epoch %d not evaluated; closed %v", want, epochs)
		}
	}

	last := r.closed[len(r.closed)-1]
	if last.epoch != e+3 || last.prev != -1 {
		t.Errorf("epoch %d: Prev = %d, want none since %d was discarded", last.epoch, last.prev, e+2)
	}
	if last.skipped != 1 {
		t.Errorf("epoch %d: SkippedBefore = %d, want 1 for the discarded %d", last.epoch, last.skipped, e+2)
	}
	if r.closed[0].skipped != 0 {
		t.Errorf("first evaluated window reports %d skipped; the start window is not a gap", r.closed[0].skipped)
	}
	if st := a.Stats(); st.Jumps != 0 {
		t.Errorf("Stats = %+v, want no jump for a one-window delay", st)
	}
}

// Waking up on time but evaluating slowly is the same hazard as waking
// up late: if the callback for e runs into e+2, slot e+2 is cleared after
// the kernel began writing it, and e+2 must be discarded.
func TestTick_SlowCallbackDiscardsTheUnclearedWindow(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	e := first + 1
	run(t, a, clk, src, first, first, func(epoch.Epoch, int) {})

	// The callback for e takes a window and a half.
	r.during = func() {
		if r.closed[len(r.closed)-1].epoch == e {
			clk.now = clk.now.Add(length + length/2)
		}
	}

	src.Add(slotOf(e), ipA, 1, 0)
	if err := clk.tick(a, at(e+1, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	// The same Tick noticed that e+1 had ended meanwhile and closed it.
	r.during = nil
	run(t, a, clk, src, e+2, e+4, func(ep epoch.Epoch, slot int) {
		src.Add(slot, ipA, 1, 0)
	})

	var epochs []epoch.Epoch
	for _, c := range r.closed {
		epochs = append(epochs, c.epoch)
	}

	if slices.Contains(epochs, e+2) {
		t.Errorf("epoch %d was evaluated although its slot was cleared after the kernel reached it; closed %v", e+2, epochs)
	}
	for _, want := range []epoch.Epoch{e, e + 1, e + 3, e + 4} {
		if !slices.Contains(epochs, want) {
			t.Errorf("epoch %d not evaluated; closed %v", want, epochs)
		}
	}
}

func TestTick_FarBehindJumps(t *testing.T) {
	a, src, r, clk := newTestAggregator(t)

	if err := clk.tick(a, at(first, 0)); err != nil {
		t.Fatal(err)
	}

	run(t, a, clk, src, first, first+2, func(e epoch.Epoch, slot int) {
		src.Add(slot, ipA, 1, 0)
	})
	before := len(r.closed)

	// A stall: the next wake-up is well past every slot's reuse.
	resume := first + 3 + 10
	if err := clk.tick(a, at(resume, time.Millisecond)); err != nil {
		t.Fatal(err)
	}

	if len(r.closed) != before {
		t.Errorf("windows evaluated across the stall: %+v", r.closed[before:])
	}

	st := a.Stats()
	if st.Jumps != 1 || st.SkippedEpochs != 10 {
		t.Errorf("Stats = %+v, want 1 jump over 10 epochs", st)
	}

	// The window open at the resume is discarded like the start window.
	// The first window evaluated after it reports the whole gap: the 10
	// lost epochs plus the discarded resume window.
	run(t, a, clk, src, resume, resume+2, func(e epoch.Epoch, slot int) {
		src.Add(slot, ipA, 2, 0)
	})

	after := r.closed[before:]
	if len(after) != 2 || after[0].epoch != resume+1 {
		t.Fatalf("after the jump closed %+v, want epochs %d and %d", after, resume+1, resume+2)
	}
	if after[0].prev != -1 {
		t.Errorf("first window after the jump was combined with %d", after[0].prev)
	}
	if after[0].skipped != 11 {
		t.Errorf("first window after the jump: SkippedBefore = %d, want 11", after[0].skipped)
	}
	if after[1].skipped != 0 || after[1].prev != resume+1 {
		t.Errorf("second window after the jump: %+v, want no gap and Prev %d", after[1], resume+1)
	}
}

func TestTick_ErrorsArePropagated(t *testing.T) {
	t.Run("map read", func(t *testing.T) {
		a, src, _, clk := newTestAggregator(t)

		if err := clk.tick(a, at(first, 0)); err != nil {
			t.Fatal(err)
		}
		run(t, a, clk, src, first, first, func(epoch.Epoch, int) {})

		boom := errors.New("map read failed")
		src.Err = boom

		if err := clk.tick(a, at(first+2, time.Millisecond)); !errors.Is(err, boom) {
			t.Errorf("Tick error = %v, want %v", err, boom)
		}
	})

	t.Run("callback", func(t *testing.T) {
		a, src, r, clk := newTestAggregator(t)

		boom := errors.New("write failed")
		r.err = boom

		if err := clk.tick(a, at(first, 0)); err != nil {
			t.Fatal(err)
		}
		run(t, a, clk, src, first, first, func(epoch.Epoch, int) {})

		if err := clk.tick(a, at(first+2, time.Millisecond)); !errors.Is(err, boom) {
			t.Errorf("Tick error = %v, want %v", err, boom)
		}
	})
}

func TestDeadlineAndFinish(t *testing.T) {
	a, src, _, clk := newTestAggregator(t)

	if _, ok := a.Deadline(); ok {
		t.Error("Deadline before the first Tick")
	}
	if _, ok := a.Finish(); ok {
		t.Error("Finish before the first Tick")
	}

	if err := clk.tick(a, at(first, length/2)); err != nil {
		t.Fatal(err)
	}

	if d, ok := a.Deadline(); !ok || !d.Equal(first.End(length)) {
		t.Errorf("Deadline = %v, %v; want end of epoch %d", d, ok, first)
	}

	src.Add(slotOf(first), ipC, 3, 300)

	d, ok := a.Finish()
	if !ok || d.Epoch != first || d.Packets != 3 || d.Bytes != 300 {
		t.Errorf("Finish = %+v, %v; want epoch %d with 3 packets, 300 bytes", d, ok, first)
	}
}

func TestConfigValidation(t *testing.T) {
	src := memsource.New()
	noop := func(Closed) error { return nil }

	if _, err := NewAggregator(DefaultConfig(), src, time.Now, noop); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}

	for name, mutate := range map[string]func(*Config){
		"length differs from the kernel's": func(c *Config) { c.Length = 500 * time.Millisecond },
		"k zero":                           func(c *Config) { c.K = 0 },
		"k above the Top-K table":          func(c *Config) { c.K = heavykeeper.K + 1 },
	} {
		cfg := DefaultConfig()
		mutate(&cfg)

		if _, err := NewAggregator(cfg, src, time.Now, noop); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

var _ Source = (*memsource.Source)(nil)
