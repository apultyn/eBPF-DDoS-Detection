package window

import (
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

const length = epoch.DefaultLength

// t0 lies on a window boundary.
var t0 = time.Unix(1_700_000_000, 0)

var (
	ipA = flow.MustParse("192.0.2.1")
	ipB = flow.MustParse("2001:db8::b")
)

// closedWindow is a copy of what the callback saw, taken before the
// window is recycled.
type closedWindow struct {
	epoch         epoch.Epoch
	start, end    time.Time
	packets       uint64
	skippedBefore int64

	hasPrev     bool
	prevEpoch   epoch.Epoch
	prevPackets uint64

	window, prev *Window
}

type recorder struct {
	closed []closedWindow
}

func (r *recorder) onClose(c Closed) {
	cw := closedWindow{
		epoch:         c.Window.Epoch,
		start:         c.Window.Start,
		end:           c.Window.End,
		packets:       c.Window.Packets,
		skippedBefore: c.Window.SkippedBefore,
		window:        c.Window,
		prev:          c.Prev,
	}

	if c.Prev != nil {
		cw.hasPrev = true
		cw.prevEpoch = c.Prev.Epoch
		cw.prevPackets = c.Prev.Packets
	}

	r.closed = append(r.closed, cw)
}

// pcapConfig is the configuration used when replaying trace files, with
// jumping over long pauses enabled.
func pcapConfig() Config {
	cfg := DefaultConfig()
	cfg.MaxEmpty = PcapMaxEmpty

	return cfg
}

func newTestAggregator(t *testing.T, cfg Config) (*Aggregator, *recorder) {
	t.Helper()

	r := &recorder{}

	a, err := NewAggregator(cfg, r.onClose)
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	return a, r
}

// at returns a packet from src at the given offset from t0.
func at(offset time.Duration, src flow.Key) capture.Packet {
	return capture.Packet{Src: src, Timestamp: t0.Add(offset), Length: 100}
}

// window returns the offset of the middle of the n:th window after t0.
func window(n int) time.Duration {
	return time.Duration(n)*length + length/2
}

func TestAggregator_ClosesOnBoundaries(t *testing.T) {
	a, r := newTestAggregator(t, DefaultConfig())

	a.Observe(at(0, ipA))
	a.Observe(at(length-time.Nanosecond, ipA)) // last instant of window 0
	a.Observe(at(length, ipB))                 // first instant of window 1
	a.Observe(at(window(2), ipA))

	if len(r.closed) != 2 {
		t.Fatalf("closed %d windows, want 2", len(r.closed))
	}

	first, second := r.closed[0], r.closed[1]

	if first.packets != 2 || second.packets != 1 {
		t.Errorf("packets = %d, %d, want 2, 1", first.packets, second.packets)
	}

	if !first.start.Equal(t0) || !first.end.Equal(t0.Add(length)) {
		t.Errorf("first window = [%v, %v), want [%v, %v)", first.start, first.end, t0, t0.Add(length))
	}

	if second.epoch != first.epoch+1 {
		t.Errorf("epochs %d, %d are not consecutive", first.epoch, second.epoch)
	}

	// The first window has no predecessor, so no combined count may be
	// formed for it; the second is paired with the first.
	if first.hasPrev {
		t.Error("first window was handed a previous window")
	}

	if !second.hasPrev || second.prevEpoch != first.epoch || second.prevPackets != 2 {
		t.Errorf("second window's prev = (%v, epoch %d, %d packets), want the first window",
			second.hasPrev, second.prevEpoch, second.prevPackets)
	}
}

func TestAggregator_ShortPauseProducesEmptyWindows(t *testing.T) {
	cfg := pcapConfig()
	a, r := newTestAggregator(t, cfg)

	a.Observe(at(window(0), ipA))
	a.Observe(at(window(cfg.MaxEmpty+1), ipA)) // exactly MaxEmpty empty windows between

	if want := cfg.MaxEmpty + 1; len(r.closed) != want {
		t.Fatalf("closed %d windows, want %d", len(r.closed), want)
	}

	for i, w := range r.closed[1:] {
		if w.packets != 0 {
			t.Errorf("window %d has %d packets, want 0", i+1, w.packets)
		}
		if !w.hasPrev || w.prevEpoch != w.epoch-1 {
			t.Errorf("window %d is not paired with its predecessor", i+1)
		}
	}

	if st := a.Stats(); st.Jumps != 0 || st.Empty != uint64(cfg.MaxEmpty) {
		t.Errorf("Stats = %+v, want %d empty windows and no jump", st, cfg.MaxEmpty)
	}
}

func TestAggregator_LongPauseJumps(t *testing.T) {
	cfg := pcapConfig()
	a, r := newTestAggregator(t, cfg)

	const resume = 1000

	a.Observe(at(window(0), ipA))
	a.Observe(at(window(resume), ipB))
	a.Observe(at(window(resume+1), ipA))

	// Window 0, then MaxEmpty empty windows, then the window the traffic
	// resumed in.
	if want := 1 + cfg.MaxEmpty + 1; len(r.closed) != want {
		t.Fatalf("closed %d windows, want %d", len(r.closed), want)
	}

	resumed := r.closed[len(r.closed)-1]

	if want := r.closed[0].epoch + resume; resumed.epoch != want {
		t.Errorf("resumed in epoch %d, want %d", resumed.epoch, want)
	}

	// Windows 1..MaxEmpty were produced; MaxEmpty+1..resume-1 were not.
	if want := int64(resume - cfg.MaxEmpty - 1); resumed.skippedBefore != want {
		t.Errorf("SkippedBefore = %d, want %d", resumed.skippedBefore, want)
	}

	// The window before the pause is not adjacent, so it must not be
	// combined with the first window after it.
	if resumed.hasPrev {
		t.Error("window after a jump was paired with a window from before the pause")
	}

	if st := a.Stats(); st.Jumps != 1 || st.SkippedEpochs != uint64(resumed.skippedBefore) {
		t.Errorf("Stats = %+v, want one jump over %d epochs", st, resumed.skippedBefore)
	}
}

func TestAggregator_ZeroMaxEmptyNeverJumps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxEmpty = LiveMaxEmpty

	a, r := newTestAggregator(t, cfg)

	const resume = 500

	a.Observe(at(window(0), ipA))

	// A live capture idling for a long time keeps closing windows.
	a.Advance(t0.Add(window(resume - 1)))

	if _, ok := a.Deadline(); !ok {
		t.Error("no deadline while idling with jumping disabled")
	}

	a.Observe(at(window(resume), ipA))
	a.Observe(at(window(resume+1), ipA))

	if len(r.closed) != resume+1 {
		t.Fatalf("closed %d windows, want %d", len(r.closed), resume+1)
	}

	for i, w := range r.closed {
		if w.epoch != r.closed[0].epoch+epoch.Epoch(i) || w.skippedBefore != 0 {
			t.Fatalf("window %d: epoch %d, skipped %d; want continuous numbering", i, w.epoch, w.skippedBefore)
		}
		if i > 0 && !w.hasPrev {
			t.Fatalf("window %d is not paired with its predecessor", i)
		}
	}

	if st := a.Stats(); st.Jumps != 0 || st.Empty != resume-1 {
		t.Errorf("Stats = %+v, want %d empty windows and no jump", st, resume-1)
	}
}

func TestAggregator_AdvanceClosesIdleWindows(t *testing.T) {
	cfg := pcapConfig()
	a, r := newTestAggregator(t, cfg)

	if _, ok := a.Deadline(); ok {
		t.Error("deadline set before the first packet")
	}

	a.Observe(at(window(0), ipA))

	if d, ok := a.Deadline(); !ok || !d.Equal(t0.Add(length)) {
		t.Errorf("Deadline = %v, %v; want end of window 0", d, ok)
	}

	// Traffic stops; the reads time out at each deadline.
	a.Advance(t0.Add(length))
	a.Advance(t0.Add(3 * length))

	if len(r.closed) != 3 {
		t.Fatalf("closed %d windows after idling to window 3, want 3", len(r.closed))
	}

	// Idle far past the limit: only MaxEmpty empty windows are closed,
	// and after that there is nothing to wait for.
	a.Advance(t0.Add(1000 * length))

	if want := 1 + cfg.MaxEmpty; len(r.closed) != want {
		t.Fatalf("closed %d windows after a long idle period, want %d", len(r.closed), want)
	}

	if _, ok := a.Deadline(); ok {
		t.Error("deadline set while waiting out a long pause")
	}

	// Traffic returns and the aggregator jumps.
	a.Observe(at(window(2000), ipB))
	a.Observe(at(window(2001), ipB))

	resumed := r.closed[len(r.closed)-1]

	if resumed.epoch != r.closed[0].epoch+2000 || resumed.hasPrev || resumed.skippedBefore == 0 {
		t.Errorf("resumed window = %+v, want epoch +2000 with a jump and no prev", resumed)
	}
}

func TestAggregator_LatePacketsAreDroppedAndCounted(t *testing.T) {
	a, r := newTestAggregator(t, DefaultConfig())

	a.Observe(at(window(0), ipA))
	a.Observe(at(window(1), ipA))
	a.Observe(at(window(0), ipB)) // reordered: its window has closed
	a.Observe(at(window(0), ipB))
	a.Observe(at(window(2), ipA))

	w := r.closed[1]

	if w.packets != 1 {
		t.Errorf("window 1 has %d packets, want 1: late packets must not be counted in it", w.packets)
	}
	if w.window.Count(ipB) != 0 {
		t.Error("late packet reached the window's sketch")
	}
	if w.window.Late != 2 {
		t.Errorf("window 1 reports %d late packets, want 2", w.window.Late)
	}
	if a.Stats().Late != 2 {
		t.Errorf("Stats().Late = %d, want 2", a.Stats().Late)
	}
}

func TestAggregator_Finish(t *testing.T) {
	a, r := newTestAggregator(t, DefaultConfig())

	if _, ok := a.Finish(); ok {
		t.Error("Finish reported a window before any packet")
	}

	a.Observe(at(window(0), ipA))
	a.Observe(at(window(1), ipA))
	a.Observe(at(window(1), ipB))

	d, ok := a.Finish()
	if !ok || d.Packets != 2 || d.Epoch != r.closed[0].epoch+1 {
		t.Errorf("Finish = %+v, %v; want window 1 with 2 packets", d, ok)
	}

	// The incomplete window is dropped, not handed to the callback.
	if len(r.closed) != 1 {
		t.Errorf("closed %d windows, want 1", len(r.closed))
	}
}

func TestAggregator_RecyclesTwoWindows(t *testing.T) {
	a, r := newTestAggregator(t, DefaultConfig())

	for i := 0; i < 50; i++ {
		a.Observe(at(window(i), ipA))
	}

	seen := map[*Window]bool{}
	for _, w := range r.closed {
		seen[w.window] = true
	}

	if len(seen) != 2 {
		t.Errorf("used %d distinct windows, want 2", len(seen))
	}

	// The previous window handed over must be the one closed just
	// before, not a copy.
	for i := 1; i < len(r.closed); i++ {
		if r.closed[i].prev != r.closed[i-1].window {
			t.Fatalf("window %d was paired with the wrong previous window", i)
		}
	}
}

func TestWindow_CountSources(t *testing.T) {
	for _, src := range []CountSource{CountHeavyKeeper, CountCountMin} {
		t.Run(src.String(), func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Counts = src

			var (
				counts []uint64
				tops   []flow.Key
			)

			a, err := NewAggregator(cfg, func(c Closed) {
				counts = append(counts, c.Window.Count(ipA))

				if cand := c.Window.Candidates(); len(cand) > 0 {
					tops = append(tops, cand[0].Item)
				}
			})
			if err != nil {
				t.Fatal(err)
			}

			for i := 0; i < 300; i++ {
				a.Observe(at(time.Duration(i)*time.Millisecond, ipA))
			}
			for i := 0; i < 10; i++ {
				a.Observe(at(window(1), ipB))
			}
			a.Observe(at(window(2), ipB))

			// A single flow is counted exactly by both structures, and a
			// recycled window must start again from zero.
			if len(counts) != 2 || counts[0] != 300 || counts[1] != 0 {
				t.Errorf("counts for %v = %v, want [300 0]", ipA, counts)
			}

			if len(tops) != 2 || tops[0] != ipA || tops[1] != ipB {
				t.Errorf("top candidates = %v, want [%v %v]", tops, ipA, ipB)
			}
		})
	}
}

func TestParseCountSource(t *testing.T) {
	for in, want := range map[string]CountSource{
		"heavykeeper": CountHeavyKeeper,
		"hk":          CountHeavyKeeper,
		"countmin":    CountCountMin,
		"cms":         CountCountMin,
	} {
		if got, err := ParseCountSource(in); err != nil || got != want {
			t.Errorf("ParseCountSource(%q) = %v, %v; want %v", in, got, err, want)
		}
	}

	if _, err := ParseCountSource("exact"); err == nil {
		t.Error("ParseCountSource accepted an unknown source")
	}
}

func TestNewAggregator_ValidatesConfig(t *testing.T) {
	broken := []func(*Config){
		func(c *Config) { c.Length = 0 },
		func(c *Config) { c.MaxEmpty = -1 },
		func(c *Config) { c.Width = 1000 },
		func(c *Config) { c.DecayBase = 1 },
		func(c *Config) { c.K = 0 },
		func(c *Config) { c.Counts = CountCountMin; c.CMSWidth = 0 },
		func(c *Config) { c.Counts = 7 },
	}

	for i, mutate := range broken {
		cfg := DefaultConfig()
		mutate(&cfg)

		if _, err := NewAggregator(cfg, func(Closed) {}); err == nil {
			t.Errorf("config %d was accepted", i)
		}
	}
}

func BenchmarkObserve(b *testing.B) {
	for _, src := range []CountSource{CountHeavyKeeper, CountCountMin} {
		b.Run(src.String(), func(b *testing.B) {
			cfg := DefaultConfig()
			cfg.Counts = src

			a, err := NewAggregator(cfg, func(Closed) {})
			if err != nil {
				b.Fatal(err)
			}

			keys := make([]flow.Key, 4096)
			for i := range keys {
				keys[i] = flow.FromIPv4([]byte{10, 0, byte(i >> 8), byte(i)})
			}

			// Spread the packets over many windows so closing and
			// recycling are part of the measurement.
			step := length / 10_000

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				a.Observe(capture.Packet{
					Src:       keys[i%len(keys)],
					Timestamp: t0.Add(time.Duration(i) * step),
					Length:    100,
				})
			}
		})
	}
}
