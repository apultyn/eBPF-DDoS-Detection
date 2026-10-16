package detector

import (
	"errors"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window/memsource"
)

const length = epoch.DefaultLength

var (
	ipA = flow.MustParse("192.0.2.1")
	ipB = flow.MustParse("2001:db8::b")
)

// traffic is one window's packets per source, as the kernel counts them.
type traffic map[flow.Key]uint32

// harness plays the kernel and the live loop for an aggregator and an
// evaluator: each window's traffic is written to that window's slot, and
// the aggregator is ticked just past the window's end.
type harness struct {
	t   testing.TB
	src *memsource.Source
	agg *window.Aggregator
	ev  *Evaluator

	// next is the epoch the next call to window fills.
	next epoch.Epoch

	results []WindowResult

	// now is the simulated CLOCK_TAI the aggregator reads.
	now time.Time
}

// base is the epoch the harness starts in.
const base epoch.Epoch = 3_000_001

// newHarness starts an aggregator and gets it past its discarded start
// window, so the first call to window produces results[0].
func newHarness(t testing.TB, dcfg Config) *harness {
	t.Helper()

	ev, err := NewEvaluator(dcfg)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, src: memsource.New(), ev: ev, next: base + 1}

	h.agg, err = window.NewAggregator(window.DefaultConfig(), h.src, func() time.Time { return h.now }, func(c window.Closed) error {
		r, err := h.ev.Evaluate(c)
		if err != nil {
			return err
		}
		h.results = append(h.results, r)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	h.tick(base, 0)
	h.tick(base+1, time.Millisecond) // closes and discards the start window

	return h
}

func (h *harness) tick(e epoch.Epoch, offset time.Duration) {
	h.t.Helper()

	h.now = e.Start(length).Add(offset)
	if err := h.agg.Tick(); err != nil {
		h.t.Fatalf("Tick at epoch %d: %v", e, err)
	}
}

func slotOf(e epoch.Epoch) int {
	return int(e) & (heavykeeper.Slots - 1)
}

// window counts tr into the next window and closes it.
func (h *harness) window(tr traffic) {
	h.t.Helper()

	for ip, n := range tr {
		h.src.Add(slotOf(h.next), ip, n, uint64(n)*100)
	}

	h.tick(h.next+1, time.Millisecond)
	h.next++
}

// windows runs one window per element of trs.
func (h *harness) windows(trs ...traffic) []WindowResult {
	h.t.Helper()

	for _, tr := range trs {
		h.window(tr)
	}

	return h.results
}

// stall makes the loop wake up n windows late, so far behind that every
// slot has been reused. The window running when it wakes is discarded,
// and the loop is back on time from its deadline on.
func (h *harness) stall(n int) {
	h.t.Helper()

	h.next += epoch.Epoch(n)
	h.tick(h.next, time.Millisecond)
	h.tick(h.next+1, time.Millisecond)
	h.next++
}

func repeat(n int, tr traffic) []traffic {
	out := make([]traffic, n)
	for i := range out {
		out[i] = tr
	}
	return out
}

func TestEvaluate_CombinesWithPreviousWindow(t *testing.T) {
	results := newHarness(t, DefaultConfig()).windows(
		traffic{ipA: 30, ipB: 5},
		traffic{ipA: 20},
	)

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	r := results[1]

	if !r.Evaluated || r.Packets != 20 || r.EvaluatedPackets != 55 {
		t.Errorf("window 1: evaluated %v, packets %d, evaluated packets %d; want true, 20, 55",
			r.Evaluated, r.Packets, r.EvaluatedPackets)
	}

	// Only A is a candidate in window 1, so B is not evaluated even
	// though it sent packets in window 0.
	if len(r.IPs) != 1 {
		t.Fatalf("got %d IP results, want 1", len(r.IPs))
	}

	ip := r.IPs[0]
	if ip.IP != ipA || ip.Current != 20 || ip.Previous != 30 || ip.Evaluated != 50 {
		t.Errorf("IP result = %+v, want A with 20 + 30 = 50", ip)
	}
}

func TestEvaluate_SkipsWindowWithoutPrevious(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2

	results := newHarness(t, dcfg).windows(repeat(5, traffic{ipA: 10})...)

	if results[0].Evaluated || results[0].IPs != nil || results[0].Verdict != (iqr.Verdict{}) {
		t.Errorf("first window was evaluated: %+v", results[0])
	}

	// Had the first window been added to the history, the warm-up would
	// end one window earlier.
	for i, wantWarmUp := range []bool{true, true, false} {
		if got := results[i+1].Verdict.WarmUp; got != wantWarmUp {
			t.Errorf("window %d: WarmUp = %v, want %v", i+1, got, wantWarmUp)
		}
	}
}

func TestEvaluate_SkipsFirstWindowAfterStall(t *testing.T) {
	h := newHarness(t, DefaultConfig())
	h.windows(traffic{ipA: 10}, traffic{ipA: 10})

	h.stall(10)
	results := h.windows(traffic{ipA: 10}, traffic{ipA: 10})

	resumed := results[2]
	if resumed.SkippedBefore == 0 || resumed.Evaluated {
		t.Errorf("first window after the stall: skipped %d, evaluated %v; want a gap and no evaluation",
			resumed.SkippedBefore, resumed.Evaluated)
	}

	if next := results[3]; next.SkippedBefore != 0 || !next.Evaluated {
		t.Errorf("second window after the stall: skipped %d, evaluated %v; want evaluated normally",
			next.SkippedBefore, next.Evaluated)
	}
}

func TestEvaluate_CurrentOnly(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.Mode = ModeCurrentOnly

	results := newHarness(t, dcfg).windows(traffic{ipA: 30}, traffic{ipA: 20})

	r := results[0]
	if !r.Evaluated || r.EvaluatedPackets != 30 || r.IPs[0].Previous != 0 || r.IPs[0].Evaluated != 30 {
		t.Errorf("current-only result = %+v, want window 0 judged alone", r)
	}
}

func TestEvaluate_RecordsTiming(t *testing.T) {
	before := time.Now()
	results := newHarness(t, DefaultConfig()).windows(traffic{ipA: 10}, traffic{ipA: 10})
	after := time.Now()

	for i, r := range results {
		e := base + 1 + epoch.Epoch(i)

		if r.Epoch != e || !r.Start.Equal(e.Start(length)) || !r.End.Equal(r.Start.Add(length)) {
			t.Errorf("window %d: epoch %d bounds [%v, %v), want epoch %d", i, r.Epoch, r.Start, r.End, e)
		}

		if r.ClosedAt.Before(before) || r.EvalStart.Before(r.ClosedAt) ||
			r.EvalEnd.Before(r.EvalStart) || r.EvalEnd.After(after) {
			t.Errorf("window %d timing out of order: closed %v, eval %v - %v", i, r.ClosedAt, r.EvalStart, r.EvalEnd)
		}
	}
}

// A failed count read must surface as an error and must not teach either
// history anything, so the window after a transient failure is judged as
// if the failed window had never happened.
func TestEvaluate_CountErrorLeavesHistoriesUntouched(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2

	h := newHarness(t, dcfg)
	h.windows(traffic{ipA: 10}, traffic{ipA: 10})

	boom := errors.New("map read failed")
	h.src.CountErr = boom
	h.src.Add(slotOf(h.next), ipA, 10, 1000)

	h.now = h.next.End(length).Add(time.Millisecond)
	err := h.agg.Tick()
	if !errors.Is(err, boom) {
		t.Fatalf("Tick error = %v, want %v", err, boom)
	}
	h.next++
	h.src.CountErr = nil

	results := h.windows(traffic{ipA: 10})
	last := results[len(results)-1]

	// Only one window has been learned from (results[1]), so with
	// MinSamples 2 the histories are still warming up. Had the failed
	// window been learned from, the window level would be past warm-up.
	if !last.Verdict.WarmUp {
		t.Errorf("window after the failure is past warm-up; the failed window was learned from")
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{"combined": ModeCombined, "current": ModeCurrentOnly} {
		if got, err := ParseMode(in); err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v, %v; want %v", in, got, err, want)
		}
	}

	if _, err := ParseMode("both"); err == nil {
		t.Error("ParseMode accepted an unknown mode")
	}
}

func TestNewEvaluator_RejectsUnknownMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = 7

	if _, err := NewEvaluator(cfg); err == nil {
		t.Error("unknown mode was accepted")
	}
}

// newSourceAttack is normal traffic from A for windows 0-9, after which B
// appears with a flood that keeps every window from 10 to 19 flagged.
func newSourceAttack() []traffic {
	trs := repeat(10, traffic{ipA: 50})
	return append(trs, repeat(10, traffic{ipA: 50, ipB: 5000})...)
}

// In per-IP mode a source never seen before cannot be flagged per IP
// while its history is in warm-up, and its history only fills in windows
// that were not flagged. While an attack keeps every window flagged, a
// new source therefore stays in warm-up and only the window-level verdict
// reports the attack. This test pins that behaviour down so a change to
// it is deliberate; the hybrid mode below exists to avoid it.
func TestEvaluate_NewSourceStaysInWarmUpDuringFlaggedWindows(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2
	dcfg.IQR.IPMode = iqr.IPModePerIP

	results := newHarness(t, dcfg).windows(newSourceAttack()...)

	for _, r := range results[11:20] {
		if !r.Verdict.IsMalicious {
			t.Fatalf("window %d was not flagged; the scenario needs every attack window flagged", r.Epoch)
		}

		for _, ip := range r.IPs {
			if ip.IP == ipB && (!ip.Verdict.WarmUp || ip.Verdict.IsMalicious) {
				t.Errorf("window %d: new source left warm-up during the attack: %+v", r.Epoch, ip.Verdict)
			}
		}
	}
}

// In hybrid mode, the default, the same new source is judged against the
// history shared by all sources and flagged in every attack window, while
// the known source A is judged against its own history and never flagged.
func TestEvaluate_HybridFlagsNewSourceDuringFlaggedWindows(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2

	if dcfg.IQR.IPMode != iqr.IPModeHybrid {
		t.Fatalf("default IP mode = %v, want hybrid", dcfg.IQR.IPMode)
	}

	results := newHarness(t, dcfg).windows(newSourceAttack()...)

	for _, r := range results[11:20] {
		if !r.Verdict.IsMalicious {
			t.Fatalf("window %d was not flagged; the scenario needs every attack window flagged", r.Epoch)
		}

		seen := false

		for _, ip := range r.IPs {
			switch ip.IP {
			case ipB:
				seen = true
				if ip.Verdict.WarmUp || !ip.Verdict.Shared || !ip.Verdict.IsMalicious {
					t.Errorf("window %d: new source %+v, want flagged against the shared history", r.Epoch, ip.Verdict)
				}
			case ipA:
				if ip.Verdict.Shared || ip.Verdict.IsMalicious {
					t.Errorf("window %d: known source %+v, want judged on its own history and not flagged", r.Epoch, ip.Verdict)
				}
			}
		}

		if !seen {
			t.Errorf("window %d: the new source was not a candidate", r.Epoch)
		}
	}
}
