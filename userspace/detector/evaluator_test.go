package detector

import (
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

const length = epoch.DefaultLength

// t0 lies on a window boundary.
var t0 = time.Unix(1_700_000_000, 0)

var (
	ipA = flow.MustParse("192.0.2.1")
	ipB = flow.MustParse("2001:db8::b")
)

// run feeds the packets through an aggregator and evaluator and returns
// every window result.
func run(t testing.TB, wcfg window.Config, dcfg Config, packets []capture.Packet) []WindowResult {
	t.Helper()

	ev, err := NewEvaluator(dcfg)
	if err != nil {
		t.Fatal(err)
	}

	var results []WindowResult

	agg, err := window.NewAggregator(wcfg, func(c window.Closed) {
		results = append(results, ev.Evaluate(c))
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range packets {
		agg.Observe(p)
	}

	return results
}

// burst returns n packets from src spread evenly over the n:th window.
func burst(n int, src flow.Key, count int) []capture.Packet {
	start := t0.Add(time.Duration(n) * length)
	step := length / time.Duration(count+1)

	packets := make([]capture.Packet, count)
	for i := range packets {
		packets[i] = capture.Packet{Src: src, Timestamp: start.Add(time.Duration(i+1) * step), Length: 100}
	}

	return packets
}

func TestEvaluate_CombinesWithPreviousWindow(t *testing.T) {
	var packets []capture.Packet
	packets = append(packets, burst(0, ipA, 30)...)
	packets = append(packets, burst(0, ipB, 5)...)
	packets = append(packets, burst(1, ipA, 20)...)
	packets = append(packets, burst(2, ipA, 1)...) // closes window 1

	for _, src := range []window.CountSource{window.CountHeavyKeeper, window.CountCountMin} {
		t.Run(src.String(), func(t *testing.T) {
			wcfg := window.DefaultConfig()
			wcfg.Counts = src

			results := run(t, wcfg, DefaultConfig(), packets)

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
		})
	}
}

func TestEvaluate_SkipsWindowWithoutPrevious(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2

	var packets []capture.Packet
	for n := 0; n < 5; n++ {
		packets = append(packets, burst(n, ipA, 10)...)
	}

	results := run(t, window.DefaultConfig(), dcfg, packets)

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

func TestEvaluate_SkipsFirstWindowAfterJump(t *testing.T) {
	wcfg := window.DefaultConfig()
	wcfg.MaxEmpty = window.PcapMaxEmpty

	var packets []capture.Packet
	packets = append(packets, burst(0, ipA, 10)...)
	packets = append(packets, burst(1, ipA, 10)...)
	packets = append(packets, burst(1000, ipA, 10)...)
	packets = append(packets, burst(1001, ipA, 10)...)

	results := run(t, wcfg, DefaultConfig(), packets)
	resumed := results[len(results)-1]

	if resumed.SkippedBefore == 0 || resumed.Evaluated {
		t.Errorf("first window after jump: skipped %d, evaluated %v; want a jump and no evaluation",
			resumed.SkippedBefore, resumed.Evaluated)
	}
}

func TestEvaluate_CurrentOnly(t *testing.T) {
	var packets []capture.Packet
	packets = append(packets, burst(0, ipA, 30)...)
	packets = append(packets, burst(1, ipA, 20)...)

	dcfg := DefaultConfig()
	dcfg.Mode = ModeCurrentOnly

	results := run(t, window.DefaultConfig(), dcfg, packets)

	r := results[0]
	if !r.Evaluated || r.EvaluatedPackets != 30 || r.IPs[0].Previous != 0 || r.IPs[0].Evaluated != 30 {
		t.Errorf("current-only result = %+v, want window 0 judged alone", r)
	}
}

func TestEvaluate_RecordsTiming(t *testing.T) {
	packets := append(burst(0, ipA, 10), burst(1, ipA, 10)...)
	packets = append(packets, burst(2, ipA, 1)...)

	before := time.Now()
	results := run(t, window.DefaultConfig(), DefaultConfig(), packets)
	after := time.Now()

	for i, r := range results {
		if !r.Start.Equal(t0.Add(time.Duration(i)*length)) || !r.End.Equal(r.Start.Add(length)) {
			t.Errorf("window %d bounds = [%v, %v)", i, r.Start, r.End)
		}

		if r.ClosedAt.Before(before) || r.EvalStart.Before(r.ClosedAt) ||
			r.EvalEnd.Before(r.EvalStart) || r.EvalEnd.After(after) {
			t.Errorf("window %d timing out of order: closed %v, eval %v - %v", i, r.ClosedAt, r.EvalStart, r.EvalEnd)
		}
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

// A source never seen before cannot be flagged per IP while its history
// is in warm-up, and its history only fills in windows that were not
// flagged. While an attack keeps every window flagged, a new source
// therefore stays in warm-up and only the window-level verdict reports
// the attack. This test pins that behaviour down so a change to it is
// deliberate.
func TestEvaluate_NewSourceStaysInWarmUpDuringFlaggedWindows(t *testing.T) {
	dcfg := DefaultConfig()
	dcfg.IQR.MinSamples = 2

	var packets []capture.Packet

	// Normal traffic from A to get the window threshold past warm-up.
	for n := 0; n < 10; n++ {
		packets = append(packets, burst(n, ipA, 50)...)
	}

	// B appears with a flood that keeps every window flagged.
	for n := 10; n < 20; n++ {
		packets = append(packets, burst(n, ipA, 50)...)
		packets = append(packets, burst(n, ipB, 5000)...)
	}

	packets = append(packets, burst(20, ipA, 1)...)

	results := run(t, window.DefaultConfig(), dcfg, packets)

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
