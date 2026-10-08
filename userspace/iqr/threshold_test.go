package iqr

import (
	"math"
	"testing"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

func approxEqual(t *testing.T, got, want, tolerance float64) {
	t.Helper()
	if math.Abs(got-want) > tolerance {
		t.Errorf("got %v, want %v (tolerance %v)", got, want, tolerance)
	}
}

func TestPercentile(t *testing.T) {
	tests := []struct {
		name   string
		sorted []float64
		p      float64
		want   float64
	}{
		{"empty", nil, 0.25, 0},
		{"single value", []float64{5}, 0.5, 5},
		{"q1 of ten values", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.25, 3.25},
		{"q3 of ten values", []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.75, 7.75},
		{"median falls exactly on a rank", []float64{10, 20, 30}, 0.5, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approxEqual(t, percentile(tt.sorted, tt.p), tt.want, 1e-9)
		})
	}
}

func TestStdDev(t *testing.T) {
	tests := []struct {
		name   string
		values []float64
		want   float64
	}{
		{"empty", nil, 0},
		{"single value", []float64{5}, 0},
		{"known sample", []float64{2, 4, 4, 4, 5, 5, 7, 9}, 2.13809}, // sqrt(32/7)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			approxEqual(t, stdDev(tt.values), tt.want, 1e-4)
		})
	}
}

func TestHistory_AddEvictsOldest(t *testing.T) {
	h := newHistory(3)
	for _, v := range []float64{1, 2, 3, 4, 5} {
		h.add(v)
	}

	want := []float64{3, 4, 5}
	if h.size() != len(want) {
		t.Fatalf("size = %d, want %d", h.size(), len(want))
	}
	for i, v := range want {
		if h.values[i] != v {
			t.Errorf("values[%d] = %v, want %v", i, h.values[i], v)
		}
	}
}

func TestDefaultConfig_MatchesThesis(t *testing.T) {
	cfg := DefaultConfig()
	approxEqual(t, cfg.BaseThreshold, 200, 0)
	approxEqual(t, cfg.IQRMultiplier, 1.5, 0)
	approxEqual(t, cfg.OffsetMultiplier, 2, 0)
}

// TestDetector_EvaluateWindow_WarmUpThenThreshold walks a Detector through
// warm-up, several normal windows, and one clear attack window, checking
// the threshold at each step against hand-computed values so a change in
// the underlying formula would be caught here.
func TestDetector_EvaluateWindow_WarmUpThenThreshold(t *testing.T) {
	cfg := Config{
		BaseThreshold:    0, // disabled so it doesn't mask the IQR math being tested
		IQRMultiplier:    1.5,
		OffsetMultiplier: 2,
		MinSamples:       4,
		MaxHistorySize:   100,
	}
	d := NewDetector(cfg)

	normalTotals := []uint64{100, 110, 120, 130, 140, 150, 160, 170}
	for i, total := range normalTotals {
		v := d.EvaluateWindow(WindowStats{TotalPackets: total})
		if v.IsMalicious {
			t.Fatalf("window %d (total=%d) flagged malicious during normal ramp-up", i, total)
		}
		if i < cfg.MinSamples {
			approxEqual(t, v.Threshold, cfg.BaseThreshold, 1e-9)
		}
	}

	// After all 8 normal windows, history holds all 8 values. Verify the
	// threshold matches the hand-computed value for that exact set:
	// Q1=117.5, Q3=152.5, IQR=35, base=max(152.5+52.5,0)=205,
	// sample stddev=24.4949, threshold=205+2*24.4949=253.9898.
	wantThreshold := 253.9898
	gotThreshold := d.windowHistory.threshold(cfg)
	approxEqual(t, gotThreshold, wantThreshold, 0.01)

	// A clear attack should now be flagged, and should not be folded into
	// history.
	attack := d.EvaluateWindow(WindowStats{TotalPackets: 100000})
	if !attack.IsMalicious {
		t.Fatalf("expected attack-sized window to be flagged malicious, got threshold=%v", attack.Threshold)
	}
	approxEqual(t, attack.Threshold, wantThreshold, 0.01)

	// Confirm the attack did not skew the baseline: the threshold for the
	// next normal-sized window should be unchanged.
	unchanged := d.EvaluateWindow(WindowStats{TotalPackets: 175})
	approxEqual(t, unchanged.Threshold, wantThreshold, 0.01)
}

// TestDetector_EvaluateIP_FreezesDuringMaliciousWindow checks that an IP's
// history is left untouched for any EvaluateIP call made with
// windowIsMalicious=true, regardless of that call's own verdict.
func TestDetector_EvaluateIP_FreezesDuringMaliciousWindow(t *testing.T) {
	cfg := Config{
		BaseThreshold:    0,
		IQRMultiplier:    1.5,
		OffsetMultiplier: 2,
		MinSamples:       2,
		MaxHistorySize:   50,
	}
	d := NewDetector(cfg)
	ip := flow.MustParse("10.0.0.5")

	// Warm-up: two calls, neither compared against a real threshold yet.
	// History becomes {50, 60}.
	d.EvaluateIP(ip, 50, false)
	d.EvaluateIP(ip, 60, false)

	// Third call: evaluated against {50, 60}, and (since windowIsMalicious
	// is false) 55 is folded in afterward. History becomes {50, 60, 55}.
	beforeAttack := d.EvaluateIP(ip, 55, false)
	if beforeAttack.IsMalicious {
		t.Fatalf("expected count=55 to be within normal range, got threshold=%v", beforeAttack.Threshold)
	}

	// Attack traffic during a window already flagged malicious overall.
	// Evaluated against {50, 60, 55}, and NOT folded in because windowIsMalicious=true.
	attack := d.EvaluateIP(ip, 5000, true)
	if !attack.IsMalicious {
		t.Fatalf("expected count=5000 to be flagged malicious, got threshold=%v", attack.Threshold)
	}

	// Also test a normal-looking count during a malicious window — it must
	// not be folded into history either.
	benignInMaliciousWindow := d.EvaluateIP(ip, 40, true)
	if benignInMaliciousWindow.IsMalicious {
		t.Fatalf("expected count=40 to be non-malicious, got threshold=%v", benignInMaliciousWindow.Threshold)
	}

	// History should still be {50, 60, 55} — the exact same baseline that
	// attack was evaluated against.
	after := d.EvaluateIP(ip, 58, false)
	approxEqual(t, after.Threshold, attack.Threshold, 1e-9)
}

func TestDetector_EvaluateIP_SeparateHistoryPerIP(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MinSamples = 2
	d := NewDetector(cfg)

	// Two different IPs should not influence each other's thresholds.
	ip1 := flow.MustParse("10.0.0.1")
	ip2 := flow.MustParse("10.0.0.2")
	d.EvaluateIP(ip1, 1000000, false) // huge, but still warm-up so not malicious
	d.EvaluateIP(ip1, 1000000, false)

	v := d.EvaluateIP(ip2, 50, false)
	if v.Threshold != cfg.BaseThreshold {
		t.Fatalf("expected a brand-new IP to start warm-up at the base threshold, got %v", v.Threshold)
	}
}
