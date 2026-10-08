// Package iqr implements the IQR-based statistical threshold model used by
// the baseline detector to decide whether a time window, or an individual
// source IP within a window, represents anomalous (likely DDoS) traffic.
//
// The threshold formula matches Wickman & Rygaard's thesis (2025),
// §3.2.5.3:
//
//	Q1  = 25th percentile of recent normal-traffic samples
//	Q3  = 75th percentile of recent normal-traffic samples
//	IQR = Q3 - Q1
//	threshold      = max(Q3 + 1.5*IQR, baseThreshold)
//	finalThreshold = threshold + offsetMultiplier*stdDev
//
// The same formula is applied at two levels: once against the total packet
// count of a time window, and once per source IP within a window. In both
// cases, a sample is only folded into future thresholds when it wasn't
// itself flagged malicious — otherwise an attack would skew the baseline
// used to detect it.

package iqr

import (
	"sync"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// Config holds the tunable parameters of the IQR threshold model. All
// fields have sane defaults via DefaultConfig; override only what you're
// deliberately tuning.
type Config struct {
	// BaseThreshold is the minimum threshold ever returned, regardless of how
	// quiet observed traffic has been. Prevents the threshold from
	// collapsing toward zero during unusually quiet periods. The thesis
	// used 200, chosen by trial and error for its dataset.
	BaseThreshold float64

	// IQRMultiplier scales the IQR before adding it to Q3. 1.5 is the
	// conventional "mild outlier" multiplier (Tukey's fences); the thesis
	// uses this value.
	IQRMultiplier float64

	// OffsetMultiplier scales the standard deviation added on top of the
	// IQR-based threshold, giving extra headroom for traffic that's
	// noisier than the IQR alone accounts for. The thesis uses 2 (roughly
	// a 2-sigma margin).
	OffsetMultiplier float64

	// MinSamples is the minimum number of historical samples required
	// before a real threshold is computed and enforced. Below this,
	// Evaluate* calls always report not-malicious and keep adding to
	// history — see the package doc comment for why. Not specified in the
	// thesis; this package's own addition.
	MinSamples int

	// MaxHistorySize bounds how many recent samples are retained per
	// history (per window, and per IP). Older samples are evicted
	// first-in-first-out, keeping memory bounded regardless of how long
	// the process runs or how many distinct IPs it has seen.
	MaxHistorySize int
}

// DefaultConfig returns the parameters used in Wickman & Rygaard's thesis,
// plus reasonable defaults for the two parameters the thesis leaves
// unspecified (MinSamples, MaxHistorySize).
func DefaultConfig() Config {
	return Config{
		BaseThreshold:    200,
		IQRMultiplier:    1.5,
		OffsetMultiplier: 2,
		MinSamples:       4,
		MaxHistorySize:   500,
	}
}

// WindowStats summarizes a single closed sliding window, ready to be
// evaluated against the window-level threshold.
type WindowStats struct {
	WindowStart  time.Time
	TotalPackets uint64
}

// Verdict is the outcome of evaluating a window or an IP against the
// current threshold.
type Verdict struct {
	// Threshold is the value the observed count was compared against,
	// included so callers (and tests) can inspect or log it without
	// recomputing it themselves.
	Threshold float64

	// IsMalicious reports whether the observed count exceeded Threshold.
	IsMalicious bool
}

// Detector holds the rolling history needed to compute IQR-based
// thresholds, both for whole time windows and for individual source IPs.
// A Detector is safe for concurrent use.
type Detector struct {
	cfg Config

	mu            sync.Mutex
	windowHistory *history
	ipHistories   map[flow.Key]*history
}

// NewDetector creates a Detector using the given configuration. Pass
// DefaultConfig() to match the thesis's parameters.
func NewDetector(cfg Config) *Detector {
	return &Detector{
		cfg:           cfg,
		windowHistory: newHistory(cfg.MaxHistorySize),
		ipHistories:   make(map[flow.Key]*history),
	}
}

// EvaluateWindow compares stats.TotalPackets against the current
// window-level threshold and returns the verdict. If the window is not
// malicious, its total is folded into the history used for future thresholds;
// if it is malicious, history is left untouched so the attack doesn't skew
// its own baseline.
func (d *Detector) EvaluateWindow(stats WindowStats) Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()

	total := float64(stats.TotalPackets)

	if d.windowHistory.size() < d.cfg.MinSamples {
		d.windowHistory.add(total)
		return Verdict{Threshold: d.cfg.BaseThreshold, IsMalicious: false}
	}

	threshold := d.windowHistory.threshold(d.cfg)
	verdict := Verdict{Threshold: threshold, IsMalicious: total > threshold}

	if !verdict.IsMalicious {
		d.windowHistory.add(total)
	}

	return verdict
}

// EvaluateIP compares count against ip's current per-IP threshold and
// returns the verdict, creating a fresh history for ip on first use.
//
// windowIsMalicious should be the IsMalicious value EvaluateWindow
// returned for the window this IP's count belongs to. When true, ip's
// history is left untouched even if this specific count is within its own
// normal threshold — matching the thesis, which freezes all per-IP history
// during a malicious window, not just for IPs that individually exceed
// their threshold. One consequence worth knowing: an IP that spikes hard
// enough to be individually flagged inside an otherwise-normal window
// still gets folded into its own baseline (since windowIsMalicious is
// false in that case), which could raise its future threshold. The thesis
// doesn't address this edge case.
func (d *Detector) EvaluateIP(ip flow.Key, count uint64, windowIsMalicious bool) Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()

	h, ok := d.ipHistories[ip]
	if !ok {
		h = newHistory(d.cfg.MaxHistorySize)
		d.ipHistories[ip] = h
	}

	c := float64(count)

	if h.size() < d.cfg.MinSamples {
		if !windowIsMalicious {
			h.add(c)
		}
		return Verdict{Threshold: d.cfg.BaseThreshold, IsMalicious: false}
	}

	threshold := h.threshold(d.cfg)
	verdict := Verdict{Threshold: threshold, IsMalicious: c > threshold}

	if !windowIsMalicious {
		h.add(c)
	}

	return verdict
}
