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
//
// BaseThreshold is uncalibrated for this detector: the thesis set it by
// trial and error for its own dataset and a 1 s window. Every verdict
// reports whether the floor or the quartile term was used, so the floor
// can be recalibrated from measured traffic.
//
// At the IP level, IPMode selects which history a source is judged
// against: its own, one history shared by all sources, or its own once it
// has one and the shared history until then (the default). The shared
// history lets a source that first appears during an attack be judged at
// once; with per-IP histories alone it would stay in warm-up for as long
// as the attack keeps every window flagged.

package iqr

import (
	"fmt"
	"sync"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// Config holds the tunable parameters of the IQR threshold model. All
// fields have sane defaults via DefaultConfig; override only what you're
// deliberately tuning.
type Config struct {
	// BaseThreshold is the minimum threshold ever returned, regardless of how
	// quiet observed traffic has been. Prevents the threshold from
	// collapsing toward zero during unusually quiet periods. The thesis
	// used 200, chosen by trial and error for its dataset and window
	// length; it has not been calibrated for this detector.
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
	// the process runs.
	MaxHistorySize int

	// MaxTrackedIPs caps how many source addresses keep a per-IP history.
	// When the cap is reached, the address evaluated least recently is
	// evicted and starts over with a fresh warm-up if it returns. Together
	// with MaxHistorySize this bounds per-IP state to a constant:
	// MaxTrackedIPs * MaxHistorySize samples of 8 bytes, 4 MB with the
	// defaults. Zero selects DefaultMaxTrackedIPs. Not specified in the
	// thesis; this package's own addition.
	MaxTrackedIPs int

	// IPMode selects which history a source is judged against. The zero
	// value is IPModePerIP, the behaviour before the modes were added;
	// DefaultConfig selects IPModeHybrid.
	IPMode IPMode

	// MaxSharedHistorySize bounds the history shared by all sources, used
	// by IPModeShared and IPModeHybrid. Every candidate of a normal window
	// adds a sample, so with K candidates per window it covers the last
	// MaxSharedHistorySize/K windows. Zero selects
	// DefaultMaxSharedHistorySize.
	MaxSharedHistorySize int
}

// DefaultMaxTrackedIPs is the per-IP history cap used when
// Config.MaxTrackedIPs is zero.
const DefaultMaxTrackedIPs = 1000

// DefaultMaxSharedHistorySize is the shared history size used when
// Config.MaxSharedHistorySize is zero: 500 windows of 10 candidates, the
// same span of windows as the default MaxHistorySize.
const DefaultMaxSharedHistorySize = 5000

// IPMode selects the history a source IP is judged against.
type IPMode int

const (
	// IPModePerIP judges every source against its own history only. A
	// source stays in warm-up until it has MinSamples samples, and its
	// history only fills in windows that were not flagged, so a source
	// first seen during an attack is never judged while the attack lasts.
	IPModePerIP IPMode = iota

	// IPModeShared judges every source against one history built from the
	// counts of all candidates in normal windows. This appears to be what
	// Wickman & Rygaard's thesis does: its per-IP endpoint answers a whole
	// list of addresses with a single threshold (§3.2.5.2, §3.2.6).
	IPModeShared

	// IPModeHybrid judges a source against its own history once that has
	// MinSamples samples, and against the shared history until then. A
	// known source keeps a threshold fitted to its own traffic, and a new
	// one is judged from its first window instead of waiting in warm-up.
	IPModeHybrid
)

func (m IPMode) String() string {
	switch m {
	case IPModePerIP:
		return "per-ip"
	case IPModeShared:
		return "shared"
	case IPModeHybrid:
		return "hybrid"
	}

	return fmt.Sprintf("IPMode(%d)", int(m))
}

// ParseIPMode converts a flag value to an IPMode.
func ParseIPMode(s string) (IPMode, error) {
	switch s {
	case "per-ip":
		return IPModePerIP, nil
	case "shared":
		return IPModeShared, nil
	case "hybrid":
		return IPModeHybrid, nil
	}

	return 0, fmt.Errorf("unknown ip mode %q (want per-ip, shared or hybrid)", s)
}

// DefaultConfig returns the parameters used in Wickman & Rygaard's thesis,
// plus reasonable defaults for the parameters the thesis leaves
// unspecified (MinSamples, MaxHistorySize, MaxTrackedIPs, IPMode,
// MaxSharedHistorySize).
func DefaultConfig() Config {
	return Config{
		BaseThreshold:        200,
		IQRMultiplier:        1.5,
		OffsetMultiplier:     2,
		MinSamples:           4,
		MaxHistorySize:       500,
		MaxTrackedIPs:        DefaultMaxTrackedIPs,
		IPMode:               IPModeHybrid,
		MaxSharedHistorySize: DefaultMaxSharedHistorySize,
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

	// WarmUp reports that too few samples were held to compute a real
	// threshold. Threshold is then BaseThreshold, but the count was not
	// compared against it and IsMalicious is always false.
	WarmUp bool

	// FromFloor reports which term of max(Q3 + IQRMultiplier*IQR,
	// BaseThreshold) the threshold was built from: true when
	// BaseThreshold was the larger, false when the quartile term was.
	// Always false during warm-up.
	FromFloor bool

	// QuartileBound is Q3 + IQRMultiplier*IQR, reported whichever term
	// won, so the distance between the floor and the traffic's own
	// statistics can be measured. Zero during warm-up.
	QuartileBound float64

	// Shared reports that an IP verdict came from the history shared by
	// all sources rather than from the source's own history. During
	// warm-up it says which history was still filling. Always false for
	// window verdicts and in IPModePerIP.
	Shared bool
}

// IPCount is one candidate source and its count in a window.
type IPCount struct {
	IP    flow.Key
	Count uint64
}

// Detector holds the rolling history needed to compute IQR-based
// thresholds, both for whole time windows and for individual source IPs.
// A Detector is safe for concurrent use.
type Detector struct {
	cfg Config

	mu            sync.Mutex
	windowHistory *history
	ipHistories   *ipHistories
	sharedHistory *history
}

// NewDetector creates a Detector using the given configuration. Pass
// DefaultConfig() to match the thesis's parameters.
func NewDetector(cfg Config) *Detector {
	if cfg.MaxTrackedIPs == 0 {
		cfg.MaxTrackedIPs = DefaultMaxTrackedIPs
	}

	if cfg.MaxSharedHistorySize == 0 {
		cfg.MaxSharedHistorySize = DefaultMaxSharedHistorySize
	}

	return &Detector{
		cfg:           cfg,
		windowHistory: newHistory(cfg.MaxHistorySize),
		ipHistories:   newIPHistories(cfg.MaxTrackedIPs, cfg.MaxHistorySize),
		sharedHistory: newHistory(cfg.MaxSharedHistorySize),
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
		return Verdict{Threshold: d.cfg.BaseThreshold, WarmUp: true}
	}

	verdict := judge(total, d.windowHistory.threshold(d.cfg))

	if !verdict.IsMalicious {
		d.windowHistory.add(total)
	}

	return verdict
}

// EvaluateIPs judges every candidate source of one window and returns a
// verdict per candidate, in order. Which history a source is judged
// against depends on Config.IPMode:
//
//   - IPModePerIP: its own history; warm-up until that has MinSamples.
//   - IPModeShared: the shared history; warm-up until that has MinSamples.
//   - IPModeHybrid: its own history once that has MinSamples, otherwise
//     the shared history, and warm-up only while both are short.
//
// A source's own history is created on first use. If MaxTrackedIPs
// addresses are already tracked, the least recently evaluated one is
// evicted to make room. IPModeShared keeps no per-source histories.
//
// windowIsMalicious should be the IsMalicious value EvaluateWindow
// returned for the window these counts belong to. When true, every
// history is left untouched even if a count is within its threshold —
// matching the thesis, which freezes all per-IP history during a
// malicious window, not just for IPs that individually exceed their
// threshold. One consequence worth knowing: an IP that spikes hard enough
// to be individually flagged inside an otherwise-normal window still gets
// folded into its baseline (since windowIsMalicious is false in that
// case), which could raise its future threshold. The thesis does the same
// at the IP level, to avoid holding on to wrongly flagged addresses.
//
// Every candidate is judged against the shared history as it stood before
// the window, and the window's counts are added to it only afterwards, so
// the order of the candidates does not change any verdict.
func (d *Detector) EvaluateIPs(ips []IPCount, windowIsMalicious bool) []Verdict {
	d.mu.Lock()
	defer d.mu.Unlock()

	usesOwn := d.cfg.IPMode != IPModeShared
	usesShared := d.cfg.IPMode != IPModePerIP

	var (
		shared      thresholdParts
		sharedReady bool
	)

	if usesShared && d.sharedHistory.size() >= d.cfg.MinSamples {
		shared = d.sharedHistory.threshold(d.cfg)
		sharedReady = true
	}

	verdicts := make([]Verdict, len(ips))

	for i, ip := range ips {
		c := float64(ip.Count)

		var own *history
		if usesOwn {
			own = d.ipHistories.get(ip.IP)
		}

		switch {
		case usesOwn && own.size() >= d.cfg.MinSamples:
			verdicts[i] = judge(c, own.threshold(d.cfg))
		case !usesShared:
			verdicts[i] = Verdict{Threshold: d.cfg.BaseThreshold, WarmUp: true}
		case sharedReady:
			verdicts[i] = judge(c, shared)
			verdicts[i].Shared = true
		default:
			verdicts[i] = Verdict{Threshold: d.cfg.BaseThreshold, WarmUp: true, Shared: true}
		}

		if usesOwn && !windowIsMalicious {
			own.add(c)
		}
	}

	if usesShared && !windowIsMalicious {
		for _, ip := range ips {
			d.sharedHistory.add(float64(ip.Count))
		}
	}

	return verdicts
}

// EvaluateIP judges a single source, as EvaluateIPs does for a window
// with one candidate. Use EvaluateIPs for a window with several
// candidates, so that they are all judged against the same shared
// history.
func (d *Detector) EvaluateIP(ip flow.Key, count uint64, windowIsMalicious bool) Verdict {
	return d.EvaluateIPs([]IPCount{{IP: ip, Count: count}}, windowIsMalicious)[0]
}

// TrackedIPs returns how many source addresses currently hold a per-IP
// history. It never exceeds Config.MaxTrackedIPs.
func (d *Detector) TrackedIPs() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.ipHistories.len()
}

// EvictedIPs returns how many per-IP histories have been evicted to stay
// within Config.MaxTrackedIPs.
func (d *Detector) EvictedIPs() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.ipHistories.evicted
}

// judge compares count against a computed threshold.
func judge(count float64, t thresholdParts) Verdict {
	return Verdict{
		Threshold:     t.final,
		IsMalicious:   count > t.final,
		FromFloor:     t.floored,
		QuartileBound: t.quartile,
	}
}
