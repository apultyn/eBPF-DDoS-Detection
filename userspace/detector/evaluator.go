// Package detector evaluates closed windows against the IQR thresholds,
// once for the window total and once for every candidate source.
//
// By default a window is judged together with the window before it, so
// the counts compared against a threshold cover twice the window length.
// An attack that straddles a boundary is then seen whole instead of as
// two halves that each stay below their threshold. The thresholds are
// built from the same combined values, so like is compared with like.
//
// The order within a window is fixed: the window-level verdict is reached
// first, because it decides whether the per-IP histories may learn from
// this window.
package detector

import (
	"fmt"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

// Mode selects which counts are compared against the thresholds.
type Mode int

const (
	// ModeCombined judges each window together with the window before
	// it. This is the detector's configuration.
	ModeCombined Mode = iota

	// ModeCurrentOnly judges each window on its own. It exists to measure
	// what combining gains, and is not meant for deployment.
	ModeCurrentOnly
)

func (m Mode) String() string {
	switch m {
	case ModeCombined:
		return "combined"
	case ModeCurrentOnly:
		return "current"
	}

	return fmt.Sprintf("Mode(%d)", int(m))
}

// ParseMode converts a flag value to a Mode.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "combined":
		return ModeCombined, nil
	case "current":
		return ModeCurrentOnly, nil
	}

	return 0, fmt.Errorf("unknown mode %q (want combined or current)", s)
}

// IPResult is the evaluation of one candidate source.
type IPResult struct {
	IP flow.Key

	// Current and Previous are the address's counts in the window and
	// its predecessor, read from the configured count source. Previous
	// is zero in ModeCurrentOnly.
	Current  uint64
	Previous uint64

	// Evaluated is the value compared against the source's threshold:
	// Current + Previous.
	Evaluated uint64

	// Verdict is the source's per-IP IQR verdict.
	Verdict iqr.Verdict
}

// WindowResult is the evaluation of one closed window.
type WindowResult struct {
	// Epoch, Start and End identify the window that closed.
	Epoch epoch.Epoch
	Start time.Time
	End   time.Time

	// SkippedBefore is non-zero for the first window after a jump over a
	// long pause, and gives the number of epochs that produced no window.
	SkippedBefore int64

	// Packets and Bytes are the window's own exact totals.
	Packets uint64
	Bytes   uint64

	// Late is the number of out-of-order packets dropped while the window
	// was open.
	Late uint64

	// Evaluated is false when the window could not be judged: in
	// ModeCombined, when there is no adjacent previous window to combine
	// with (the first window, and the first after a jump). Nothing is
	// then compared or added to any history, and the fields below are
	// zero.
	Evaluated bool

	// EvaluatedPackets is the window-level count compared against the
	// threshold, Packets plus the previous window's in ModeCombined.
	EvaluatedPackets uint64

	// Verdict is the window-level IQR verdict.
	Verdict iqr.Verdict

	// IPs holds the verdict for every candidate, largest first.
	IPs []IPResult

	// ClosedAt is when the aggregator closed the window; EvalStart and
	// EvalEnd bracket the evaluation itself. All three are wall-clock
	// times, used to measure detection latency.
	ClosedAt  time.Time
	EvalStart time.Time
	EvalEnd   time.Time
}

// Malicious reports whether the window or any candidate was flagged.
func (r *WindowResult) Malicious() bool {
	if r.Verdict.IsMalicious {
		return true
	}

	for _, ip := range r.IPs {
		if ip.Verdict.IsMalicious {
			return true
		}
	}

	return false
}

// Config configures an Evaluator.
type Config struct {
	Mode Mode

	// IQR configures the thresholds at both levels.
	IQR iqr.Config
}

// DefaultConfig returns the detector's configuration.
func DefaultConfig() Config {
	return Config{
		Mode: ModeCombined,
		IQR:  iqr.DefaultConfig(),
	}
}

// Evaluator judges closed windows against IQR thresholds. Not safe for
// concurrent use; it runs inside the aggregator's callback.
type Evaluator struct {
	detector *iqr.Detector
	mode     Mode
	now      func() time.Time
}

// NewEvaluator creates an evaluator with its own threshold histories.
func NewEvaluator(cfg Config) (*Evaluator, error) {
	switch cfg.Mode {
	case ModeCombined, ModeCurrentOnly:
	default:
		return nil, fmt.Errorf("detector: unknown mode %v", cfg.Mode)
	}

	return &Evaluator{
		detector: iqr.NewDetector(cfg.IQR),
		mode:     cfg.Mode,
		now:      time.Now,
	}, nil
}

// Detector returns the underlying threshold model, for reporting how many
// per-IP histories it holds.
func (e *Evaluator) Detector() *iqr.Detector {
	return e.detector
}

// Evaluate judges a closed window. It must be called from the
// aggregator's callback, while both windows in c are still valid.
func (e *Evaluator) Evaluate(c window.Closed) WindowResult {
	w := c.Window

	r := WindowResult{
		Epoch:         w.Epoch,
		Start:         w.Start,
		End:           w.End,
		SkippedBefore: w.SkippedBefore,
		Packets:       w.Packets,
		Bytes:         w.Bytes,
		Late:          w.Late,
		ClosedAt:      c.ClosedAt,
		EvalStart:     e.now(),
	}

	var prev *window.Window

	if e.mode == ModeCombined {
		// A lone window would be compared against thresholds built from
		// combined values, mixing two time scales. Skip it instead.
		if c.Prev == nil {
			r.EvalEnd = e.now()
			return r
		}

		prev = c.Prev
	}

	r.Evaluated = true

	r.EvaluatedPackets = w.Packets
	if prev != nil {
		r.EvaluatedPackets += prev.Packets
	}

	// The window-level verdict comes first: it decides whether the
	// per-IP histories may learn from this window.
	r.Verdict = e.detector.EvaluateWindow(iqr.WindowStats{
		WindowStart:  w.Start,
		TotalPackets: r.EvaluatedPackets,
	})

	candidates := w.Candidates()
	r.IPs = make([]IPResult, 0, len(candidates))

	for _, cand := range candidates {
		ip := IPResult{
			IP:      cand.Item,
			Current: w.Count(cand.Item),
		}

		if prev != nil {
			ip.Previous = prev.Count(cand.Item)
		}

		ip.Evaluated = ip.Current + ip.Previous
		ip.Verdict = e.detector.EvaluateIP(cand.Item, ip.Evaluated, r.Verdict.IsMalicious)

		r.IPs = append(r.IPs, ip)
	}

	r.EvalEnd = e.now()

	return r
}
