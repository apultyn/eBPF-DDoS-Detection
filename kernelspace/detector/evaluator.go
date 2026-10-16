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

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/resource"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
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

	// Blocked reports that the source is on the blocklist because of this
	// verdict, newly added or with its TTL restarted. It is set by the
	// caller, and is always false when blocking is off.
	Blocked bool
}

// WindowResult is the evaluation of one closed window.
type WindowResult struct {
	// Epoch, Start and End identify the window that closed.
	Epoch epoch.Epoch
	Start time.Time
	End   time.Time

	// SkippedBefore is non-zero when windows right before this one were
	// not evaluated because the detector fell behind the kernel, and gives
	// how many.
	SkippedBefore int64

	// Packets and Bytes are the window's own exact totals, as counted by
	// the kernel.
	Packets uint64
	Bytes   uint64

	// BlockedPackets and BlockedBytes are what the blocklist dropped
	// during the window. They are not part of Packets and Bytes.
	BlockedPackets uint64
	BlockedBytes   uint64

	// KernelDrops is the number of packets dropped before reaching the
	// detector between the previous window closing and this one. It is
	// set by the caller, and is -1 when not measured.
	KernelDrops int64

	// Evaluated is false when the window could not be judged: in
	// ModeCombined, when there is no adjacent previous window to combine
	// with (the first window, and the first after skipped windows).
	// Nothing is then compared or added to any history, and the fields
	// below are zero.
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

	// BlockedAt is the wall-clock time the flagged sources were pushed to
	// the blocklist, set by the caller. It is zero if none were.
	BlockedAt time.Time

	// Resources is the detector process's own memory and CPU use over the
	// interval since the previous window was evaluated, up to and
	// including this window's evaluation. It is set by the caller; a zero
	// Resources.Interval means it was not measured.
	Resources resource.Sample
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
//
// The per-IP counts are read from the kernel. If a read fails, the error
// is returned before anything is added to a history, so a failed window
// leaves the thresholds as they were.
func (e *Evaluator) Evaluate(c window.Closed) (WindowResult, error) {
	w := c.Window

	r := WindowResult{
		Epoch:         w.Epoch,
		Start:         w.Start,
		End:           w.End,
		SkippedBefore: w.SkippedBefore,
		Packets:       w.Packets,
		Bytes:         w.Bytes,
		KernelDrops:   -1,

		BlockedPackets: w.BlockedPackets,
		BlockedBytes:   w.BlockedBytes,

		ClosedAt:  c.ClosedAt,
		EvalStart: e.now(),
	}

	var prev *window.Window

	if e.mode == ModeCombined {
		// A lone window would be compared against thresholds built from
		// combined values, mixing two time scales. Skip it instead.
		if c.Prev == nil {
			r.EvalEnd = e.now()
			return r, nil
		}

		prev = c.Prev
	}

	// Every count is read before anything is judged: a judgement adds to
	// a history, and a read that fails halfway must not leave the window
	// learned from at one level but not the other.
	candidates := w.Candidates()
	ips := make([]IPResult, 0, len(candidates))
	counts := make([]iqr.IPCount, 0, len(candidates))

	for _, cand := range candidates {
		ip := IPResult{IP: cand.Item}

		var err error
		if ip.Current, err = w.Count(cand.Item); err != nil {
			return r, fmt.Errorf("detector: %w", err)
		}

		if prev != nil {
			if ip.Previous, err = prev.Count(cand.Item); err != nil {
				return r, fmt.Errorf("detector: %w", err)
			}
		}

		ip.Evaluated = ip.Current + ip.Previous

		ips = append(ips, ip)
		counts = append(counts, iqr.IPCount{IP: ip.IP, Count: ip.Evaluated})
	}

	r.Evaluated = true
	r.IPs = ips

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

	// All candidates are judged in one call, so that they are compared
	// against the same shared history and the window is learned from
	// only once every candidate has been judged.
	for i, v := range e.detector.EvaluateIPs(counts, r.Verdict.IsMalicious) {
		r.IPs[i].Verdict = v
	}

	r.EvalEnd = e.now()

	return r, nil
}
