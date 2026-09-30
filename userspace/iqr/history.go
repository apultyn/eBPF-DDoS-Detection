package iqr

import (
	"math"
	"sort"
)

// history is a bounded, FIFO-evicting buffer of recent samples, along with
// the quartile and standard-deviation calculations the threshold formula
// needs. It is not safe for concurrent use on its own — Detector is
// responsible for serializing access to it.
type history struct {
	values  []float64
	maxSize int
}

func newHistory(maxSize int) *history {
	if maxSize <= 0 {
		maxSize = 1
	}
	return &history{
		values:  make([]float64, 0, maxSize),
		maxSize: maxSize,
	}
}

// size returns the number of samples currently held.
func (h *history) size() int {
	return len(h.values)
}

// add appends a new sample, evicting the oldest sample first if the
// history is already at capacity.
func (h *history) add(v float64) {
	if len(h.values) >= h.maxSize {
		// Drop the oldest sample. Shifting is O(n), but n is bounded by
		// maxSize (typically a few hundred) and add is called at most
		// once per window (or per IP per window) — this isn't a hot path.
		h.values = append(h.values[:0], h.values[1:]...)
	}
	h.values = append(h.values, v)
}

// threshold computes the IQR-based threshold from the samples currently
// held, per the formula in the package doc comment:
//
//	threshold      = max(Q3 + IQRMultiplier*IQR, FloorValue)
//	finalThreshold = threshold + OffsetMultiplier*stdDev
//
// threshold does not itself check whether enough samples exist to be
// meaningful — that policy (MinSamples, and what to do below it) lives in
// Detector, since it also determines whether Detector should be adding
// samples during warm-up. Called directly with very few samples, threshold
// still returns a number, just a less statistically meaningful one.
func (h *history) threshold(cfg Config) float64 {
	sorted := make([]float64, len(h.values))
	copy(sorted, h.values)
	sort.Float64s(sorted)

	q1 := percentile(sorted, 0.25)
	q3 := percentile(sorted, 0.75)
	iqrValue := q3 - q1

	base := math.Max(q3+cfg.IQRMultiplier*iqrValue, cfg.FloorValue)
	return base + cfg.OffsetMultiplier*stdDev(h.values)
}

// percentile returns the p-th percentile (0 <= p <= 1) of an
// already-sorted slice, using linear interpolation between the two
// nearest ranks — the same method NumPy uses by default.
func percentile(sorted []float64, p float64) float64 {
	switch len(sorted) {
	case 0:
		return 0
	case 1:
		return sorted[0]
	}

	rank := p * float64(len(sorted)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))
	if lower == upper {
		return sorted[lower]
	}

	frac := rank - float64(lower)
	return sorted[lower] + frac*(sorted[upper]-sorted[lower])
}

// stdDev returns the sample standard deviation (n-1 denominator) of
// values. The thesis does not specify sample vs. population standard
// deviation; sample standard deviation is used here since these values are
// a limited sample of "normal" traffic, not the full population of all
// traffic that will ever occur.
func stdDev(values []float64) float64 {
	n := len(values)
	if n < 2 {
		return 0
	}

	var mean float64
	for _, v := range values {
		mean += v
	}
	mean /= float64(n)

	var sumSq float64
	for _, v := range values {
		diff := v - mean
		sumSq += diff * diff
	}

	return math.Sqrt(sumSq / float64(n-1))
}