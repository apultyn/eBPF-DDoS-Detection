// Package countmin implements a Count-Min Sketch: a probabilistic data
// structure that estimates the frequency of items in a data stream using
// sub-linear memory.
//
// The sketch never underestimates a true count, but may overestimate it
// due to hash collisions. Width (w) and depth (d) of the counter matrix
// control the accuracy/memory trade-off:
//
//	w = ceil(e / epsilon)
//	d = ceil(ln(1 / delta))
//
// With these parameters, an estimate is guaranteed to fall within
// true_count + epsilon*totalCount with probability at least 1 - delta.
//
// This mirrors the Count-Min Sketch used in Wickman & Rygaard's thesis
// (2025) for per-source-IP packet counting within a sliding time window.
// Because a Count-Min Sketch supports no deletion, callers using one
// sketch per sliding window should discard the sketch when the window
// closes and construct a fresh one for the next window, rather than
// trying to decay individual entries.
//
// Reference: Cormode & Muthukrishnan, "An Improved Data Stream Summary:
// The Count-Min Sketch and its Applications", Journal of Algorithms, 2005.
package countmin

import (
	"errors"
	"hash/maphash"
	"math"
)

// Sketch is a Count-Min Sketch counter matrix.
//
// A zero-value Sketch is not usable; construct one with New or
// NewWithDimensions.
type Sketch struct {
	width  uint64
	depth  uint64
	counts [][]uint64
	seeds  []maphash.Seed
	total  uint64 // running sum of all deltas passed to Add
}

// New creates a Sketch sized for the given accuracy parameters.
//
// epsilon controls the error bound relative to the total stream count
// (smaller epsilon = more accurate = more memory). delta controls the
// confidence that the error bound holds (smaller delta = higher
// confidence = more memory). Typical starting values are epsilon = 0.001
// and delta = 0.01, but the right values depend on expected traffic
// volume and the memory budget — tune per dataset.
func New(epsilon, delta float64) (*Sketch, error) {
	if epsilon <= 0 || epsilon >= 1 {
		return nil, errors.New("countmin: epsilon must be in (0, 1)")
	}
	if delta <= 0 || delta >= 1 {
		return nil, errors.New("countmin: delta must be in (0, 1)")
	}

	width := uint64(math.Ceil(math.E / epsilon))
	depth := uint64(math.Ceil(math.Log(1 / delta)))

	return NewWithDimensions(width, depth), nil
}

// NewWithDimensions creates a Sketch with an explicit width and depth,
// bypassing the epsilon/delta calculation in New. Useful for tests and
// for callers that already know their memory budget in terms of counters
// rather than in terms of an accuracy guarantee.
func NewWithDimensions(width, depth uint64) *Sketch {
	if width == 0 {
		width = 1
	}
	if depth == 0 {
		depth = 1
	}

	counts := make([][]uint64, depth)
	seeds := make([]maphash.Seed, depth)
	for i := range counts {
		counts[i] = make([]uint64, width)
		seeds[i] = maphash.MakeSeed()
	}

	return &Sketch{
		width:  width,
		depth:  depth,
		counts: counts,
		seeds:  seeds,
	}
}

// Add increments the estimated count for key by delta. Passing delta = 1
// per observed packet is the common case; a caller that has already
// pre-aggregated counts for a key can pass the aggregate directly.
func (s *Sketch) Add(key string, delta uint64) {
	for row, seed := range s.seeds {
		col := maphash.String(seed, key) % s.width
		s.counts[row][col] += delta
	}
	s.total += delta
}

// Estimate returns the estimated frequency of key. The result is never
// lower than the true count for key, but may be higher due to hash
// collisions with other keys.
func (s *Sketch) Estimate(key string) uint64 {
	if s.depth == 0 {
		return 0
	}

	min := uint64(math.MaxUint64)
	for row, seed := range s.seeds {
		col := maphash.String(seed, key) % s.width
		if c := s.counts[row][col]; c < min {
			min = c
		}
	}
	return min
}

// Total returns the sum of all deltas passed to Add since the sketch was
// created (or last Reset). This is the N used in the sketch's epsilon*N
// error bound.
func (s *Sketch) Total() uint64 {
	return s.total
}

// Reset clears all counters and the running total without reallocating
// the underlying matrix. Prefer constructing a new Sketch per sliding
// window over calling Reset mid-window: Reset wipes every key at once,
// which is exactly what you want between windows, but it cannot remove
// a single stale entry.
func (s *Sketch) Reset() {
	for row := range s.counts {
		for col := range s.counts[row] {
			s.counts[row][col] = 0
		}
	}
	s.total = 0
}

// Width returns the number of columns (counters per row).
func (s *Sketch) Width() uint64 { return s.width }

// Depth returns the number of rows (independent hash functions).
func (s *Sketch) Depth() uint64 { return s.depth }