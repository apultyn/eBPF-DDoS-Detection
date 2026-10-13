// Package epoch divides time into the fixed-length windows the detector
// counts traffic in.
//
// An epoch is the number of whole window lengths since the Unix epoch:
//
//	epoch = floor(timestamp_ns / length_ns)
//
// The kernel-space implementation computes the same formula on its own
// timestamp, so a packet lands in the same window on both sides as long
// as both use the same clock and window length. With unsigned
// nanoseconds, as returned by the BPF time helpers, the floor is plain
// integer division.
//
// Clock base matters for the epoch numbers, not for the boundaries:
// bpf_ktime_get_ns counts from boot, so its epoch numbers differ from
// the ones computed here, and its boundaries only coincide with ours if
// boot time happens to fall on a multiple of the window length.
// bpf_ktime_get_tai_ns runs on TAI, which is offset from Unix time by a
// whole number of seconds, so with a window length that divides one
// second the boundaries coincide exactly.
package epoch

import "time"

// DefaultLength is the window length used by the detector.
const DefaultLength = 500 * time.Millisecond

// Epoch numbers a window. Consecutive windows have consecutive numbers.
type Epoch int64

// Of returns the epoch that t falls in.
//
// A timestamp exactly on a boundary belongs to the window that starts
// there, so every instant falls in exactly one window.
func Of(t time.Time, length time.Duration) Epoch {
	return FromNanos(t.UnixNano(), length)
}

// FromNanos returns the epoch for a timestamp given in nanoseconds since
// the Unix epoch. This is the form the kernel side computes.
func FromNanos(ns int64, length time.Duration) Epoch {
	l := int64(length)

	// Go's division truncates toward zero; floor it so timestamps before
	// 1970 still fall in the window that contains them.
	e := ns / l
	if ns%l < 0 {
		e--
	}

	return Epoch(e)
}

// Start returns the first instant of the window.
func (e Epoch) Start(length time.Duration) time.Time {
	return time.Unix(0, int64(e)*int64(length))
}

// End returns the first instant after the window, which is the start of
// the next one.
func (e Epoch) End(length time.Duration) time.Time {
	return (e + 1).Start(length)
}
