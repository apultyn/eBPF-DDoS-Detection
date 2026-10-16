package epoch

import (
	"testing"
	"time"
)

func TestOf(t *testing.T) {
	const l = DefaultLength

	// An epoch from late 2023, and the instant it starts.
	const e0 Epoch = 3_166_496_754
	base := time.Unix(0, int64(e0)*int64(l))

	tests := []struct {
		name string
		t    time.Time
		want Epoch
	}{
		{"on a boundary", base, e0},
		{"just after a boundary", base.Add(time.Nanosecond), e0},
		{"just before the next boundary", base.Add(l - time.Nanosecond), e0},
		{"on the next boundary", base.Add(l), e0 + 1},
		{"unix epoch", time.Unix(0, 0), 0},
		{"before the unix epoch", time.Unix(0, -1), -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Of(tt.t, l); got != tt.want {
				t.Errorf("Of(%v) = %d, want %d", tt.t, got, tt.want)
			}
		})
	}
}

// The kernel numbers windows as bpf_ktime_get_tai_ns() >> 29. Both sides
// must agree on every epoch, or the detector reads the wrong slot.
func TestMatchesKernelShift(t *testing.T) {
	if DefaultLength != 1<<29 {
		t.Fatalf("DefaultLength = %v, heavy_keeper.c shifts by 29", DefaultLength)
	}

	for _, ns := range []int64{0, 1, 1<<29 - 1, 1 << 29, 1_700_000_000_123_456_789, 1<<62 + 12345} {
		if got, want := FromNanos(ns, DefaultLength), Epoch(uint64(ns)>>29); got != want {
			t.Errorf("FromNanos(%d) = %d, kernel computes %d", ns, got, want)
		}
	}
}

func TestStartEnd(t *testing.T) {
	const l = DefaultLength

	for _, ts := range []time.Time{
		time.Unix(1_700_000_000, 123_456_789),
		time.Unix(0, -1),
	} {
		e := Of(ts, l)

		if start := e.Start(l); start.After(ts) || !e.End(l).After(ts) {
			t.Errorf("%v not within [%v, %v)", ts, start, e.End(l))
		}

		if got := e.End(l).Sub(e.Start(l)); got != l {
			t.Errorf("window length = %v, want %v", got, l)
		}

		if Of(e.End(l), l) != e+1 {
			t.Errorf("End of epoch %d does not start epoch %d", e, e+1)
		}
	}
}
