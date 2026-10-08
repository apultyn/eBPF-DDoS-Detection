package epoch

import (
	"testing"
	"time"
)

func TestOf(t *testing.T) {
	const l = DefaultLength

	base := time.Unix(1_700_000_000, 0) // a whole second, so on a boundary

	tests := []struct {
		name string
		t    time.Time
		want Epoch
	}{
		{"on a boundary", base, 3_400_000_000},
		{"just after a boundary", base.Add(time.Nanosecond), 3_400_000_000},
		{"just before the next boundary", base.Add(l - time.Nanosecond), 3_400_000_000},
		{"on the next boundary", base.Add(l), 3_400_000_001},
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
