package resource

import (
	"testing"
	"time"
)

func TestSampler_HostFromProcStat(t *testing.T) {
	s := NewSampler()

	burnUser(300 * time.Millisecond)
	got := s.Sample()

	if !got.HostMeasured {
		t.Fatal("/proc/stat not read")
	}

	// This process kept a core busy, so the machine was at least that
	// busy, give or take the 10 ms ticks.
	if got.HostBusy < 150*time.Millisecond {
		t.Errorf("machine busy %v while spinning 300ms", got.HostBusy)
	}

	if got.HostBusy > got.HostTotal || got.HostTotal < got.Interval/2 {
		t.Errorf("busy %v of %v over %v", got.HostBusy, got.HostTotal, got.Interval)
	}

	// The spinning goroutine may move between cores, so only check that
	// the busiest core is at least as busy as the average.
	avg := float64(got.HostBusy) / float64(got.HostTotal)
	if got.HostMaxCoreShare < avg || got.HostMaxCoreShare > 1 {
		t.Errorf("busiest core = %.2f, average %.2f", got.HostMaxCoreShare, avg)
	}
}
