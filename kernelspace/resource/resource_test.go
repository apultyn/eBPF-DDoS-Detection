package resource

import (
	"os"
	"testing"
	"time"
)

// burnUser spins in user mode for about d.
func burnUser(d time.Duration) {
	end := time.Now().Add(d)

	x := 0
	for time.Now().Before(end) {
		for i := 0; i < 1000; i++ {
			x += i
		}
	}

	_ = x
}

// burnSys makes system calls for about d.
func burnSys(t *testing.T, d time.Duration) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	buf := make([]byte, 1)
	end := time.Now().Add(d)

	for time.Now().Before(end) {
		for i := 0; i < 100; i++ {
			f.Read(buf)
			f.Seek(0, 0)
		}
	}
}

func TestSampler_MeasuresSinceLastSample(t *testing.T) {
	s := NewSampler()

	burnUser(200 * time.Millisecond)
	busy := s.Sample()

	if busy.UserCPU < 100*time.Millisecond {
		t.Errorf("user CPU = %v after spinning 200ms, want at least 100ms", busy.UserCPU)
	}

	if share := busy.CPUShare(); share < 0.5 || share > 2 {
		t.Errorf("CPU share = %.2f while spinning on one goroutine, want about 1", share)
	}

	if busy.HeapAlloc == 0 {
		t.Error("heap in use reported as zero")
	}

	// The next sample covers only the time since the previous one.
	time.Sleep(200 * time.Millisecond)
	idle := s.Sample()

	if idle.UserCPU > 50*time.Millisecond {
		t.Errorf("user CPU = %v while sleeping; the previous interval leaked into this one", idle.UserCPU)
	}

	if idle.Interval < 150*time.Millisecond || idle.Interval > time.Second {
		t.Errorf("interval = %v, want about 200ms", idle.Interval)
	}
}

func TestSampler_SeparatesSystemTime(t *testing.T) {
	s := NewSampler()

	burnSys(t, 300*time.Millisecond)
	sample := s.Sample()

	// The loop is mostly read and seek system calls, so the kernel's share
	// must show up separately. Exact proportions depend on the OS.
	if sample.SysCPU < 20*time.Millisecond {
		t.Errorf("system CPU = %v (user %v) during a system call loop", sample.SysCPU, sample.UserCPU)
	}
}

func TestSample_CPUShareOfEmptyInterval(t *testing.T) {
	if got := (Sample{UserCPU: time.Second}).CPUShare(); got != 0 {
		t.Errorf("CPUShare with no interval = %v, want 0", got)
	}
}
