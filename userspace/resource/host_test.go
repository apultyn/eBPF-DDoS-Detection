package resource

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Two /proc/stat snapshots one second apart on a two-core machine:
// columns are user nice system idle iowait irq softirq steal guest
// guest_nice, in ticks of 10 ms. cpu0 handles the packets and is busy for
// 90 of its 100 ticks, 50 of them in softirq; cpu1 is busy for 10.
const (
	statBefore = `cpu  2000 0 1000 50000 100 0 500 0 900 0
cpu0 1000 0 500 25000 50 0 400 0 900 0
cpu1 1000 0 500 25000 50 0 100 0 0 0
intr 123456 0 0
ctxt 987654
`
	statAfter = `cpu  2040 0 1010 50100 100 0 550 0 950 0
cpu0 1030 0 510 25010 50 0 450 0 950 0
cpu1 1010 0 500 25090 50 0 100 0 0 0
intr 123999 0 0
ctxt 987999
`
)

// fakeHost returns a readHost that serves the given snapshots in turn,
// and fails where an entry is empty.
func fakeHost(t *testing.T, snapshots ...string) func(*hostTimes) error {
	t.Helper()

	return func(h *hostTimes) error {
		if len(snapshots) == 0 {
			t.Fatal("more /proc/stat reads than snapshots")
		}

		s := snapshots[0]
		snapshots = snapshots[1:]

		if s == "" {
			return errors.New("unreadable")
		}

		return parseProcStat(strings.NewReader(s), h)
	}
}

func TestParseProcStat(t *testing.T) {
	var h hostTimes

	if err := parseProcStat(strings.NewReader(statBefore), &h); err != nil {
		t.Fatal(err)
	}

	if h.all[statUser] != 2000 || h.all[statSoftIRQ] != 500 || h.all[statSteal] != 0 {
		t.Errorf("cpu line = %v", h.all)
	}

	if len(h.cores) != 2 || h.cores[0].id != 0 || h.cores[1].id != 1 || h.cores[0].ticks[statSoftIRQ] != 400 {
		t.Errorf("cores = %+v, want cpu0 and cpu1", h.cores)
	}

	// A kernel older than 2.6.11 stops after iowait; the missing columns
	// read as zero.
	if err := parseProcStat(strings.NewReader("cpu 1 2 3 4 5\ncpu0 1 2 3 4 5\n"), &h); err != nil {
		t.Fatal(err)
	}
	if h.all[statIOWait] != 5 || h.all[statSteal] != 0 || len(h.cores) != 1 {
		t.Errorf("short lines parsed as %v, %+v", h.all, h.cores)
	}

	for name, bad := range map[string]string{
		"no cpu line":  "intr 1 2 3\n",
		"short line":   "cpu 1 2 3\n",
		"not a number": "cpu 1 2 x 4\n",
	} {
		if err := parseProcStat(strings.NewReader(bad), &h); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSampler_Host(t *testing.T) {
	s := newSampler(time.Now, fakeHost(t, statBefore, statAfter))

	got := s.Sample()

	if !got.HostMeasured {
		t.Fatal("host not measured")
	}

	// busy = user 40 + system 10 + softirq 50 = 100 ticks; guest's 50 is
	// already in user and must not be added again. total adds idle 100.
	if got.HostBusy != time.Second || got.HostTotal != 2*time.Second {
		t.Errorf("busy %v of %v, want 1s of 2s", got.HostBusy, got.HostTotal)
	}

	if got.HostSoftirq != 500*time.Millisecond {
		t.Errorf("softirq = %v, want 500ms", got.HostSoftirq)
	}

	if got.HostMaxCoreShare != 0.9 {
		t.Errorf("busiest core = %v, want 0.9 (cpu0)", got.HostMaxCoreShare)
	}
}

func TestSampler_HostCounterGoingBackwards(t *testing.T) {
	// iowait drops by 20 ticks between the snapshots; it must count as
	// zero rather than wrapping around.
	before := "cpu 100 0 0 1000 50 0 0 0\ncpu0 100 0 0 1000 50 0 0 0\n"
	after := "cpu 150 0 0 1050 30 0 0 0\ncpu0 150 0 0 1050 30 0 0 0\n"

	got := newSampler(time.Now, fakeHost(t, before, after)).Sample()

	if got.HostBusy != 500*time.Millisecond || got.HostTotal != time.Second || got.HostMaxCoreShare != 0.5 {
		t.Errorf("busy %v of %v, busiest core %v; want 500ms of 1s and 0.5",
			got.HostBusy, got.HostTotal, got.HostMaxCoreShare)
	}
}

func TestSampler_HostCoreOnlyAtOneEnd(t *testing.T) {
	// cpu1 goes offline and cpu2 comes online: only cpu0 is seen at both
	// ends, so only it counts toward the busiest core.
	before := "cpu 0 0 0 0\ncpu0 0 0 0 100\ncpu1 0 0 0 0\n"
	after := "cpu 30 0 0 170\ncpu0 30 0 0 170\ncpu2 100 0 0 0\n"

	got := newSampler(time.Now, fakeHost(t, before, after)).Sample()

	if got.HostMaxCoreShare != 0.3 {
		t.Errorf("busiest core = %v, want 0.3 (cpu0 only)", got.HostMaxCoreShare)
	}
}

func TestSampler_HostUnreadable(t *testing.T) {
	// The first read fails, so the first interval has no start; the
	// second has both ends; the third has no end.
	s := newSampler(time.Now, fakeHost(t, "", statBefore, statAfter, ""))

	if got := s.Sample(); got.HostMeasured {
		t.Errorf("measured without a starting snapshot: %+v", got)
	}

	if got := s.Sample(); !got.HostMeasured || got.HostBusy != time.Second {
		t.Errorf("second sample = %+v, want measured with 1s busy", got)
	}

	if got := s.Sample(); got.HostMeasured || got.HostBusy != 0 {
		t.Errorf("measured without an ending snapshot: %+v", got)
	}
}
