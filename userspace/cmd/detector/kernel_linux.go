package main

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/blocklist"
)

// openBlocklist opens the pinned blocklist of blocklist.c and clears it,
// so the run does not start with sources blocked by an earlier one.
func openBlocklist(pinDir string) (blocklistMap, error) {
	b, err := blocklist.Open(pinDir)
	if err != nil {
		return nil, err
	}

	if err := b.Clear(); err != nil {
		b.Close()
		return nil, err
	}

	return b, nil
}

// taiClock returns a function reading CLOCK_TAI, the clock XDP stamps a
// blocked source's last drop with bpf_ktime_get_tai_ns. The clock is read
// once here, so a kernel without it fails at start rather than mid-run.
func taiClock() (func() time.Time, error) {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_TAI, &ts); err != nil {
		return nil, fmt.Errorf("reading CLOCK_TAI: %w", err)
	}

	return func() time.Time {
		var ts unix.Timespec

		// It worked above; CLOCK_TAI does not go away mid-run.
		_ = unix.ClockGettime(unix.CLOCK_TAI, &ts)

		return time.Unix(ts.Unix())
	}, nil
}
