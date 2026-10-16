package main

import (
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/unix"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

// openKernel opens the pinned maps of the XDP program and clears them, so
// the run does not start with counts left over from before it.
func openKernel(pinDir string) (window.Source, io.Closer, error) {
	s, err := heavykeeper.Open(pinDir)
	if err != nil {
		return nil, nil, err
	}

	if err := s.ResetAll(); err != nil {
		s.Close()
		return nil, nil, err
	}

	return s, s, nil
}

// taiClock returns a function reading CLOCK_TAI, the clock XDP picks a
// packet's window by with bpf_ktime_get_tai_ns. The clock is read once
// here, so a kernel without it fails at start rather than mid-run.
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
