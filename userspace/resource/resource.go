// Package resource measures the detector process's own memory and CPU
// use, once per window.
//
// CPU time is read from getrusage, which is cumulative, so each sample
// reports the time used since the previous one. User and system time are
// kept apart: system time is largely the per-packet system calls of the
// AF_PACKET capture, which is the cost moving to XDP should remove.
package resource

import (
	"runtime"
	"syscall"
	"time"
)

// Sample is the process's resource use over one interval.
type Sample struct {
	// HeapAlloc is the bytes of live heap objects at the end of the
	// interval, from runtime.MemStats.Alloc.
	HeapAlloc uint64

	// UserCPU and SysCPU are the CPU time spent in user mode and in the
	// kernel during the interval, summed over all threads.
	UserCPU time.Duration
	SysCPU  time.Duration

	// Interval is the wall-clock time the CPU figures cover.
	Interval time.Duration
}

// CPUShare returns the CPU time used as a fraction of one core over the
// interval: 1.0 means one core fully busy. It is zero for an empty
// interval.
func (s Sample) CPUShare() float64 {
	if s.Interval <= 0 {
		return 0
	}

	return float64(s.UserCPU+s.SysCPU) / float64(s.Interval)
}

// Sampler takes consecutive samples. Not safe for concurrent use.
type Sampler struct {
	user, sys time.Duration
	wall      time.Time

	mem runtime.MemStats
	now func() time.Time
}

// NewSampler starts measuring from now: the first sample covers the time
// since NewSampler was called.
func NewSampler() *Sampler {
	s := &Sampler{now: time.Now}

	s.user, s.sys = cpuTimes()
	s.wall = s.now()

	return s
}

// Sample returns the resource use since the previous sample.
//
// It reads runtime.MemStats, which briefly stops the program, so it is
// meant to be called once per window, never per packet.
func (s *Sampler) Sample() Sample {
	user, sys := cpuTimes()
	wall := s.now()

	runtime.ReadMemStats(&s.mem)

	out := Sample{
		HeapAlloc: s.mem.Alloc,
		UserCPU:   user - s.user,
		SysCPU:    sys - s.sys,
		Interval:  wall.Sub(s.wall),
	}

	s.user, s.sys, s.wall = user, sys, wall

	return out
}

// cpuTimes returns the process's cumulative user and system CPU time.
//
// On Linux the split between the two is derived from scheduler ticks, so
// it has a resolution of one tick (4 ms at the common HZ=250); the sum is
// exact. Over a 0.5 s window that is about one percent of a core.
func cpuTimes() (user, sys time.Duration) {
	var ru syscall.Rusage

	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0
	}

	return time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano())
}
