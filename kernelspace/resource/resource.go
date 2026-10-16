// Package resource measures the detector process's own memory and CPU
// use, and the CPU use of the whole machine, once per window.
//
// CPU time is read from getrusage, which is cumulative, so each sample
// reports the time used since the previous one. User and system time are
// kept apart: system time is largely the per-packet system calls of the
// AF_PACKET capture, which is the cost moving to XDP should remove.
//
// The process's own figures miss the packet processing the kernel does in
// softirq, which is where XDP runs. The machine's CPU time, read from
// /proc/stat in the same way, includes it, so the two detectors can be
// compared on it.
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

	// HostBusy and HostTotal are the CPU time of the whole machine over
	// the interval, summed over all cores: HostTotal is all of it, idle
	// included, so about Interval times the number of cores, and HostBusy
	// the part that was not idle. HostSoftirq is the part of HostBusy
	// spent in softirq, where the kernel processes received packets and
	// XDP runs.
	HostBusy    time.Duration
	HostTotal   time.Duration
	HostSoftirq time.Duration

	// HostMaxCoreShare is the busy fraction of the busiest core over the
	// interval. Packet processing runs on the cores that receive the
	// packets, so one core can be saturated while the machine as a whole
	// is not.
	HostMaxCoreShare float64

	// HostMeasured reports whether the host fields were measured. They
	// are not off Linux, or when /proc/stat could not be read at either
	// end of the interval.
	HostMeasured bool
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

	// host and hostNext are the previous and the current /proc/stat
	// snapshot, swapped after each sample so their core slices are
	// reused. hostOK reports whether host holds a valid snapshot.
	host, hostNext hostTimes
	hostOK         bool

	mem      runtime.MemStats
	now      func() time.Time
	readHost func(*hostTimes) error
}

// NewSampler starts measuring from now: the first sample covers the time
// since NewSampler was called.
func NewSampler() *Sampler {
	return newSampler(time.Now, readHostTimes)
}

func newSampler(now func() time.Time, readHost func(*hostTimes) error) *Sampler {
	s := &Sampler{now: now, readHost: readHost}

	s.user, s.sys = cpuTimes()
	s.wall = s.now()
	s.hostOK = s.readHost(&s.host) == nil

	return s
}

// Sample returns the resource use since the previous sample.
//
// It reads runtime.MemStats, which briefly stops the program, so it is
// meant to be called once per window, never per packet.
func (s *Sampler) Sample() Sample {
	user, sys := cpuTimes()
	wall := s.now()
	hostErr := s.readHost(&s.hostNext)

	runtime.ReadMemStats(&s.mem)

	out := Sample{
		HeapAlloc: s.mem.Alloc,
		UserCPU:   user - s.user,
		SysCPU:    sys - s.sys,
		Interval:  wall.Sub(s.wall),
	}

	s.user, s.sys, s.wall = user, sys, wall

	if hostErr == nil && s.hostOK {
		hostDelta(&out, s.hostNext, s.host)
	}
	s.host, s.hostNext = s.hostNext, s.host
	s.hostOK = hostErr == nil

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
