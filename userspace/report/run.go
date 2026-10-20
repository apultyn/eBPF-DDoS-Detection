package report

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/mitigate"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

// TraceTimingNote explains the wall-clock columns of a trace replay, and
// is written into its run.json so the two latency measures are not
// confused.
const TraceTimingNote = "closed_at_ns, eval_start_ns and eval_end_ns are wall-clock " +
	"times on the machine running the detector. eval_end_ns - eval_start_ns " +
	"is the processing time per window. When replaying a trace, the trace is " +
	"read faster than real time, so eval_end_ns - closed_at_ns is NOT the " +
	"detection latency. Detection latency is measured in trace time: from the " +
	"attack start in the dataset labels to end_ns of the first flagged window, " +
	"and is computed in the analysis."

// LiveTimingNote explains the timing columns of a live capture.
const LiveTimingNote = "Packet timestamps are the kernel's receive times, and " +
	"start_ns/end_ns, closed_at_ns, eval_start_ns and eval_end_ns are all on the " +
	"same wall clock. eval_end_ns - end_ns is the detection delay after the window " +
	"ended; it includes the grace period the detector waits for late packets " +
	"before closing a quiet window. eval_end_ns - eval_start_ns is the processing " +
	"time per window. Detection latency from attack start is eval_end_ns of the " +
	"first flagged window minus the attack start."

// ResourceNote explains the resource columns of windows.csv.
const ResourceNote = "heap_alloc_bytes, user_cpu_ns, sys_cpu_ns, cpu_interval_ns and " +
	"cpu_share describe the detector process itself, sampled once per window " +
	"right after the window is evaluated. The CPU columns cover the wall-clock " +
	"interval since the previous sample (cpu_interval_ns) and are summed over " +
	"all threads; cpu_share is (user + sys) / interval, where 1.0 is one core " +
	"fully busy. In a live capture the interval is about one window length. In " +
	"a trace replay the input is read as fast as possible, so cpu_share is " +
	"close to 1 by construction; use (user_cpu_ns + sys_cpu_ns) / packets as " +
	"the cost per packet instead. sys_cpu_ns is mostly the capture's system " +
	"calls. On Linux the user/sys split has a resolution of one scheduler tick."

// HostCPUNote explains the machine-wide CPU columns of windows.csv.
const HostCPUNote = "host_busy_ns, host_total_ns, host_softirq_ns and " +
	"host_max_core_share describe the CPU use of the whole machine, read from " +
	"/proc/stat at the same moments as the detector's own CPU columns. They " +
	"include the packet processing the kernel does in softirq, which the process's own columns miss, and " +
	"everything else running on the machine, such as memwatch, so the sender " +
	"should run on another machine. host_total_ns is all CPU time over the " +
	"interval summed over the cores, idle included, about cpu_interval_ns times " +
	"the number of cores; host_busy_ns / host_total_ns is the share of the whole " +
	"machine in use. host_softirq_ns is the part of host_busy_ns spent in " +
	"softirq. host_max_core_share is the busy share of the busiest core: packets " +
	"are processed on the cores that receive them, so one core can be saturated " +
	"while the machine is not. /proc/stat counts in 10 ms ticks per core. The " +
	"cost of the detector itself is host_busy_ns minus that of a baseline run " +
	"with the same traffic and no detector."

// SentPacketsNote reminds that the number of packets sent is not recorded
// by the detector.
const SentPacketsNote = "The number of packets sent is not recorded here: the " +
	"detector only sees what arrives. Save the tcpreplay output from the sender " +
	"next to this run.json; together with live.socket and live.nic_delta it " +
	"shows how many packets were lost before the detector and at which layer."

// BlocklistNote explains blocking, for runs that had it on.
const BlocklistNote = "Sources flagged by their per-IP verdict were added to the " +
	"blocklist of blocklist.c, an XDP program on the interface, which dropped their " +
	"packets before they reached the capture socket. Dropped packets are not in " +
	"packets/bytes, kernel_drops or live.socket, nor in any count the thresholds " +
	"see; they are in blocked_packets/blocked_bytes. Unlike the kernel-space " +
	"detector's, these are counted when a window closes, not by the time of the " +
	"dropped packet: a window's figure is what was dropped since the previous " +
	"window closed, including the grace period after the window's end. " +
	"blocked_at_ns - end_ns is the delay from the end of the window to the " +
	"sources being blocked. A source stays blocked for block_ttl after it was " +
	"last flagged (0: until the run ends); when the blocklist is full, the source " +
	"XDP saw last in the oldest window is evicted, the one with the fewest drops " +
	"among equals. The blocklist is cleared when the run starts but not when it " +
	"ends."

// BPFMemoryNote explains bpf_memory.
const BPFMemoryNote = "bpf_memory is the kernel memory of the XDP blocklist's maps, " +
	"each as the kernel reports it (memlock in the map's fdinfo: computed per " +
	"map type from Linux 6.4 on, estimated from the map's dimensions before). " +
	"The maps are charged to the memory cgroup of the process that loaded " +
	"blocklist.o (ip link), not to the detector's, so memwatch's main for the " +
	"detector does not include them. Both maps are per-CPU, grow with the number " +
	"of possible CPUs, and are preallocated, so their memory does not depend on " +
	"the traffic. The program itself, its instructions and JIT image, is not " +
	"included."

// How a run ended.
const (
	EndSourceEnded     = "source_ended"
	EndInterrupted     = "interrupted"
	EndDurationReached = "duration_reached"
	EndError           = "error"
)

// Run describes one detector run: what it read, how it was configured, and
// what happened. It is written to run.json next to the CSV files.
type Run struct {
	Tool       string    `json:"tool"`
	Version    Version   `json:"version"`
	Args       []string  `json:"args"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`

	// EndReason is how the run ended: EndSourceEnded when the trace
	// files ran out, EndInterrupted on Ctrl-C, EndDurationReached when a
	// live capture reached its -duration, or EndError.
	EndReason string `json:"end_reason"`

	// Source is "pcap" or "live".
	Source string `json:"source"`

	Config Config `json:"config"`

	// Inputs lists every file read, in reading order, for a trace replay.
	// A file never reached, because the run ended early, is not included.
	Inputs []capture.FileStat `json:"inputs,omitempty"`

	// Live describes a live capture.
	Live *Live `json:"live,omitempty"`

	Stats Stats `json:"stats"`

	// BPFMemory is the kernel memory of the XDP blocklist's maps. Nil when
	// blocking was off.
	BPFMemory *BPFMemory `json:"bpf_memory,omitempty"`

	Notes []string `json:"notes"`
}

// BPFMemory is the kernel memory of the XDP blocklist's maps, as the
// kernel reports it for each map.
type BPFMemory struct {
	// Maps is each map's memory at the end of the run, by pin name. Nil
	// if it could not be read.
	Maps map[string]uint64 `json:"maps,omitempty"`

	// TotalBytes is the sum of Maps, and StartTotalBytes the same sum at
	// the start of the run. The maps are preallocated, so the two should
	// be equal; a warning says when they are not. Zero if not read.
	TotalBytes      uint64 `json:"total_bytes"`
	StartTotalBytes uint64 `json:"start_total_bytes"`

	Warnings []string `json:"warnings,omitempty"`
}

// Live describes a live capture: where it listened, and how many packets
// were lost at each layer below the detector.
type Live struct {
	Interface string `json:"interface"`

	// Duration is the requested capture length, empty for no limit.
	Duration string `json:"duration,omitempty"`

	// RequestedRecvBuffer is the -rcvbuf value; zero means the system
	// default was kept.
	RequestedRecvBuffer int `json:"requested_recv_buffer_bytes"`

	// Socket is the AF_PACKET socket's own view: packets offered to it,
	// packets it dropped for lack of buffer space, and how packets were
	// timestamped.
	Socket capture.LiveStats `json:"socket"`

	// BlocklistPinned reports that the maps of blocklist.c were pinned at
	// start, so the XDP blocklist was most likely attached and every
	// packet passed through it before the socket, even with blocking off.
	// It is always true when blocking was on.
	BlocklistPinned bool `json:"blocklist_pinned"`

	// NICStart and NICEnd are the interface counters at start and end,
	// and NICDelta their difference. NICWarnings records counters that
	// could not be read, such as ethtool being unavailable.
	NICStart    capture.NICCounters `json:"nic_start,omitempty"`
	NICEnd      capture.NICCounters `json:"nic_end,omitempty"`
	NICDelta    capture.NICCounters `json:"nic_delta,omitempty"`
	NICWarnings []string            `json:"nic_warnings,omitempty"`
}

// Version identifies the code that produced the run.
type Version struct {
	Commit   string `json:"commit"`
	Modified bool   `json:"modified"`
	Go       string `json:"go"`
}

// Config is the full configuration of a run, flattened to plain values.
type Config struct {
	WindowLength string `json:"window_length"`
	MaxEmpty     int    `json:"max_empty"`

	Counts string `json:"counts"`
	Mode   string `json:"mode"`

	Depth     int     `json:"hk_depth"`
	Width     int     `json:"hk_width"`
	DecayBase float64 `json:"hk_decay_base"`
	K         int     `json:"k"`
	Seed      uint64  `json:"seed"`
	CMSWidth  uint64  `json:"cms_width"`
	CMSDepth  uint64  `json:"cms_depth"`

	BaseThreshold    float64 `json:"iqr_base_threshold"`
	IQRMultiplier    float64 `json:"iqr_multiplier"`
	OffsetMultiplier float64 `json:"iqr_offset_multiplier"`
	MinSamples       int     `json:"iqr_min_samples"`
	MaxHistorySize   int     `json:"iqr_max_history"`
	MaxTrackedIPs    int     `json:"iqr_max_tracked_ips"`

	IPMode               string `json:"iqr_ip_mode"`
	MaxSharedHistorySize int    `json:"iqr_max_shared_history"`

	// Block reports whether flagged sources were blocked. BlockTTL,
	// BlockCapacity and BlockAllow are only set when they were.
	Block         bool     `json:"block"`
	BlockTTL      string   `json:"block_ttl,omitempty"`
	BlockCapacity int      `json:"block_capacity,omitempty"`
	BlockAllow    []string `json:"block_allow,omitempty"`
}

// Stats summarizes the run.
type Stats struct {
	Packets uint64 `json:"packets"`
	Skipped uint64 `json:"skipped_frames"`

	Window window.Stats `json:"windows"`

	EvaluatedWindows uint64 `json:"evaluated_windows"`
	FlaggedWindows   uint64 `json:"flagged_windows"`
	FlaggedIPRows    uint64 `json:"flagged_ip_rows"`

	// Dropped is the incomplete last window, discarded rather than
	// evaluated. Nil if no packet was read.
	Dropped *window.Dropped `json:"dropped_last_window"`

	TrackedIPs uint64 `json:"tracked_ips"`
	EvictedIPs uint64 `json:"evicted_ips"`

	// BlockedPackets is the total dropped by the XDP blocklist over the
	// windows evaluated, and Blocklist what the detector did with the
	// blocklist. Blocklist is nil when blocking was off.
	BlockedPackets uint64          `json:"blocked_packets"`
	Blocklist      *mitigate.Stats `json:"blocklist,omitempty"`

	WallSeconds      float64 `json:"wall_seconds"`
	PacketsPerSecond float64 `json:"packets_per_second"`
}

// CurrentVersion reports the commit the binary was built from. A binary
// built with go build in the repository carries it; for go run it is
// read from git in the working directory instead.
func CurrentVersion() Version {
	v := Version{Commit: "unknown"}

	if info, ok := debug.ReadBuildInfo(); ok {
		v.Go = info.GoVersion

		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				v.Commit = s.Value
			case "vcs.modified":
				v.Modified = s.Value == "true"
			}
		}
	}

	if v.Commit == "unknown" {
		if out, err := exec.Command("git", "rev-parse", "HEAD").Output(); err == nil {
			v.Commit = strings.TrimSpace(string(out))

			status, err := exec.Command("git", "status", "--porcelain", "--untracked-files=no").Output()
			v.Modified = err == nil && len(status) > 0
		}
	}

	return v
}

// WriteRun writes run.json into dir.
func WriteRun(dir string, r *Run, overwrite bool) error {
	path := filepath.Join(dir, RunFile)

	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}

	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return fmt.Errorf("report: %w", err)
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	if err := enc.Encode(r); err != nil {
		f.Close()
		return fmt.Errorf("report: %w", err)
	}

	return f.Close()
}
