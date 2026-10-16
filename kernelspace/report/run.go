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

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/mitigate"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

// TimingNote explains the timing columns.
const TimingNote = "XDP assigns each packet to a window by the kernel's CLOCK_TAI. " +
	"start_ns and end_ns are converted to the wall clock (CLOCK_REALTIME) by " +
	"subtracting the TAI offset measured at start (tai_offset_seconds), so " +
	"start_ns/end_ns, closed_at_ns, eval_start_ns and eval_end_ns are all on the " +
	"same wall clock. eval_end_ns - end_ns is the detection delay after the window " +
	"ended; it includes the grace period the detector waits after each boundary " +
	"for packets still in XDP on other CPUs. eval_end_ns - eval_start_ns is the " +
	"processing time per window, including the map reads for the per-IP counts. " +
	"Detection latency from attack start is eval_end_ns of the first flagged " +
	"window minus the attack start."

// ResourceNote explains the resource columns of windows.csv.
const ResourceNote = "heap_alloc_bytes, user_cpu_ns, sys_cpu_ns, cpu_interval_ns and " +
	"cpu_share describe the user-space detector process only, sampled once per " +
	"window right after the window is evaluated. The per-packet work done by XDP " +
	"runs in the kernel and is not included. The CPU columns cover the wall-clock " +
	"interval since the previous sample (cpu_interval_ns), about one window " +
	"length, and are summed over all threads; cpu_share is (user + sys) / " +
	"interval, where 1.0 is one core fully busy. sys_cpu_ns is mostly the BPF " +
	"map reads and clears. On Linux the user/sys split has a resolution of one " +
	"scheduler tick."

// SentPacketsNote reminds that the number of packets sent is not recorded
// by the detector.
const SentPacketsNote = "The number of packets sent is not recorded here: the " +
	"detector only sees what XDP counted. Save the tcpreplay output from the " +
	"sender next to this run.json; together with live.nic_delta it shows how " +
	"many packets were lost before XDP."

// BlocklistNote explains blocking, for runs that had it on.
const BlocklistNote = "Sources flagged by their per-IP verdict were added to the " +
	"kernel blocklist, and XDP dropped their packets before the sketch. Dropped " +
	"packets are not in packets/bytes nor in any count the thresholds see; they " +
	"are in blocked_packets/blocked_bytes of the window they were dropped in. " +
	"blocked_at_ns - end_ns is the delay from the end of the window to the " +
	"sources being blocked. A source stays blocked for block_ttl after it was " +
	"last flagged (0: until the run ends); when the blocklist is full, the source " +
	"XDP saw last in the oldest window is evicted, the one with the fewest drops " +
	"among equals. The blocklist is cleared when the run starts but not when it " +
	"ends."

// How a run ended.
const (
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

	// EndReason is how the run ended: EndInterrupted on Ctrl-C,
	// EndDurationReached when the run reached its -duration, or EndError.
	EndReason string `json:"end_reason"`

	// Source is "xdp".
	Source string `json:"source"`

	Config Config `json:"config"`

	// Live describes where the kernel counted the traffic.
	Live *Live `json:"live,omitempty"`

	Stats Stats `json:"stats"`

	Notes []string `json:"notes"`
}

// Live describes a run: where the XDP program's maps were read from, and
// how many packets the interface lost before XDP.
type Live struct {
	// Interface is the interface the XDP program is attached to, used
	// only to read its counters. Empty if not given.
	Interface string `json:"interface,omitempty"`

	// PinDir is the directory the sketch maps were opened from.
	PinDir string `json:"pin_dir"`

	// TAIOffsetSeconds is CLOCK_TAI minus CLOCK_REALTIME at start, the
	// offset subtracted from the window bounds in windows.csv.
	TAIOffsetSeconds int64 `json:"tai_offset_seconds"`

	// Duration is the requested run length, empty for no limit.
	Duration string `json:"duration,omitempty"`

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
	Mode         string `json:"mode"`

	// Depth, Width and TopK are the kernel sketch's compiled-in
	// dimensions, as mirrored by the heavykeeper package; K is how many
	// of its candidates are evaluated per window.
	Depth int `json:"hk_depth"`
	Width int `json:"hk_width"`
	TopK  int `json:"hk_topk"`
	K     int `json:"k"`

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
	// Packets is the total counted by the kernel over the windows handed
	// to the detector.
	Packets uint64 `json:"packets"`

	Window window.Stats `json:"windows"`

	EvaluatedWindows uint64 `json:"evaluated_windows"`
	FlaggedWindows   uint64 `json:"flagged_windows"`
	FlaggedIPRows    uint64 `json:"flagged_ip_rows"`

	// Dropped is the incomplete last window, discarded rather than
	// evaluated. Nil if the run ended before any window was opened.
	Dropped *window.Dropped `json:"dropped_last_window"`

	TrackedIPs uint64 `json:"tracked_ips"`
	EvictedIPs uint64 `json:"evicted_ips"`

	// BlockedPackets is the total dropped by the blocklist over the
	// windows handed to the detector, and Blocklist what the detector did
	// with the blocklist. Blocklist is nil when blocking was off.
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
