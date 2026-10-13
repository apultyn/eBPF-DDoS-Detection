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

	Notes []string `json:"notes"`
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
