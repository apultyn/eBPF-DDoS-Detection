// Package report writes detection results to disk: one CSV row per window,
// one CSV row per evaluated candidate, and a run.json describing the run
// they came from.
package report

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/resource"
)

// Output file names inside the output directory.
const (
	WindowsFile = "windows.csv"
	IPsFile     = "ips.csv"
	RunFile     = "run.json"
)

// Sink receives every window result of a run.
type Sink interface {
	Write(r *detector.WindowResult) error
	Close() error
}

// windowColumns is the header of windows.csv. Timestamps are integer
// nanoseconds since the Unix epoch.
var windowColumns = []string{
	"epoch", "start_ns", "end_ns",
	"skipped_before", "packets", "bytes", "kernel_drops",
	"evaluated", "evaluated_packets",
	"warm_up", "threshold", "quartile_bound", "threshold_term", "malicious",
	"flagged_ips",
	"closed_at_ns", "eval_start_ns", "eval_end_ns",
	"heap_alloc_bytes", "user_cpu_ns", "sys_cpu_ns", "cpu_interval_ns", "cpu_share",
	"blocked_packets", "blocked_bytes", "blocked_at_ns",
	"host_busy_ns", "host_total_ns", "host_softirq_ns", "host_max_core_share",
}

// ipColumns is the header of ips.csv. Rows join windows.csv on epoch.
// threshold_source and blocked are last so that the columns before them
// keep the positions they had before they were added.
var ipColumns = []string{
	"epoch", "ip",
	"current", "previous", "evaluated",
	"warm_up", "threshold", "quartile_bound", "threshold_term", "malicious",
	"threshold_source", "blocked",
}

// CSVSink writes windows.csv and ips.csv.
//
// Every closed window gets a row in windows.csv, including windows that
// could not be evaluated; their detection columns are left empty. Every
// candidate of an evaluated window gets a row in ips.csv, flagged or not,
// since the unflagged ones are what a threshold is calibrated from.
type CSVSink struct {
	files   []*os.File
	bufs    []*bufio.Writer
	windows *csv.Writer
	ips     *csv.Writer

	row []string
}

// NewCSVSink creates the two CSV files in dir. Existing files are only
// replaced when overwrite is set, so a calibration run is not lost to a
// mistyped output directory.
func NewCSVSink(dir string, overwrite bool) (*CSVSink, error) {
	s := &CSVSink{}

	w, err := s.create(filepath.Join(dir, WindowsFile), overwrite)
	if err != nil {
		return nil, err
	}

	ip, err := s.create(filepath.Join(dir, IPsFile), overwrite)
	if err != nil {
		s.Close()
		return nil, err
	}

	s.windows, s.ips = w, ip

	s.windows.Write(windowColumns)
	s.ips.Write(ipColumns)

	return s, nil
}

func (s *CSVSink) create(path string, overwrite bool) (*csv.Writer, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !overwrite {
		flags |= os.O_EXCL
	}

	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("report: %s already exists (use -force to overwrite)", path)
		}
		return nil, fmt.Errorf("report: %w", err)
	}

	b := bufio.NewWriterSize(f, 1<<16)

	s.files = append(s.files, f)
	s.bufs = append(s.bufs, b)

	return csv.NewWriter(b), nil
}

// Write appends the window's row and its candidates' rows.
func (s *CSVSink) Write(r *detector.WindowResult) error {
	epoch := strconv.FormatInt(int64(r.Epoch), 10)

	row := s.row[:0]
	row = append(row,
		epoch, ns(r.Start), ns(r.End),
		strconv.FormatInt(r.SkippedBefore, 10), u(r.Packets), u(r.Bytes),
		drops(r.KernelDrops),
		strconv.FormatBool(r.Evaluated),
	)

	if r.Evaluated {
		flagged := 0
		for _, ip := range r.IPs {
			if ip.Verdict.IsMalicious {
				flagged++
			}
		}

		row = append(row, u(r.EvaluatedPackets))
		row = appendVerdict(row, r.Verdict)
		row = append(row, strconv.Itoa(flagged))
	} else {
		row = append(row, "", "", "", "", "", "", "")
	}

	row = append(row, ns(r.ClosedAt), ns(r.EvalStart), ns(r.EvalEnd))
	row = appendResources(row, r.Resources)
	row = append(row, u(r.BlockedPackets), u(r.BlockedBytes), ns(r.BlockedAt))
	row = appendHost(row, r.Resources)
	s.row = row

	if err := s.windows.Write(row); err != nil {
		return err
	}

	for _, ip := range r.IPs {
		row = row[:0]
		row = append(row,
			epoch, ip.IP.String(),
			u(ip.Current), u(ip.Previous), u(ip.Evaluated),
		)
		row = appendVerdict(row, ip.Verdict)
		row = append(row, thresholdSource(ip.Verdict), strconv.FormatBool(ip.Blocked))

		if err := s.ips.Write(row); err != nil {
			return err
		}
	}

	s.row = row

	return nil
}

// thresholdSource names the history an IP verdict came from: the
// source's own, or the one shared by all sources. During warm-up it is
// the history that was still filling.
func thresholdSource(v iqr.Verdict) string {
	if v.Shared {
		return "shared"
	}

	return "own"
}

// appendVerdict adds warm_up, threshold, quartile_bound, threshold_term
// and malicious. During warm-up no threshold was applied, so the
// threshold columns are left empty.
func appendVerdict(row []string, v iqr.Verdict) []string {
	if v.WarmUp {
		return append(row, "true", "", "", "", "false")
	}

	term := "iqr"
	if v.FromFloor {
		term = "floor"
	}

	return append(row,
		"false",
		strconv.FormatFloat(v.Threshold, 'f', 2, 64),
		strconv.FormatFloat(v.QuartileBound, 'f', 2, 64),
		term,
		strconv.FormatBool(v.IsMalicious),
	)
}

// Close flushes and closes both files.
func (s *CSVSink) Close() error {
	var err error

	for _, w := range []*csv.Writer{s.windows, s.ips} {
		if w != nil {
			w.Flush()
			err = errors.Join(err, w.Error())
		}
	}

	for i, f := range s.files {
		err = errors.Join(err, s.bufs[i].Flush(), f.Close())
	}

	s.files, s.bufs = nil, nil

	return err
}

// appendResources adds the resource columns, leaving them empty when they
// were not measured.
func appendResources(row []string, s resource.Sample) []string {
	if s.Interval <= 0 {
		return append(row, "", "", "", "", "")
	}

	return append(row,
		u(s.HeapAlloc),
		strconv.FormatInt(int64(s.UserCPU), 10),
		strconv.FormatInt(int64(s.SysCPU), 10),
		strconv.FormatInt(int64(s.Interval), 10),
		strconv.FormatFloat(s.CPUShare(), 'f', 4, 64),
	)
}

// appendHost adds the machine-wide CPU columns, leaving them empty when
// they were not measured.
func appendHost(row []string, s resource.Sample) []string {
	if !s.HostMeasured {
		return append(row, "", "", "", "")
	}

	return append(row,
		strconv.FormatInt(int64(s.HostBusy), 10),
		strconv.FormatInt(int64(s.HostTotal), 10),
		strconv.FormatInt(int64(s.HostSoftirq), 10),
		strconv.FormatFloat(s.HostMaxCoreShare, 'f', 4, 64),
	)
}

// drops writes a kernel drop count, leaving the cell empty when it was not
// measured so that it cannot be mistaken for zero.
func drops(v int64) string {
	if v < 0 {
		return ""
	}

	return strconv.FormatInt(v, 10)
}

func u(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func ns(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return strconv.FormatInt(t.UnixNano(), 10)
}
