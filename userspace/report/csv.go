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

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
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
	"skipped_before", "packets", "bytes", "late",
	"evaluated", "evaluated_packets",
	"warm_up", "threshold", "quartile_bound", "threshold_term", "malicious",
	"flagged_ips",
	"closed_at_ns", "eval_start_ns", "eval_end_ns",
}

// ipColumns is the header of ips.csv. Rows join windows.csv on epoch.
var ipColumns = []string{
	"epoch", "ip",
	"current", "previous", "evaluated",
	"warm_up", "threshold", "quartile_bound", "threshold_term", "malicious",
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
		strconv.FormatInt(r.SkippedBefore, 10), u(r.Packets), u(r.Bytes), u(r.Late),
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

		if err := s.ips.Write(row); err != nil {
			return err
		}
	}

	s.row = row

	return nil
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

func u(v uint64) string {
	return strconv.FormatUint(v, 10)
}

func ns(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return strconv.FormatInt(t.UnixNano(), 10)
}
