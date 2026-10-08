package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
)

func readCSV(t *testing.T, path string) []map[string]string {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	records, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	var rows []map[string]string
	for _, rec := range records[1:] {
		row := map[string]string{}
		for i, col := range records[0] {
			row[col] = rec[i]
		}
		rows = append(rows, row)
	}

	return rows
}

func TestCSVSink(t *testing.T) {
	dir := t.TempDir()

	sink, err := NewCSVSink(dir, false)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Unix(1_700_000_000, 0)
	closed := time.Unix(1_800_000_000, 5)

	results := []detector.WindowResult{
		// The first window: nothing to combine with, so not evaluated.
		{Epoch: 10, Start: start, End: start.Add(500 * time.Millisecond), Packets: 7, Bytes: 700, ClosedAt: closed},

		// A window after a jump with late packets, evaluated, threshold
		// from the floor, one flagged source and one in warm-up.
		{
			Epoch: 20, Start: start.Add(5 * time.Second), End: start.Add(5500 * time.Millisecond),
			SkippedBefore: 9, Packets: 50, Bytes: 5000, Late: 2,
			Evaluated: true, EvaluatedPackets: 90,
			Verdict: iqr.Verdict{Threshold: 210.5, QuartileBound: 120, FromFloor: true},
			IPs: []detector.IPResult{
				{IP: flow.MustParse("2001:db8::1"), Current: 40, Previous: 30, Evaluated: 70,
					Verdict: iqr.Verdict{Threshold: 60, QuartileBound: 55.25, IsMalicious: true}},
				{IP: flow.MustParse("192.0.2.9"), Current: 5, Previous: 0, Evaluated: 5,
					Verdict: iqr.Verdict{Threshold: 200, WarmUp: true}},
			},
			ClosedAt: closed, EvalStart: closed.Add(1), EvalEnd: closed.Add(2),
		},
	}

	for i := range results {
		if err := sink.Write(&results[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}

	windows := readCSV(t, filepath.Join(dir, WindowsFile))
	ips := readCSV(t, filepath.Join(dir, IPsFile))

	if len(windows) != 2 || len(ips) != 2 {
		t.Fatalf("got %d window rows and %d IP rows, want 2 and 2", len(windows), len(ips))
	}

	skipped := windows[0]
	if skipped["evaluated"] != "false" || skipped["threshold"] != "" || skipped["malicious"] != "" {
		t.Errorf("unevaluated window row = %v, want empty detection columns", skipped)
	}

	w := windows[1]
	for col, want := range map[string]string{
		"epoch":             "20",
		"start_ns":          "1700000005000000000",
		"skipped_before":    "9",
		"late":              "2",
		"evaluated_packets": "90",
		"threshold":         "210.50",
		"quartile_bound":    "120.00",
		"threshold_term":    "floor",
		"malicious":         "false",
		"flagged_ips":       "1",
		"eval_end_ns":       "1800000000000000007",
	} {
		if w[col] != want {
			t.Errorf("windows.csv %s = %q, want %q", col, w[col], want)
		}
	}

	flagged, warming := ips[0], ips[1]

	if flagged["ip"] != "2001:db8::1" || flagged["evaluated"] != "70" ||
		flagged["threshold_term"] != "iqr" || flagged["malicious"] != "true" {
		t.Errorf("flagged IP row = %v", flagged)
	}

	if warming["ip"] != "192.0.2.9" || warming["warm_up"] != "true" || warming["threshold"] != "" {
		t.Errorf("warm-up IP row = %v, want an IPv4 address with no threshold", warming)
	}
}

func TestCSVSink_RefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, WindowsFile), []byte("old results"), 0o644)

	if _, err := NewCSVSink(dir, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("err = %v, want a refusal to overwrite", err)
	}

	sink, err := NewCSVSink(dir, true)
	if err != nil {
		t.Fatalf("overwrite with force: %v", err)
	}
	sink.Close()
}
