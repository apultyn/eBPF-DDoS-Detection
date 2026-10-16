package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/resource"
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
		{Epoch: 10, Start: start, End: start.Add(500 * time.Millisecond), Packets: 7, Bytes: 700,
			KernelDrops: -1, ClosedAt: closed},

		// A window after skipped windows, evaluated, threshold
		// from the floor, one flagged source and one in warm-up.
		{
			Epoch: 20, Start: start.Add(5 * time.Second), End: start.Add(5500 * time.Millisecond),
			SkippedBefore: 9, Packets: 50, Bytes: 5000, KernelDrops: 13,
			Evaluated: true, EvaluatedPackets: 90,
			Verdict: iqr.Verdict{Threshold: 210.5, QuartileBound: 120, FromFloor: true},
			IPs: []detector.IPResult{
				{IP: flow.MustParse("2001:db8::1"), Current: 40, Previous: 30, Evaluated: 70,
					Verdict: iqr.Verdict{Threshold: 60, QuartileBound: 55.25, IsMalicious: true}, Blocked: true},
				{IP: flow.MustParse("192.0.2.9"), Current: 5, Previous: 0, Evaluated: 5,
					Verdict: iqr.Verdict{Threshold: 200, WarmUp: true, Shared: true}},
			},
			ClosedAt: closed, EvalStart: closed.Add(1), EvalEnd: closed.Add(2),
			BlockedPackets: 300, BlockedBytes: 30000, BlockedAt: closed.Add(3),
			Resources: resource.Sample{
				HeapAlloc: 4 << 20,
				UserCPU:   300 * time.Millisecond,
				SysCPU:    100 * time.Millisecond,
				Interval:  500 * time.Millisecond,

				HostBusy:         1500 * time.Millisecond,
				HostTotal:        2 * time.Second,
				HostSoftirq:      600 * time.Millisecond,
				HostMaxCoreShare: 0.95,
				HostMeasured:     true,
			},
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
	if skipped["evaluated"] != "false" || skipped["threshold"] != "" || skipped["malicious"] != "" ||
		skipped["kernel_drops"] != "" || skipped["cpu_share"] != "" || skipped["heap_alloc_bytes"] != "" ||
		skipped["host_busy_ns"] != "" || skipped["host_max_core_share"] != "" ||
		skipped["blocked_packets"] != "0" || skipped["blocked_at_ns"] != "" {
		t.Errorf("unevaluated window row = %v, want empty detection columns", skipped)
	}

	w := windows[1]
	for col, want := range map[string]string{
		"epoch":               "20",
		"start_ns":            "1700000005000000000",
		"skipped_before":      "9",
		"kernel_drops":        "13",
		"evaluated_packets":   "90",
		"threshold":           "210.50",
		"quartile_bound":      "120.00",
		"threshold_term":      "floor",
		"malicious":           "false",
		"flagged_ips":         "1",
		"eval_end_ns":         "1800000000000000007",
		"heap_alloc_bytes":    "4194304",
		"user_cpu_ns":         "300000000",
		"sys_cpu_ns":          "100000000",
		"cpu_interval_ns":     "500000000",
		"cpu_share":           "0.8000",
		"host_busy_ns":        "1500000000",
		"host_total_ns":       "2000000000",
		"host_softirq_ns":     "600000000",
		"host_max_core_share": "0.9500",
		"blocked_packets":     "300",
		"blocked_bytes":       "30000",
		"blocked_at_ns":       "1800000000000000008",
	} {
		if w[col] != want {
			t.Errorf("windows.csv %s = %q, want %q", col, w[col], want)
		}
	}

	flagged, warming := ips[0], ips[1]

	if flagged["ip"] != "2001:db8::1" || flagged["evaluated"] != "70" ||
		flagged["threshold_term"] != "iqr" || flagged["malicious"] != "true" ||
		flagged["threshold_source"] != "own" || flagged["blocked"] != "true" {
		t.Errorf("flagged IP row = %v", flagged)
	}

	if warming["ip"] != "192.0.2.9" || warming["warm_up"] != "true" || warming["threshold"] != "" ||
		warming["threshold_source"] != "shared" || warming["blocked"] != "false" {
		t.Errorf("warm-up IP row = %v, want an IPv4 address with no threshold, waiting on the shared history", warming)
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
