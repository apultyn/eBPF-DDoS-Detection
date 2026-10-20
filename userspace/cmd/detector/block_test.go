package main

import (
	"errors"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/blocklist"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/mitigate"
)

// memBlocklist is an in-memory blocklistMap. totals stands in for what
// XDP has dropped, and totalsErr for a failed read of it.
type memBlocklist struct {
	entries   map[flow.Key]time.Time
	totals    blocklist.Totals
	totalsErr error
}

func newMemBlocklist() *memBlocklist {
	return &memBlocklist{entries: map[flow.Key]time.Time{}}
}

func (m *memBlocklist) Block(k flow.Key, now time.Time) error { m.entries[k] = now; return nil }
func (m *memBlocklist) Unblock(k flow.Key) error              { delete(m.entries, k); return nil }
func (m *memBlocklist) Close() error                          { return nil }

func (m *memBlocklist) MapMemory() (map[string]uint64, error) {
	return map[string]uint64{"us_blocklist_map": 1, "us_blocked_stats": 1}, nil
}

func (m *memBlocklist) Entries() ([]blocklist.BlockEntry, error) {
	var out []blocklist.BlockEntry
	for k, t := range m.entries {
		out = append(out, blocklist.BlockEntry{IP: k, LastSeen: t})
	}
	return out, nil
}

func (m *memBlocklist) Totals() (blocklist.Totals, error) {
	return m.totals, m.totalsErr
}

func TestSessionBlock_BlocksOnlyFlaggedSources(t *testing.T) {
	flagged := flow.MustParse("198.51.100.7")
	benign := flow.MustParse("198.51.100.8")
	allowed := flow.MustParse("192.0.2.10")

	bl := newMemBlocklist()

	cfg := mitigate.DefaultConfig()
	cfg.TTL = 2 * time.Second
	cfg.Allow = []flow.Key{allowed}

	mit, err := mitigate.New(cfg, bl)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	s := &session{mit: mit, bl: bl, clock: func() time.Time { return now }}

	r := detector.WindowResult{
		IPs: []detector.IPResult{
			{IP: flagged, Verdict: iqr.Verdict{IsMalicious: true}},
			{IP: benign},
			{IP: allowed, Verdict: iqr.Verdict{IsMalicious: true}},
		},
	}

	s.block(&r)

	if !r.IPs[0].Blocked || r.IPs[1].Blocked || r.IPs[2].Blocked {
		t.Errorf("Blocked = %v %v %v, want only the flagged source", r.IPs[0].Blocked, r.IPs[1].Blocked, r.IPs[2].Blocked)
	}
	if _, ok := bl.entries[flagged]; !ok || len(bl.entries) != 1 {
		t.Errorf("blocklist = %v, want only %v", bl.entries, flagged)
	}
	if r.BlockedAt.IsZero() {
		t.Error("BlockedAt not set")
	}

	// A window with nothing flagged leaves BlockedAt zero, and still
	// expires sources whose TTL ran out.
	now = now.Add(3 * time.Second)
	quiet := detector.WindowResult{IPs: []detector.IPResult{{IP: benign}}}

	s.block(&quiet)

	if !quiet.BlockedAt.IsZero() {
		t.Error("BlockedAt set for a window with nothing flagged")
	}
	if len(bl.entries) != 0 {
		t.Errorf("blocklist = %v after the TTL, want empty", bl.entries)
	}
}

func TestSessionCountBlocked_TakesDifferences(t *testing.T) {
	bl := newMemBlocklist()

	// Drops from before the run, when the baseline was read, are not
	// counted.
	s := &session{bl: bl, lastBlocked: blocklist.Totals{Packets: 100, Bytes: 6000}}

	bl.totals = blocklist.Totals{Packets: 130, Bytes: 7800}
	var first detector.WindowResult
	s.countBlocked(&first)

	if first.BlockedPackets != 30 || first.BlockedBytes != 1800 {
		t.Errorf("first window: %d packets, %d bytes; want 30, 1800", first.BlockedPackets, first.BlockedBytes)
	}

	// A failed read leaves the window at zero and the baseline where it
	// was, so the next window picks the drops up.
	bl.totalsErr = errors.New("map gone")
	var failed detector.WindowResult
	s.countBlocked(&failed)

	if failed.BlockedPackets != 0 {
		t.Errorf("failed read: %d packets, want 0", failed.BlockedPackets)
	}

	bl.totals, bl.totalsErr = blocklist.Totals{Packets: 135, Bytes: 8100}, nil
	var next detector.WindowResult
	s.countBlocked(&next)

	if next.BlockedPackets != 5 || next.BlockedBytes != 300 {
		t.Errorf("next window: %d packets, %d bytes; want 5, 300", next.BlockedPackets, next.BlockedBytes)
	}
	if s.stats.BlockedPackets != 35 {
		t.Errorf("run total %d, want 35", s.stats.BlockedPackets)
	}
}

func TestCheckOptions(t *testing.T) {
	live := options{iface: "ens7", outDir: "out"}
	trace := options{inputs: listFlag{"a.pcap"}, outDir: "out"}

	blockLive := live
	blockLive.block = true

	blockTrace := trace
	blockTrace.block = true

	both := live
	both.inputs = trace.inputs

	for _, tc := range []struct {
		name    string
		opt     options
		wantErr bool
	}{
		{"live", live, false},
		{"trace", trace, false},
		{"block live", blockLive, false},
		{"block trace", blockTrace, true},
		{"both inputs", both, true},
		{"no out", options{iface: "ens7"}, true},
	} {
		if _, err := checkOptions(tc.opt); (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestParseAllow(t *testing.T) {
	keys, err := parseAllow(" 192.0.2.10, 2001:db8::1 ,")
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 2 || keys[0] != flow.MustParse("192.0.2.10") || keys[1] != flow.MustParse("2001:db8::1") {
		t.Errorf("got %v", keys)
	}

	if _, err := parseAllow("not-an-ip"); err == nil {
		t.Error("accepted an invalid address")
	}
}
