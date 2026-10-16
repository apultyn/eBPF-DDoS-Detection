package main

import (
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/mitigate"
)

// memBlocklist is an in-memory mitigate.Map.
type memBlocklist map[flow.Key]time.Time

func (m memBlocklist) Block(k flow.Key, now time.Time) error { m[k] = now; return nil }
func (m memBlocklist) Unblock(k flow.Key) error              { delete(m, k); return nil }

func (m memBlocklist) Entries() ([]heavykeeper.BlockEntry, error) {
	var out []heavykeeper.BlockEntry
	for k, t := range m {
		out = append(out, heavykeeper.BlockEntry{IP: k, LastSeen: t})
	}
	return out, nil
}

func TestSessionBlock_BlocksOnlyFlaggedSources(t *testing.T) {
	flagged := flow.MustParse("198.51.100.7")
	benign := flow.MustParse("198.51.100.8")
	allowed := flow.MustParse("192.0.2.10")

	bl := memBlocklist{}

	cfg := mitigate.DefaultConfig()
	cfg.TTL = 2 * time.Second
	cfg.Allow = []flow.Key{allowed}

	mit, err := mitigate.New(cfg, bl)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	s := &session{mit: mit, clock: func() time.Time { return now }}

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
	if _, ok := bl[flagged]; !ok || len(bl) != 1 {
		t.Errorf("blocklist = %v, want only %v", bl, flagged)
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
	if len(bl) != 0 {
		t.Errorf("blocklist = %v after the TTL, want empty", bl)
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
