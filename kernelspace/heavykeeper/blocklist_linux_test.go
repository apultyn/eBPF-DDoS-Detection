package heavykeeper

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// newTestBlocklist creates an unpinned map with the definition of
// blocklist_map. It needs root or CAP_BPF; the test is skipped without.
func newTestBlocklist(t *testing.T) *Blocklist {
	t.Helper()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    16,
		ValueSize:  16,
		MaxEntries: BlocklistSize,
	})
	if err != nil {
		t.Skipf("creating a BPF map: %v (needs root or CAP_BPF)", err)
	}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}

	b := &Blocklist{m: m, buf: make([]blockEntry, cpus)}
	t.Cleanup(func() { b.Close() })

	return b
}

func TestBlocklist_RoundTrip(t *testing.T) {
	b := newTestBlocklist(t)

	v4 := flow.MustParse("192.0.2.9")
	v6 := flow.MustParse("2001:db8::1")
	now := time.Unix(0, 1_700_000_000_123_456_789)

	for _, k := range []flow.Key{v4, v6} {
		if err := b.Block(k, now); err != nil {
			t.Fatal(err)
		}
	}

	// The key is stored as XDP builds it: IPv4-mapped, network order.
	want := [16]byte{10: 0xff, 11: 0xff, 12: 192, 13: 0, 14: 2, 15: 9}
	var perCPU []blockEntry
	if err := b.m.Lookup(want, &perCPU); err != nil {
		t.Fatalf("IPv4 entry not under ::ffff:192.0.2.9: %v", err)
	}

	entries, err := b.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	for _, e := range entries {
		if !e.LastSeen.Equal(now) || e.Drops != 0 {
			t.Errorf("%v: last seen %v, %d drops; want %v, 0", e.IP, e.LastSeen, e.Drops, now)
		}
	}

	if err := b.Unblock(v4); err != nil {
		t.Fatal(err)
	}
	if err := b.Unblock(v4); err != nil {
		t.Errorf("unblocking an absent key: %v", err)
	}

	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if entries, _ := b.Entries(); len(entries) != 0 {
		t.Errorf("%d entries after Clear", len(entries))
	}
}
