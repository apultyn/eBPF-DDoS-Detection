package blocklist

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// newTestBlocklist creates unpinned maps with the definitions of
// us_blocklist_map and us_blocked_stats. It needs root or CAP_BPF; the
// test is skipped without.
func newTestBlocklist(t *testing.T) *Blocklist {
	t.Helper()

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    16,
		ValueSize:  16,
		MaxEntries: Size,
	})
	if err != nil {
		t.Skipf("creating a BPF map: %v (needs root or CAP_BPF)", err)
	}

	stats, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.PerCPUArray,
		KeySize:    4,
		ValueSize:  16,
		MaxEntries: 1,
	})
	if err != nil {
		m.Close()
		t.Skipf("creating a BPF map: %v (needs root or CAP_BPF)", err)
	}

	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}

	b := &Blocklist{m: m, stats: stats, buf: make([]blockEntry, cpus), statsBuf: make([]blockedTotals, cpus)}
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

func TestBlocklist_Totals(t *testing.T) {
	b := newTestBlocklist(t)

	got, err := b.Totals()
	if err != nil {
		t.Fatal(err)
	}
	if got != (Totals{}) {
		t.Errorf("fresh map: got %+v, want zero", got)
	}

	// Stand in for XDP, which adds to the entry of the CPU it runs on.
	perCPU := make([]blockedTotals, len(b.statsBuf))
	perCPU[0] = blockedTotals{Packets: 2, Bytes: 120}
	perCPU[len(perCPU)-1].Packets += 3
	perCPU[len(perCPU)-1].Bytes += 180
	if err := b.stats.Update(uint32(0), perCPU, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}

	if got, err = b.Totals(); err != nil {
		t.Fatal(err)
	}
	if want := (Totals{Packets: 5, Bytes: 300}); got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	// Clear only empties the blocklist; the totals are read as differences.
	if err := b.Clear(); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.Totals(); got.Packets != 5 {
		t.Errorf("Clear changed the totals to %+v", got)
	}
}

func TestBlocklist_MapMemory(t *testing.T) {
	b := newTestBlocklist(t)

	got, err := b.MapMemory()
	if err != nil {
		t.Fatal(err)
	}

	// At least the keys, and the values once per possible CPU.
	cpus, _ := ebpf.PossibleCPU()
	if want := uint64(Size * (16 + 16*cpus)); len(got) != 2 || got[mapName] < want {
		t.Errorf("got %v, want %s of at least %d bytes", got, mapName, want)
	}
	if got[statsName] == 0 {
		t.Errorf("%s: no memory reported", statsName)
	}

	// A closed map is an error, not a zero.
	b.Close()
	if _, err := b.MapMemory(); err == nil {
		t.Error("closed map gave no error")
	}
}
