package heavykeeper

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestBlocklist_MapMemory(t *testing.T) {
	b := newTestBlocklist(t)

	got, err := b.MapMemory()
	if err != nil {
		t.Fatal(err)
	}

	// At least the keys, and the values once per possible CPU.
	cpus, _ := ebpf.PossibleCPU()
	if want := uint64(BlocklistSize * (16 + 16*cpus)); len(got) != 1 || got["blocklist_map"] < want {
		t.Errorf("got %v, want blocklist_map of at least %d bytes", got, want)
	}
}

func TestSketch_MapMemory(t *testing.T) {
	newArray := func(perCPU bool, valueSize uint32, entries uint32) *ebpf.Map {
		t.Helper()

		typ := ebpf.Array
		if perCPU {
			typ = ebpf.PerCPUArray
		}

		m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: 4, ValueSize: valueSize, MaxEntries: entries})
		if err != nil {
			t.Skipf("creating a BPF map: %v (needs root or CAP_BPF)", err)
		}
		t.Cleanup(func() { m.Close() })

		return m
	}

	s := &Sketch{}
	for slot := 0; slot < Slots; slot++ {
		s.sketches[slot] = newArray(false, 8, TotalBuckets)
		s.topk[slot] = newArray(false, 20, K)
	}
	s.stats = newArray(true, 16, Slots)
	s.blocked = newArray(true, 16, Slots)

	got, err := s.MapMemory()
	if err != nil {
		t.Fatal(err)
	}

	want := []string{"sketch_0", "sketch_1", "sketch_2", "sketch_3",
		"topk_map_0", "topk_map_1", "topk_map_2", "topk_map_3", "slot_stats", "blocked_stats"}
	if len(got) != len(want) {
		t.Errorf("got %d maps %v, want %v", len(got), got, want)
	}

	for _, name := range want {
		if got[name] == 0 {
			t.Errorf("%s: no memory reported", name)
		}
	}

	if got["sketch_0"] < TotalBuckets*8 {
		t.Errorf("sketch_0 = %d bytes, want at least its %d buckets of 8 bytes", got["sketch_0"], TotalBuckets)
	}

	// A closed map is an error, not a zero.
	s.blocked = nil
	if _, err := s.MapMemory(); err == nil {
		t.Error("closed map gave no error")
	}
}
