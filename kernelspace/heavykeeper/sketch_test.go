package heavykeeper

import (
	"testing"
	"unsafe"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// The mirrors must have the exact sizes of the C structs, or every map
// read decodes garbage.
func TestStructSizes(t *testing.T) {
	cases := []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"bucket", unsafe.Sizeof(bucket{}), 8},
		{"topk_entry", unsafe.Sizeof(topkEntry{}), 20},
		{"slot_stats", unsafe.Sizeof(slotStats{}), 16},
		{"block_entry", unsafe.Sizeof(blockEntry{}), 16},
	}

	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: %d bytes, C struct is %d", c.name, c.got, c.want)
		}
	}
}

func TestIndexStaysInRow(t *testing.T) {
	keys := []flow.Key{
		flow.MustParse("10.0.0.1"),
		flow.MustParse("192.168.1.200"),
		flow.MustParse("2001:db8::1"),
	}

	for _, k := range keys {
		for row := 0; row < Depth; row++ {
			i := index(k, row)
			if i < uint32(row*Width) || i >= uint32((row+1)*Width) {
				t.Errorf("%v row %d: index %d outside the row", k, row, i)
			}
		}

		if fingerprint(k) == 0 {
			t.Errorf("%v: fingerprint 0 is reserved for empty buckets", k)
		}
	}
}

func TestCandidates(t *testing.T) {
	a := flow.MustParse("10.0.0.1")
	b := flow.MustParse("10.0.0.2")
	c := flow.MustParse("10.0.0.3")

	raw := []topkEntry{
		{IP: b, Count: 40},
		{},                 // empty entry
		{IP: a, Count: 90}, // duplicate from a CPU race; the larger count wins
		{IP: c, Count: 40},
		{IP: a, Count: 75},
	}

	got := candidates(raw)
	want := []TopKEntry{{a, 90}, {b, 40}, {c, 40}}

	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestSumStats(t *testing.T) {
	p, b := sumStats([]slotStats{{10, 1000}, {0, 0}, {5, 300}})
	if p != 15 || b != 1300 {
		t.Errorf("got %d packets, %d bytes; want 15, 1300", p, b)
	}
}

func TestMergeBlockEntry(t *testing.T) {
	last, drops := mergeBlockEntry([]blockEntry{{100, 3}, {0, 0}, {250, 7}, {90, 1}})
	if last != 250 || drops != 11 {
		t.Errorf("got last seen %d, %d drops; want 250, 11", last, drops)
	}
}
