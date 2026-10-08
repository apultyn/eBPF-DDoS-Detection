package heavykeeper

import (
	"fmt"
	"testing"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

const (
	testDepth     = 4
	testWidth     = 1024
	testDecayBase = 1.08
	testK         = 10
	testSeed      = 42
)

// observe mirrors the packet-path wiring: a zero estimate marks a mouse
// flow, which must not reach the candidate set.
func observe(hk *HeavyKeeper, topK *TopK, key flow.Key) {
	if estimate := hk.Insert(key); estimate > 0 {
		topK.Update(key, estimate)
	}
}

func TestHeavyKeeper_FindsElephants(t *testing.T) {
	hk := New(testDepth, testWidth, testDecayBase, testSeed)
	topK := NewTopK(testK)

	v4 := flow.MustParse("192.168.1.100")
	v6 := flow.MustParse("2001:db8::bad")

	// Interleave the elephants with background traffic from both
	// families so they compete for buckets.
	for i := 0; i < 3000; i++ {
		observe(hk, topK, v4)
		observe(hk, topK, v6)
		observe(hk, topK, flow.MustParse(fmt.Sprintf("10.0.%d.%d", i%7, i%250)))
		observe(hk, topK, flow.MustParse(fmt.Sprintf("2001:db8::%x", i%500)))
	}

	got := topK.Get()
	if len(got) == 0 {
		t.Fatal("Top-K is empty")
	}

	top := map[flow.Key]bool{got[0].Item: true, got[1].Item: true}
	if !top[v4] || !top[v6] {
		t.Fatalf("expected both elephants in the top two, got %v and %v", got[0].Item, got[1].Item)
	}

	for _, key := range []flow.Key{v4, v6} {
		// HeavyKeeper never overestimates a flow it holds without a
		// fingerprint collision, and the elephants should be close.
		if est := hk.Query(key); est > 3000 || est < 2700 {
			t.Errorf("Query(%v) = %d, want close to 3000", key, est)
		}
	}
}

func TestHeavyKeeper_FamiliesAreDistinct(t *testing.T) {
	hk := New(testDepth, testWidth, testDecayBase, testSeed)

	// The IPv4 address and an IPv6 address carrying the same four bytes
	// in its last word must not be treated as the same flow.
	v4 := flow.MustParse("10.0.0.1")
	v6 := flow.MustParse("::a00:1")

	for i := 0; i < 100; i++ {
		hk.Insert(v4)
	}

	if got := hk.Query(v6); got != 0 {
		t.Errorf("Query(%v) = %d after inserting only %v, want 0", v6, got, v4)
	}
}

func TestHeavyKeeper_CounterSaturates(t *testing.T) {
	hk := New(1, 1, testDecayBase, testSeed)
	key := flow.MustParse("10.0.0.1")

	hk.Insert(key)
	hk.table[0][0].Count = maxCounter - 1

	hk.Insert(key)
	hk.Insert(key)

	if got := hk.Query(key); got != maxCounter {
		t.Errorf("Query after saturation = %d, want %d", got, maxCounter)
	}
}

func TestHeavyKeeper_Reset(t *testing.T) {
	hk := New(testDepth, testWidth, testDecayBase, testSeed)
	key := flow.MustParse("2001:db8::1")

	for i := 0; i < 10; i++ {
		hk.Insert(key)
	}

	hk.Reset()

	if got := hk.Query(key); got != 0 {
		t.Errorf("Query after Reset = %d, want 0", got)
	}
}

func TestTopK_RejectsJumpAboveMinimum(t *testing.T) {
	topK := NewTopK(2)

	topK.Update(flow.MustParse("10.0.0.1"), 5)
	topK.Update(flow.MustParse("10.0.0.2"), 7)

	// Optimization I: a newcomer must arrive at exactly min + 1.
	intruder := flow.MustParse("10.0.0.3")
	topK.Update(intruder, 50)

	for _, e := range topK.Get() {
		if e.Item == intruder {
			t.Fatal("newcomer with count far above the minimum was admitted")
		}
	}

	topK.Update(intruder, 6)

	got := topK.Get()
	if got[0].Count != 7 || got[1].Item != intruder {
		t.Fatalf("expected intruder to replace the minimum, got %v", got)
	}
}

func Example() {
	hk := New(testDepth, testWidth, testDecayBase, testSeed)
	topK := NewTopK(3)

	attackers := []flow.Key{
		flow.MustParse("192.168.1.100"),
		flow.MustParse("2001:db8::bad"),
	}

	for i := 0; i < 2000; i++ {
		for _, a := range attackers {
			observe(hk, topK, a)
		}

		observe(hk, topK, flow.MustParse(fmt.Sprintf("10.0.0.%d", i%250+1)))
	}

	for _, e := range topK.Get()[:2] {
		fmt.Println(e.Item)
	}

	// Unordered output:
	// 192.168.1.100
	// 2001:db8::bad
}

func BenchmarkInsertIPv4(b *testing.B) {
	benchmarkInsert(b, func(i int) flow.Key {
		return flow.FromIPv4([]byte{10, 0, byte(i >> 8), byte(i)})
	})
}

func BenchmarkInsertIPv6(b *testing.B) {
	benchmarkInsert(b, func(i int) flow.Key {
		return flow.MustParse(fmt.Sprintf("2001:db8::%x", i))
	})
}

func benchmarkInsert(b *testing.B, mk func(int) flow.Key) {
	hk := New(testDepth, testWidth, testDecayBase, testSeed)

	keys := make([]flow.Key, 4096)
	for i := range keys {
		keys[i] = mk(i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		hk.Insert(keys[i%len(keys)])
	}
}
