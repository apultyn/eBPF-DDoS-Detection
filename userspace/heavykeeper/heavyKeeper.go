package main

import (
	"fmt"
	"math"
	"math/bits"
)

// decayLUTSize bounds the precomputed decay table.
//
// With b = 1.08, b^-64 is already below 0.008. The paper notes that
// the probability can be treated as zero once the counter is large
// (around 50), so truncating here costs nothing measurable and keeps
// the table inside L1.
const decayLUTSize = 64

// fpSalt must never coincide with any row seed, otherwise the
// fingerprint would be a deterministic function of the bucket index.
const fpSalt = 0xa5a5a5a5

// maxCounter is the saturation point for a bucket counter.
//
// Counters must never wrap: a wrapped elephant would read as an empty
// bucket and be evicted on the next packet.
const maxCounter = ^uint16(0)

// ============================================================
// HeavyKeeper sketch
// ============================================================

// Bucket is one cell in the HeavyKeeper matrix.
//
// Laid out as 2 + 2 bytes so the struct is exactly 4 bytes with no
// padding, matching the paper and the future BPF map layout. Sixteen
// buckets therefore share one 64-byte cache line.
type Bucket struct {
	Fingerprint uint16
	Count       uint16
}

// HeavyKeeper is the Hardware Parallel version of the sketch: on a
// fingerprint miss, every mapped bucket is decayed independently.
//
// Not safe for concurrent use. One sketch belongs to one time window
// and is driven by a single goroutine; locking per packet would cost
// an atomic operation in the hot path and has no counterpart in XDP.
type HeavyKeeper struct {
	depth     int
	width     int
	mask      uint32
	decayBase float64

	table    [][]Bucket
	decayLUT [decayLUTSize]uint32
	seeds    []uint32

	rng splitMix64
}

// NewHeavyKeeper creates a new HeavyKeeper sketch.
//
// width must be a power of two so the bucket index can be masked
// instead of taken modulo.
//
// rngSeed is explicitly supplied so experiments can be reproduced.
func NewHeavyKeeper(
	depth int,
	width int,
	decayBase float64,
	rngSeed uint64,
) *HeavyKeeper {

	if depth <= 0 {
		panic("depth must be > 0")
	}

	if width <= 0 || bits.OnesCount32(uint32(width)) != 1 {
		panic("width must be a power of two")
	}

	if decayBase <= 1.0 {
		panic("decayBase must be > 1")
	}

	hk := &HeavyKeeper{
		depth:     depth,
		width:     width,
		mask:      uint32(width - 1),
		decayBase: decayBase,

		table: make([][]Bucket, depth),
		seeds: make([]uint32, depth),

		rng: splitMix64{state: rngSeed},
	}

	// Allocate rows and generate deterministic, distinct seeds.
	for row := 0; row < depth; row++ {
		hk.table[row] = make([]Bucket, width)

		hk.seeds[row] = mix32(uint32(row) + 0x9e3779b9)

		// A row seed equal to the fingerprint salt would make the
		// fingerprint carry no information independent of the index.
		if hk.seeds[row] == fpSalt {
			panic("row seed collides with fingerprint salt")
		}
	}

	// decayLUT[c] is decayBase^(-c) scaled to the uint32 range, so the
	// coin flip is an integer comparison rather than a float one. This
	// is both faster here and directly portable to bpf_get_prandom_u32.
	for c := 0; c < decayLUTSize; c++ {
		p := math.Pow(decayBase, -float64(c))
		hk.decayLUT[c] = uint32(p * float64(math.MaxUint32))
	}

	return hk
}

// Reset clears the sketch so it can be reused for a new time window.
//
// Windows are created and retired continuously, so reusing sketches
// from a pool avoids reallocating the table on every window.
func (hk *HeavyKeeper) Reset() {
	for row := range hk.table {
		clear(hk.table[row])
	}
}

// ============================================================
// Randomness
// ============================================================

// splitMix64 is a small deterministic PRNG.
//
// It has no interface dispatch and no locking, unlike math/rand, and
// produces the integers the decay comparison needs directly.
type splitMix64 struct {
	state uint64
}

func (r *splitMix64) next() uint32 {
	r.state += 0x9e3779b97f4a7c15

	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb

	return uint32(z >> 32)
}

// ============================================================
// Hashing
// ============================================================

// mix32 is an integer mixing function with good avalanche.
//
// IP addresses cluster heavily in their low bits, so the input must be
// mixed before it is reduced to a bucket index. This particular
// constant set is a bijection on uint32, meaning all bucket collisions
// come from the index reduction rather than from the mixing itself.
func mix32(x uint32) uint32 {
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16

	return x
}

// hash maps a flow to one bucket in a specific row.
func (hk *HeavyKeeper) hash(item uint32, row int) uint32 {
	return mix32(item^hk.seeds[row]) & hk.mask
}

// fingerprint produces a 16-bit fingerprint.
//
// Computed once per flow and identical in every row, since it is the
// flow's identity rather than its location. The upper half of the
// mixed word is used to keep the separation from the index explicit.
func (hk *HeavyKeeper) fingerprint(item uint32) uint16 {
	return uint16(mix32(item^fpSalt) >> 16)
}

// ============================================================
// HeavyKeeper operations
// ============================================================

// Insert processes one occurrence of item.
//
// It returns the estimated frequency after the update, or zero if the
// item is held in no bucket, which marks it as a mouse flow.
func (hk *HeavyKeeper) Insert(item uint32) uint32 {

	fp := hk.fingerprint(item)

	var best uint16

	for row := 0; row < hk.depth; row++ {

		bucket := &hk.table[row][hk.hash(item, row)]

		switch {

		// Empty bucket: claim it.
		case bucket.Count == 0:
			bucket.Fingerprint = fp
			bucket.Count = 1

			if best < 1 {
				best = 1
			}

		// Same flow.
		case bucket.Fingerprint == fp:
			if bucket.Count < maxCounter {
				bucket.Count++
			}

			if bucket.Count > best {
				best = bucket.Count
			}

		// Held by another flow: exponential-weakening decay.
		default:
			if hk.rng.next() < hk.decayThreshold(bucket.Count) {
				bucket.Count--

				// The previous owner has been evicted.
				if bucket.Count == 0 {
					bucket.Fingerprint = fp
					bucket.Count = 1

					if best < 1 {
						best = 1
					}
				}
			}
		}
	}

	return uint32(best)
}

// decayThreshold returns the scaled probability of decaying a bucket
// whose counter currently holds count.
func (hk *HeavyKeeper) decayThreshold(count uint16) uint32 {
	if count < decayLUTSize {
		return hk.decayLUT[count]
	}

	return 0
}

// Query returns the estimated frequency for an item.
//
// The maximum counter among matching rows is used: decay can only push
// a counter below the true size, never above it, so the row where the
// flow was least disturbed carries the best estimate.
func (hk *HeavyKeeper) Query(item uint32) uint32 {

	fp := hk.fingerprint(item)

	var best uint16

	for row := 0; row < hk.depth; row++ {

		bucket := hk.table[row][hk.hash(item, row)]

		if bucket.Fingerprint == fp && bucket.Count > best {
			best = bucket.Count
		}
	}

	return uint32(best)
}

// ============================================================
// Top-K candidate tracking
// ============================================================

// TopKEntry stores the real flow identifier.
//
// This is necessary because HeavyKeeper itself only stores
// fingerprints, from which the original IP cannot be recovered.
type TopKEntry struct {
	Item  uint32
	Count uint32
}

// TopK maintains the candidate heavy hitters alongside the sketch.
//
// K is small, so a flat slice with a linear minimum scan beats a heap:
// ten entries fit in a couple of cache lines and there is no interface
// boxing. This part stays in user space even after the sketch itself
// moves into the kernel.
type TopK struct {
	k int

	entries []TopKEntry
	index   map[uint32]int

	minPos   int
	minCount uint32
}

func NewTopK(k int) *TopK {
	if k <= 0 {
		panic("k must be > 0")
	}

	return &TopK{
		k:       k,
		entries: make([]TopKEntry, 0, k),
		index:   make(map[uint32]int, k),
	}
}

// Reset clears the candidate set for reuse in a new time window.
func (t *TopK) Reset() {
	t.entries = t.entries[:0]
	clear(t.index)

	t.minPos = 0
	t.minCount = 0
}

// Update updates the candidate set using HeavyKeeper's current
// estimate for item.
//
// Callers must not pass a zero count: an item held in no bucket is a
// mouse flow and does not belong in the candidate set.
func (t *TopK) Update(item uint32, count uint32) {

	// Already a candidate.
	if pos, ok := t.index[item]; ok {
		t.entries[pos].Count = count

		if pos == t.minPos {
			t.findMin()
		} else if count < t.minCount {
			t.minPos = pos
			t.minCount = count
		}

		return
	}

	// Still room for another candidate.
	if len(t.entries) < t.k {
		t.entries = append(t.entries, TopKEntry{Item: item, Count: count})
		t.index[item] = len(t.entries) - 1

		t.findMin()

		return
	}

	// Optimization I from the paper.
	//
	// Without a fingerprint collision, a flow entering the candidate
	// set can only do so at exactly one above the current minimum. A
	// larger estimate means the flow inherited another flow's counter
	// through a fingerprint collision, and admitting it would let a
	// badly overestimated mouse flow squat in the candidate set.
	if count != t.minCount+1 {
		return
	}

	delete(t.index, t.entries[t.minPos].Item)

	t.entries[t.minPos] = TopKEntry{Item: item, Count: count}
	t.index[item] = t.minPos

	t.findMin()
}

func (t *TopK) findMin() {
	t.minPos = 0
	t.minCount = t.entries[0].Count

	for i := 1; i < len(t.entries); i++ {
		if t.entries[i].Count < t.minCount {
			t.minPos = i
			t.minCount = t.entries[i].Count
		}
	}
}

// Get returns the candidates ordered from largest estimate to
// smallest. The returned slice is a copy and is safe to hand to
// another goroutine after the window's structures are recycled.
func (t *TopK) Get() []TopKEntry {

	result := make([]TopKEntry, len(t.entries))
	copy(result, t.entries)

	// K is small, so insertion sort is fine.
	for i := 1; i < len(result); i++ {
		current := result[i]
		j := i - 1

		for j >= 0 && result[j].Count < current.Count {
			result[j+1] = result[j]
			j--
		}

		result[j+1] = current
	}

	return result
}

// ============================================================
// IPv4 helpers
// ============================================================

// ipv4FromBytes converts four header bytes to a flow key.
//
// This is the conversion used in the packet path. The string variants
// below allocate and are meant for tests and fixtures only.
func ipv4FromBytes(b []byte) uint32 {
	return uint32(b[0])<<24 |
		uint32(b[1])<<16 |
		uint32(b[2])<<8 |
		uint32(b[3])
}

func ipv4ToUint32(ip string) uint32 {
	var a, b, c, d uint32

	n, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d)
	if err != nil || n != 4 || a > 255 || b > 255 || c > 255 || d > 255 {
		panic("invalid IPv4 address: " + ip)
	}

	return a<<24 | b<<16 | c<<8 | d
}

func uint32ToIPv4(ip uint32) string {
	return fmt.Sprintf(
		"%d.%d.%d.%d",
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}

// ============================================================
// Example
// ============================================================

func main() {

	const (
		depth     = 4
		width     = 1024
		decayBase = 1.08
		k         = 10

		// Fixed seed for reproducible experiments.
		rngSeed = 42
	)

	hk := NewHeavyKeeper(depth, width, decayBase, rngSeed)
	topK := NewTopK(k)

	observe := func(ip uint32) {
		// A zero estimate means the flow is held in no bucket, which
		// marks it as a mouse flow. It must not reach the candidate
		// set, where it would otherwise occupy a slot with count zero.
		if estimate := hk.Insert(ip); estimate > 0 {
			topK.Update(ip, estimate)
		}
	}

	// --------------------------------------------------------
	// Simulated DDoS source
	// --------------------------------------------------------

	elephant := ipv4ToUint32("192.168.1.100")

	for i := 0; i < 5000; i++ {
		observe(elephant)
	}

	// --------------------------------------------------------
	// Background traffic
	// --------------------------------------------------------

	for i := 0; i < 2000; i++ {
		observe(ipv4ToUint32(fmt.Sprintf("10.0.0.%d", (i%250)+1)))
	}

	// --------------------------------------------------------
	// Results
	// --------------------------------------------------------

	fmt.Printf("Elephant estimate: %d (true: 5000)\n\n", hk.Query(elephant))

	fmt.Println("HeavyKeeper Top-K candidates:")

	for rank, entry := range topK.Get() {
		fmt.Printf(
			"%2d. %-15s HK estimate: %d\n",
			rank+1,
			uint32ToIPv4(entry.Item),
			entry.Count,
		)
	}
}
