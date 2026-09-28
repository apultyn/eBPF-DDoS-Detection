package main

import (
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"sync"
	"time"
)

const (
	MaxLUTSize = 1024 // How deeply we precompute decay probabilities
)

// Bucket represents a single cell in the matrix
type Bucket struct {
	Fingerprint uint16
	Count       uint32
}

// HeavyKeeper data structure
type HeavyKeeper struct {
	depth     int
	width     int
	decayBase float64
	table     [][]Bucket
	decayLUT  []float64 // Lookup table for b^(-C)
	seeds     []uint32
	rng       *rand.Rand
	mu        sync.Mutex // Protect RNG and table during concurrent access
}

// NewHeavyKeeper initializes the structure
func NewHeavyKeeper(depth, width int, decayBase float64) *HeavyKeeper {
	hk := &HeavyKeeper{
		depth:     depth,
		width:     width,
		decayBase: decayBase,
		table:     make([][]Bucket, depth),
		decayLUT:  make([]float64, MaxLUTSize),
		seeds:     make([]uint32, depth),
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// 1. Allocate the table rows and buckets
	for i := 0; i < depth; i++ {
		hk.table[i] = make([]Bucket, width)
		hk.seeds[i] = uint32(i*10007 + 1) // Simple seed per row
	}

	// 2. Precompute decay probabilities: LUT[C] = b^(-C)
	for c := 1; c < MaxLUTSize; c++ {
		hk.decayLUT[c] = math.Pow(decayBase, -float64(c))
	}

	return hk
}

// hash computes an index 0..width-1 for a specific row
func (hk *HeavyKeeper) hash(item string, row int) int {
	h := fnv.New32a()
	h.Write([]byte(item))
	// Mix in the row seed
	val := h.Sum32() ^ hk.seeds[row]
	return int(val % uint32(hk.width))
}

// fingerprint creates a 16-bit fingerprint (0 is reserved for "empty")
func (hk *HeavyKeeper) fingerprint(item string) uint16 {
	h := fnv.New32a()
	h.Write([]byte(item))
	h.Write([]byte("fp_salt"))
	val := uint16(h.Sum32() & 0xFFFF)
	if val == 0 {
		return 1
	}
	return val
}

// getDecayProb looks up the probability from the LUT
func (hk *HeavyKeeper) getDecayProb(count uint32) float64 {
	if count < MaxLUTSize {
		return hk.decayLUT[count]
	}
	// For extremely large elephants, the probability is effectively 0
	return math.Pow(hk.decayBase, -float64(count))
}

// Insert adds a flow ID / key to HeavyKeeper
func (hk *HeavyKeeper) Insert(item string) {
	hk.mu.Lock()
	defer hk.mu.Unlock()

	fp := hk.fingerprint(item)

	for i := 0; i < hk.depth; i++ {
		idx := hk.hash(item, i)
		bucket := &hk.table[i][idx]

		if bucket.Count == 0 {
			// Case A: The bucket is empty
			bucket.Fingerprint = fp
			bucket.Count = 1
		} else if bucket.Fingerprint == fp {
			// Case B: Match (the fingerprint matches)
			bucket.Count++
		} else {
			// Case C: Collision -> probabilistic decay
			prob := hk.getDecayProb(bucket.Count)
			if hk.rng.Float64() < prob {
				bucket.Count--
				if bucket.Count == 0 {
					// Old flow is evicted, take over the slot
					bucket.Fingerprint = fp
					bucket.Count = 1
				}
			}
		}
	}
}

// Query asks for the frequency of a specific element
func (hk *HeavyKeeper) Query(item string) uint32 {
	hk.mu.Lock()
	defer hk.mu.Unlock()

	fp := hk.fingerprint(item)
	var maxCount uint32 = 0

	for i := 0; i < hk.depth; i++ {
		idx := hk.hash(item, i)
		bucket := hk.table[i][idx]

		// Take the maximum among rows where the fingerprint matches
		if bucket.Fingerprint == fp && bucket.Count > maxCount {
			maxCount = bucket.Count
		}
	}

	return maxCount
}

// Generates an "example" data stream. Needs to be integrted with the actual traffic
func main() {
	// 4 rows, 1024 buckets per row, decay factor 1.08
	hk := NewHeavyKeeper(4, 1024, 1.08)

	// Simulate a large "elephant" (DDoS attack or heavy flow)
	elephantFlow := "192.168.1.100:443"
	for i := 0; i < 5000; i++ {
		hk.Insert(elephantFlow)
	}

	// Simulate many small "mice" (background noise with collisions)
	for i := 0; i < 2000; i++ {
		mouseFlow := fmt.Sprintf("10.0.0.%d:80", i%250)
		hk.Insert(mouseFlow)
	}

	fmt.Printf("Estimated count for elephant (%s): %d (True: 5000)\n",
		elephantFlow, hk.Query(elephantFlow))

	fmt.Printf("Estimated count for a mouse (10.0.0.1:80): %d (True: ~8)\n",
		hk.Query("10.0.0.1:80"))

	fmt.Printf("Estimated count for unseen flow (1.1.1.1:53): %d (True: 0)\n",
		hk.Query("1.1.1.1:53"))
}
