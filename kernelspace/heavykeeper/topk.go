package heavykeeper

import "github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"

// TopKEntry stores the real flow identifier.
//
// This is necessary because HeavyKeeper itself only stores
// fingerprints, from which the original address cannot be recovered.
type TopKEntry struct {
	Item  flow.Key
	Count uint32
}

// TopK maintains the candidate heavy hitters alongside the sketch.
//
// K is small, so a flat slice with a linear minimum scan beats a heap:
// ten entries fit in a few cache lines and there is no interface
// boxing. This part stays in user space even after the sketch itself
// moves into the kernel.
type TopK struct {
	k int

	entries []TopKEntry
	index   map[flow.Key]int

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
		index:   make(map[flow.Key]int, k),
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
func (t *TopK) Update(item flow.Key, count uint32) {

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
