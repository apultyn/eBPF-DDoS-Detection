package iqr

import "github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"

// ipEntry is one tracked source address and its history, linked into the
// recency list.
type ipEntry struct {
	key        flow.Key
	hist       *history
	prev, next *ipEntry
}

// ipHistories holds per-IP histories under a hard cap on the number of
// addresses, evicting the least recently evaluated address when full.
//
// An attack from rotating source addresses would otherwise add a history
// for every address it uses, so memory would grow with run time instead
// of staying constant. With the cap, the per-IP state never exceeds
// capacity * MaxHistorySize samples.
//
// Evicted entries and their sample buffers are reused for the address
// that displaced them, so once the cap is reached nothing more is
// allocated.
type ipHistories struct {
	capacity    int
	historySize int

	entries map[flow.Key]*ipEntry

	// head is the most recently used entry, tail the least.
	head, tail *ipEntry

	evicted uint64
}

func newIPHistories(capacity, historySize int) *ipHistories {
	if capacity <= 0 {
		capacity = 1
	}

	return &ipHistories{
		capacity:    capacity,
		historySize: historySize,
		entries:     make(map[flow.Key]*ipEntry, capacity),
	}
}

// get returns the history for key, creating an empty one if the address
// is not tracked, and marks it most recently used.
func (c *ipHistories) get(key flow.Key) *history {
	if e, ok := c.entries[key]; ok {
		c.moveToFront(e)
		return e.hist
	}

	var e *ipEntry

	if len(c.entries) < c.capacity {
		e = &ipEntry{hist: newHistory(c.historySize)}
	} else {
		// Reuse the least recently used entry. The address it held starts
		// over with an empty history, and so a new warm-up, if it returns.
		e = c.tail
		c.unlink(e)
		delete(c.entries, e.key)
		e.hist.reset()
		c.evicted++
	}

	e.key = key
	c.entries[key] = e
	c.pushFront(e)

	return e.hist
}

func (c *ipHistories) len() int {
	return len(c.entries)
}

func (c *ipHistories) moveToFront(e *ipEntry) {
	if c.head == e {
		return
	}

	c.unlink(e)
	c.pushFront(e)
}

func (c *ipHistories) pushFront(e *ipEntry) {
	e.prev = nil
	e.next = c.head

	if c.head != nil {
		c.head.prev = e
	}

	c.head = e

	if c.tail == nil {
		c.tail = e
	}
}

func (c *ipHistories) unlink(e *ipEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}

	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}

	e.prev, e.next = nil, nil
}
