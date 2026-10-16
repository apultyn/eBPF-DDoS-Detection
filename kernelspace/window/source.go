package window

import (
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

// Source is where a window's traffic is read from once it has closed.
//
// The kernel counts every packet into the slot of the current window, so
// the window package never sees packets. It only reads a slot back after
// its window has closed and clears it before the kernel reuses it. A slot
// is int(epoch) & (heavykeeper.Slots-1), the same formula XDP uses.
//
// On Linux the Source is a *heavykeeper.Sketch over the pinned maps. Tests
// use memsource.Source, which holds exact counts in memory.
type Source interface {
	// Count returns the estimated number of packets key sent in slot.
	Count(slot int, key flow.Key) (uint32, error)

	// Candidates returns the heavy-hitter candidates of slot, largest
	// count first.
	Candidates(slot int) ([]heavykeeper.TopKEntry, error)

	// Totals returns the exact packet and byte totals of slot.
	Totals(slot int) (packets, bytes uint64, err error)

	// Reset clears slot so it can hold a new window.
	Reset(slot int) error
}
