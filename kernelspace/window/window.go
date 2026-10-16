// Package window divides time into fixed-length tumbling windows and
// hands each window to the caller when it closes, together with the
// window immediately before it.
//
// The packets themselves are counted in the kernel: XDP adds every packet
// to the slot of the current window, and this package reads a slot back
// through a Source once its window has closed. A window is identified by
// its epoch, and its slot is int(epoch) & (heavykeeper.Slots-1), the same
// formula XDP uses.
//
// The detector judges the sum of a window and its predecessor, so an
// attack that straddles a boundary is not split into two halves that are
// each small enough to pass. The previous window's slot is kept intact
// until that sum has been formed, so a source that only became a
// candidate in the current window still has its earlier packets counted.
//
// Everything runs on one goroutine. A closing window is handed to the
// callback and evaluated before the next one is closed, so no structure
// here is synchronized.
package window

import (
	"fmt"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

// Window holds the traffic counted during one epoch.
//
// Windows are recycled: one handed to a callback is only valid until the
// callback returns.
type Window struct {
	// Epoch numbers the window; Start and End are its boundaries, End
	// being exclusive.
	Epoch epoch.Epoch
	Start time.Time
	End   time.Time

	// SkippedBefore is the number of epochs immediately before this
	// window that were not evaluated because the detector fell behind the
	// kernel and could not read them intact. Zero means the window
	// directly follows the last one handed to the callback.
	SkippedBefore int64

	// Packets and Bytes are exact totals for the window, as counted by
	// the kernel. They are filled in when the window closes.
	Packets uint64
	Bytes   uint64

	// BlockedPackets and BlockedBytes are the traffic the blocklist
	// dropped during the window. It never reached the sketch and is not
	// part of Packets and Bytes.
	BlockedPackets uint64
	BlockedBytes   uint64

	src    Source
	slot   int
	k      int
	length time.Duration

	// clean reports whether the slot was cleared before the kernel began
	// writing this window into it. A window whose slot still held another
	// window's counts, or was cleared while the kernel was already
	// writing to it, is not evaluated and not combined with.
	clean bool

	// candidates is read from the kernel when the window closes.
	candidates []heavykeeper.TopKEntry
}

func newWindow(cfg Config, src Source) *Window {
	return &Window{
		src:    src,
		k:      cfg.K,
		length: cfg.Length,
	}
}

// Slot returns the kernel slot holding this window's traffic.
func (w *Window) Slot() int {
	return w.slot
}

// Candidates returns the window's heavy-hitter candidates, largest first,
// at most Config.K of them. The counts in the entries are the kernel's
// Top-K estimates; use Count for the sketch estimate.
//
// The slice is read fresh from the kernel each time the window closes, so
// it stays valid after the window is recycled.
func (w *Window) Candidates() []heavykeeper.TopKEntry {
	return w.candidates
}

// Count returns the estimated number of packets key sent in this window,
// read from the window's slot in the kernel sketch.
func (w *Window) Count(key flow.Key) (uint64, error) {
	n, err := w.src.Count(w.slot, key)
	if err != nil {
		return 0, fmt.Errorf("window: epoch %d: %w", w.Epoch, err)
	}

	return uint64(n), nil
}

// load reads the window's totals and candidates from its slot. It is
// called once, when the window closes and the kernel has moved on to the
// next slot.
func (w *Window) load() error {
	packets, bytes, err := w.src.Totals(w.slot)
	if err != nil {
		return fmt.Errorf("window: epoch %d: %w", w.Epoch, err)
	}

	blockedPackets, blockedBytes, err := w.src.Blocked(w.slot)
	if err != nil {
		return fmt.Errorf("window: epoch %d: %w", w.Epoch, err)
	}

	candidates, err := w.src.Candidates(w.slot)
	if err != nil {
		return fmt.Errorf("window: epoch %d: %w", w.Epoch, err)
	}

	if len(candidates) > w.k {
		candidates = candidates[:w.k]
	}

	w.Packets = packets
	w.Bytes = bytes
	w.BlockedPackets = blockedPackets
	w.BlockedBytes = blockedBytes
	w.candidates = candidates

	return nil
}

// reset clears what the window has read and assigns it to epoch e. The
// kernel slot itself is cleared separately, through Source.Reset, and
// clean records whether that happened before the kernel reached e.
func (w *Window) reset(e epoch.Epoch, clean bool) {
	w.setEpoch(e)

	w.SkippedBefore = 0
	w.Packets = 0
	w.Bytes = 0
	w.BlockedPackets = 0
	w.BlockedBytes = 0
	w.candidates = nil
	w.clean = clean
}

func (w *Window) setEpoch(e epoch.Epoch) {
	w.Epoch = e
	w.Start = e.Start(w.length)
	w.End = e.End(w.length)

	// Same as epoch & SLOT_MASK in heavy_keeper.c. For a power-of-two
	// mask this is the non-negative remainder even for a negative epoch.
	w.slot = int(e) & (heavykeeper.Slots - 1)
}
