// Package window groups packets into fixed-length tumbling windows and
// hands each window to the caller when it closes, together with the
// window immediately before it.
//
// The detector judges the sum of a window and its predecessor, so an
// attack that straddles a boundary is not split into two halves that are
// each small enough to pass. Keeping the whole previous window, sketch
// included, rather than just its candidate list, means a source that only
// became a candidate in the current window still has its earlier packets
// counted.
//
// Everything runs on the goroutine that reads packets. A closing window is
// handed to the callback on that goroutine and evaluated before the next
// packet is read, so no structure here is synchronized.
package window

import (
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/countmin"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/heavykeeper"
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

	// SkippedBefore is the number of epochs jumped over immediately
	// before this window because traffic stopped for longer than
	// Config.MaxEmpty windows. Zero means the numbering is continuous.
	SkippedBefore int64

	// Packets and Bytes are exact totals for the window.
	Packets uint64
	Bytes   uint64

	// Late is the number of packets dropped while this window was open
	// because they belonged to an earlier, already closed window.
	Late uint64

	hk      *heavykeeper.HeavyKeeper
	topK    *heavykeeper.TopK
	counter Counter
	length  time.Duration
}

func newWindow(cfg Config, seed uint64) *Window {
	w := &Window{
		hk:     heavykeeper.New(cfg.Depth, cfg.Width, cfg.DecayBase, seed),
		topK:   heavykeeper.NewTopK(cfg.K),
		length: cfg.Length,
	}

	switch cfg.Counts {
	case CountHeavyKeeper:
		w.counter = hkCounter{hk: w.hk}
	case CountCountMin:
		w.counter = cmsCounter{cms: countmin.NewWithDimensions(cfg.CMSWidth, cfg.CMSDepth)}
	}

	return w
}

// Candidates returns the window's heavy-hitter candidates, largest first.
// The counts in the entries are HeavyKeeper's; use Count for the count
// from the configured source.
func (w *Window) Candidates() []heavykeeper.TopKEntry {
	return w.topK.Get()
}

// Count returns the estimated number of packets key sent in this window,
// read from the configured CountSource.
func (w *Window) Count(key flow.Key) uint64 {
	return w.counter.Count(key)
}

// observe adds one packet to the window.
func (w *Window) observe(p capture.Packet) {
	w.Packets++
	w.Bytes += uint64(p.Length)

	// A zero estimate means the flow is held in no bucket, which marks
	// it as a mouse flow that does not belong in the candidate set.
	if estimate := w.hk.Insert(p.Src); estimate > 0 {
		w.topK.Update(p.Src, estimate)
	}

	w.counter.Add(p.Src)
}

// reset clears the window and assigns it to epoch e.
func (w *Window) reset(e epoch.Epoch) {
	w.setEpoch(e)

	w.SkippedBefore = 0
	w.Packets = 0
	w.Bytes = 0
	w.Late = 0

	w.hk.Reset()
	w.topK.Reset()
	w.counter.Reset()
}

func (w *Window) setEpoch(e epoch.Epoch) {
	w.Epoch = e
	w.Start = e.Start(w.length)
	w.End = e.End(w.length)
}
