package window

import (
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/epoch"
)

// Config holds the window length and the parameters of the structures
// kept in every window.
type Config struct {
	// Length is the length of one tumbling window.
	Length time.Duration

	// MaxEmpty is the largest number of consecutive empty windows that
	// are closed during a pause in traffic before the aggregator gives up
	// and jumps straight to the epoch of the next packet, recording the
	// jump in Window.SkippedBefore. Zero disables jumping: every empty
	// window is closed, however long the pause.
	//
	// Use PcapMaxEmpty for trace files and LiveMaxEmpty for live capture.
	MaxEmpty int

	// Depth, Width, DecayBase and K configure each window's HeavyKeeper
	// sketch and candidate set. Width must be a power of two.
	Depth     int
	Width     int
	DecayBase float64
	K         int

	// Seed seeds the first window's HeavyKeeper; the second uses Seed+1.
	// With a fixed seed a trace replay is fully reproducible.
	Seed uint64

	// Counts selects where per-IP counts are read from.
	Counts CountSource

	// CMSWidth and CMSDepth size the Count-Min Sketch. Only used when
	// Counts is CountCountMin.
	CMSWidth uint64
	CMSDepth uint64
}

const (
	// PcapMaxEmpty is the empty-window limit for trace files. Datasets
	// such as CIC-DDoS2019 are split into many files with gaps between
	// the recordings; those gaps are artifacts of the dataset, not quiet
	// traffic, and must not flood the history with zeros.
	PcapMaxEmpty = 10

	// LiveMaxEmpty is the empty-window limit for live capture, where a
	// quiet period is real data. Jumping is disabled so that a stall in
	// the capture shows up as empty windows instead of being hidden.
	LiveMaxEmpty = 0
)

// DefaultConfig returns the configuration the detector is evaluated with.
//
// MaxEmpty is set for live capture; set it to PcapMaxEmpty when replaying
// trace files.
//
// The Count-Min dimensions give it the same 32 KB as the HeavyKeeper
// sketch (4 x 1024 counters of 8 bytes), so switching count source
// compares the two at equal memory.
func DefaultConfig() Config {
	return Config{
		Length:    epoch.DefaultLength,
		MaxEmpty:  LiveMaxEmpty,
		Depth:     4,
		Width:     1024,
		DecayBase: 1.08,
		K:         10,
		Seed:      42,
		Counts:    CountHeavyKeeper,
		CMSWidth:  1024,
		CMSDepth:  4,
	}
}

func (c Config) validate() error {
	switch {
	case c.Length <= 0:
		return errors.New("window length must be positive")
	case c.MaxEmpty < 0:
		return errors.New("MaxEmpty must not be negative")
	case c.Depth <= 0:
		return errors.New("depth must be positive")
	case c.Width <= 0 || bits.OnesCount(uint(c.Width)) != 1:
		return errors.New("width must be a power of two")
	case c.DecayBase <= 1:
		return errors.New("decay base must be greater than 1")
	case c.K <= 0:
		return errors.New("k must be positive")
	}

	switch c.Counts {
	case CountHeavyKeeper:
	case CountCountMin:
		if c.CMSWidth == 0 || c.CMSDepth == 0 {
			return errors.New("Count-Min width and depth must be positive")
		}
	default:
		return fmt.Errorf("unknown count source %v", c.Counts)
	}

	return nil
}

// Closed is what the aggregator hands to the callback when a window
// closes. Both windows are only valid until the callback returns.
type Closed struct {
	// Window is the window that just closed.
	Window *Window

	// Prev is the window for the epoch immediately before Window, or nil
	// when there is none: for the very first window, and for the first
	// window after a jump. A combined count may only be formed when Prev
	// is non-nil.
	Prev *Window

	// ClosedAt is the wall-clock time the window was closed, the starting
	// point for measuring detection latency.
	ClosedAt time.Time
}

// Dropped describes the incomplete window discarded by Finish.
type Dropped struct {
	Epoch   epoch.Epoch `json:"epoch"`
	Start   time.Time   `json:"start"`
	End     time.Time   `json:"end"`
	Packets uint64      `json:"packets"`
	Bytes   uint64      `json:"bytes"`
}

// Stats counts what the aggregator has done so far.
type Stats struct {
	// Closed is the number of windows handed to the callback, Empty how
	// many of those had no packets.
	Closed uint64 `json:"closed"`
	Empty  uint64 `json:"empty"`

	// Jumps is the number of times a long pause was skipped, and
	// SkippedEpochs the total number of epochs skipped by them.
	Jumps         uint64 `json:"jumps"`
	SkippedEpochs uint64 `json:"skipped_epochs"`

	// Late is the number of packets dropped because their timestamp fell
	// in an epoch that had already closed. Both trace files and a single
	// live interface deliver packets in timestamp order, so a non-zero
	// value means that assumption does not hold for the input.
	Late uint64 `json:"late_packets"`
}

// Aggregator assigns packets to windows and closes windows as time passes.
//
// It owns exactly two windows, the current one and the previous one, and
// swaps their roles each time a window closes. Not safe for concurrent
// use.
type Aggregator struct {
	cfg     Config
	onClose func(Closed)
	now     func() time.Time

	cur  *Window
	prev *Window

	// emptyRun is the number of consecutive empty windows closed so far.
	emptyRun int

	stats Stats
}

// NewAggregator creates an aggregator that calls onClose, on the calling
// goroutine, each time a window closes.
func NewAggregator(cfg Config, onClose func(Closed)) (*Aggregator, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("window: %w", err)
	}

	return &Aggregator{
		cfg:     cfg,
		onClose: onClose,
		now:     time.Now,
	}, nil
}

// Observe adds a packet, first closing every window that ended before the
// packet's timestamp.
//
// Windows are driven by packet timestamps. For a trace file that is the
// trace's own clock, which makes a replay independent of how fast it is
// read; for a live capture the timestamp is the arrival time, so it is
// the wall clock.
func (a *Aggregator) Observe(p capture.Packet) {
	e := epoch.Of(p.Timestamp, a.cfg.Length)

	switch {
	case a.cur == nil:
		a.cur = newWindow(a.cfg, a.cfg.Seed)
		a.cur.reset(e)

	case e > a.cur.Epoch:
		a.advanceTo(e, true)

	case e < a.cur.Epoch:
		// The packet's window has already been evaluated. Counting it in
		// the current one would place it in an epoch its timestamp does
		// not belong to, so it is dropped and reported instead.
		a.stats.Late++
		a.cur.Late++

		return
	}

	a.cur.observe(p)
}

// Advance closes every window that ended at or before now, without a
// packet having arrived. A live capture calls it when a read times out,
// so windows close on time even when traffic stops.
//
// With MaxEmpty set, Advance closes at most that many consecutive empty
// windows. After that the aggregator waits for the next packet and jumps
// to its epoch.
func (a *Aggregator) Advance(now time.Time) {
	if a.cur == nil {
		return
	}

	if e := epoch.Of(now, a.cfg.Length); e > a.cur.Epoch {
		a.advanceTo(e, false)
	}
}

// Deadline returns when the current window ends, which is how long a live
// capture should wait for a packet before calling Advance. It returns
// false when nothing is due: before the first packet, and after MaxEmpty
// empty windows, when the next window only opens with the next packet.
//
// The deadline may already have passed if the caller fell behind; Advance
// then catches up.
func (a *Aggregator) Deadline() (time.Time, bool) {
	if a.cur == nil || a.dormant() {
		return time.Time{}, false
	}

	return a.cur.End, true
}

// Finish discards the current window, which is incomplete, and returns
// what it held so the caller can log it. It returns false if no packet
// was ever observed.
func (a *Aggregator) Finish() (Dropped, bool) {
	if a.cur == nil {
		return Dropped{}, false
	}

	w := a.cur

	return Dropped{
		Epoch:   w.Epoch,
		Start:   w.Start,
		End:     w.End,
		Packets: w.Packets,
		Bytes:   w.Bytes,
	}, true
}

// Stats returns the counts accumulated so far.
func (a *Aggregator) Stats() Stats {
	return a.stats
}

// dormant reports whether the current window is an empty one that will
// not be closed, because MaxEmpty empty windows have already been.
func (a *Aggregator) dormant() bool {
	return a.cfg.MaxEmpty > 0 &&
		a.cur.Packets == 0 &&
		a.emptyRun >= a.cfg.MaxEmpty
}

// advanceTo closes windows until the current one is epoch e. When the
// empty-window limit is reached it jumps straight to e if jump is set,
// and otherwise stops and leaves the jump to the next packet.
func (a *Aggregator) advanceTo(e epoch.Epoch, jump bool) {
	for a.cur.Epoch < e {
		if a.dormant() {
			if !jump {
				return
			}

			skipped := uint64(e - a.cur.Epoch)

			a.cur.SkippedBefore += int64(skipped)
			a.cur.setEpoch(e)

			a.stats.Jumps++
			a.stats.SkippedEpochs += skipped

			return
		}

		a.close()
	}
}

// close hands the current window to the callback and makes it the
// previous window, recycling the old previous window as the new current
// one.
func (a *Aggregator) close() {
	w := a.cur

	if w.Packets == 0 {
		a.emptyRun++
		a.stats.Empty++
	} else {
		a.emptyRun = 0
	}

	// Only an adjacent window may be combined with this one. After a
	// jump the previous window is from before the pause.
	var prev *Window
	if a.prev != nil && a.prev.Epoch == w.Epoch-1 {
		prev = a.prev
	}

	a.stats.Closed++
	a.onClose(Closed{Window: w, Prev: prev, ClosedAt: a.now()})

	next := a.prev
	if next == nil {
		next = newWindow(a.cfg, a.cfg.Seed+1)
	}

	next.reset(w.Epoch + 1)

	a.prev = w
	a.cur = next
}
