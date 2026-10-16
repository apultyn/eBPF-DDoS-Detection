package window

import (
	"fmt"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

// Config holds the settings of the windows.
//
// The sketch dimensions are not configurable here: they are compiled
// into heavy_keeper.c and mirrored by the heavykeeper package.
type Config struct {
	// Length is the length of one tumbling window. It must equal the
	// kernel's window length, which XDP applies as a shift by 29, so it
	// can only be epoch.DefaultLength.
	Length time.Duration

	// K is how many of the kernel's candidates are passed on per window,
	// at most heavykeeper.K. The IQR shared history is sized for the
	// default of 10.
	K int
}

// DefaultConfig returns the configuration the detector is evaluated with.
func DefaultConfig() Config {
	return Config{
		Length: epoch.DefaultLength,
		K:      10,
	}
}

func (c Config) validate() error {
	switch {
	case c.Length != epoch.DefaultLength:
		return fmt.Errorf("window length must be %v to match the kernel, got %v", epoch.DefaultLength, c.Length)
	case c.K <= 0 || c.K > heavykeeper.K:
		return fmt.Errorf("k must be between 1 and %d, the size of the kernel's Top-K table", heavykeeper.K)
	}

	return nil
}

// Closed is what the aggregator hands to the callback when a window
// closes. Both windows are only valid until the callback returns.
type Closed struct {
	// Window is the window that just closed.
	Window *Window

	// Prev is the window for the epoch immediately before Window, or nil
	// when it cannot be combined with: for the first evaluated window,
	// after a jump, and when its slot was not read intact. A combined
	// count may only be formed when Prev is non-nil.
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

	// Discarded is the number of windows that ended but were not handed
	// to the callback because their slot did not hold exactly their
	// traffic: the window running when the aggregator started, and
	// windows whose slot was cleared too late after falling behind.
	Discarded uint64 `json:"discarded"`

	// Jumps is the number of times the aggregator fell so far behind that
	// the kernel had reused slots it had not read yet, and SkippedEpochs
	// the total number of epochs lost to those jumps. A non-zero value
	// means the evaluation does not keep up with the window length.
	Jumps         uint64 `json:"jumps"`
	SkippedEpochs uint64 `json:"skipped_epochs"`
}

// Aggregator closes windows as time passes and hands each one to a
// callback, read back from the kernel through a Source.
//
// Windows are driven by the clock, not by packets: XDP picks the slot of
// a packet from the kernel's CLOCK_TAI, so the aggregator's clock must be
// the same one, or it reads a different slot from the one the kernel is
// writing.
//
// A slot is reused every heavykeeper.Slots windows. Closing window e
// reads slots e and e-1 and then clears slot e+2, which the kernel only
// starts writing a full window later. As long as Tick is called within a
// window of each boundary, no slot is cleared while it is being read or
// written. When the aggregator falls further behind, the windows whose
// slots could not be cleared in time are discarded rather than evaluated
// with mixed counts. The clock is read again after every step that can
// take time, so a slow callback is noticed as well as a late Tick.
//
// The aggregator owns two windows, the current one and the previous one,
// and swaps their roles each time a window closes. Not safe for
// concurrent use.
type Aggregator struct {
	cfg     Config
	src     Source
	clock   func() time.Time
	onClose func(Closed) error
	now     func() time.Time

	cur  *Window
	prev *Window

	// nextClean is whether the slot of the window after cur was cleared
	// before the kernel began writing it.
	nextClean bool

	stats Stats
}

// NewAggregator creates an aggregator that reads windows from src and
// calls onClose, on the calling goroutine, each time a window closes. An
// error from onClose is returned by the Tick that closed the window.
//
// clock must read CLOCK_TAI, the clock XDP assigns packets to windows by.
func NewAggregator(cfg Config, src Source, clock func() time.Time, onClose func(Closed) error) (*Aggregator, error) {
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("window: %w", err)
	}

	return &Aggregator{
		cfg:     cfg,
		src:     src,
		clock:   clock,
		onClose: onClose,
		now:     time.Now,
	}, nil
}

// Tick closes every window that has ended.
//
// The first call starts the aggregator: it clears every slot and opens
// the current window. That window began before the aggregator was
// watching, so it is discarded when it ends, and the first window handed
// to the callback is the one after it.
//
// The caller should call Tick shortly after Deadline. A small grace
// period past the deadline lets packets the kernel stamped just before
// the boundary finish their way through XDP on other CPUs.
func (a *Aggregator) Tick() error {
	if a.cur == nil {
		return a.restart(a.epochNow(), 0)
	}

	for {
		// Read for every window: closing one can take long enough for
		// the kernel to move on.
		n := a.epochNow()
		if a.cur.Epoch >= n {
			return nil
		}

		// Every slot has been reused since cur began: nothing left
		// unread is intact, so start over from the current epoch.
		if n-a.cur.Epoch >= heavykeeper.Slots {
			lost := int64(n - a.cur.Epoch)

			a.stats.Jumps++
			a.stats.SkippedEpochs += uint64(lost)

			return a.restart(n, a.cur.SkippedBefore+lost)
		}

		if err := a.close(n); err != nil {
			return err
		}
	}
}

// epochNow returns the epoch the kernel is in.
func (a *Aggregator) epochNow() epoch.Epoch {
	return epoch.Of(a.clock(), a.cfg.Length)
}

// Deadline returns when the current window ends, which is when Tick
// should next be called. It returns false before the first Tick.
//
// The deadline may already have passed if the caller fell behind; Tick
// then catches up.
func (a *Aggregator) Deadline() (time.Time, bool) {
	if a.cur == nil {
		return time.Time{}, false
	}

	return a.cur.End, true
}

// Finish discards the current window, which is incomplete, and returns
// what it held so the caller can log it. It returns false if Tick was
// never called. The totals are read best-effort: if the read fails they
// are reported as zero.
func (a *Aggregator) Finish() (Dropped, bool) {
	if a.cur == nil {
		return Dropped{}, false
	}

	w := a.cur
	packets, bytes, _ := a.src.Totals(w.slot)

	return Dropped{
		Epoch:   w.Epoch,
		Start:   w.Start,
		End:     w.End,
		Packets: packets,
		Bytes:   bytes,
	}, true
}

// Stats returns the counts accumulated so far.
func (a *Aggregator) Stats() Stats {
	return a.stats
}

// restart clears every slot and opens epoch n as an unevaluated window,
// recording skipped epochs before it. It is how the aggregator starts,
// and how it recovers after falling too far behind.
func (a *Aggregator) restart(n epoch.Epoch, skipped int64) error {
	for slot := 0; slot < heavykeeper.Slots; slot++ {
		if err := a.src.Reset(slot); err != nil {
			return fmt.Errorf("window: %w", err)
		}
	}

	if a.cur == nil {
		a.cur = newWindow(a.cfg, a.src)
	}

	// The kernel has been writing n since it began, and its slot was
	// just cleared under it, so n is not clean. The slots of every later
	// window are clean: they were cleared before the kernel reached them.
	a.cur.reset(n, false)
	a.cur.SkippedBefore = skipped
	a.nextClean = true

	// Nothing before n may be combined with.
	a.prev = nil

	return nil
}

// close hands the current window to the callback, clears the slot two
// windows ahead, and makes the current window the previous one. n is the
// epoch the kernel is in, which may be several windows past the current
// one when the aggregator is catching up.
func (a *Aggregator) close(n epoch.Epoch) error {
	w := a.cur
	e := w.Epoch

	var cbErr error

	// carry is the gap the next window reports in SkippedBefore: the
	// gap this window was carrying plus this window itself, when it is
	// not evaluated. The start window is not a gap; nothing was
	// evaluated before it.
	var carry int64

	if w.clean {
		if err := w.load(); err != nil {
			return err
		}

		// The previous window's slot is the next one the kernel reuses,
		// at e+3; it is only intact for combining before that.
		var prev *Window
		if a.prev != nil && a.prev.clean && a.prev.Epoch == e-1 && n <= e+2 {
			prev = a.prev
		}

		if w.Packets == 0 {
			a.stats.Empty++
		}
		a.stats.Closed++

		cbErr = a.onClose(Closed{Window: w, Prev: prev, ClosedAt: a.now()})
	} else {
		start := a.stats.Closed == 0 && a.stats.Discarded == 0

		carry = w.SkippedBefore
		if !start {
			carry++
		}

		a.stats.Discarded++
	}

	// Slot e+2 held e-2, which is no longer needed. It is clean for e+2
	// only if the kernel had not started writing e+2 yet when the clear
	// finished. The clock is read again here, not taken from n: the
	// callback above may have taken long enough for the kernel to move on.
	if err := a.src.Reset(int(e+2) & (heavykeeper.Slots - 1)); err != nil {
		return fmt.Errorf("window: %w", err)
	}
	clean2 := a.epochNow() <= e+1

	next := a.prev
	if next == nil {
		next = newWindow(a.cfg, a.src)
	}

	next.reset(e+1, a.nextClean)
	next.SkippedBefore = carry
	a.nextClean = clean2

	a.prev = w
	a.cur = next

	return cbErr
}
