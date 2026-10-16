package heavykeeper

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// Sketch is a handle to the pinned maps of heavy_keeper.c: per slot one
// sketch, one Top-K table and one entry in slot_stats.
//
// A slot holds one window. The kernel only ever adds to the slot of the
// current window; clearing a slot before the kernel reuses it is the
// caller's job, through Reset.
type Sketch struct {
	sketches [Slots]*ebpf.Map
	topk     [Slots]*ebpf.Map
	stats    *ebpf.Map

	// Buffers built once in Open so that reading and clearing a slot
	// allocates nothing beyond the returned candidate list.
	bucketKeys  []uint32
	zeroBuckets []bucket
	topkKeys    []uint32
	zeroTopK    []topkEntry
	topkBuf     []topkEntry
	statsBuf    []slotStats
	zeroStats   []slotStats
}

// Open opens the pinned maps in dir, normally DefaultPinDir. The maps
// must already be pinned, which happens when heavy_keeper.o is loaded,
// and the caller needs root or CAP_BPF.
func Open(dir string) (*Sketch, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("heavykeeper: counting CPUs: %w", err)
	}

	s := &Sketch{
		bucketKeys:  make([]uint32, TotalBuckets),
		zeroBuckets: make([]bucket, TotalBuckets),
		topkKeys:    make([]uint32, K),
		zeroTopK:    make([]topkEntry, K),
		topkBuf:     make([]topkEntry, K),
		statsBuf:    make([]slotStats, cpus),
		zeroStats:   make([]slotStats, cpus),
	}

	for i := range s.bucketKeys {
		s.bucketKeys[i] = uint32(i)
	}
	for i := range s.topkKeys {
		s.topkKeys[i] = uint32(i)
	}

	open := func(path string) (*ebpf.Map, error) {
		m, err := ebpf.LoadPinnedMap(path, nil)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("heavykeeper: opening %s: %w", path, err)
		}
		return m, nil
	}

	for slot := 0; slot < Slots; slot++ {
		if s.sketches[slot], err = open(sketchPath(dir, slot)); err != nil {
			return nil, err
		}
		if s.topk[slot], err = open(topkPath(dir, slot)); err != nil {
			return nil, err
		}
	}

	if s.stats, err = open(statsPath(dir)); err != nil {
		return nil, err
	}

	return s, nil
}

// Close releases the map handles. The maps themselves stay pinned.
func (s *Sketch) Close() error {
	var errs []error

	closeMap := func(m **ebpf.Map) {
		if *m != nil {
			errs = append(errs, (*m).Close())
			*m = nil
		}
	}

	for i := range s.sketches {
		closeMap(&s.sketches[i])
		closeMap(&s.topk[i])
	}
	closeMap(&s.stats)

	return errors.Join(errs...)
}

// Count returns the estimated number of packets key sent in slot: the
// largest count among the rows whose bucket holds key's fingerprint, as
// HeavyKeeper.Query does in user space.
func (s *Sketch) Count(slot int, key flow.Key) (uint32, error) {
	if err := s.check(slot); err != nil {
		return 0, err
	}

	fp := fingerprint(key)

	var best uint32

	for row := 0; row < Depth; row++ {
		var b bucket
		if err := s.sketches[slot].Lookup(index(key, row), &b); err != nil {
			return 0, fmt.Errorf("heavykeeper: sketch %d row %d: %w", slot, row, err)
		}

		if b.Fp == fp && b.Count > best {
			best = b.Count
		}
	}

	return best, nil
}

// Candidates returns the heavy-hitter candidates of slot, largest count
// first, with duplicates and empty entries removed.
func (s *Sketch) Candidates(slot int) ([]TopKEntry, error) {
	if err := s.check(slot); err != nil {
		return nil, err
	}

	for i, k := range s.topkKeys {
		if err := s.topk[slot].Lookup(k, &s.topkBuf[i]); err != nil {
			return nil, fmt.Errorf("heavykeeper: topk %d entry %d: %w", slot, k, err)
		}
	}

	return candidates(s.topkBuf), nil
}

// Totals returns the exact number of packets and bytes counted in slot,
// summed over all CPUs.
func (s *Sketch) Totals(slot int) (packets, bytes uint64, err error) {
	if err := s.check(slot); err != nil {
		return 0, 0, err
	}

	if err := s.stats.Lookup(uint32(slot), &s.statsBuf); err != nil {
		return 0, 0, fmt.Errorf("heavykeeper: stats %d: %w", slot, err)
	}

	packets, bytes = sumStats(s.statsBuf)

	return packets, bytes, nil
}

// Reset clears slot: its sketch, its Top-K table and its totals. Call it
// only on a slot the kernel is not writing to, i.e. one whose window has
// passed and is no longer needed for evaluation.
func (s *Sketch) Reset(slot int) error {
	if err := s.check(slot); err != nil {
		return err
	}

	if err := clearArray(s.sketches[slot], s.bucketKeys, s.zeroBuckets); err != nil {
		return fmt.Errorf("heavykeeper: clearing sketch %d: %w", slot, err)
	}

	if err := clearArray(s.topk[slot], s.topkKeys, s.zeroTopK); err != nil {
		return fmt.Errorf("heavykeeper: clearing topk %d: %w", slot, err)
	}

	if err := s.stats.Update(uint32(slot), s.zeroStats, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("heavykeeper: clearing stats %d: %w", slot, err)
	}

	return nil
}

// ResetAll clears every slot, so a run does not start with counts left
// over from before it. Call it once at startup.
func (s *Sketch) ResetAll() error {
	for slot := 0; slot < Slots; slot++ {
		if err := s.Reset(slot); err != nil {
			return err
		}
	}

	return nil
}

// clearArray writes zeros over every entry of an array map in one batch
// call, falling back to one update per entry on kernels before 5.6.
func clearArray[V any](m *ebpf.Map, keys []uint32, zeros []V) error {
	_, err := m.BatchUpdate(keys, zeros, nil)
	if !errors.Is(err, ebpf.ErrNotSupported) {
		return err
	}

	for i, k := range keys {
		if err := m.Update(k, zeros[i], ebpf.UpdateAny); err != nil {
			return err
		}
	}

	return nil
}

func (s *Sketch) check(slot int) error {
	if slot < 0 || slot >= Slots {
		return fmt.Errorf("heavykeeper: slot %d out of range [0, %d)", slot, Slots)
	}

	if s.stats == nil {
		return errors.New("heavykeeper: sketch is closed")
	}

	return nil
}
