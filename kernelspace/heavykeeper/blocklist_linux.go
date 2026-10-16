package heavykeeper

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// Blocklist is a handle to blocklist_map, the sources XDP drops before
// they reach the sketch.
//
// Only user space adds and removes entries; XDP only refreshes the entry
// of a source it drops a packet from.
type Blocklist struct {
	m *ebpf.Map

	// buf holds one value per possible CPU, as the per-CPU map expects.
	buf []blockEntry
}

// OpenBlocklist opens the pinned blocklist_map in dir, normally
// DefaultPinDir.
func OpenBlocklist(dir string) (*Blocklist, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("heavykeeper: counting CPUs: %w", err)
	}

	path := blocklistPath(dir)

	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("heavykeeper: opening %s: %w", path, err)
	}

	return &Blocklist{m: m, buf: make([]blockEntry, cpus)}, nil
}

// Block adds key to the blocklist, or refreshes it if it is already there.
// now is CLOCK_TAI; it is stored as the last time key was seen, so a new
// entry is not mistaken for the most stale one.
func (b *Blocklist) Block(key flow.Key, now time.Time) error {
	for i := range b.buf {
		b.buf[i] = blockEntry{}
	}
	b.buf[0].LastSeenNs = uint64(now.UnixNano())

	if err := b.m.Update(key, b.buf, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("heavykeeper: blocking %v: %w", key, err)
	}

	return nil
}

// Unblock removes key from the blocklist. Removing a key that is not on it
// is not an error.
func (b *Blocklist) Unblock(key flow.Key) error {
	if err := b.m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("heavykeeper: unblocking %v: %w", key, err)
	}

	return nil
}

// Entries returns every source on the blocklist with its per-CPU copies
// merged.
func (b *Blocklist) Entries() ([]BlockEntry, error) {
	var (
		key    flow.Key
		perCPU []blockEntry
		out    []BlockEntry
	)

	it := b.m.Iterate()
	for it.Next(&key, &perCPU) {
		last, drops := mergeBlockEntry(perCPU)
		out = append(out, BlockEntry{IP: key, LastSeen: time.Unix(0, int64(last)), Drops: drops})
	}

	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("heavykeeper: reading blocklist: %w", err)
	}

	return out, nil
}

// Clear removes every entry, so a run does not start with sources blocked
// by an earlier one.
func (b *Blocklist) Clear() error {
	entries, err := b.Entries()
	if err != nil {
		return err
	}

	for _, e := range entries {
		if err := b.Unblock(e.IP); err != nil {
			return err
		}
	}

	return nil
}

// Close releases the map handle. The map itself stays pinned, and the
// sources on it stay blocked.
func (b *Blocklist) Close() error {
	if b.m == nil {
		return nil
	}

	err := b.m.Close()
	b.m = nil

	return err
}
