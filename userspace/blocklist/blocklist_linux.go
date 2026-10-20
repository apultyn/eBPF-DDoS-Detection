package blocklist

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// Blocklist is a handle to us_blocklist_map, the sources XDP drops before
// they reach the capture socket, and to us_blocked_stats, what it has
// dropped.
//
// Only user space adds and removes entries; XDP only refreshes the entry
// of a source it drops a packet from.
type Blocklist struct {
	m     *ebpf.Map
	stats *ebpf.Map

	// buf and statsBuf hold one value per possible CPU, as the per-CPU
	// maps expect.
	buf      []blockEntry
	statsBuf []blockedTotals
}

// Open opens the pinned maps in dir, normally DefaultPinDir. The maps
// must already be pinned, which happens when blocklist.o is attached, and
// the caller needs root or CAP_BPF.
func Open(dir string) (*Blocklist, error) {
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, fmt.Errorf("blocklist: counting CPUs: %w", err)
	}

	path := mapPath(dir)

	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return nil, fmt.Errorf("blocklist: opening %s (is blocklist.o attached?): %w", path, err)
	}

	path = statsPath(dir)

	stats, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("blocklist: opening %s (is blocklist.o attached?): %w", path, err)
	}

	return &Blocklist{
		m:        m,
		stats:    stats,
		buf:      make([]blockEntry, cpus),
		statsBuf: make([]blockedTotals, cpus),
	}, nil
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
		return fmt.Errorf("blocklist: blocking %v: %w", key, err)
	}

	return nil
}

// Unblock removes key from the blocklist. Removing a key that is not on it
// is not an error.
func (b *Blocklist) Unblock(key flow.Key) error {
	if err := b.m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("blocklist: unblocking %v: %w", key, err)
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
		return nil, fmt.Errorf("blocklist: reading blocklist: %w", err)
	}

	return out, nil
}

// Totals returns what XDP has dropped since blocklist.o was loaded.
func (b *Blocklist) Totals() (Totals, error) {
	if err := b.stats.Lookup(uint32(0), &b.statsBuf); err != nil {
		return Totals{}, fmt.Errorf("blocklist: reading %s: %w", statsName, err)
	}

	return sumTotals(b.statsBuf), nil
}

// Clear removes every entry, so a run does not start with sources blocked
// by an earlier one. The totals are left as they are, since they are only
// ever read as differences.
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

// MapMemory returns the kernel memory of both maps, by their pin names.
// It is the memlock figure of each map's fdinfo: the bytes the kernel
// allocated for it, computed per map type from Linux 6.4 on and estimated
// from the map's dimensions before.
func (b *Blocklist) MapMemory() (map[string]uint64, error) {
	out := make(map[string]uint64, 2)

	for name, m := range map[string]*ebpf.Map{mapName: b.m, statsName: b.stats} {
		if m == nil {
			return nil, fmt.Errorf("blocklist: memory of %s: map is closed", name)
		}

		info, err := m.Info()
		if err != nil {
			return nil, fmt.Errorf("blocklist: memory of %s: %w", name, err)
		}

		v, ok := info.Memlock()
		if !ok {
			return nil, fmt.Errorf("blocklist: memory of %s: the kernel does not report it", name)
		}

		out[name] = v
	}

	return out, nil
}

// Close releases the map handles. The maps themselves stay pinned, and
// the sources on the blocklist stay blocked.
func (b *Blocklist) Close() error {
	var errs []error

	for _, m := range []**ebpf.Map{&b.m, &b.stats} {
		if *m == nil {
			continue
		}

		errs = append(errs, (*m).Close())
		*m = nil
	}

	return errors.Join(errs...)
}
