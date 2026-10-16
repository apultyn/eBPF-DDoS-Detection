package heavykeeper

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// MapMemory returns the kernel memory of each map, by its pin name. The
// path helpers with an empty directory give the bare pin names.
func (s *Sketch) MapMemory() (map[string]uint64, error) {
	out := make(map[string]uint64, 2*Slots+2)

	for slot := 0; slot < Slots; slot++ {
		if err := addMemlock(out, sketchPath("", slot), s.sketches[slot]); err != nil {
			return nil, err
		}
		if err := addMemlock(out, topkPath("", slot), s.topk[slot]); err != nil {
			return nil, err
		}
	}

	if err := addMemlock(out, statsPath(""), s.stats); err != nil {
		return nil, err
	}
	if err := addMemlock(out, blockedStatsPath(""), s.blocked); err != nil {
		return nil, err
	}

	return out, nil
}

// MapMemory returns the kernel memory of blocklist_map, by its pin name.
func (b *Blocklist) MapMemory() (map[string]uint64, error) {
	out := make(map[string]uint64, 1)

	if err := addMemlock(out, blocklistPath(""), b.m); err != nil {
		return nil, err
	}

	return out, nil
}

var errNoMemlock = errors.New("the kernel does not report it")

// addMemlock adds the memory of m to out under name. It is the memlock
// figure of the map's fdinfo: the bytes the kernel allocated for it,
// computed per map type from Linux 6.4 on and estimated from the map's
// dimensions before.
func addMemlock(out map[string]uint64, name string, m *ebpf.Map) error {
	if m == nil {
		return fmt.Errorf("heavykeeper: memory of %s: map is closed", name)
	}

	info, err := m.Info()
	if err != nil {
		return fmt.Errorf("heavykeeper: memory of %s: %w", name, err)
	}

	v, ok := info.Memlock()
	if !ok {
		return fmt.Errorf("heavykeeper: memory of %s: %w", name, errNoMemlock)
	}

	out[name] = v

	return nil
}
