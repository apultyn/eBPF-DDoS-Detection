// Package memsource is an in-memory stand-in for the kernel maps, for
// testing the window and detector packages without XDP.
//
// It implements window.Source with exact counts: Count returns exactly
// what was added, and Candidates is the true top K. Tests that exercise
// the window logic therefore see no sketch error, the same way the
// userspace tests could select exact counts.
package memsource

import (
	"fmt"
	"slices"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

// Source holds the traffic of heavykeeper.Slots slots in memory.
//
// Not safe for concurrent use.
type Source struct {
	slots [heavykeeper.Slots]slot

	// Resets records the slot of every Reset call in order, so tests can
	// check that a slot is never cleared while it is still in use.
	Resets []int

	// Err, when set, is returned by every method, for testing how
	// callers handle a failed map read.
	Err error

	// CountErr, when set, is returned by Count only, so a window can be
	// closed and loaded normally and then fail while it is evaluated.
	CountErr error
}

type slot struct {
	counts  map[flow.Key]uint32
	packets uint64
	bytes   uint64

	blockedPackets uint64
	blockedBytes   uint64
}

// New returns a Source with every slot empty.
func New() *Source {
	s := &Source{}

	for i := range s.slots {
		s.slots[i].counts = make(map[flow.Key]uint32)
	}

	return s
}

// Add records packets from key in slot, totalling bytes, as the kernel
// would while slot is the current window's.
func (s *Source) Add(slot int, key flow.Key, packets uint32, bytes uint64) {
	sl := &s.slots[s.mustIndex(slot)]

	sl.counts[key] += packets
	sl.packets += uint64(packets)
	sl.bytes += bytes
}

// AddBlocked records packets totalling bytes that the blocklist dropped in
// slot. They are not counted anywhere else, as in the kernel.
func (s *Source) AddBlocked(slot int, packets, bytes uint64) {
	sl := &s.slots[s.mustIndex(slot)]

	sl.blockedPackets += packets
	sl.blockedBytes += bytes
}

func (s *Source) Count(slot int, key flow.Key) (uint32, error) {
	if s.CountErr != nil {
		return 0, s.CountErr
	}

	sl, err := s.get(slot)
	if err != nil {
		return 0, err
	}

	return sl.counts[key], nil
}

// Candidates returns the heavykeeper.K largest sources of slot, largest
// first, mirroring the size of the kernel's Top-K table. Ties are broken
// by address so the order is deterministic.
func (s *Source) Candidates(slot int) ([]heavykeeper.TopKEntry, error) {
	sl, err := s.get(slot)
	if err != nil {
		return nil, err
	}

	out := make([]heavykeeper.TopKEntry, 0, len(sl.counts))
	for ip, n := range sl.counts {
		if n > 0 {
			out = append(out, heavykeeper.TopKEntry{Item: ip, Count: n})
		}
	}

	slices.SortFunc(out, func(a, b heavykeeper.TopKEntry) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return slices.Compare(a.Item[:], b.Item[:])
	})

	if len(out) > heavykeeper.K {
		out = out[:heavykeeper.K]
	}

	return out, nil
}

func (s *Source) Totals(slot int) (packets, bytes uint64, err error) {
	sl, err := s.get(slot)
	if err != nil {
		return 0, 0, err
	}

	return sl.packets, sl.bytes, nil
}

func (s *Source) Blocked(slot int) (packets, bytes uint64, err error) {
	sl, err := s.get(slot)
	if err != nil {
		return 0, 0, err
	}

	return sl.blockedPackets, sl.blockedBytes, nil
}

func (s *Source) Reset(slot int) error {
	sl, err := s.get(slot)
	if err != nil {
		return err
	}

	clear(sl.counts)
	sl.packets = 0
	sl.bytes = 0
	sl.blockedPackets = 0
	sl.blockedBytes = 0

	s.Resets = append(s.Resets, slot)

	return nil
}

func (s *Source) get(slot int) (*slot, error) {
	if s.Err != nil {
		return nil, s.Err
	}

	if slot < 0 || slot >= heavykeeper.Slots {
		return nil, fmt.Errorf("memsource: slot %d out of range [0, %d)", slot, heavykeeper.Slots)
	}

	return &s.slots[slot], nil
}

// mustIndex validates a slot passed by a test; a bad slot there is a bug
// in the test itself.
func (s *Source) mustIndex(slot int) int {
	if slot < 0 || slot >= heavykeeper.Slots {
		panic(fmt.Sprintf("memsource: slot %d out of range [0, %d)", slot, heavykeeper.Slots))
	}

	return slot
}
