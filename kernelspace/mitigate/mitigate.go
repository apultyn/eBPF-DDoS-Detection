// Package mitigate pushes the sources the detector flags onto the kernel
// blocklist, where XDP drops their packets before they reach the sketch.
//
// A source stays blocked for a fixed TTL from when it was last flagged.
// When the blocklist is full, the most stale entries make room: those XDP
// has not dropped a packet from for the most windows, and among those the
// ones it has dropped the fewest packets from. Staleness is compared in
// whole windows so that the tie-break on drops actually comes into play.
//
// Not safe for concurrent use; it runs inside the aggregator's callback,
// like the evaluator.
package mitigate

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

// Map is the kernel blocklist. On Linux it is a *heavykeeper.Blocklist;
// tests use an in-memory map.
type Map interface {
	// Block adds key, or refreshes it if it is already there. now is
	// stored as the last time key was seen.
	Block(key flow.Key, now time.Time) error

	// Unblock removes key; a key that is not there is not an error.
	Unblock(key flow.Key) error

	// Entries returns every blocked source with its last-seen time and
	// drop count.
	Entries() ([]heavykeeper.BlockEntry, error)
}

// Config configures a Mitigator.
type Config struct {
	// TTL is how long a source stays blocked after it was last flagged.
	// Zero blocks until the source is evicted or the run ends.
	TTL time.Duration

	// Capacity is the number of entries the blocklist holds,
	// heavykeeper.BlocklistSize.
	Capacity int

	// WindowLength is the granularity staleness is compared at.
	WindowLength time.Duration

	// Allow lists sources that are never blocked, such as the host the
	// experiment is controlled from.
	Allow []flow.Key
}

// DefaultConfig returns the configuration used by the detector.
func DefaultConfig() Config {
	return Config{
		TTL:          60 * time.Second,
		Capacity:     heavykeeper.BlocklistSize,
		WindowLength: epoch.DefaultLength,
	}
}

// Stats counts what the Mitigator has done over a run.
type Stats struct {
	// Blocked is the number of times a source was added to the
	// blocklist, and Refreshed the number of times a source already on it
	// was flagged again, restarting its TTL.
	Blocked   uint64 `json:"blocked"`
	Refreshed uint64 `json:"refreshed"`

	// Expired is the number of sources removed when their TTL ran out,
	// and Evicted the number removed to make room for new ones.
	Expired uint64 `json:"expired"`
	Evicted uint64 `json:"evicted"`

	// Allowlisted is the number of times a flagged source was not blocked
	// because it is on the allowlist.
	Allowlisted uint64 `json:"allowlisted"`

	// Errors is the number of failed map operations.
	Errors uint64 `json:"errors"`

	// Active is the number of sources blocked now, and Peak the largest
	// number blocked at once.
	Active int `json:"active"`
	Peak   int `json:"peak"`
}

// Mitigator decides which sources are on the blocklist.
type Mitigator struct {
	cfg   Config
	m     Map
	allow map[flow.Key]struct{}

	// blocked holds every source this Mitigator put on the blocklist and
	// when it was last flagged. Only user space adds entries, so this is
	// also what the kernel map holds.
	blocked map[flow.Key]time.Time

	stats Stats
}

// New returns a Mitigator over m, which should be empty.
func New(cfg Config, m Map) (*Mitigator, error) {
	if cfg.Capacity <= 0 {
		return nil, fmt.Errorf("mitigate: capacity %d, want > 0", cfg.Capacity)
	}
	if cfg.WindowLength <= 0 {
		return nil, fmt.Errorf("mitigate: window length %v, want > 0", cfg.WindowLength)
	}
	if cfg.TTL < 0 {
		return nil, fmt.Errorf("mitigate: TTL %v, want >= 0", cfg.TTL)
	}

	allow := make(map[flow.Key]struct{}, len(cfg.Allow))
	for _, k := range cfg.Allow {
		allow[k] = struct{}{}
	}

	return &Mitigator{
		cfg:     cfg,
		m:       m,
		allow:   allow,
		blocked: make(map[flow.Key]time.Time),
	}, nil
}

// Stats returns the counts accumulated so far.
func (mt *Mitigator) Stats() Stats {
	s := mt.stats
	s.Active = len(mt.blocked)

	return s
}

// Expire unblocks every source last flagged at least TTL before now, a
// CLOCK_TAI time. A source that cannot be removed stays tracked and is
// retried on the next call.
func (mt *Mitigator) Expire(now time.Time) error {
	if mt.cfg.TTL == 0 {
		return nil
	}

	var errs []error

	for k, at := range mt.blocked {
		if now.Sub(at) < mt.cfg.TTL {
			continue
		}

		if err := mt.m.Unblock(k); err != nil {
			mt.stats.Errors++
			errs = append(errs, err)
			continue
		}

		delete(mt.blocked, k)
		mt.stats.Expired++
	}

	return errors.Join(errs...)
}

// Block puts the flagged sources on the blocklist, largest first, and
// reports for each whether it is on the blocklist afterwards. now is
// CLOCK_TAI.
//
// A source already on the blocklist has its TTL restarted. When there is
// not room for the new sources, the most stale entries are evicted first;
// if more sources are flagged than the blocklist holds, the smallest are
// left out.
//
// A failed map operation does not stop the others: the error is returned
// and counted, and the source it concerned is reported as not blocked.
func (mt *Mitigator) Block(flagged []flow.Key, now time.Time) ([]bool, error) {
	ok := make([]bool, len(flagged))

	// keep holds every source flagged in this call, so that none of them
	// is evicted to make room for another.
	keep := make(map[flow.Key]struct{}, len(flagged))

	// first maps a source to its first position in flagged, so that a
	// duplicate is reported like the first occurrence.
	first := make(map[flow.Key]int, len(flagged))

	var fresh []int

	for i, k := range flagged {
		if _, allowed := mt.allow[k]; allowed {
			mt.stats.Allowlisted++
			continue
		}

		if _, dup := first[k]; dup {
			continue
		}
		first[k] = i
		keep[k] = struct{}{}

		if _, blocked := mt.blocked[k]; blocked {
			mt.blocked[k] = now
			mt.stats.Refreshed++
			ok[i] = true
			continue
		}

		fresh = append(fresh, i)
	}

	if len(fresh) > mt.cfg.Capacity {
		fresh = fresh[:mt.cfg.Capacity]
	}

	var errs []error

	if need := len(mt.blocked) + len(fresh) - mt.cfg.Capacity; need > 0 {
		if err := mt.evict(need, keep); err != nil {
			errs = append(errs, err)
		}
	}

	for _, i := range fresh {
		k := flagged[i]

		if err := mt.m.Block(k, now); err != nil {
			mt.stats.Errors++
			errs = append(errs, err)
			continue
		}

		mt.blocked[k] = now
		mt.stats.Blocked++
		ok[i] = true
	}

	for i, k := range flagged {
		if j, seen := first[k]; seen && j != i {
			ok[i] = ok[j]
		}
	}

	mt.stats.Peak = max(mt.stats.Peak, len(mt.blocked))

	return ok, errors.Join(errs...)
}

// evict removes the n most stale entries that are not in keep.
func (mt *Mitigator) evict(n int, keep map[flow.Key]struct{}) error {
	entries, err := mt.m.Entries()
	if err != nil {
		mt.stats.Errors++
		return fmt.Errorf("mitigate: making room: %w", err)
	}

	var errs []error

	for _, k := range chooseVictims(entries, n, mt.cfg.WindowLength, keep) {
		if err := mt.m.Unblock(k); err != nil {
			mt.stats.Errors++
			errs = append(errs, err)
			continue
		}

		delete(mt.blocked, k)
		mt.stats.Evicted++
	}

	return errors.Join(errs...)
}

// chooseVictims returns up to n entries to evict, most stale first: the
// oldest window XDP last saw a packet in, then the fewest packets
// dropped. Entries in keep are never chosen. The address breaks the
// remaining ties so the choice is deterministic.
func chooseVictims(entries []heavykeeper.BlockEntry, n int, length time.Duration, keep map[flow.Key]struct{}) []flow.Key {
	candidates := make([]heavykeeper.BlockEntry, 0, len(entries))
	for _, e := range entries {
		if _, kept := keep[e.IP]; !kept {
			candidates = append(candidates, e)
		}
	}

	slices.SortFunc(candidates, func(a, b heavykeeper.BlockEntry) int {
		if ea, eb := epoch.Of(a.LastSeen, length), epoch.Of(b.LastSeen, length); ea != eb {
			if ea < eb {
				return -1
			}
			return 1
		}

		if a.Drops != b.Drops {
			if a.Drops < b.Drops {
				return -1
			}
			return 1
		}

		return slices.Compare(a.IP[:], b.IP[:])
	})

	n = min(n, len(candidates))

	victims := make([]flow.Key, n)
	for i := range victims {
		victims[i] = candidates[i].IP
	}

	return victims
}
