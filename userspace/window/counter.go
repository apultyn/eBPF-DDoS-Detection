package window

import (
	"fmt"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/countmin"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/heavykeeper"
)

// CountSource selects where per-IP packet counts are read from.
//
// HeavyKeeper always decides which addresses are candidates; this only
// changes which structure is asked how many packets a candidate sent.
// The choice is fixed for the lifetime of an Aggregator, so the current
// and previous window always answer from the same kind of structure and
// a combined count never mixes an underestimate with an overestimate.
type CountSource int

const (
	// CountHeavyKeeper reads counts from the window's HeavyKeeper sketch.
	// This is the configuration the detector is primarily evaluated with.
	CountHeavyKeeper CountSource = iota

	// CountCountMin reads counts from a Count-Min Sketch kept alongside
	// the HeavyKeeper sketch in every window.
	CountCountMin
)

func (c CountSource) String() string {
	switch c {
	case CountHeavyKeeper:
		return "heavykeeper"
	case CountCountMin:
		return "countmin"
	}

	return fmt.Sprintf("CountSource(%d)", int(c))
}

// ParseCountSource converts a flag value to a CountSource.
func ParseCountSource(s string) (CountSource, error) {
	switch s {
	case "heavykeeper", "hk":
		return CountHeavyKeeper, nil
	case "countmin", "cms":
		return CountCountMin, nil
	}

	return 0, fmt.Errorf("unknown count source %q (want heavykeeper or countmin)", s)
}

// Counter answers how many packets a key sent in one window.
//
// Each window owns one Counter, built once when the window is allocated,
// so the packet path calls through the interface instead of branching on
// the configuration.
type Counter interface {
	// Add records one packet from key.
	Add(key flow.Key)

	// Count returns the estimated number of packets from key.
	Count(key flow.Key) uint64

	// Reset clears the counter for reuse in a new window.
	Reset()
}

// hkCounter answers from the window's HeavyKeeper sketch.
//
// The sketch is already updated for every packet to drive the candidate
// set, so Add has nothing left to do and Reset is left to the window.
type hkCounter struct {
	hk *heavykeeper.HeavyKeeper
}

func (c hkCounter) Add(flow.Key) {}

func (c hkCounter) Count(key flow.Key) uint64 {
	return uint64(c.hk.Query(key))
}

func (c hkCounter) Reset() {}

// cmsCounter answers from a Count-Min Sketch that sees every packet.
type cmsCounter struct {
	cms *countmin.Sketch
}

func (c cmsCounter) Add(key flow.Key) {
	c.cms.Add(key, 1)
}

func (c cmsCounter) Count(key flow.Key) uint64 {
	return c.cms.Estimate(key)
}

func (c cmsCounter) Reset() {
	c.cms.Reset()
}
