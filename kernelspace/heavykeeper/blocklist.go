package heavykeeper

import (
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

// BlockEntry is one source on the blocklist, its per-CPU copies merged.
type BlockEntry struct {
	IP flow.Key

	// LastSeen is the CLOCK_TAI time XDP last dropped a packet from IP,
	// or the time it was blocked if nothing has been dropped since.
	LastSeen time.Time

	// Drops is the number of packets XDP has dropped from IP.
	Drops uint64
}
