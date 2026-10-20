// Package blocklist reads and writes the maps of blocklist.c, the XDP
// program that drops the sources the user-space detector flags before
// they reach its capture socket.
//
// Everything in this file mirrors blocklist.c and must be kept in sync
// with it: the struct layouts, the size and the map names. If they differ,
// opening the maps fails or entries are written under the wrong layout.
package blocklist

import (
	"path/filepath"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// Size is BLOCKLIST_SIZE, the max_entries of us_blocklist_map.
const Size = 1000

// DefaultPinDir is where libbpf pins maps declared with
// LIBBPF_PIN_BY_NAME.
const DefaultPinDir = "/sys/fs/bpf"

// Pin names of the maps, as declared in blocklist.c.
const (
	mapName   = "us_blocklist_map"
	statsName = "us_blocked_stats"
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

// Totals is what the blocklist has dropped since blocklist.o was loaded,
// summed over all CPUs. The counts only grow; per-window figures are the
// difference between two readings.
type Totals struct {
	Packets uint64
	Bytes   uint64
}

// blockEntry mirrors struct block_entry. us_blocklist_map is per-CPU, so
// the kernel returns one of these for every possible CPU.
type blockEntry struct {
	LastSeenNs uint64
	Drops      uint64
}

// blockedTotals mirrors struct blocked_totals. us_blocked_stats is
// per-CPU, so the kernel returns one of these for every possible CPU.
type blockedTotals struct {
	Packets uint64
	Bytes   uint64
}

func mapPath(dir string) string {
	return filepath.Join(dir, mapName)
}

func statsPath(dir string) string {
	return filepath.Join(dir, statsName)
}

// mergeBlockEntry combines the per-CPU copies of one blocklist entry: the
// latest drop on any CPU, and the drops on all of them.
func mergeBlockEntry(perCPU []blockEntry) (lastSeenNs, drops uint64) {
	for _, e := range perCPU {
		lastSeenNs = max(lastSeenNs, e.LastSeenNs)
		drops += e.Drops
	}

	return lastSeenNs, drops
}

// sumTotals adds up the per-CPU values of us_blocked_stats.
func sumTotals(perCPU []blockedTotals) Totals {
	var t Totals

	for _, c := range perCPU {
		t.Packets += c.Packets
		t.Bytes += c.Bytes
	}

	return t
}
