// Package heavykeeper reads the HeavyKeeper sketches, Top-K tables and
// window totals that heavy_keeper.c maintains in kernel space.
//
// Everything in this file mirrors heavy_keeper.c and must be kept in sync
// with it: the struct layouts, the dimensions, the seeds, the hash and the
// map names. If any of them differ, lookups read the wrong buckets and
// return wrong counts without any error.
package heavykeeper

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"path/filepath"
	"slices"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
)

const (
	Depth        = 4    // DEPTH
	Width        = 1024 // WIDTH
	TotalBuckets = Depth * Width
	K            = 10 // K_SIZE, entries in each topk_map_N
	Slots        = 4  // SLOTS, number of sketch_N and topk_map_N maps

	BlocklistSize = 1000 // BLOCKLIST_SIZE, max_entries of blocklist_map
)

// DefaultPinDir is where libbpf pins maps declared with
// LIBBPF_PIN_BY_NAME.
const DefaultPinDir = "/sys/fs/bpf"

// bucket mirrors struct bucket.
type bucket struct {
	Fp    uint16
	Pad   uint16 // matches _pad; keep it a named field so encoding is exact
	Count uint32
}

// topkEntry mirrors struct topk_entry. struct in6_addr has the same 16-byte
// layout as flow.Key, and the struct has no padding.
type topkEntry struct {
	IP    flow.Key
	Count uint32
}

// slotStats mirrors struct slot_stats. The map is per-CPU, so the kernel
// returns one of these for every possible CPU.
type slotStats struct {
	Packets uint64
	Bytes   uint64
}

// blockEntry mirrors struct block_entry. blocklist_map is per-CPU, so the
// kernel returns one of these for every possible CPU.
type blockEntry struct {
	LastSeenNs uint64
	Drops      uint64
}

// indexSeeds mirrors INDEX_SEEDS.
var indexSeeds = [Depth]uint32{0x9747b28c, 0x5bd1e995, 0x239b921b}

// fingerprintSeed mirrors FINGERPRINT_SEED.
const fingerprintSeed = 0x75a2e345

func sketchPath(dir string, slot int) string {
	return filepath.Join(dir, fmt.Sprintf("sketch_%d", slot))
}

func topkPath(dir string, slot int) string {
	return filepath.Join(dir, fmt.Sprintf("topk_map_%d", slot))
}

func statsPath(dir string) string {
	return filepath.Join(dir, "slot_stats")
}

func blockedStatsPath(dir string) string {
	return filepath.Join(dir, "blocked_stats")
}

func blocklistPath(dir string) string {
	return filepath.Join(dir, "blocklist_map")
}

// hash32 mirrors hash32 in heavy_keeper.c, a MurmurHash3 over the 16-byte
// address.
//
// The C code reads s6_addr32[i] as a native-endian word, so the words are
// read in native byte order here too, not in network order.
func hash32(k flow.Key, seed uint32) uint32 {
	h := seed

	for i := 0; i < 4; i++ {
		w := binary.NativeEndian.Uint32(k[4*i:])
		w *= 0xcc9e2d51
		w = bits.RotateLeft32(w, 15)
		w *= 0x1b873593

		h ^= w
		h = bits.RotateLeft32(h, 13)
		h = h*5 + 0xe6546b64
	}

	h ^= 16
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16

	return h
}

// fingerprint mirrors the fingerprint computed at the top of update().
func fingerprint(k flow.Key) uint16 {
	raw := hash32(k, fingerprintSeed)

	fp := uint16(raw ^ raw>>16)
	if fp == 0 {
		fp = 1 // 0 marks an empty bucket
	}

	return fp
}

// index returns the flat map key of key's bucket in row.
func index(k flow.Key, row int) uint32 {
	return uint32(row*Width) + hash32(k, indexSeeds[row])&(Width-1)
}

// candidates turns a raw Top-K table into the candidate list, largest
// count first.
//
// Empty entries are dropped. The kernel updates the table from every CPU
// without a lock, so the same address can occupy two entries; only the
// larger count is kept.
func candidates(raw []topkEntry) []TopKEntry {
	best := make(map[flow.Key]uint32, len(raw))

	for _, e := range raw {
		if e.Count > best[e.IP] {
			best[e.IP] = e.Count
		}
	}

	out := make([]TopKEntry, 0, len(best))
	for ip, n := range best {
		out = append(out, TopKEntry{Item: ip, Count: n})
	}

	// Ties are broken by address so the order does not depend on map
	// iteration.
	slices.SortFunc(out, func(a, b TopKEntry) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return slices.Compare(a.Item[:], b.Item[:])
	})

	return out
}

// sumStats adds up the per-CPU values of one slot_stats entry.
func sumStats(perCPU []slotStats) (packets, bytes uint64) {
	for _, s := range perCPU {
		packets += s.Packets
		bytes += s.Bytes
	}

	return packets, bytes
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
