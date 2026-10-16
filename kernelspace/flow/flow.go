// Package flow defines the flow key shared by the sketches and the
// detector, together with the hashing used to place keys in a sketch.
//
// Keeping the key and the hash in one place means every structure in the
// pipeline identifies a flow the same way, and none of them has to go
// through a string in the packet path.
package flow

import (
	"encoding/binary"
	"net/netip"
)

// Key identifies a flow by its source address.
//
// Both address families share one fixed-size representation: an IPv6
// address is stored as is, and an IPv4 address is stored IPv4-mapped
// (::ffff:a.b.c.d). This is the same layout netip.Addr.As16 produces, and
// it is a plain 16-byte array, so it can be used as a map key, copied
// without allocation, and mirrored directly as a BPF map key.
type Key [16]byte

// v4Prefix is the first 12 bytes of every IPv4-mapped address.
var v4Prefix = [12]byte{10: 0xff, 11: 0xff}

// FromIPv4 converts the four address bytes of an IPv4 header to a Key.
//
// This and FromIPv6 are the conversions used in the packet path. The
// string variants below allocate and are meant for tests and fixtures.
func FromIPv4(b []byte) Key {
	var k Key
	copy(k[:12], v4Prefix[:])
	copy(k[12:], b[:4])

	return k
}

// FromIPv6 converts the sixteen address bytes of an IPv6 header to a Key.
func FromIPv6(b []byte) Key {
	return Key(b[:16])
}

// FromAddr converts a netip.Addr to a Key.
func FromAddr(a netip.Addr) Key {
	return a.As16()
}

// MustParse converts an address string to a Key and panics on invalid
// input. Intended for tests and fixtures only.
func MustParse(s string) Key {
	return FromAddr(netip.MustParseAddr(s))
}

// Addr returns the address as a netip.Addr, unmapping IPv4 addresses so
// they print in dotted form.
func (k Key) Addr() netip.Addr {
	return netip.AddrFrom16(k).Unmap()
}

// Is4 reports whether the key holds an IPv4 address.
func (k Key) Is4() bool {
	return [12]byte(k[:12]) == v4Prefix
}

func (k Key) String() string {
	return k.Addr().String()
}

// Hash reduces the key to 32 bits.
//
// The key is folded one 32-bit word at a time, mixing after each word.
// Each step is a bijection in the word it absorbs, so two IPv4 keys,
// which share their first three words, never collide here. For IPv6 the
// result is an ordinary 32-bit hash.
//
// Callers derive per-row indices from this value with Mix32 and a row
// seed, so the key itself is read only once per packet.
func (k Key) Hash() uint32 {
	h := Mix32(binary.BigEndian.Uint32(k[0:4]))
	h = Mix32(h ^ binary.BigEndian.Uint32(k[4:8]))
	h = Mix32(h ^ binary.BigEndian.Uint32(k[8:12]))
	h = Mix32(h ^ binary.BigEndian.Uint32(k[12:16]))

	return h
}

// Mix32 is an integer mixing function with good avalanche.
//
// Addresses cluster heavily in their low bits, so the input must be mixed
// before it is reduced to a bucket index. This particular constant set is
// a bijection on uint32, meaning all bucket collisions come from the index
// reduction rather than from the mixing itself.
func Mix32(x uint32) uint32 {
	x ^= x >> 16
	x *= 0x7feb352d
	x ^= x >> 15
	x *= 0x846ca68b
	x ^= x >> 16

	return x
}
