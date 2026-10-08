package capture

import (
	"encoding/binary"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// LinkType identifies the framing in front of the IP header, using the
// numbering from the pcap file format.
type LinkType uint32

const (
	// LinkTypeEthernet is Ethernet II, what FABRIC NICs deliver.
	LinkTypeEthernet LinkType = 1

	// LinkTypeRaw is a bare IP packet with no link-layer header. The
	// CAIDA anonymized traces use this.
	LinkTypeRaw LinkType = 101

	// LinkTypeRawAlt and LinkTypeRawBSD are older platform-specific
	// numbers for the same raw IP framing.
	LinkTypeRawAlt LinkType = 12
	LinkTypeRawBSD LinkType = 14

	// LinkTypeLinuxSLL and LinkTypeLinuxSLL2 are what tcpdump writes when
	// capturing on the "any" pseudo-interface.
	LinkTypeLinuxSLL  LinkType = 113
	LinkTypeLinuxSLL2 LinkType = 276
)

const (
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86dd
	etherTypeVLAN  = 0x8100
	etherTypeQinQ  = 0x88a8
	etherTypeQinQ2 = 0x9100

	ethernetHeaderLen = 14
	vlanTagLen        = 4
	sllHeaderLen      = 16
	sll2HeaderLen     = 20

	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40
)

// supported reports whether parse understands the link type.
func (lt LinkType) supported() bool {
	switch lt {
	case LinkTypeEthernet, LinkTypeRaw, LinkTypeRawAlt, LinkTypeRawBSD,
		LinkTypeLinuxSLL, LinkTypeLinuxSLL2:
		return true
	}

	return false
}

// parse extracts the source address from a captured frame.
//
// It returns false for anything that is not IPv4 or IPv6, or that is
// truncated before the source address. Only fixed offsets are read and
// nothing is allocated, mirroring what the XDP program will do in the
// kernel.
func parse(lt LinkType, data []byte) (flow.Key, bool) {
	switch lt {

	case LinkTypeEthernet:
		if len(data) < ethernetHeaderLen {
			return flow.Key{}, false
		}

		etherType := binary.BigEndian.Uint16(data[12:14])
		data = data[ethernetHeaderLen:]

		// Skip any VLAN tags. FABRIC slices often see one on the
		// dataplane, and stacked tags are cheap to handle.
		for etherType == etherTypeVLAN ||
			etherType == etherTypeQinQ ||
			etherType == etherTypeQinQ2 {

			if len(data) < vlanTagLen {
				return flow.Key{}, false
			}

			etherType = binary.BigEndian.Uint16(data[2:4])
			data = data[vlanTagLen:]
		}

		return parseIP(etherType, data)

	case LinkTypeRaw, LinkTypeRawAlt, LinkTypeRawBSD:
		if len(data) < 1 {
			return flow.Key{}, false
		}

		// No link header, so the IP version nibble is the only hint.
		switch data[0] >> 4 {
		case 4:
			return parseIP(etherTypeIPv4, data)
		case 6:
			return parseIP(etherTypeIPv6, data)
		}

		return flow.Key{}, false

	case LinkTypeLinuxSLL:
		if len(data) < sllHeaderLen {
			return flow.Key{}, false
		}

		return parseIP(binary.BigEndian.Uint16(data[14:16]), data[sllHeaderLen:])

	case LinkTypeLinuxSLL2:
		if len(data) < sll2HeaderLen {
			return flow.Key{}, false
		}

		return parseIP(binary.BigEndian.Uint16(data[0:2]), data[sll2HeaderLen:])
	}

	return flow.Key{}, false
}

// parseIP extracts the source address from an IP header whose protocol
// is given by etherType.
//
// The source address sits at a fixed offset in both versions, so IPv6
// extension headers and IPv4 options never need to be walked.
func parseIP(etherType uint16, ip []byte) (flow.Key, bool) {
	switch etherType {

	case etherTypeIPv4:
		if len(ip) < ipv4MinHeaderLen || ip[0]>>4 != 4 {
			return flow.Key{}, false
		}

		return flow.FromIPv4(ip[12:16]), true

	case etherTypeIPv6:
		if len(ip) < ipv6HeaderLen || ip[0]>>4 != 6 {
			return flow.Key{}, false
		}

		return flow.FromIPv6(ip[8:24]), true
	}

	return flow.Key{}, false
}
