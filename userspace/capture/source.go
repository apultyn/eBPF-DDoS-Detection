// Package capture reads packets from a trace file or a live interface and
// reduces each one to what the detector needs: the source address, the
// time it was seen, and its size.
//
// Every source implements Source, so the rest of the pipeline does not
// know whether it is replaying a CAIDA trace or listening on a FABRIC
// node. Packets that are not IPv4 or IPv6 are skipped inside the source
// and only show up in Stats.
package capture

import (
	"errors"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// Packet is the part of a captured packet the detector uses.
type Packet struct {
	// Src is the packet's source address.
	Src flow.Key

	// Timestamp is when the packet was captured. For a trace file this
	// is the time recorded in the file, not the time it was read, so a
	// replay produces the same windows no matter how fast it runs.
	Timestamp time.Time

	// Length is the packet's length on the wire in bytes, which may be
	// larger than what was captured if the trace is truncated.
	Length uint32
}

// Stats counts what a source has read so far.
type Stats struct {
	// Packets is the number of IPv4 and IPv6 packets returned by Next.
	Packets uint64

	// Skipped is the number of frames dropped because they were not
	// IPv4 or IPv6, or were too short to hold an IP header.
	Skipped uint64
}

// Source delivers packets one at a time.
//
// A Source is not safe for concurrent use: it is read by the single
// goroutine that feeds the sketches.
type Source interface {
	// Next returns the next IPv4 or IPv6 packet. It returns io.EOF when
	// a trace file is exhausted and ErrClosed once Close has been
	// called on a live source.
	Next() (Packet, error)

	// Stats returns the counts accumulated so far.
	Stats() Stats

	// Close releases the underlying file or socket.
	Close() error
}

// ErrClosed is returned by Next after Close has been called.
var ErrClosed = errors.New("capture: source closed")
