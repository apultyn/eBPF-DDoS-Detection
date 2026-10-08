//go:build linux

package capture

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// packetIgnoreOutgoing is PACKET_IGNORE_OUTGOING (Linux 4.20+), which the
// syscall package does not define.
const packetIgnoreOutgoing = 23

// liveBufLen is large enough for any frame the kernel hands to a packet
// socket, including GRO-merged frames up to 64 KiB.
const liveBufLen = 1 << 18

// LiveConfig configures a live capture.
type LiveConfig struct {
	// Interface is the name of the interface to capture on, such as
	// "ens7" on a FABRIC node.
	Interface string

	// Promiscuous also captures frames addressed to other hosts. Needed
	// when the node observes traffic it is not the destination of, for
	// example on a mirrored port.
	Promiscuous bool
}

// LiveSource captures from a network interface through an AF_PACKET
// socket. It needs CAP_NET_RAW, which in practice means running as root.
//
// Only incoming frames are captured; packets the node sends itself are
// not part of the traffic being judged.
//
// One system call is made per packet, which is fine for a user-space
// baseline but tops out well below line rate. The XDP path is what
// removes that limit.
type LiveSource struct {
	file *os.File
	buf  []byte

	stats Stats
}

// OpenLive opens a capture on the configured interface.
func OpenLive(cfg LiveConfig) (*LiveSource, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}

	proto := htons(syscall.ETH_P_ALL)

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("capture: opening packet socket (needs root or CAP_NET_RAW): %w", err)
	}

	if err := setupLive(fd, iface.Index, proto, cfg.Promiscuous); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: %s: %w", cfg.Interface, err)
	}

	// A non-blocking descriptor handed to os.NewFile is registered with
	// the runtime poller, so Read parks the goroutine instead of a thread
	// and Close safely wakes a Read that is in progress.
	return &LiveSource{
		file: os.NewFile(uintptr(fd), "packet:"+cfg.Interface),
		buf:  make([]byte, liveBufLen),
	}, nil
}

func setupLive(fd, ifindex int, proto uint16, promisc bool) error {
	err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetIgnoreOutgoing, 1)
	if err != nil {
		return fmt.Errorf("ignoring outgoing packets (needs Linux 4.20+): %w", err)
	}

	if promisc {
		// The membership is dropped automatically when the socket closes,
		// so the interface never stays promiscuous after we exit.
		mreq := packetMreq{ifindex: int32(ifindex), typ: syscall.PACKET_MR_PROMISC}

		_, _, errno := syscall.Syscall6(
			syscall.SYS_SETSOCKOPT,
			uintptr(fd),
			syscall.SOL_PACKET,
			syscall.PACKET_ADD_MEMBERSHIP,
			uintptr(unsafe.Pointer(&mreq)),
			unsafe.Sizeof(mreq),
			0,
		)
		if errno != 0 {
			return fmt.Errorf("enabling promiscuous mode: %w", errno)
		}
	}

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifindex,
	}); err != nil {
		return fmt.Errorf("binding: %w", err)
	}

	return syscall.SetNonblock(fd, true)
}

// packetMreq mirrors struct packet_mreq from <linux/if_packet.h>.
type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	address [8]byte
}

// Next blocks until the next IPv4 or IPv6 packet arrives, and returns
// ErrClosed once Close has been called.
//
// The timestamp is taken when the packet reaches user space, so it
// includes socket queueing delay.
func (s *LiveSource) Next() (Packet, error) {
	for {
		n, err := s.file.Read(s.buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return Packet{}, ErrClosed
			}
			return Packet{}, err
		}

		src, ok := parse(LinkTypeEthernet, s.buf[:n])
		if !ok {
			s.stats.Skipped++
			continue
		}

		s.stats.Packets++

		return Packet{
			Src:       src,
			Timestamp: time.Now(),
			Length:    uint32(n),
		}, nil
	}
}

func (s *LiveSource) Stats() Stats {
	return s.stats
}

// Close stops the capture. It may be called from another goroutine to
// unblock a pending Next.
func (s *LiveSource) Close() error {
	return s.file.Close()
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
