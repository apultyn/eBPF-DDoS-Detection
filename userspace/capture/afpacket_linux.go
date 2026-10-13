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

	// RecvBuffer requests a socket receive buffer of this many bytes. The
	// buffer is where packets wait between the kernel and this program,
	// so its size decides how large a burst can be absorbed before the
	// kernel starts dropping. Zero keeps the system default. The size
	// actually granted is reported by LiveStats.
	RecvBuffer int
}

// LiveStats describes a live capture as seen from the kernel.
type LiveStats struct {
	// RecvBuffer is the socket receive buffer the kernel granted, in
	// bytes. Linux doubles the requested value to allow for bookkeeping.
	RecvBuffer int `json:"recv_buffer_bytes"`

	// KernelTotal is the number of packets the kernel tried to queue on
	// the socket, and KernelDropped how many of those it dropped because
	// the receive buffer was full. KernelTotal includes the dropped ones.
	KernelTotal   uint64 `json:"kernel_total"`
	KernelDropped uint64 `json:"kernel_dropped"`

	// KernelStamps counts packets timestamped by the kernel on arrival,
	// FallbackStamps those that carried no kernel timestamp and were
	// stamped when read instead. FallbackStamps should stay zero.
	KernelStamps   uint64 `json:"kernel_timestamps"`
	FallbackStamps uint64 `json:"fallback_timestamps"`
}

// LiveSource captures from a network interface through an AF_PACKET
// socket. It needs CAP_NET_RAW, which in practice means running as root.
//
// Only incoming frames are captured; packets the node sends itself are
// not part of the traffic being judged. Each packet carries the time the
// kernel received it, not the time it was read, so time spent waiting in
// the socket buffer does not shift packets between windows.
//
// One system call is made per packet. The socket's drop counter shows
// when that is too slow for the offered load, which is the bottleneck the
// XDP path removes.
type LiveSource struct {
	file *os.File
	raw  syscall.RawConn

	buf []byte
	oob []byte
	iov syscall.Iovec
	msg syscall.Msghdr

	// recv is the read callback handed to the runtime poller, created
	// once so that reading allocates nothing. n, oobn and rerr carry its
	// results back.
	recv func(fd uintptr) bool
	n    int
	oobn int
	rerr error

	stats Stats
	live  LiveStats
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

	granted, err := setupLive(fd, iface.Index, proto, cfg)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("capture: %s: %w", cfg.Interface, err)
	}

	// A non-blocking descriptor handed to os.NewFile is registered with
	// the runtime poller, so a read parks the goroutine instead of a
	// thread, honours read deadlines, and is woken by Close.
	file := os.NewFile(uintptr(fd), "packet:"+cfg.Interface)

	raw, err := file.SyscallConn()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("capture: %w", err)
	}

	s := &LiveSource{
		file: file,
		raw:  raw,
		buf:  make([]byte, liveBufLen),
		oob:  make([]byte, syscall.CmsgSpace(int(unsafe.Sizeof(syscall.Timespec{})))),
	}

	s.live.RecvBuffer = granted

	s.iov.Base = &s.buf[0]
	s.iov.SetLen(len(s.buf))

	s.msg.Iov = &s.iov
	s.msg.Iovlen = 1
	s.msg.Control = &s.oob[0]

	s.recv = s.recvmsg

	return s, nil
}

func setupLive(fd, ifindex int, proto uint16, cfg LiveConfig) (int, error) {
	err := syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetIgnoreOutgoing, 1)
	if err != nil {
		return 0, fmt.Errorf("ignoring outgoing packets (needs Linux 4.20+): %w", err)
	}

	// Ask the kernel to attach its receive timestamp to every packet.
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMPNS, 1); err != nil {
		return 0, fmt.Errorf("enabling kernel timestamps: %w", err)
	}

	if cfg.RecvBuffer > 0 {
		// SO_RCVBUFFORCE may exceed net.core.rmem_max but needs
		// CAP_NET_ADMIN; fall back to the capped option without it.
		err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, cfg.RecvBuffer)
		if err != nil {
			err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, cfg.RecvBuffer)
		}
		if err != nil {
			return 0, fmt.Errorf("setting receive buffer: %w", err)
		}
	}

	granted, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0, fmt.Errorf("reading receive buffer size: %w", err)
	}

	if cfg.Promiscuous {
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
			return 0, fmt.Errorf("enabling promiscuous mode: %w", errno)
		}
	}

	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  ifindex,
	}); err != nil {
		return 0, fmt.Errorf("binding: %w", err)
	}

	return granted, syscall.SetNonblock(fd, true)
}

// packetMreq mirrors struct packet_mreq from <linux/if_packet.h>.
type packetMreq struct {
	ifindex int32
	typ     uint16
	alen    uint16
	address [8]byte
}

// tpacketStats mirrors struct tpacket_stats from <linux/if_packet.h>.
type tpacketStats struct {
	packets uint32
	drops   uint32
}

// recvmsg reads one frame and its control data. It is called by the
// runtime poller; returning false means "not ready, wait and call again".
func (s *LiveSource) recvmsg(fd uintptr) bool {
	s.msg.SetControllen(len(s.oob))

	n, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, fd, uintptr(unsafe.Pointer(&s.msg)), syscall.MSG_DONTWAIT)

	switch errno {
	case 0:
		s.n, s.oobn, s.rerr = int(n), int(s.msg.Controllen), nil
		return true
	case syscall.EAGAIN, syscall.EINTR:
		return false
	}

	s.rerr = errno

	return true
}

// SetDeadline makes Next return ErrTimeout if no packet has arrived by t.
// The zero time removes the deadline.
func (s *LiveSource) SetDeadline(t time.Time) error {
	return s.file.SetReadDeadline(t)
}

// Next blocks until the next IPv4 or IPv6 packet arrives. It returns
// ErrTimeout when the deadline set with SetDeadline passes first, and
// ErrClosed once Close has been called.
func (s *LiveSource) Next() (Packet, error) {
	for {
		if err := s.raw.Read(s.recv); err != nil {
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				return Packet{}, ErrTimeout
			case errors.Is(err, os.ErrClosed):
				return Packet{}, ErrClosed
			}
			return Packet{}, err
		}

		if s.rerr != nil {
			return Packet{}, fmt.Errorf("capture: %w", s.rerr)
		}

		src, ok := parse(LinkTypeEthernet, s.buf[:s.n])
		if !ok {
			s.stats.Skipped++
			continue
		}

		s.stats.Packets++

		return Packet{
			Src:       src,
			Timestamp: s.timestamp(),
			Length:    uint32(s.n),
		}, nil
	}
}

// timestamp returns the kernel's receive time for the frame just read,
// from the SCM_TIMESTAMPNS control message, or the current time if the
// frame carried none.
func (s *LiveSource) timestamp() time.Time {
	hdrLen := syscall.CmsgLen(0)

	if s.oobn >= hdrLen+int(unsafe.Sizeof(syscall.Timespec{})) {
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&s.oob[0]))

		if h.Level == syscall.SOL_SOCKET && h.Type == syscall.SCM_TIMESTAMPNS {
			ts := (*syscall.Timespec)(unsafe.Pointer(&s.oob[hdrLen]))
			s.live.KernelStamps++

			return time.Unix(ts.Unix())
		}
	}

	s.live.FallbackStamps++

	return time.Now()
}

func (s *LiveSource) Stats() Stats {
	return s.stats
}

// LiveStats returns the kernel's view of the capture so far.
//
// Reading the kernel counters resets them, so they are accumulated here;
// LiveStats must therefore be the only reader.
func (s *LiveSource) LiveStats() (LiveStats, error) {
	var (
		st     tpacketStats
		errno  syscall.Errno
		length = uint32(unsafe.Sizeof(st))
	)

	err := s.raw.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_PACKET,
			syscall.PACKET_STATISTICS,
			uintptr(unsafe.Pointer(&st)),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
	})
	if err == nil && errno != 0 {
		err = errno
	}
	if err != nil {
		return s.live, fmt.Errorf("capture: reading socket statistics: %w", err)
	}

	s.live.KernelTotal += uint64(st.packets)
	s.live.KernelDropped += uint64(st.drops)

	return s.live, nil
}

// Close stops the capture. It may be called from another goroutine to
// unblock a pending Next.
func (s *LiveSource) Close() error {
	return s.file.Close()
}

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}
