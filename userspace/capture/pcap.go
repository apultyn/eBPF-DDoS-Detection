package capture

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	pcapMagicMicro = 0xa1b2c3d4
	pcapMagicNano  = 0xa1b23c4d
	pcapngMagic    = 0x0a0d0d0a

	pcapGlobalHeaderLen = 24
	pcapRecordHeaderLen = 16

	// maxRecordLen guards against a corrupt record header asking for an
	// absurd allocation. No real link layer comes close.
	maxRecordLen = 1 << 18
)

// PcapSource replays a classic pcap file, optionally gzip-compressed.
//
// pcapng is not supported. tcpdump writes classic pcap by default; a
// pcapng file can be converted with `editcap -F pcap in.pcapng out.pcap`.
type PcapSource struct {
	file *os.File
	gz   *gzip.Reader
	r    *bufio.Reader

	order    binary.ByteOrder
	nanos    bool
	linkType LinkType

	header [pcapRecordHeaderLen]byte
	buf    []byte

	stats Stats
}

// OpenPcap opens a pcap file for reading. Files compressed with gzip,
// such as .pcap.gz, are detected from their content and decompressed on
// the fly.
func OpenPcap(path string) (*PcapSource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	s, err := newPcapSource(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("capture: %s: %w", path, err)
	}

	s.file = f

	return s, nil
}

func newPcapSource(r io.Reader) (*PcapSource, error) {
	s := &PcapSource{
		r:   bufio.NewReaderSize(r, 1<<20),
		buf: make([]byte, 0, 1<<16),
	}

	// gzip streams start with 1f 8b.
	if magic, err := s.r.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(s.r)
		if err != nil {
			return nil, err
		}

		s.gz = gz
		s.r = bufio.NewReaderSize(gz, 1<<20)
	}

	var hdr [pcapGlobalHeaderLen]byte
	if _, err := io.ReadFull(s.r, hdr[:]); err != nil {
		return nil, fmt.Errorf("reading pcap header: %w", err)
	}

	// The magic number is written in the capturing host's byte order,
	// so reading it both ways tells us which order the file uses.
	switch {
	case binary.LittleEndian.Uint32(hdr[0:4]) == pcapMagicMicro:
		s.order = binary.LittleEndian
	case binary.BigEndian.Uint32(hdr[0:4]) == pcapMagicMicro:
		s.order = binary.BigEndian
	case binary.LittleEndian.Uint32(hdr[0:4]) == pcapMagicNano:
		s.order, s.nanos = binary.LittleEndian, true
	case binary.BigEndian.Uint32(hdr[0:4]) == pcapMagicNano:
		s.order, s.nanos = binary.BigEndian, true
	case binary.BigEndian.Uint32(hdr[0:4]) == pcapngMagic:
		return nil, errors.New("pcapng is not supported, convert with: editcap -F pcap in.pcapng out.pcap")
	default:
		return nil, errors.New("not a pcap file")
	}

	// The upper bits of the link type field carry FCS information.
	s.linkType = LinkType(s.order.Uint32(hdr[20:24]) & 0xffff)
	if !s.linkType.supported() {
		return nil, fmt.Errorf("unsupported link type %d", s.linkType)
	}

	return s, nil
}

// LinkType returns the link type declared in the file header.
func (s *PcapSource) LinkType() LinkType {
	return s.linkType
}

// Next returns the next IPv4 or IPv6 packet in the file, or io.EOF at the
// end. A file that ends partway through a record returns
// io.ErrUnexpectedEOF, which is common for traces cut off by a full disk
// or an interrupted capture.
func (s *PcapSource) Next() (Packet, error) {
	for {
		if _, err := io.ReadFull(s.r, s.header[:]); err != nil {
			return Packet{}, err
		}

		sec := s.order.Uint32(s.header[0:4])
		frac := s.order.Uint32(s.header[4:8])
		capLen := s.order.Uint32(s.header[8:12])
		wireLen := s.order.Uint32(s.header[12:16])

		if capLen > maxRecordLen {
			return Packet{}, fmt.Errorf("capture: record length %d exceeds limit", capLen)
		}

		// Reuse one buffer for every record so reading allocates nothing.
		s.buf = s.buf[:capLen]
		if _, err := io.ReadFull(s.r, s.buf); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return Packet{}, err
		}

		src, ok := parse(s.linkType, s.buf)
		if !ok {
			s.stats.Skipped++
			continue
		}

		s.stats.Packets++

		nsec := int64(frac)
		if !s.nanos {
			nsec *= 1000
		}

		return Packet{
			Src:       src,
			Timestamp: time.Unix(int64(sec), nsec),
			Length:    wireLen,
		}, nil
	}
}

func (s *PcapSource) Stats() Stats {
	return s.stats
}

func (s *PcapSource) Close() error {
	var err error

	if s.gz != nil {
		err = s.gz.Close()
	}

	if s.file != nil {
		err = errors.Join(err, s.file.Close())
	}

	return err
}
