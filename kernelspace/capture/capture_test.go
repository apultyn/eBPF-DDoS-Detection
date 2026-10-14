package capture

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
)

// Both sources must satisfy the interface on every platform.
var (
	_ Source = (*PcapSource)(nil)
	_ Source = (*LiveSource)(nil)
)

var (
	srcV4 = flow.MustParse("192.0.2.7")
	srcV6 = flow.MustParse("2001:db8::bad")
)

// ipv4Packet builds a minimal IPv4 header with the given source.
func ipv4Packet(src flow.Key) []byte {
	p := make([]byte, 20)
	p[0] = 0x45
	copy(p[12:16], src[12:])

	return p
}

// ipv6Packet builds a minimal IPv6 header with the given source.
func ipv6Packet(src flow.Key) []byte {
	p := make([]byte, 40)
	p[0] = 0x60
	copy(p[8:24], src[:])

	return p
}

func ethernet(etherType uint16, payload []byte, vlans ...uint16) []byte {
	frame := make([]byte, 12) // destination and source MAC

	for _, tpid := range vlans {
		frame = binary.BigEndian.AppendUint16(frame, tpid)
		frame = binary.BigEndian.AppendUint16(frame, 42) // VLAN ID
	}

	frame = binary.BigEndian.AppendUint16(frame, etherType)

	return append(frame, payload...)
}

func TestParse(t *testing.T) {
	sll := make([]byte, 16)
	binary.BigEndian.PutUint16(sll[14:], etherTypeIPv6)

	sll2 := make([]byte, 20)
	binary.BigEndian.PutUint16(sll2[0:], etherTypeIPv4)

	tests := []struct {
		name string
		lt   LinkType
		data []byte
		want flow.Key
		ok   bool
	}{
		{"ethernet ipv4", LinkTypeEthernet, ethernet(etherTypeIPv4, ipv4Packet(srcV4)), srcV4, true},
		{"ethernet ipv6", LinkTypeEthernet, ethernet(etherTypeIPv6, ipv6Packet(srcV6)), srcV6, true},
		{"single vlan", LinkTypeEthernet, ethernet(etherTypeIPv4, ipv4Packet(srcV4), etherTypeVLAN), srcV4, true},
		{"stacked vlans", LinkTypeEthernet, ethernet(etherTypeIPv6, ipv6Packet(srcV6), etherTypeQinQ, etherTypeVLAN), srcV6, true},
		{"raw ipv4", LinkTypeRaw, ipv4Packet(srcV4), srcV4, true},
		{"raw ipv6", LinkTypeRaw, ipv6Packet(srcV6), srcV6, true},
		{"linux sll", LinkTypeLinuxSLL, append(sll, ipv6Packet(srcV6)...), srcV6, true},
		{"linux sll2", LinkTypeLinuxSLL2, append(sll2, ipv4Packet(srcV4)...), srcV4, true},

		{"arp", LinkTypeEthernet, ethernet(0x0806, make([]byte, 28)), flow.Key{}, false},
		{"truncated ethernet", LinkTypeEthernet, make([]byte, 10), flow.Key{}, false},
		{"truncated ipv4", LinkTypeEthernet, ethernet(etherTypeIPv4, ipv4Packet(srcV4)[:15]), flow.Key{}, false},
		{"truncated ipv6", LinkTypeRaw, ipv6Packet(srcV6)[:30], flow.Key{}, false},
		{"version mismatch", LinkTypeEthernet, ethernet(etherTypeIPv4, ipv6Packet(srcV6)), flow.Key{}, false},
		{"raw garbage", LinkTypeRaw, []byte{0x00, 0x01}, flow.Key{}, false},
		{"empty", LinkTypeRaw, nil, flow.Key{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parse(tt.lt, tt.data)
			if ok != tt.ok || got != tt.want {
				t.Errorf("parse = (%v, %v), want (%v, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

type record struct {
	ts      time.Time
	data    []byte
	wireLen uint32
}

// writePcap encodes records as a classic pcap file.
func writePcap(order binary.AppendByteOrder, nanos bool, lt LinkType, records []record) []byte {
	var b []byte

	magic := uint32(pcapMagicMicro)
	if nanos {
		magic = pcapMagicNano
	}

	b = order.AppendUint32(b, magic)
	b = order.AppendUint16(b, 2)
	b = order.AppendUint16(b, 4)
	b = order.AppendUint32(b, 0)
	b = order.AppendUint32(b, 0)
	b = order.AppendUint32(b, 65535)
	b = order.AppendUint32(b, uint32(lt))

	for _, r := range records {
		frac := uint32(r.ts.Nanosecond())
		if !nanos {
			frac /= 1000
		}

		b = order.AppendUint32(b, uint32(r.ts.Unix()))
		b = order.AppendUint32(b, frac)
		b = order.AppendUint32(b, uint32(len(r.data)))
		b = order.AppendUint32(b, r.wireLen)
		b = append(b, r.data...)
	}

	return b
}

func readAll(t *testing.T, s Source) []Packet {
	t.Helper()

	var got []Packet

	for {
		p, err := s.Next()
		if err == io.EOF {
			return got
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}

		got = append(got, p)
	}
}

func TestPcapSource(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 123_456_789)

	records := []record{
		{t0, ethernet(etherTypeIPv4, ipv4Packet(srcV4)), 1500},
		{t0.Add(time.Millisecond), ethernet(0x0806, make([]byte, 28)), 60},
		{t0.Add(2 * time.Millisecond), ethernet(etherTypeIPv6, ipv6Packet(srcV6)), 80},
	}

	tests := []struct {
		name  string
		order binary.AppendByteOrder
		nanos bool
		gzip  bool
	}{
		{"little endian micro", binary.LittleEndian, false, false},
		{"big endian nano", binary.BigEndian, true, false},
		{"gzip", binary.LittleEndian, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := writePcap(tt.order, tt.nanos, LinkTypeEthernet, records)

			if tt.gzip {
				var buf bytes.Buffer
				zw := gzip.NewWriter(&buf)
				zw.Write(raw)
				zw.Close()
				raw = buf.Bytes()
			}

			s, err := newPcapSource(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("newPcapSource: %v", err)
			}

			got := readAll(t, s)

			if len(got) != 2 {
				t.Fatalf("got %d packets, want 2", len(got))
			}

			resolution := time.Microsecond
			if tt.nanos {
				resolution = time.Nanosecond
			}

			want := []Packet{
				{srcV4, t0.Truncate(resolution), 1500},
				{srcV6, t0.Add(2 * time.Millisecond).Truncate(resolution), 80},
			}

			for i := range want {
				if got[i].Src != want[i].Src ||
					!got[i].Timestamp.Equal(want[i].Timestamp) ||
					got[i].Length != want[i].Length {
					t.Errorf("packet %d = %+v, want %+v", i, got[i], want[i])
				}
			}

			if st := s.Stats(); st.Packets != 2 || st.Skipped != 1 {
				t.Errorf("Stats = %+v, want 2 packets and 1 skipped", st)
			}
		})
	}
}

func TestPcapSource_RawIP(t *testing.T) {
	raw := writePcap(binary.LittleEndian, false, LinkTypeRaw, []record{
		{time.Unix(0, 0), ipv6Packet(srcV6), 40},
	})

	s, err := newPcapSource(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("newPcapSource: %v", err)
	}

	if got := readAll(t, s); len(got) != 1 || got[0].Src != srcV6 {
		t.Fatalf("got %+v, want one packet from %v", got, srcV6)
	}
}

func TestPcapSource_TruncatedRecord(t *testing.T) {
	raw := writePcap(binary.LittleEndian, false, LinkTypeRaw, []record{
		{time.Unix(0, 0), ipv4Packet(srcV4), 20},
	})

	s, err := newPcapSource(bytes.NewReader(raw[:len(raw)-5]))
	if err != nil {
		t.Fatalf("newPcapSource: %v", err)
	}

	if _, err := s.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Next = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestPcapSource_RejectsBadInput(t *testing.T) {
	pcapng := binary.BigEndian.AppendUint32(nil, pcapngMagic)
	pcapng = append(pcapng, make([]byte, 20)...)

	tests := []struct {
		name string
		data []byte
		want string
	}{
		{"pcapng", pcapng, "pcapng"},
		{"not pcap", make([]byte, 24), "not a pcap file"},
		{"unsupported link type", writePcap(binary.LittleEndian, false, 105, nil), "unsupported link type"},
		{"short header", []byte{0xd4, 0xc3}, "reading pcap header"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newPcapSource(bytes.NewReader(tt.data))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}

func BenchmarkPcapSource(b *testing.B) {
	frame := ethernet(etherTypeIPv4, ipv4Packet(srcV4))

	records := make([]record, 1024)
	for i := range records {
		records[i] = record{time.Unix(int64(i), 0), frame, 64}
	}

	raw := writePcap(binary.LittleEndian, false, LinkTypeEthernet, records)

	b.ReportAllocs()
	b.ResetTimer()

	var s *PcapSource

	for i := 0; i < b.N; i++ {
		if i%len(records) == 0 {
			b.StopTimer()
			s, _ = newPcapSource(bytes.NewReader(raw))
			b.StartTimer()
		}

		if _, err := s.Next(); err != nil {
			b.Fatal(err)
		}
	}
}
