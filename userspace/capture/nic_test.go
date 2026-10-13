package capture

import (
	"os"
	"path/filepath"
	"testing"
)

const procNetDevSample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     789    0    0    0     0          0         0   123456     789    0    0    0     0       0          0
  ens7: 9876543210 12345678    1    2    3     4          0        99 5555 66    0    0    0     0       0          0
`

// mlx5 virtual functions report counters like these.
const ethtoolSample = `NIC statistics:
     rx_packets: 12345000
     rx_bytes: 9876543000
     rx_out_of_buffer: 42
     rx_vport_unicast_packets: 12345100
     ch0_arm: 7
     link_state: up
`

func TestParseProcNetDev(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev")
	os.WriteFile(path, []byte(procNetDevSample), 0o644)

	f, _ := os.Open(path)
	defer f.Close()

	c := NICCounters{}
	if err := parseProcNetDev(f, "ens7", c); err != nil {
		t.Fatal(err)
	}

	for key, want := range map[string]uint64{
		"dev.rx_bytes":     9876543210,
		"dev.rx_packets":   12345678,
		"dev.rx_drop":      2,
		"dev.rx_fifo":      3,
		"dev.rx_multicast": 99,
		"dev.tx_packets":   66,
	} {
		if c[key] != want {
			t.Errorf("%s = %d, want %d", key, c[key], want)
		}
	}

	f.Seek(0, 0)
	if err := parseProcNetDev(f, "ens8", NICCounters{}); err == nil {
		t.Error("a missing interface was accepted")
	}
}

func TestParseEthtool(t *testing.T) {
	c := NICCounters{}
	parseEthtool(ethtoolSample, c)

	if c["ethtool.rx_out_of_buffer"] != 42 || c["ethtool.rx_packets"] != 12345000 {
		t.Errorf("counters = %v", c)
	}

	// Non-numeric lines and the header are ignored.
	if _, ok := c["ethtool.link_state"]; ok {
		t.Error("a non-numeric value was kept")
	}
	if len(c) != 5 {
		t.Errorf("kept %d counters, want 5", len(c))
	}
}

func TestNICCounters_Delta(t *testing.T) {
	start := NICCounters{"dev.rx_packets": 100, "dev.rx_drop": 5, "ethtool.reset": 50, "only.start": 1}
	end := NICCounters{"dev.rx_packets": 1100, "dev.rx_drop": 5, "ethtool.reset": 3, "only.end": 1}

	d, err := start.Delta(end)

	if d["dev.rx_packets"] != 1000 || d["dev.rx_drop"] != 0 {
		t.Errorf("delta = %v", d)
	}
	if _, ok := d["ethtool.reset"]; ok || err == nil {
		t.Error("a counter that went backwards was not reported")
	}
	if len(d) != 2 {
		t.Errorf("delta has %d keys, want 2", len(d))
	}
}
