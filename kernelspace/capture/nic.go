// Package capture reads the receiving interface's counters, so a run can
// show how many packets were lost before XDP saw them.
package capture

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// NICCounters is a snapshot of an interface's counters, keyed by source:
// "dev.<field>" from /proc/net/dev and "ethtool.<name>" from ethtool -S.
//
// The two sources answer different questions. /proc/net/dev counts what
// the driver handed to the kernel and what it dropped on the way; the
// ethtool counters are driver-specific and include what the card itself
// dropped, for example for lack of receive descriptors, before the kernel
// ever saw it. Comparing them with the packets XDP counted shows at
// which layer packets were lost.
type NICCounters map[string]uint64

// procNetDevFields names the columns of /proc/net/dev in order.
var procNetDevFields = []string{
	"rx_bytes", "rx_packets", "rx_errs", "rx_drop", "rx_fifo", "rx_frame", "rx_compressed", "rx_multicast",
	"tx_bytes", "tx_packets", "tx_errs", "tx_drop", "tx_fifo", "tx_colls", "tx_carrier", "tx_compressed",
}

// ReadNICCounters snapshots the interface's counters. The /proc/net/dev
// counters are required and their failure is returned as err. ethtool is
// optional, since it may not be installed or may not support the driver;
// its failure is returned as warning, with the /proc/net/dev counters
// still filled in.
func ReadNICCounters(iface string) (c NICCounters, warning, err error) {
	c = NICCounters{}

	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil, nil, fmt.Errorf("capture: reading interface counters: %w", err)
	}
	defer f.Close()

	if err := parseProcNetDev(f, iface, c); err != nil {
		return nil, nil, err
	}

	out, err := exec.Command("ethtool", "-S", iface).Output()
	if err != nil {
		return c, fmt.Errorf("capture: ethtool -S %s: %w", iface, err), nil
	}

	parseEthtool(string(out), c)

	return c, nil, nil
}

func parseProcNetDev(f *os.File, iface string, c NICCounters) error {
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}

		fields := strings.Fields(rest)
		if len(fields) < len(procNetDevFields) {
			return fmt.Errorf("capture: /proc/net/dev line for %s has %d fields", iface, len(fields))
		}

		for i, key := range procNetDevFields {
			v, err := strconv.ParseUint(fields[i], 10, 64)
			if err != nil {
				return fmt.Errorf("capture: /proc/net/dev %s %s: %w", iface, key, err)
			}

			c["dev."+key] = v
		}

		return nil
	}

	if err := sc.Err(); err != nil {
		return err
	}

	return fmt.Errorf("capture: interface %s not in /proc/net/dev", iface)
}

// parseEthtool reads the "name: value" lines of ethtool -S output and
// keeps the numeric ones.
func parseEthtool(out string, c NICCounters) {
	for _, line := range strings.Split(out, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		v, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		if err != nil {
			continue
		}

		c["ethtool."+strings.TrimSpace(name)] = v
	}
}

// Delta returns end minus start for every counter present in both. A
// counter that went backwards, as after a driver reset, is reported as
// an error rather than as a huge unsigned difference.
func (start NICCounters) Delta(end NICCounters) (NICCounters, error) {
	d := NICCounters{}

	var errs []error

	for k, s := range start {
		e, ok := end[k]
		if !ok {
			continue
		}

		if e < s {
			errs = append(errs, fmt.Errorf("%s went from %d to %d", k, s, e))
			continue
		}

		d[k] = e - s
	}

	return d, errors.Join(errs...)
}
