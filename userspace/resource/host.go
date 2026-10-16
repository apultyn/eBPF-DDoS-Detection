package resource

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// tick is the unit of the CPU times in /proc/stat. They are counted in
// USER_HZ, which Linux fixes at 100 for user space whatever the kernel's
// own HZ, so the resolution is 10 ms per core.
const tick = 10 * time.Millisecond

// Columns of a cpu line in /proc/stat, in order. guest and guest_nice
// follow but are already counted in user and nice, so they are not read.
const (
	statUser = iota
	statNice
	statSystem
	statIdle
	statIOWait
	statIRQ
	statSoftIRQ
	statSteal
	statFields
)

// cpuTicks is one cpu line of /proc/stat: cumulative ticks per column.
type cpuTicks [statFields]uint64

// hostTimes is a snapshot of /proc/stat: the machine as a whole, and each
// online core in the order listed.
type hostTimes struct {
	all   cpuTicks
	cores []coreTicks
}

type coreTicks struct {
	id    int
	ticks cpuTicks
}

// cpuDelta is the time spent in each state between two snapshots.
type cpuDelta struct {
	busy, total, softirq time.Duration
}

// delta returns the time spent since prev. A column that went backwards
// counts as zero: iowait is known to do so on some kernels.
func (t cpuTicks) delta(prev cpuTicks) cpuDelta {
	var d [statFields]time.Duration
	for i := range t {
		if t[i] > prev[i] {
			d[i] = time.Duration(t[i]-prev[i]) * tick
		}
	}

	busy := d[statUser] + d[statNice] + d[statSystem] + d[statIRQ] + d[statSoftIRQ] + d[statSteal]

	return cpuDelta{
		busy:    busy,
		total:   busy + d[statIdle] + d[statIOWait],
		softirq: d[statSoftIRQ],
	}
}

// hostDelta fills in the host fields of out with the time spent since
// prev. Cores are matched by number, so a core that went offline or came
// online in between is left out of the busiest-core figure.
func hostDelta(out *Sample, cur, prev hostTimes) {
	all := cur.all.delta(prev.all)

	out.HostBusy = all.busy
	out.HostTotal = all.total
	out.HostSoftirq = all.softirq
	out.HostMaxCoreShare = 0
	out.HostMeasured = true

	// Both lists are in ascending core order, as /proc/stat lists them.
	j := 0
	for _, c := range cur.cores {
		for j < len(prev.cores) && prev.cores[j].id < c.id {
			j++
		}
		if j == len(prev.cores) || prev.cores[j].id != c.id {
			continue
		}

		d := c.ticks.delta(prev.cores[j].ticks)
		if d.total > 0 {
			out.HostMaxCoreShare = max(out.HostMaxCoreShare, float64(d.busy)/float64(d.total))
		}
	}
}

var errNoCPULine = errors.New("resource: no cpu line in /proc/stat")

// parseProcStat reads the cpu lines of /proc/stat into t, reusing its core
// slice.
func parseProcStat(r io.Reader, t *hostTimes) error {
	t.cores = t.cores[:0]
	found := false

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") {
			// The cpu lines come first; nothing after them is needed.
			if found {
				break
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 1+statIdle+1 {
			return fmt.Errorf("resource: short /proc/stat line %q", line)
		}

		var ticks cpuTicks
		for i := 0; i < statFields && 1+i < len(fields); i++ {
			v, err := strconv.ParseUint(fields[1+i], 10, 64)
			if err != nil {
				return fmt.Errorf("resource: /proc/stat line %q: %w", line, err)
			}
			ticks[i] = v
		}

		if fields[0] == "cpu" {
			t.all = ticks
			found = true
			continue
		}

		id, err := strconv.Atoi(strings.TrimPrefix(fields[0], "cpu"))
		if err != nil {
			return fmt.Errorf("resource: /proc/stat line %q: %w", line, err)
		}
		t.cores = append(t.cores, coreTicks{id: id, ticks: ticks})
	}

	if err := sc.Err(); err != nil {
		return fmt.Errorf("resource: reading /proc/stat: %w", err)
	}

	if !found {
		return errNoCPULine
	}

	return nil
}
