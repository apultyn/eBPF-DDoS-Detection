package main

import (
	"fmt"
	"io"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/report"
)

// kernelMaps is an open handle to some of the XDP program's maps.
type kernelMaps interface {
	io.Closer

	// MapMemory returns the kernel memory of each map, by its pin name.
	MapMemory() (map[string]uint64, error)
}

// readBPFMemory returns the memory of every map in maps, and its total.
func readBPFMemory(maps ...kernelMaps) (map[string]uint64, uint64, error) {
	all := map[string]uint64{}
	var total uint64

	for _, m := range maps {
		byName, err := m.MapMemory()
		if err != nil {
			return nil, 0, err
		}

		for name, bytes := range byName {
			all[name] = bytes
			total += bytes
		}
	}

	return all, total, nil
}

// bpfMemory reads the memory of the maps at the end of the run. startTotal
// and startErr are the reading taken at the start, which it is checked
// against: the maps are preallocated, so the two should agree.
func bpfMemory(startTotal uint64, startErr error, maps ...kernelMaps) *report.BPFMemory {
	mem := &report.BPFMemory{StartTotalBytes: startTotal}

	if startErr != nil {
		mem.Warnings = append(mem.Warnings, "start: "+startErr.Error())
	}

	byName, total, err := readBPFMemory(maps...)
	if err != nil {
		mem.Warnings = append(mem.Warnings, "end: "+err.Error())
		return mem
	}

	mem.Maps, mem.TotalBytes = byName, total

	if startErr == nil && total != startTotal {
		mem.Warnings = append(mem.Warnings, fmt.Sprintf(
			"map memory changed during the run, from %d to %d bytes", startTotal, total))
	}

	return mem
}
