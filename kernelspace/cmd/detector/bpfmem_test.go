package main

import (
	"errors"
	"strings"
	"testing"
)

// fakeMaps reports the memory of a fixed set of maps, or fails.
type fakeMaps struct {
	maps map[string]uint64
	err  error
}

func (f *fakeMaps) Close() error { return nil }

func (f *fakeMaps) MapMemory() (map[string]uint64, error) {
	return f.maps, f.err
}

func TestReadBPFMemory(t *testing.T) {
	sketch := &fakeMaps{maps: map[string]uint64{"sketch_0": 4096, "slot_stats": 512}}
	blocklist := &fakeMaps{maps: map[string]uint64{"blocklist_map": 1000}}

	byName, total, err := readBPFMemory(sketch, blocklist)
	if err != nil {
		t.Fatal(err)
	}

	if total != 5608 || len(byName) != 3 || byName["blocklist_map"] != 1000 {
		t.Errorf("got %v, total %d; want the three maps, 5608 bytes", byName, total)
	}

	if _, _, err := readBPFMemory(sketch, &fakeMaps{err: errors.New("boom")}); err == nil {
		t.Error("an unreadable map gave no error")
	}
}

func TestBPFMemory(t *testing.T) {
	maps := &fakeMaps{maps: map[string]uint64{"sketch_0": 4096, "blocklist_map": 1000}}

	got := bpfMemory(5096, nil, maps)
	if got.TotalBytes != 5096 || got.StartTotalBytes != 5096 || len(got.Maps) != 2 || got.Warnings != nil {
		t.Errorf("unchanged maps: %+v", got)
	}

	// The maps are preallocated, so a change is worth a warning.
	got = bpfMemory(4096, nil, maps)
	if got.TotalBytes != 5096 || len(got.Warnings) != 1 || !strings.Contains(got.Warnings[0], "from 4096 to 5096") {
		t.Errorf("changed maps: %+v", got)
	}

	// No start reading: the end is still reported, without comparing.
	got = bpfMemory(0, errors.New("no memlock"), maps)
	if got.TotalBytes != 5096 || len(got.Warnings) != 1 || !strings.HasPrefix(got.Warnings[0], "start: ") {
		t.Errorf("unreadable at start: %+v", got)
	}

	// No end reading: no map figures, and a warning.
	got = bpfMemory(5096, nil, &fakeMaps{err: errors.New("closed")})
	if got.Maps != nil || got.TotalBytes != 0 || got.StartTotalBytes != 5096 ||
		len(got.Warnings) != 1 || !strings.HasPrefix(got.Warnings[0], "end: ") {
		t.Errorf("unreadable at end: %+v", got)
	}
}
