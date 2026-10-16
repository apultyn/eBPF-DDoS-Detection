package memsource

import (
	"errors"
	"fmt"
	"testing"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

var (
	ipA = flow.MustParse("10.0.0.1")
	ipB = flow.MustParse("10.0.0.2")
)

func TestSlotsAreIndependent(t *testing.T) {
	s := New()

	s.Add(0, ipA, 5, 500)
	s.Add(1, ipA, 2, 200)
	s.Add(0, ipA, 3, 300)

	if n, _ := s.Count(0, ipA); n != 8 {
		t.Errorf("slot 0 count = %d, want 8", n)
	}
	if n, _ := s.Count(1, ipA); n != 2 {
		t.Errorf("slot 1 count = %d, want 2", n)
	}
	if p, b, _ := s.Totals(0); p != 8 || b != 800 {
		t.Errorf("slot 0 totals = %d, %d; want 8, 800", p, b)
	}
}

func TestCandidatesSortedAndCapped(t *testing.T) {
	s := New()

	for i := 0; i < heavykeeper.K+5; i++ {
		s.Add(2, flow.MustParse(fmt.Sprintf("10.1.0.%d", i)), uint32(i+1), 0)
	}

	c, err := s.Candidates(2)
	if err != nil {
		t.Fatal(err)
	}

	if len(c) != heavykeeper.K {
		t.Fatalf("%d candidates, want %d", len(c), heavykeeper.K)
	}
	for i := 1; i < len(c); i++ {
		if c[i].Count > c[i-1].Count {
			t.Fatalf("not sorted: %v", c)
		}
	}
	if c[0].Count != uint32(heavykeeper.K+5) {
		t.Errorf("largest = %d, want %d", c[0].Count, heavykeeper.K+5)
	}
}

func TestResetClearsOnlyThatSlotAndIsRecorded(t *testing.T) {
	s := New()

	s.Add(0, ipA, 1, 10)
	s.Add(3, ipB, 1, 10)

	if err := s.Reset(3); err != nil {
		t.Fatal(err)
	}

	if n, _ := s.Count(3, ipB); n != 0 {
		t.Errorf("slot 3 not cleared: %d", n)
	}
	if c, _ := s.Candidates(3); len(c) != 0 {
		t.Errorf("slot 3 candidates not cleared: %v", c)
	}
	if n, _ := s.Count(0, ipA); n != 1 {
		t.Errorf("slot 0 touched by Reset(3): %d", n)
	}
	if len(s.Resets) != 1 || s.Resets[0] != 3 {
		t.Errorf("Resets = %v, want [3]", s.Resets)
	}
}

func TestErrors(t *testing.T) {
	s := New()

	if _, err := s.Count(heavykeeper.Slots, ipA); err == nil {
		t.Error("out-of-range slot accepted")
	}

	boom := errors.New("map read failed")
	s.Err = boom

	if _, err := s.Count(0, ipA); !errors.Is(err, boom) {
		t.Errorf("Count error = %v, want %v", err, boom)
	}
	if _, err := s.Candidates(0); !errors.Is(err, boom) {
		t.Errorf("Candidates error = %v, want %v", err, boom)
	}
	if _, _, err := s.Totals(0); !errors.Is(err, boom) {
		t.Errorf("Totals error = %v, want %v", err, boom)
	}
	if err := s.Reset(0); !errors.Is(err, boom) {
		t.Errorf("Reset error = %v, want %v", err, boom)
	}
}
