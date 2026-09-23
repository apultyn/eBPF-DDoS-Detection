package countmin

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestNew_ValidatesParameters(t *testing.T) {
	tests := []struct {
		name    string
		epsilon float64
		delta   float64
		wantErr bool
	}{
		{"valid parameters", 0.001, 0.01, false},
		{"epsilon zero", 0, 0.01, true},
		{"epsilon negative", -0.1, 0.01, true},
		{"epsilon at least one", 1, 0.01, true},
		{"delta zero", 0.001, 0, true},
		{"delta negative", 0.001, -0.1, true},
		{"delta at least one", 0.001, 1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := New(tt.epsilon, tt.delta)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("New(%v, %v) = nil error, want error", tt.epsilon, tt.delta)
				}
				return
			}
			if err != nil {
				t.Fatalf("New(%v, %v) returned unexpected error: %v", tt.epsilon, tt.delta, err)
			}
			if s.Width() == 0 || s.Depth() == 0 {
				t.Fatalf("New(%v, %v) produced zero-sized sketch: width=%d depth=%d", tt.epsilon, tt.delta, s.Width(), s.Depth())
			}
		})
	}
}

func TestSketch_AddAndEstimate_SingleKey(t *testing.T) {
	s := NewWithDimensions(64, 4)

	s.Add("10.0.0.1", 5)
	s.Add("10.0.0.1", 3)

	if got := s.Estimate("10.0.0.1"); got != 8 {
		t.Errorf("Estimate(10.0.0.1) = %d, want 8", got)
	}
	if got := s.Estimate("10.0.0.2"); got != 0 {
		t.Errorf("Estimate(10.0.0.2) = %d, want 0 for an unseen key", got)
	}
}

func TestSketch_NeverUndercounts(t *testing.T) {
	// A Count-Min Sketch may overestimate due to collisions but must
	// never report a frequency below the true count for a key that
	// was actually added. This test uses a deliberately small width
	// relative to the number of distinct keys to make collisions
	// likely, which is exactly the condition that would expose an
	// undercount bug.
	const width, depth = 16, 4
	s := NewWithDimensions(width, depth)

	rng := rand.New(rand.NewSource(1))
	trueCounts := make(map[string]uint64)
	for i := 0; i < 500; i++ {
		key := fmt.Sprintf("10.0.%d.%d", rng.Intn(20), rng.Intn(20))
		delta := uint64(rng.Intn(5) + 1)
		s.Add(key, delta)
		trueCounts[key] += delta
	}

	for key, want := range trueCounts {
		if got := s.Estimate(key); got < want {
			t.Errorf("Estimate(%q) = %d, want >= %d (true count) — sketch undercounted", key, got, want)
		}
	}
}

func TestSketch_ErrorBound(t *testing.T) {
	// With epsilon/delta-derived dimensions, the expected overestimate
	// for any key should stay within epsilon * total with high
	// probability. This is a statistical property, not an exact
	// guarantee, so the test uses a generous margin to avoid flaking
	// on the rare unlucky hash collision pattern.
	const epsilon, delta = 0.01, 0.01
	s, err := New(epsilon, delta)
	if err != nil {
		t.Fatalf("New(%v, %v) returned error: %v", epsilon, delta, err)
	}

	rng := rand.New(rand.NewSource(42))
	trueCounts := make(map[string]uint64)
	const numKeys = 200
	const totalInserts = 20000
	for i := 0; i < totalInserts; i++ {
		key := fmt.Sprintf("key-%d", rng.Intn(numKeys))
		s.Add(key, 1)
		trueCounts[key]++
	}

	bound := epsilon * float64(s.Total())
	for key, want := range trueCounts {
		got := s.Estimate(key)
		if overestimate := float64(got) - float64(want); overestimate > bound {
			t.Errorf("Estimate(%q) = %d, true count = %d, overestimate %.1f exceeds error bound %.1f",
				key, got, want, overestimate, bound)
		}
	}
}

func TestSketch_Reset(t *testing.T) {
	s := NewWithDimensions(32, 4)
	s.Add("10.0.0.1", 10)

	if s.Total() == 0 {
		t.Fatal("expected non-zero total before Reset")
	}

	s.Reset()

	if got := s.Estimate("10.0.0.1"); got != 0 {
		t.Errorf("Estimate(10.0.0.1) after Reset = %d, want 0", got)
	}
	if s.Total() != 0 {
		t.Errorf("Total() after Reset = %d, want 0", s.Total())
	}
}

func BenchmarkAdd(b *testing.B) {
	s := NewWithDimensions(2048, 5)
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Add(keys[i%len(keys)], 1)
	}
}

func BenchmarkEstimate(b *testing.B) {
	s := NewWithDimensions(2048, 5)
	keys := make([]string, 1000)
	for i := range keys {
		keys[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		s.Add(keys[i], 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Estimate(keys[i%len(keys)])
	}
}