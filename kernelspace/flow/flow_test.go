package flow

import "testing"

func TestKey_RoundTrip(t *testing.T) {
	tests := []struct {
		in  string
		is4 bool
	}{
		{"192.168.1.100", true},
		{"0.0.0.0", true},
		{"2001:db8::bad", false},
		{"::1", false},
	}

	for _, tt := range tests {
		k := MustParse(tt.in)

		if got := k.String(); got != tt.in {
			t.Errorf("MustParse(%q).String() = %q", tt.in, got)
		}
		if got := k.Is4(); got != tt.is4 {
			t.Errorf("MustParse(%q).Is4() = %v, want %v", tt.in, got, tt.is4)
		}
	}
}

func TestFromHeaderBytes_MatchesParse(t *testing.T) {
	if got, want := FromIPv4([]byte{192, 168, 1, 100}), MustParse("192.168.1.100"); got != want {
		t.Errorf("FromIPv4 = %v, want %v", got, want)
	}

	v6 := MustParse("2001:db8::bad")
	if got := FromIPv6(v6[:]); got != v6 {
		t.Errorf("FromIPv6 = %v, want %v", got, v6)
	}
}

func TestHash_NoCollisionsAcrossIPv4(t *testing.T) {
	// The fold is a bijection in the last word, so every IPv4 key must
	// hash uniquely. Checked over a /16 to keep the test fast.
	seen := make(map[uint32]bool, 1<<16)

	for i := 0; i < 1<<16; i++ {
		h := FromIPv4([]byte{10, 0, byte(i >> 8), byte(i)}).Hash()

		if seen[h] {
			t.Fatalf("hash collision at 10.0.%d.%d", i>>8, i&0xff)
		}
		seen[h] = true
	}
}
