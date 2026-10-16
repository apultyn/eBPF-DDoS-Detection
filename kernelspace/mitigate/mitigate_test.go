package mitigate

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/epoch"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
)

const length = epoch.DefaultLength

// fakeMap is an in-memory blocklist. drop simulates XDP dropping packets.
type fakeMap struct {
	entries map[flow.Key]heavykeeper.BlockEntry

	blockErr   error
	unblockErr error
	entriesErr error
}

func newFakeMap() *fakeMap {
	return &fakeMap{entries: make(map[flow.Key]heavykeeper.BlockEntry)}
}

func (f *fakeMap) Block(k flow.Key, now time.Time) error {
	if f.blockErr != nil {
		return f.blockErr
	}
	f.entries[k] = heavykeeper.BlockEntry{IP: k, LastSeen: now}
	return nil
}

func (f *fakeMap) Unblock(k flow.Key) error {
	if f.unblockErr != nil {
		return f.unblockErr
	}
	delete(f.entries, k)
	return nil
}

func (f *fakeMap) Entries() ([]heavykeeper.BlockEntry, error) {
	if f.entriesErr != nil {
		return nil, f.entriesErr
	}
	out := make([]heavykeeper.BlockEntry, 0, len(f.entries))
	for _, e := range f.entries {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeMap) drop(k flow.Key, packets uint64, at time.Time) {
	e := f.entries[k]
	e.Drops += packets
	e.LastSeen = at
	f.entries[k] = e
}

func (f *fakeMap) has(k flow.Key) bool {
	_, ok := f.entries[k]
	return ok
}

var (
	a = flow.MustParse("10.0.0.1")
	b = flow.MustParse("10.0.0.2")
	c = flow.MustParse("10.0.0.3")
	d = flow.MustParse("2001:db8::4")
)

// t0 is the start of a window, so t0 + n*length is the start of the n-th
// window after it.
var t0 = epoch.Epoch(4_000_000).Start(length)

func newMitigator(t *testing.T, cfg Config, m Map) *Mitigator {
	t.Helper()

	if cfg.WindowLength == 0 {
		cfg.WindowLength = length
	}

	mt, err := New(cfg, m)
	if err != nil {
		t.Fatal(err)
	}

	return mt
}

func TestBlock_AddsFlaggedSources(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10}, m)

	ok, err := mt.Block([]flow.Key{a, b}, t0)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(ok, []bool{true, true}) || !m.has(a) || !m.has(b) {
		t.Errorf("ok = %v, map = %v; want a and b blocked", ok, m.entries)
	}

	if got := m.entries[a].LastSeen; !got.Equal(t0) {
		t.Errorf("a last seen %v, want the block time %v", got, t0)
	}

	if st := mt.Stats(); st.Blocked != 2 || st.Active != 2 || st.Peak != 2 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestBlock_FlaggedAgainRefreshesTTL(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10, TTL: 10 * time.Second}, m)

	mt.Block([]flow.Key{a}, t0)
	m.drop(a, 50, t0.Add(time.Second))

	if _, err := mt.Block([]flow.Key{a}, t0.Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}

	// The kernel entry is left alone, so its drops are kept.
	if m.entries[a].Drops != 50 {
		t.Errorf("drops = %d after refresh, want 50", m.entries[a].Drops)
	}

	// 12 s after the first block but only 4 s after the refresh.
	mt.Expire(t0.Add(12 * time.Second))
	if !m.has(a) {
		t.Fatal("a expired although it was flagged again 4 s ago")
	}

	mt.Expire(t0.Add(18 * time.Second))
	if m.has(a) {
		t.Fatal("a still blocked 10 s after it was last flagged")
	}

	if st := mt.Stats(); st.Blocked != 1 || st.Refreshed != 1 || st.Expired != 1 || st.Active != 0 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestExpire_ZeroTTLNeverExpires(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10}, m)

	mt.Block([]flow.Key{a}, t0)
	mt.Expire(t0.Add(24 * time.Hour))

	if !m.has(a) {
		t.Error("a expired with TTL 0")
	}
}

func TestBlock_AllowlistIsNeverBlocked(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10, Allow: []flow.Key{b}}, m)

	ok, _ := mt.Block([]flow.Key{a, b}, t0)

	if !slices.Equal(ok, []bool{true, false}) || m.has(b) {
		t.Errorf("ok = %v, map = %v; want b left alone", ok, m.entries)
	}

	if st := mt.Stats(); st.Allowlisted != 1 {
		t.Errorf("Stats = %+v, want one allowlisted", st)
	}
}

func TestBlock_EvictsMostStaleWhenFull(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 3}, m)

	mt.Block([]flow.Key{a, b, c}, t0)

	// a and c were last seen in the same, oldest window; c dropped fewer.
	// b is still active two windows later.
	m.drop(a, 900, t0.Add(length/4))
	m.drop(c, 10, t0.Add(length/2))
	m.drop(b, 5, t0.Add(2*length))

	if _, err := mt.Block([]flow.Key{d}, t0.Add(3*length)); err != nil {
		t.Fatal(err)
	}

	if m.has(c) || !m.has(a) || !m.has(b) || !m.has(d) {
		t.Errorf("map = %v; want c evicted for d", m.entries)
	}

	if st := mt.Stats(); st.Evicted != 1 || st.Active != 3 || st.Peak != 3 {
		t.Errorf("Stats = %+v", st)
	}
}

func TestBlock_NeverEvictsASourceFlaggedInTheSameCall(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 2}, m)

	mt.Block([]flow.Key{a, b}, t0)

	// a is the most stale, but it is flagged again together with c.
	m.drop(b, 1, t0.Add(2*length))

	mt.Block([]flow.Key{a, c}, t0.Add(3*length))

	if !m.has(a) || !m.has(c) || m.has(b) {
		t.Errorf("map = %v; want b evicted, a kept", m.entries)
	}
}

func TestBlock_MoreFlaggedThanCapacityKeepsTheLargest(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 2}, m)

	ok, err := mt.Block([]flow.Key{a, b, c}, t0)
	if err != nil {
		t.Fatal(err)
	}

	if !slices.Equal(ok, []bool{true, true, false}) || len(m.entries) != 2 {
		t.Errorf("ok = %v, map = %v; want the first two blocked", ok, m.entries)
	}
}

func TestBlock_DuplicateReportedLikeFirst(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10}, m)

	ok, _ := mt.Block([]flow.Key{a, a}, t0)

	if !slices.Equal(ok, []bool{true, true}) {
		t.Errorf("ok = %v", ok)
	}
	if st := mt.Stats(); st.Blocked != 1 {
		t.Errorf("Stats = %+v, want a blocked once", st)
	}
}

func TestBlock_MapErrorsAreCountedNotFatal(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10}, m)

	boom := errors.New("map full")
	m.blockErr = boom

	ok, err := mt.Block([]flow.Key{a, b}, t0)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}

	if !slices.Equal(ok, []bool{false, false}) {
		t.Errorf("ok = %v, want nothing blocked", ok)
	}

	if st := mt.Stats(); st.Errors != 2 || st.Active != 0 {
		t.Errorf("Stats = %+v", st)
	}

	// Once the map works again, the sources can be blocked.
	m.blockErr = nil
	if ok, _ := mt.Block([]flow.Key{a}, t0); !ok[0] {
		t.Error("a not blocked after the map recovered")
	}
}

func TestExpire_FailedUnblockIsRetried(t *testing.T) {
	m := newFakeMap()
	mt := newMitigator(t, Config{Capacity: 10, TTL: time.Second}, m)

	mt.Block([]flow.Key{a}, t0)

	m.unblockErr = errors.New("busy")
	if err := mt.Expire(t0.Add(2 * time.Second)); err == nil {
		t.Fatal("no error from a failed unblock")
	}

	m.unblockErr = nil
	if err := mt.Expire(t0.Add(3 * time.Second)); err != nil || m.has(a) {
		t.Errorf("err = %v, map = %v; want a removed on retry", err, m.entries)
	}
}

func TestChooseVictims(t *testing.T) {
	entries := []heavykeeper.BlockEntry{
		{IP: a, LastSeen: t0.Add(2 * length), Drops: 1},
		{IP: b, LastSeen: t0.Add(length / 3), Drops: 500},
		{IP: c, LastSeen: t0.Add(length / 2), Drops: 20}, // same window as b, fewer drops
		{IP: d, LastSeen: t0.Add(length), Drops: 0},
	}

	got := chooseVictims(entries, 3, length, map[flow.Key]struct{}{d: {}})
	want := []flow.Key{c, b, a}

	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got := chooseVictims(entries, 10, length, nil); len(got) != 4 {
		t.Errorf("asked for more than there are: got %d, want all 4", len(got))
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	for _, cfg := range []Config{
		{Capacity: 0, WindowLength: length},
		{Capacity: 1, WindowLength: 0},
		{Capacity: 1, WindowLength: length, TTL: -time.Second},
	} {
		if _, err := New(cfg, newFakeMap()); err == nil {
			t.Errorf("New(%+v) accepted", cfg)
		}
	}
}
