package capture

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestNaturalCompare(t *testing.T) {
	names := []string{
		"SAT-01-12-2018_10",
		"SAT-01-12-2018_2",
		"SAT-01-12-2018_0",
		"SAT-01-12-2018_100",
		"SAT-01-12-2018_1",
		"SAT-01-12-2018_02",
	}

	slices.SortFunc(names, naturalCompare)

	want := []string{
		"SAT-01-12-2018_0",
		"SAT-01-12-2018_1",
		"SAT-01-12-2018_2",
		"SAT-01-12-2018_02",
		"SAT-01-12-2018_10",
		"SAT-01-12-2018_100",
	}

	if !slices.Equal(names, want) {
		t.Errorf("sorted = %v, want %v", names, want)
	}
}

// writeTrace writes a raw-IP pcap file with one IPv4 packet per second,
// starting at start.
func writeTrace(t *testing.T, path string, start int64, n int) {
	t.Helper()

	records := make([]record, n)
	for i := range records {
		records[i] = record{time.Unix(start+int64(i), 0), ipv4Packet(srcV4), 20}
	}

	if err := os.WriteFile(path, writePcap(binary.LittleEndian, false, LinkTypeRaw, records), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExpandPaths(t *testing.T) {
	dir := t.TempDir()

	for _, name := range []string{"day_10", "day_2", "day_1", ".DS_Store"} {
		writeTrace(t, filepath.Join(dir, name), 0, 1)
	}

	if err := os.Mkdir(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	extra := filepath.Join(t.TempDir(), "extra.pcap")
	writeTrace(t, extra, 0, 1)

	got, err := ExpandPaths([]string{extra, dir})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		extra,
		filepath.Join(dir, "day_1"),
		filepath.Join(dir, "day_2"),
		filepath.Join(dir, "day_10"),
	}

	if !slices.Equal(got, want) {
		t.Errorf("ExpandPaths = %v, want %v", got, want)
	}

	if _, err := ExpandPaths([]string{filepath.Join(dir, "missing")}); err == nil {
		t.Error("a missing path was accepted")
	}
}

func TestMultiSource_ReadsFilesInOrder(t *testing.T) {
	dir := t.TempDir()

	paths := []string{
		filepath.Join(dir, "a"),
		filepath.Join(dir, "b"),
		filepath.Join(dir, "c"),
	}

	writeTrace(t, paths[0], 0, 3)
	writeTrace(t, paths[1], 100, 2)

	// The last file is cut off partway through its final record.
	writeTrace(t, paths[2], 200, 4)
	raw, _ := os.ReadFile(paths[2])
	os.WriteFile(paths[2], raw[:len(raw)-5], 0o644)

	m, err := OpenFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var stamps []int64
	for {
		p, err := m.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}

		stamps = append(stamps, p.Timestamp.Unix())
	}

	want := []int64{0, 1, 2, 100, 101, 200, 201, 202}
	if !slices.Equal(stamps, want) {
		t.Errorf("timestamps = %v, want %v", stamps, want)
	}

	files := m.Files()
	if len(files) != 3 {
		t.Fatalf("Files() has %d entries, want 3", len(files))
	}

	for i, f := range files {
		if f.Path != paths[i] {
			t.Errorf("file %d = %s, want %s", i, f.Path, paths[i])
		}
	}

	if files[0].Packets != 3 || files[1].Packets != 2 || files[2].Packets != 3 {
		t.Errorf("packets per file = %d, %d, %d; want 3, 2, 3", files[0].Packets, files[1].Packets, files[2].Packets)
	}

	if files[0].Truncated || files[1].Truncated || !files[2].Truncated {
		t.Error("only the last file should be marked truncated")
	}

	if st := m.Stats(); st.Packets != 8 {
		t.Errorf("Stats().Packets = %d, want 8", st.Packets)
	}
}

func TestOpenFiles_FailsOnBadFirstFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.csv")
	os.WriteFile(path, []byte("Flow ID,Source IP,Label\n"), 0o644)

	if _, err := OpenFiles([]string{path}); err == nil {
		t.Error("a non-pcap file was accepted")
	}
}
