package capture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// FileStat records what was read from one trace file.
type FileStat struct {
	Path     string   `json:"path"`
	LinkType LinkType `json:"link_type"`
	Packets  uint64   `json:"packets"`
	Skipped  uint64   `json:"skipped"`

	// Truncated reports that the file ended partway through a record.
	// The rest of the file was ignored and reading went on with the next.
	Truncated bool `json:"truncated"`
}

// MultiSource replays several trace files in order as one stream.
//
// Windows carry on across file boundaries, so a gap between two
// recordings is handled like any other pause in traffic. Files are opened
// one at a time, as they are reached.
type MultiSource struct {
	paths []string
	next  int

	cur  *PcapSource
	read []FileStat
}

// OpenFiles prepares the files for reading in the given order. The first
// file is opened immediately so an unreadable input fails early.
func OpenFiles(paths []string) (*MultiSource, error) {
	if len(paths) == 0 {
		return nil, errors.New("capture: no input files")
	}

	m := &MultiSource{paths: paths}

	if err := m.openNext(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *MultiSource) openNext() error {
	path := m.paths[m.next]
	m.next++

	s, err := OpenPcap(path)
	if err != nil {
		return err
	}

	m.cur = s
	m.read = append(m.read, FileStat{Path: path, LinkType: s.LinkType()})

	return nil
}

// Next returns the next IPv4 or IPv6 packet across all files, or io.EOF
// after the last one. A file that ends partway through a record is
// recorded as truncated and skipped past, rather than ending the run.
func (m *MultiSource) Next() (Packet, error) {
	for {
		if m.cur == nil {
			return Packet{}, io.EOF
		}

		p, err := m.cur.Next()
		if err == nil {
			return p, nil
		}

		if err != io.EOF && err != io.ErrUnexpectedEOF {
			return Packet{}, fmt.Errorf("capture: %s: %w", m.CurrentFile(), err)
		}

		m.finishCurrent(err == io.ErrUnexpectedEOF)

		if m.next == len(m.paths) {
			return Packet{}, io.EOF
		}

		if err := m.openNext(); err != nil {
			return Packet{}, err
		}
	}
}

// finishCurrent records the current file's counts and closes it.
func (m *MultiSource) finishCurrent(truncated bool) {
	st := m.cur.Stats()

	fs := &m.read[len(m.read)-1]
	fs.Packets = st.Packets
	fs.Skipped = st.Skipped
	fs.Truncated = truncated

	m.cur.Close()
	m.cur = nil
}

// CurrentFile returns the file being read, or "" once all are done.
func (m *MultiSource) CurrentFile() string {
	if m.cur == nil {
		return ""
	}

	return m.read[len(m.read)-1].Path
}

// Files returns the files opened so far, in reading order, with their
// counts. The entry for a file still being read has the counts so far.
func (m *MultiSource) Files() []FileStat {
	files := slices.Clone(m.read)

	if m.cur != nil {
		st := m.cur.Stats()
		files[len(files)-1].Packets = st.Packets
		files[len(files)-1].Skipped = st.Skipped
	}

	return files
}

// Stats returns the counts summed over all files read so far.
func (m *MultiSource) Stats() Stats {
	var total Stats

	for _, f := range m.Files() {
		total.Packets += f.Packets
		total.Skipped += f.Skipped
	}

	return total
}

// Close closes the file being read, if any.
func (m *MultiSource) Close() error {
	if m.cur == nil {
		return nil
	}

	err := m.cur.Close()
	m.cur = nil

	return err
}

// ExpandPaths turns a list of files and directories into the list of
// files to read. Files are kept where they appear. A directory is
// replaced by the regular, non-hidden files directly inside it, in
// natural order, so that "x_2" comes before "x_10". Subdirectories are
// not entered.
func ExpandPaths(args []string) ([]string, error) {
	var paths []string

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, err
		}

		if !info.IsDir() {
			paths = append(paths, arg)
			continue
		}

		entries, err := os.ReadDir(arg)
		if err != nil {
			return nil, err
		}

		var names []string
		for _, e := range entries {
			if e.Type().IsRegular() && !strings.HasPrefix(e.Name(), ".") {
				names = append(names, e.Name())
			}
		}

		slices.SortFunc(names, naturalCompare)

		for _, name := range names {
			paths = append(paths, filepath.Join(arg, name))
		}
	}

	return paths, nil
}

// naturalCompare orders strings so that runs of digits compare by
// numeric value: "SAT_2" < "SAT_10". Without it the CIC-DDoS2019 files
// would be read as _0, _1, _10, _100, _2, out of time order.
func naturalCompare(a, b string) int {
	for a != "" && b != "" {
		ca, cb := chunk(a), chunk(b)
		a, b = a[len(ca):], b[len(cb):]

		if c := compareChunks(ca, cb); c != 0 {
			return c
		}
	}

	return len(a) - len(b)
}

// chunk returns the leading run of digits, or of non-digits, in s.
func chunk(s string) string {
	digit := isDigit(s[0])

	i := 1
	for i < len(s) && isDigit(s[i]) == digit {
		i++
	}

	return s[:i]
}

func compareChunks(a, b string) int {
	if isDigit(a[0]) && isDigit(b[0]) {
		ta, tb := strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")

		// More significant digits means a larger number.
		if len(ta) != len(tb) {
			return len(ta) - len(tb)
		}
		if c := strings.Compare(ta, tb); c != 0 {
			return c
		}

		// Equal value: fewer leading zeros first, for a stable order.
		return len(a) - len(b)
	}

	return strings.Compare(a, b)
}

func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}
