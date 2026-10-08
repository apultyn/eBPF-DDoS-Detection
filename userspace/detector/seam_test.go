package detector

// The seam experiment: does judging a window together with its
// predecessor catch an attack that a window boundary splits in two?
//
// One host that has behaved normally sends a burst of extra packets. The
// burst is placed either entirely inside one window, or split 50/50 across
// a boundary. Each placement is run in both evaluation modes and with both
// count sources, and the attacker's counts and per-IP thresholds in the
// attack windows are reported. Each verdict also records whether its
// threshold came from the quartiles or from the BaseThreshold floor.
//
// Two traffic mixes are used. In "sparse" every flow has a bucket of its
// own, so both count sources are exact and only the window logic is
// tested. In "crowded" thousands of extra flows compete for buckets, which
// is where HeavyKeeper's underestimates and Count-Min's overestimates
// show up.
//
// Run with -v to print the table, and pass an absolute path to also write
// it as CSV:
//
//	go test ./userspace/detector -run TestSeam -v -args -seam.csv=$PWD/seam.csv

import (
	"cmp"
	"encoding/csv"
	"flag"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

var seamCSV = flag.String("seam.csv", "", "write the seam experiment table to this CSV file")

// seamScenario describes the synthetic traffic.
type seamScenario struct {
	Name string

	// Seed makes the background traffic reproducible.
	Seed uint64

	// HeavyHosts send HeavyRate ± HeavyJitter packets per window and are
	// always candidates. The attacker is one more host at the same rate.
	HeavyHosts  int
	HeavyRate   int
	HeavyJitter int

	// LightHosts send LightRate ± LightJitter packets per window. They
	// make up the bulk of the window total but never become candidates.
	LightHosts  int
	LightRate   int
	LightJitter int

	// NormalWindows of background traffic precede the attack, enough to
	// get every history past warm-up; TailWindows follow it.
	NormalWindows int
	TailWindows   int

	// AttackPackets is the size of the burst, on top of the attacker's
	// normal traffic. AttackSpan is how long it lasts.
	AttackPackets int
	AttackSpan    time.Duration
}

var sparseScenario = seamScenario{
	Name:          "sparse",
	Seed:          1,
	HeavyHosts:    8,
	HeavyRate:     100,
	HeavyJitter:   10,
	LightHosts:    200,
	LightRate:     10,
	LightJitter:   3,
	NormalWindows: 40,
	TailWindows:   4,
	AttackPackets: 160,
	AttackSpan:    length / 2,
}

// crowdedScenario adds 8000 light flows, eight per HeavyKeeper bucket row
// and per Count-Min column.
var crowdedScenario = func() seamScenario {
	s := sparseScenario
	s.Name = "crowded"
	s.LightHosts = 8000
	s.LightRate = 2
	s.LightJitter = 1

	return s
}()

type placement int

const (
	// inside places the whole burst in the middle of one window.
	inside placement = iota

	// straddling centres the burst on a boundary, half on each side.
	straddling
)

func (p placement) String() string {
	if p == inside {
		return "inside"
	}

	return "straddling"
}

var attacker = flow.MustParse("198.51.100.66")

// seamTraffic generates the packets, in timestamp order, and returns the
// first of the two windows the attack can touch and the attacker's true
// packet count in every window.
func seamTraffic(s seamScenario, place placement) ([]capture.Packet, int, map[int]uint64) {
	rng := rand.New(rand.NewPCG(s.Seed, 0))

	var packets []capture.Packet
	truth := map[int]uint64{}

	emit := func(src flow.Key, ts time.Time) {
		packets = append(packets, capture.Packet{Src: src, Timestamp: ts, Length: 100})

		if src == attacker {
			truth[int(ts.Sub(t0)/length)]++
		}
	}

	spread := func(n, window int, src flow.Key) {
		start := t0.Add(time.Duration(window) * length)
		for i := 0; i < n; i++ {
			emit(src, start.Add(time.Duration(rng.Int64N(int64(length)))))
		}
	}

	jitter := func(rate, j int) int {
		return rate - j + rng.IntN(2*j+1)
	}

	heavy := make([]flow.Key, s.HeavyHosts)
	for i := range heavy {
		heavy[i] = flow.FromIPv4([]byte{192, 0, 2, byte(10 + i)})
	}

	light := make([]flow.Key, s.LightHosts)
	for i := range light {
		light[i] = flow.FromIPv4([]byte{10, 1, byte(i >> 8), byte(i)})
	}

	total := s.NormalWindows + 2 + s.TailWindows
	for w := 0; w < total; w++ {
		for _, h := range heavy {
			spread(jitter(s.HeavyRate, s.HeavyJitter), w, h)
		}

		spread(jitter(s.HeavyRate, s.HeavyJitter), w, attacker)

		for _, h := range light {
			spread(jitter(s.LightRate, s.LightJitter), w, h)
		}
	}

	attackWindow := s.NormalWindows

	var centre time.Time
	if place == inside {
		centre = t0.Add(time.Duration(attackWindow)*length + length/2)
	} else {
		centre = t0.Add(time.Duration(attackWindow+1) * length)
	}

	// Evenly spaced and symmetric around the centre, so a straddling
	// burst is split exactly in half.
	step := s.AttackSpan / time.Duration(s.AttackPackets)
	first := centre.Add(-s.AttackSpan/2 + step/2)

	for i := 0; i < s.AttackPackets; i++ {
		emit(attacker, first.Add(time.Duration(i)*step))
	}

	slices.SortStableFunc(packets, func(a, b capture.Packet) int {
		return a.Timestamp.Compare(b.Timestamp)
	})

	return packets, attackWindow, truth
}

// seamRow is one line of the result table: the attacker in one of the two
// attack windows under one configuration.
type seamRow struct {
	Scenario  string
	Placement placement
	Mode      Mode
	Counts    window.CountSource

	// Window is 0 for the first attack window and 1 for the next.
	Window int

	TrueCurrent  uint64
	TruePrevious uint64

	Current     uint64
	Previous    uint64
	Evaluated   uint64
	IPThreshold float64
	IPFlagged   bool
	IPWarmUp    bool
	IPFromFloor bool
	IPQuartile  float64

	WindowEvaluated uint64
	WindowThreshold float64
	WindowFlagged   bool
	WindowFromFloor bool
	WindowQuartile  float64

	// OthersFlagged counts flagged sources other than the attacker, to
	// show the detection is not bought with false positives.
	OthersFlagged int
}

func runSeam(t *testing.T, s seamScenario, place placement, mode Mode, counts window.CountSource) []seamRow {
	t.Helper()

	packets, attackWindow, truth := seamTraffic(s, place)

	wcfg := window.DefaultConfig()
	wcfg.MaxEmpty = window.PcapMaxEmpty
	wcfg.Counts = counts

	dcfg := DefaultConfig()
	dcfg.Mode = mode

	results := run(t, wcfg, dcfg, packets)

	var rows []seamRow

	for offset := 0; offset < 2; offset++ {
		n := attackWindow + offset
		r := results[n]

		row := seamRow{
			Scenario:        s.Name,
			Placement:       place,
			Mode:            mode,
			Counts:          counts,
			Window:          offset,
			TrueCurrent:     truth[n],
			WindowEvaluated: r.EvaluatedPackets,
			WindowThreshold: r.Verdict.Threshold,
			WindowFlagged:   r.Verdict.IsMalicious,
			WindowFromFloor: r.Verdict.FromFloor,
			WindowQuartile:  r.Verdict.QuartileBound,
		}

		if mode == ModeCombined {
			row.TruePrevious = truth[n-1]
		}

		found := false

		for _, ip := range r.IPs {
			if ip.IP != attacker {
				if ip.Verdict.IsMalicious {
					row.OthersFlagged++
				}
				continue
			}

			found = true
			row.Current = ip.Current
			row.Previous = ip.Previous
			row.Evaluated = ip.Evaluated
			row.IPThreshold = ip.Verdict.Threshold
			row.IPFlagged = ip.Verdict.IsMalicious
			row.IPWarmUp = ip.Verdict.WarmUp
			row.IPFromFloor = ip.Verdict.FromFloor
			row.IPQuartile = ip.Verdict.QuartileBound
		}

		if !found {
			t.Fatalf("%s/%v/%v/%v: attacker is not a candidate in attack window %d", s.Name, place, mode, counts, offset)
		}

		rows = append(rows, row)
	}

	return rows
}

// detected reports whether the attacker was flagged in either window.
func detected(rows []seamRow) bool {
	for _, r := range rows {
		if r.IPFlagged {
			return true
		}
	}

	return false
}

func TestSeam(t *testing.T) {
	var all []seamRow

	for _, s := range []seamScenario{sparseScenario, crowdedScenario} {
		all = append(all, runSeamMatrix(t, s)...)
	}

	logSeamTable(t, all)

	if *seamCSV != "" {
		if err := writeSeamCSV(*seamCSV, all); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", *seamCSV)
	}
}

// runSeamMatrix runs every placement, mode and count source for one
// scenario and checks the claim under test.
func runSeamMatrix(t *testing.T, s seamScenario) []seamRow {
	t.Helper()

	var all []seamRow

	for _, counts := range []window.CountSource{window.CountHeavyKeeper, window.CountCountMin} {
		for _, place := range []placement{inside, straddling} {
			for _, mode := range []Mode{ModeCurrentOnly, ModeCombined} {
				rows := runSeam(t, s, place, mode, counts)
				all = append(all, rows...)

				name := s.Name + "/" + place.String() + "/" + mode.String() + "/" + counts.String()

				for _, r := range rows {
					if r.IPWarmUp {
						t.Errorf("%s: attacker still in warm-up; lengthen NormalWindows", name)
					}
					if r.OthersFlagged > 0 {
						t.Errorf("%s window %d: %d normal hosts flagged", name, r.Window, r.OthersFlagged)
					}
				}

				// The claim under test: a burst inside one window is
				// caught either way, while a burst split by a boundary
				// is only caught when windows are combined.
				want := place == inside || mode == ModeCombined

				if got := detected(rows); got != want {
					t.Errorf("%s: detected = %v, want %v", name, got, want)
				}
			}
		}
	}

	return all
}

func logSeamTable(t *testing.T, rows []seamRow) {
	for _, s := range []seamScenario{sparseScenario, crowdedScenario} {
		t.Logf("%s: burst of %d packets over %v; %d heavy hosts at %d±%d and %d light hosts at %d±%d per window",
			s.Name, s.AttackPackets, s.AttackSpan,
			s.HeavyHosts+1, s.HeavyRate, s.HeavyJitter,
			s.LightHosts, s.LightRate, s.LightJitter)
	}

	t.Logf("'term' is the side of max(Q3 + 1.5*IQR, BaseThreshold) the threshold was built from")

	t.Logf("%-8s %-11s %-9s %-12s %3s | %9s %9s | %7s %7s %9s %9s %8s %5s %7s | %9s %9s %8s %5s %7s",
		"scenario", "placement", "mode", "counts", "win",
		"true cur", "true prev",
		"cur", "prev", "evaluated", "threshold", "Q3+1.5I", "term", "flagged",
		"win total", "threshold", "Q3+1.5I", "term", "flagged")

	sorted := slices.Clone(rows)
	slices.SortStableFunc(sorted, func(a, b seamRow) int {
		return cmp.Or(
			cmp.Compare(a.Scenario, b.Scenario),
			cmp.Compare(a.Counts, b.Counts),
			cmp.Compare(a.Placement, b.Placement),
			cmp.Compare(a.Mode, b.Mode),
		)
	})

	for _, r := range sorted {
		t.Logf("%-8s %-11v %-9v %-12v %3d | %9d %9d | %7d %7d %9d %9.1f %8.1f %5s %7v | %9d %9.1f %8.1f %5s %7v",
			r.Scenario, r.Placement, r.Mode, r.Counts, r.Window,
			r.TrueCurrent, r.TruePrevious,
			r.Current, r.Previous, r.Evaluated, r.IPThreshold, r.IPQuartile, term(r.IPFromFloor), r.IPFlagged,
			r.WindowEvaluated, r.WindowThreshold, r.WindowQuartile, term(r.WindowFromFloor), r.WindowFlagged)
	}
}

// term names the side of max(Q3 + 1.5*IQR, BaseThreshold) that was used.
func term(fromFloor bool) string {
	if fromFloor {
		return "floor"
	}

	return "iqr"
}

func writeSeamCSV(path string, rows []seamRow) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	w.Write([]string{
		"scenario", "placement", "mode", "counts", "window",
		"true_current", "true_previous",
		"ip_current", "ip_previous", "ip_evaluated", "ip_threshold", "ip_quartile_bound", "ip_term", "ip_flagged",
		"window_evaluated", "window_threshold", "window_quartile_bound", "window_term", "window_flagged",
		"others_flagged",
	})

	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	f64 := func(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

	for _, r := range rows {
		w.Write([]string{
			r.Scenario, r.Placement.String(), r.Mode.String(), r.Counts.String(), strconv.Itoa(r.Window),
			u(r.TrueCurrent), u(r.TruePrevious),
			u(r.Current), u(r.Previous), u(r.Evaluated),
			f64(r.IPThreshold, 2), f64(r.IPQuartile, 2), term(r.IPFromFloor), strconv.FormatBool(r.IPFlagged),
			u(r.WindowEvaluated),
			f64(r.WindowThreshold, 2), f64(r.WindowQuartile, 2), term(r.WindowFromFloor), strconv.FormatBool(r.WindowFlagged),
			strconv.Itoa(r.OthersFlagged),
		})
	}

	w.Flush()

	return w.Error()
}
