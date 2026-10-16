package detector

// The seam experiment: does judging a window together with its
// predecessor catch an attack that a window boundary splits in two?
//
// One host that has behaved normally sends a burst of extra packets. The
// burst is placed either entirely inside one window, or split 50/50 across
// a boundary. Each placement is run in both evaluation modes, and the
// attacker's counts and per-IP thresholds in the attack windows are
// reported. Each verdict also records whether its threshold came from the
// quartiles or from the BaseThreshold floor.
//
// The counts are exact, as if the kernel sketch made no error, so only the
// window logic is tested. How the kernel sketch's estimates affect the
// result can only be measured on a live interface.
//
// Run with -v to print the table, and pass an absolute path to also write
// it as CSV:
//
//	go test ./kernelspace/detector -run TestSeam -v -args -seam.csv=$PWD/seam.csv

import (
	"cmp"
	"encoding/csv"
	"flag"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"testing"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
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
	// normal traffic.
	AttackPackets int
}

var seamScenario1 = seamScenario{
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
}

type placement int

const (
	// inside places the whole burst in one window.
	inside placement = iota

	// straddling splits the burst evenly across a boundary.
	straddling
)

func (p placement) String() string {
	if p == inside {
		return "inside"
	}

	return "straddling"
}

var attacker = flow.MustParse("198.51.100.66")

// seamTraffic generates each window's traffic and returns it together
// with the first of the two windows the attack can touch and the
// attacker's true packet count in every window.
func seamTraffic(s seamScenario, place placement) ([]traffic, int, map[int]uint64) {
	rng := rand.New(rand.NewPCG(s.Seed, 0))

	jitter := func(rate, j int) uint32 {
		return uint32(rate - j + rng.IntN(2*j+1))
	}

	heavy := make([]flow.Key, s.HeavyHosts)
	for i := range heavy {
		heavy[i] = flow.FromIPv4([]byte{192, 0, 2, byte(10 + i)})
	}

	light := make([]flow.Key, s.LightHosts)
	for i := range light {
		light[i] = flow.FromIPv4([]byte{10, 1, byte(i >> 8), byte(i)})
	}

	trs := make([]traffic, s.NormalWindows+2+s.TailWindows)
	for w := range trs {
		tr := traffic{}

		for _, h := range heavy {
			tr[h] = jitter(s.HeavyRate, s.HeavyJitter)
		}

		tr[attacker] = jitter(s.HeavyRate, s.HeavyJitter)

		for _, h := range light {
			tr[h] = jitter(s.LightRate, s.LightJitter)
		}

		trs[w] = tr
	}

	attackWindow := s.NormalWindows
	burst := uint32(s.AttackPackets)

	if place == inside {
		trs[attackWindow][attacker] += burst
	} else {
		trs[attackWindow][attacker] += burst / 2
		trs[attackWindow+1][attacker] += burst - burst/2
	}

	truth := map[int]uint64{}
	for w, tr := range trs {
		truth[w] = uint64(tr[attacker])
	}

	return trs, attackWindow, truth
}

// seamRow is one line of the result table: the attacker in one of the two
// attack windows under one configuration.
type seamRow struct {
	Scenario  string
	Placement placement
	Mode      Mode

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

func runSeam(t *testing.T, s seamScenario, place placement, mode Mode) []seamRow {
	t.Helper()

	trs, attackWindow, truth := seamTraffic(s, place)

	dcfg := DefaultConfig()
	dcfg.Mode = mode

	results := newHarness(t, dcfg).windows(trs...)

	var rows []seamRow

	for offset := 0; offset < 2; offset++ {
		n := attackWindow + offset
		r := results[n]

		row := seamRow{
			Scenario:        s.Name,
			Placement:       place,
			Mode:            mode,
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
			t.Fatalf("%s/%v/%v: attacker is not a candidate in attack window %d", s.Name, place, mode, offset)
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

	for _, place := range []placement{inside, straddling} {
		for _, mode := range []Mode{ModeCurrentOnly, ModeCombined} {
			rows := runSeam(t, seamScenario1, place, mode)
			all = append(all, rows...)

			name := place.String() + "/" + mode.String()

			for _, r := range rows {
				if r.IPWarmUp {
					t.Errorf("%s: attacker still in warm-up; lengthen NormalWindows", name)
				}
				if r.OthersFlagged > 0 {
					t.Errorf("%s window %d: %d normal hosts flagged", name, r.Window, r.OthersFlagged)
				}
				if r.Current != r.TrueCurrent || r.Previous != r.TruePrevious {
					t.Errorf("%s window %d: counts %d + %d, want the exact %d + %d",
						name, r.Window, r.Current, r.Previous, r.TrueCurrent, r.TruePrevious)
				}
			}

			// The claim under test: a burst inside one window is caught
			// either way, while a burst split by a boundary is only
			// caught when windows are combined.
			want := place == inside || mode == ModeCombined

			if got := detected(rows); got != want {
				t.Errorf("%s: detected = %v, want %v", name, got, want)
			}
		}
	}

	logSeamTable(t, all)

	if *seamCSV != "" {
		if err := writeSeamCSV(*seamCSV, all); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", *seamCSV)
	}
}

func logSeamTable(t *testing.T, rows []seamRow) {
	s := seamScenario1
	t.Logf("%s: burst of %d packets; %d heavy hosts at %d±%d and %d light hosts at %d±%d per window",
		s.Name, s.AttackPackets,
		s.HeavyHosts+1, s.HeavyRate, s.HeavyJitter,
		s.LightHosts, s.LightRate, s.LightJitter)

	t.Logf("'term' is the side of max(Q3 + 1.5*IQR, BaseThreshold) the threshold was built from")

	t.Logf("%-8s %-11s %-9s %3s | %9s %9s | %7s %7s %9s %9s %8s %5s %7s | %9s %9s %8s %5s %7s",
		"scenario", "placement", "mode", "win",
		"true cur", "true prev",
		"cur", "prev", "evaluated", "threshold", "Q3+1.5I", "term", "flagged",
		"win total", "threshold", "Q3+1.5I", "term", "flagged")

	sorted := slices.Clone(rows)
	slices.SortStableFunc(sorted, func(a, b seamRow) int {
		return cmp.Or(
			cmp.Compare(a.Scenario, b.Scenario),
			cmp.Compare(a.Placement, b.Placement),
			cmp.Compare(a.Mode, b.Mode),
		)
	})

	for _, r := range sorted {
		t.Logf("%-8s %-11v %-9v %3d | %9d %9d | %7d %7d %9d %9.1f %8.1f %5s %7v | %9d %9.1f %8.1f %5s %7v",
			r.Scenario, r.Placement, r.Mode, r.Window,
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
		"scenario", "placement", "mode", "window",
		"true_current", "true_previous",
		"ip_current", "ip_previous", "ip_evaluated", "ip_threshold", "ip_quartile_bound", "ip_term", "ip_flagged",
		"window_evaluated", "window_threshold", "window_quartile_bound", "window_term", "window_flagged",
		"others_flagged",
	})

	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	f64 := func(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

	for _, r := range rows {
		w.Write([]string{
			r.Scenario, r.Placement.String(), r.Mode.String(), strconv.Itoa(r.Window),
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
