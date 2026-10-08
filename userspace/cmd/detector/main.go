// Command detector replays trace files through the user-space detection
// pipeline and writes the results to an output directory:
//
//	windows.csv  one row per closed window
//	ips.csv      one row per evaluated candidate source
//	run.json     configuration, input files in reading order, and summary
//
// Inputs are files or directories. A directory stands for the trace files
// directly inside it, read in natural order. All inputs are read as one
// continuous stream, so the threshold history built on one input carries
// into the next; to keep recordings apart, such as the two days of
// CIC-DDoS2019, run once per directory with separate output directories:
//
//	detector -pcap PCAP-01-12 -out results/day1
//	detector -pcap PCAP-03-11 -out results/day2
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/window"
)

// progressInterval is how often a progress line is printed.
const progressInterval = 10 * time.Second

// lateLogLimit caps how many windows with late packets are logged one by
// one; the total is always in the summary.
const lateLogLimit = 10

// listFlag collects a flag that may be given more than once.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	log.SetFlags(0)
	log.SetPrefix("detector: ")

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	wcfg := window.DefaultConfig()
	wcfg.MaxEmpty = window.PcapMaxEmpty

	dcfg := detector.DefaultConfig()

	var (
		inputs listFlag
		outDir string
		force  bool
		quiet  bool
		counts string
		mode   string
	)

	flag.Var(&inputs, "pcap", "trace file or directory of trace files; may be repeated")
	flag.StringVar(&outDir, "out", "", "output directory for windows.csv, ips.csv and run.json")
	flag.BoolVar(&force, "force", false, "overwrite existing output files")
	flag.BoolVar(&quiet, "quiet", false, "do not print progress")

	flag.DurationVar(&wcfg.Length, "window", wcfg.Length, "window length")
	flag.IntVar(&wcfg.MaxEmpty, "max-empty", wcfg.MaxEmpty, "empty windows closed before jumping over a pause; 0 never jumps")

	flag.StringVar(&counts, "counts", wcfg.Counts.String(), "per-IP count source: heavykeeper or countmin")
	flag.StringVar(&mode, "mode", dcfg.Mode.String(), "evaluation mode: combined or current")

	flag.IntVar(&wcfg.Depth, "depth", wcfg.Depth, "HeavyKeeper depth")
	flag.IntVar(&wcfg.Width, "width", wcfg.Width, "HeavyKeeper width, a power of two")
	flag.Float64Var(&wcfg.DecayBase, "decay", wcfg.DecayBase, "HeavyKeeper decay base")
	flag.IntVar(&wcfg.K, "k", wcfg.K, "number of candidates per window")
	flag.Uint64Var(&wcfg.Seed, "seed", wcfg.Seed, "HeavyKeeper random seed")
	flag.Uint64Var(&wcfg.CMSWidth, "cms-width", wcfg.CMSWidth, "Count-Min width")
	flag.Uint64Var(&wcfg.CMSDepth, "cms-depth", wcfg.CMSDepth, "Count-Min depth")

	flag.Float64Var(&dcfg.IQR.BaseThreshold, "base-threshold", dcfg.IQR.BaseThreshold, "IQR floor (uncalibrated)")
	flag.Float64Var(&dcfg.IQR.IQRMultiplier, "iqr-mult", dcfg.IQR.IQRMultiplier, "IQR multiplier")
	flag.Float64Var(&dcfg.IQR.OffsetMultiplier, "offset-mult", dcfg.IQR.OffsetMultiplier, "standard deviation multiplier")
	flag.IntVar(&dcfg.IQR.MinSamples, "min-samples", dcfg.IQR.MinSamples, "samples needed before a threshold is enforced")
	flag.IntVar(&dcfg.IQR.MaxHistorySize, "history", dcfg.IQR.MaxHistorySize, "samples kept per history")
	flag.IntVar(&dcfg.IQR.MaxTrackedIPs, "max-ips", dcfg.IQR.MaxTrackedIPs, "source addresses with a per-IP history")

	flag.Parse()

	if len(inputs) == 0 || outDir == "" {
		flag.Usage()
		return errors.New("-pcap and -out are required")
	}

	var err error

	if wcfg.Counts, err = window.ParseCountSource(counts); err != nil {
		return err
	}

	if dcfg.Mode, err = detector.ParseMode(mode); err != nil {
		return err
	}

	paths, err := capture.ExpandPaths(inputs)
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		return errors.New("no trace files found in the inputs")
	}

	if len(inputs) > 1 {
		log.Printf("note: %d inputs are read as one stream; history carries from one into the next", len(inputs))
	}

	if err := prepareOutput(outDir, force); err != nil {
		return err
	}

	started := time.Now()

	src, err := capture.OpenFiles(paths)
	if err != nil {
		return err
	}
	defer src.Close()

	ev, err := detector.NewEvaluator(dcfg)
	if err != nil {
		return err
	}

	sink, err := report.NewCSVSink(outDir, force)
	if err != nil {
		return err
	}

	var (
		stats      report.Stats
		sinkErr    error
		lateLogged int
	)

	agg, err := window.NewAggregator(wcfg, func(c window.Closed) {
		r := ev.Evaluate(c)

		if r.Evaluated {
			stats.EvaluatedWindows++
		}
		if r.Verdict.IsMalicious {
			stats.FlaggedWindows++
		}
		for _, ip := range r.IPs {
			if ip.Verdict.IsMalicious {
				stats.FlaggedIPRows++
			}
		}

		if r.Late > 0 {
			lateLogged++
			switch {
			case lateLogged <= lateLogLimit:
				log.Printf("warning: %d out-of-order packets dropped in window %d; inputs are assumed to be in time order",
					r.Late, r.Epoch)
			case lateLogged == lateLogLimit+1:
				log.Printf("warning: further windows with out-of-order packets are not logged; see run.json")
			}
		}

		if sinkErr == nil {
			sinkErr = sink.Write(&r)
		}
	})
	if err != nil {
		return err
	}

	// Ctrl-C ends the run cleanly: the windows closed so far are kept and
	// run.json is still written.
	var stop atomic.Bool

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		stop.Store(true)
		signal.Stop(interrupt)
	}()

	log.Printf("reading %d files into %s", len(paths), outDir)

	nextProgress := started.Add(progressInterval)

	var readErr error

	for n := uint64(0); ; n++ {
		// Checking the clock and the stop flag every packet would cost
		// more than the rest of the loop.
		if n&0xffff == 0 {
			if stop.Load() {
				break
			}

			if now := time.Now(); !quiet && now.After(nextProgress) {
				printProgress(now.Sub(started), src, agg, &stats)
				nextProgress = now.Add(progressInterval)
			}
		}

		p, err := src.Next()
		if err != nil {
			if err != io.EOF {
				readErr = err
			}
			break
		}

		agg.Observe(p)

		if sinkErr != nil {
			break
		}
	}

	finished := time.Now()

	if d, ok := agg.Finish(); ok {
		stats.Dropped = &d
		log.Printf("dropped the incomplete last window %d (%d packets); it is not in windows.csv", d.Epoch, d.Packets)
	}

	closeErr := sink.Close()

	srcStats := src.Stats()
	stats.Packets = srcStats.Packets
	stats.Skipped = srcStats.Skipped
	stats.Window = agg.Stats()
	stats.TrackedIPs = uint64(ev.Detector().TrackedIPs())
	stats.EvictedIPs = ev.Detector().EvictedIPs()
	stats.WallSeconds = finished.Sub(started).Seconds()
	if stats.WallSeconds > 0 {
		stats.PacketsPerSecond = float64(stats.Packets) / stats.WallSeconds
	}

	runInfo := &report.Run{
		Tool:        "detector",
		Version:     report.CurrentVersion(),
		Args:        os.Args[1:],
		StartedAt:   started,
		FinishedAt:  finished,
		Interrupted: stop.Load(),
		Config:      runConfig(wcfg, dcfg),
		Inputs:      src.Files(),
		Stats:       stats,
		Notes:       []string{report.TimingNote},
	}

	if err := report.WriteRun(outDir, runInfo, force); err != nil {
		return err
	}

	printSummary(runInfo)

	return errors.Join(readErr, sinkErr, closeErr)
}

// prepareOutput creates the output directory and refuses to start if a
// previous run's results would be overwritten, so a long run does not
// fail only at the end when writing run.json.
func prepareOutput(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if force {
		return nil
	}

	for _, name := range []string{report.WindowsFile, report.IPsFile, report.RunFile} {
		path := filepath.Join(dir, name)

		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use -force to overwrite)", path)
		}
	}

	return nil
}

func runConfig(w window.Config, d detector.Config) report.Config {
	return report.Config{
		WindowLength: w.Length.String(),
		MaxEmpty:     w.MaxEmpty,

		Counts: w.Counts.String(),
		Mode:   d.Mode.String(),

		Depth:     w.Depth,
		Width:     w.Width,
		DecayBase: w.DecayBase,
		K:         w.K,
		Seed:      w.Seed,
		CMSWidth:  w.CMSWidth,
		CMSDepth:  w.CMSDepth,

		BaseThreshold:    d.IQR.BaseThreshold,
		IQRMultiplier:    d.IQR.IQRMultiplier,
		OffsetMultiplier: d.IQR.OffsetMultiplier,
		MinSamples:       d.IQR.MinSamples,
		MaxHistorySize:   d.IQR.MaxHistorySize,
		MaxTrackedIPs:    d.IQR.MaxTrackedIPs,
	}
}

func printProgress(elapsed time.Duration, src *capture.MultiSource, agg *window.Aggregator, stats *report.Stats) {
	files := src.Files()

	log.Printf("%v: %d packets, %d windows (%d flagged), file %d: %s",
		elapsed.Round(time.Second),
		src.Stats().Packets,
		agg.Stats().Closed,
		stats.FlaggedWindows,
		len(files),
		filepath.Base(src.CurrentFile()))
}

func printSummary(r *report.Run) {
	s := r.Stats

	truncated := 0
	for _, f := range r.Inputs {
		if f.Truncated {
			truncated++
		}
	}

	suffix := ""
	if r.Interrupted {
		suffix = ", interrupted by user"
	}

	log.Printf("done in %.1fs (%.0f packets/s)%s", s.WallSeconds, s.PacketsPerSecond, suffix)
	log.Printf("  files:    %d read, %d truncated", len(r.Inputs), truncated)
	log.Printf("  packets:  %d IP, %d non-IP frames skipped, %d out of order", s.Packets, s.Skipped, s.Window.Late)
	log.Printf("  windows:  %d closed, %d empty, %d evaluated, %d flagged", s.Window.Closed, s.Window.Empty, s.EvaluatedWindows, s.FlaggedWindows)
	log.Printf("  pauses:   %d jumps over %d epochs", s.Window.Jumps, s.Window.SkippedEpochs)
	log.Printf("  sources:  %d flagged IP rows, %d tracked, %d evicted", s.FlaggedIPRows, s.TrackedIPs, s.EvictedIPs)

	if s.Window.Late > 0 {
		log.Printf("warning: %d out-of-order packets were dropped; the inputs are not in time order", s.Window.Late)
	}
}
