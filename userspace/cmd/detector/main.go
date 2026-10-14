// Command detector runs the user-space detection pipeline on trace files
// or on a live interface and writes the results to an output directory:
//
//	windows.csv  one row per closed window
//	ips.csv      one row per evaluated candidate source
//	run.json     configuration, inputs, how the run ended, and a summary
//
// Trace replay: inputs are files or directories. A directory stands for
// the trace files directly inside it, read in natural order. All inputs
// are read as one continuous stream, so the threshold history built on
// one input carries into the next; to keep recordings apart, such as the
// two days of CIC-DDoS2019, run once per directory:
//
//	detector -pcap PCAP-01-12 -out results/day1
//	detector -pcap PCAP-03-11 -out results/day2
//
// Live capture (Linux, as root):
//
//	detector -iface ens7 -duration 10m -out results/live1
//
// Live capture also records how many packets the socket and the interface
// dropped, since that is where the user-space path runs out of capacity.
// Turn off receive offloads first so the kernel does not merge packets:
//
//	ethtool -K ens7 gro off lro off
//
// The number of packets sent is only known on the sender. Save the
// tcpreplay output next to run.json, since it is needed to find the
// capacity limit:
//
//	tcpreplay -i ens7 --pps 100000 attack.pcap 2>&1 | tee results/live1/tcpreplay.txt
//
// Every window row also carries the detector's own heap in use and the
// user and system CPU time it spent since the previous window.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/resource"
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

// options are the settings that are not part of the window or detector
// configuration.
type options struct {
	inputs   listFlag
	iface    string
	duration time.Duration
	rcvbuf   int
	outDir   string
	force    bool
	quiet    bool
}

func run() error {
	wcfg := window.DefaultConfig()
	dcfg := detector.DefaultConfig()

	var (
		opt    options
		counts string
		mode   string
		ipMode string
	)

	flag.Var(&opt.inputs, "pcap", "trace file or directory of trace files; may be repeated")
	flag.StringVar(&opt.iface, "iface", "", "capture live on this interface instead (Linux, needs root)")
	flag.DurationVar(&opt.duration, "duration", 0, "stop a live capture after this long; 0 runs until Ctrl-C")
	flag.IntVar(&opt.rcvbuf, "rcvbuf", 0, "live socket receive buffer in bytes; 0 keeps the system default")
	flag.StringVar(&opt.outDir, "out", "", "output directory for windows.csv, ips.csv and run.json")
	flag.BoolVar(&opt.force, "force", false, "overwrite existing output files")
	flag.BoolVar(&opt.quiet, "quiet", false, "do not print progress")

	flag.DurationVar(&wcfg.Length, "window", wcfg.Length, "window length")
	flag.IntVar(&wcfg.MaxEmpty, "max-empty", window.PcapMaxEmpty,
		"empty windows closed before jumping over a pause; 0 never jumps (default 10 for -pcap, 0 for -iface)")

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
	flag.StringVar(&ipMode, "ip-mode", dcfg.IQR.IPMode.String(),
		"history a source is judged against: per-ip, shared, or hybrid (own once warmed up, shared until then)")
	flag.IntVar(&dcfg.IQR.MaxSharedHistorySize, "shared-history", dcfg.IQR.MaxSharedHistorySize,
		"samples kept in the history shared by all sources (shared and hybrid modes)")

	flag.Parse()

	live := opt.iface != ""

	switch {
	case live == (len(opt.inputs) > 0):
		flag.Usage()
		return errors.New("give exactly one of -pcap or -iface")
	case opt.outDir == "":
		flag.Usage()
		return errors.New("-out is required")
	case !live && (opt.duration != 0 || opt.rcvbuf != 0):
		return errors.New("-duration and -rcvbuf only apply to -iface")
	}

	// A quiet period on a live interface is real traffic information, so
	// live capture never jumps unless asked to explicitly.
	if live && !flagSet("max-empty") {
		wcfg.MaxEmpty = window.LiveMaxEmpty
	}

	var err error

	if wcfg.Counts, err = window.ParseCountSource(counts); err != nil {
		return err
	}

	if dcfg.Mode, err = detector.ParseMode(mode); err != nil {
		return err
	}

	if dcfg.IQR.IPMode, err = iqr.ParseIPMode(ipMode); err != nil {
		return err
	}

	if err := prepareOutput(opt.outDir, opt.force); err != nil {
		return err
	}

	if live {
		return runLive(opt, wcfg, dcfg)
	}

	return runTrace(opt, wcfg, dcfg)
}

// session is a run in progress: the pipeline and its accumulated stats.
type session struct {
	opt  options
	wcfg window.Config
	dcfg detector.Config

	ev   *detector.Evaluator
	agg  *window.Aggregator
	sink *report.CSVSink

	stats      report.Stats
	sinkErr    error
	lateLogged int

	// drops, when set, returns the live socket's cumulative drop count.
	drops     func() (uint64, bool)
	lastDrops uint64

	// resources samples the process's memory and CPU once per window.
	resources *resource.Sampler

	stop    atomic.Bool
	started time.Time
	next    time.Time

	progress func() string
}

func newSession(opt options, wcfg window.Config, dcfg detector.Config) (*session, error) {
	s := &session{opt: opt, wcfg: wcfg, dcfg: dcfg, started: time.Now()}
	s.next = s.started.Add(progressInterval)

	var err error

	if s.ev, err = detector.NewEvaluator(dcfg); err != nil {
		return nil, err
	}

	if s.agg, err = window.NewAggregator(wcfg, s.onClose); err != nil {
		return nil, err
	}

	if s.sink, err = report.NewCSVSink(opt.outDir, opt.force); err != nil {
		return nil, err
	}

	// The first window's figures run from here, after setup.
	s.resources = resource.NewSampler()

	return s, nil
}

// onClose evaluates a closed window and writes the result.
func (s *session) onClose(c window.Closed) {
	r := s.ev.Evaluate(c)

	// Sampled after the evaluation, so a window's figures include the
	// cost of judging it; writing the row falls to the next window.
	r.Resources = s.resources.Sample()

	if s.drops != nil {
		if total, ok := s.drops(); ok {
			r.KernelDrops = int64(total - s.lastDrops)
			s.lastDrops = total
		}
	}

	if r.Evaluated {
		s.stats.EvaluatedWindows++
	}
	if r.Verdict.IsMalicious {
		s.stats.FlaggedWindows++
	}
	for _, ip := range r.IPs {
		if ip.Verdict.IsMalicious {
			s.stats.FlaggedIPRows++
		}
	}

	if r.Late > 0 {
		s.lateLogged++
		switch {
		case s.lateLogged <= lateLogLimit:
			log.Printf("warning: %d out-of-order packets dropped in window %d; inputs are assumed to be in time order",
				r.Late, r.Epoch)
		case s.lateLogged == lateLogLimit+1:
			log.Printf("warning: further windows with out-of-order packets are not logged; see run.json")
		}
	}

	if s.sinkErr == nil {
		s.sinkErr = s.sink.Write(&r)
	}
}

func (s *session) loop() *loop {
	return &loop{
		agg:    s.agg,
		stop:   &s.stop,
		failed: func() error { return s.sinkErr },
		tick:   s.tick,
	}
}

func (s *session) tick() {
	if s.opt.quiet {
		return
	}

	if now := time.Now(); now.After(s.next) {
		log.Printf("%v: %s, %d windows (%d flagged)",
			now.Sub(s.started).Round(time.Second), s.progress(), s.agg.Stats().Closed, s.stats.FlaggedWindows)
		s.next = now.Add(progressInterval)
	}
}

// interruptOn makes Ctrl-C end the run cleanly: the windows closed so far
// are kept and run.json is still written. wake, if set, is called to
// unblock a read that is waiting for packets.
func (s *session) interruptOn(wake func()) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		s.stop.Store(true)
		signal.Stop(interrupt)

		if wake != nil {
			wake()
		}
	}()
}

// finish drops the incomplete last window, closes the CSV files and fills
// in the stats common to both modes.
func (s *session) finish(src capture.Source, finished time.Time) error {
	if d, ok := s.agg.Finish(); ok {
		s.stats.Dropped = &d
		log.Printf("dropped the incomplete last window %d (%d packets); it is not in windows.csv", d.Epoch, d.Packets)
	}

	err := s.sink.Close()

	st := src.Stats()
	s.stats.Packets = st.Packets
	s.stats.Skipped = st.Skipped
	s.stats.Window = s.agg.Stats()
	s.stats.TrackedIPs = uint64(s.ev.Detector().TrackedIPs())
	s.stats.EvictedIPs = s.ev.Detector().EvictedIPs()
	s.stats.WallSeconds = finished.Sub(s.started).Seconds()
	if s.stats.WallSeconds > 0 {
		s.stats.PacketsPerSecond = float64(s.stats.Packets) / s.stats.WallSeconds
	}

	return errors.Join(err, s.sinkErr)
}

func (s *session) runInfo(source, endReason string, finished time.Time) *report.Run {
	return &report.Run{
		Tool:       "detector",
		Version:    report.CurrentVersion(),
		Args:       os.Args[1:],
		StartedAt:  s.started,
		FinishedAt: finished,
		EndReason:  endReason,
		Source:     source,
		Config:     runConfig(s.wcfg, s.dcfg),
		Stats:      s.stats,
	}
}

func runTrace(opt options, wcfg window.Config, dcfg detector.Config) error {
	paths, err := capture.ExpandPaths(opt.inputs)
	if err != nil {
		return err
	}

	if len(paths) == 0 {
		return errors.New("no trace files found in the inputs")
	}

	if len(opt.inputs) > 1 {
		log.Printf("note: %d inputs are read as one stream; history carries from one into the next", len(opt.inputs))
	}

	// The source is opened before the output files are created, so a bad
	// input leaves no half-written results behind.
	src, err := capture.OpenFiles(paths)
	if err != nil {
		return err
	}
	defer src.Close()

	s, err := newSession(opt, wcfg, dcfg)
	if err != nil {
		return err
	}

	s.progress = func() string {
		return fmt.Sprintf("%d packets, file %d: %s",
			src.Stats().Packets, len(src.Files()), filepath.Base(src.CurrentFile()))
	}

	s.interruptOn(nil)

	log.Printf("reading %d files into %s", len(paths), opt.outDir)

	endReason, loopErr := s.loop().trace(src)
	finished := time.Now()

	finishErr := s.finish(src, finished)

	info := s.runInfo("pcap", endReason, finished)
	info.Inputs = src.Files()
	info.Notes = []string{report.TraceTimingNote, report.ResourceNote}

	if err := report.WriteRun(opt.outDir, info, opt.force); err != nil {
		return err
	}

	printSummary(info)

	return errors.Join(loopErr, finishErr)
}

func runLive(opt options, wcfg window.Config, dcfg detector.Config) error {
	src, err := capture.OpenLive(capture.LiveConfig{Interface: opt.iface, RecvBuffer: opt.rcvbuf})
	if err != nil {
		return err
	}
	defer src.Close()

	s, err := newSession(opt, wcfg, dcfg)
	if err != nil {
		return err
	}

	info := &report.Live{
		Interface:           opt.iface,
		RequestedRecvBuffer: opt.rcvbuf,
	}
	if opt.duration > 0 {
		info.Duration = opt.duration.String()
	}

	// Snapshot the interface counters after the socket is open, so that
	// both cover the same span as the socket's own counters.
	nicStart, warn, err := capture.ReadNICCounters(opt.iface)
	if err != nil {
		info.NICWarnings = append(info.NICWarnings, "start: "+err.Error())
	} else if warn != nil {
		info.NICWarnings = append(info.NICWarnings, "start: "+warn.Error())
	}

	s.drops = func() (uint64, bool) {
		st, err := src.LiveStats()
		return st.KernelDropped, err == nil
	}

	// LiveStats is cumulative, so reading it for progress does not
	// disturb the per-window drop counts.
	s.progress = func() string {
		st, _ := src.LiveStats()
		return fmt.Sprintf("%d packets, %d dropped by the socket", src.Stats().Packets, st.KernelDropped)
	}

	s.interruptOn(func() { src.SetDeadline(time.Now()) })

	var end time.Time
	if opt.duration > 0 {
		end = s.started.Add(opt.duration)
	}

	log.Printf("capturing on %s into %s", opt.iface, opt.outDir)

	endReason, loopErr := s.loop().live(src, end, time.Now)
	finished := time.Now()

	if st, err := src.LiveStats(); err == nil {
		info.Socket = st
	} else {
		loopErr = errors.Join(loopErr, err)
	}

	if nicStart != nil {
		nicEnd, warn, err := capture.ReadNICCounters(opt.iface)

		switch {
		case err != nil:
			info.NICWarnings = append(info.NICWarnings, "end: "+err.Error())
		default:
			if warn != nil {
				info.NICWarnings = append(info.NICWarnings, "end: "+warn.Error())
			}

			info.NICStart, info.NICEnd = nicStart, nicEnd

			delta, err := nicStart.Delta(nicEnd)
			if err != nil {
				info.NICWarnings = append(info.NICWarnings, "delta: "+err.Error())
			}
			info.NICDelta = delta
		}
	}

	finishErr := s.finish(src, finished)

	run := s.runInfo("live", endReason, finished)
	run.Live = info
	run.Notes = []string{report.LiveTimingNote, report.ResourceNote, report.SentPacketsNote}

	if err := report.WriteRun(opt.outDir, run, opt.force); err != nil {
		return err
	}

	printSummary(run)

	return errors.Join(loopErr, finishErr)
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

// flagSet reports whether a flag was given on the command line.
func flagSet(name string) bool {
	set := false

	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})

	return set
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

		IPMode:               d.IQR.IPMode.String(),
		MaxSharedHistorySize: d.IQR.MaxSharedHistorySize,
	}
}

func printSummary(r *report.Run) {
	s := r.Stats

	log.Printf("done in %.1fs (%.0f packets/s), ended: %s", s.WallSeconds, s.PacketsPerSecond, r.EndReason)

	if r.Source == "pcap" {
		truncated := 0
		for _, f := range r.Inputs {
			if f.Truncated {
				truncated++
			}
		}

		log.Printf("  files:    %d read, %d truncated", len(r.Inputs), truncated)
	}

	log.Printf("  packets:  %d IP, %d non-IP frames skipped, %d out of order", s.Packets, s.Skipped, s.Window.Late)

	if l := r.Live; l != nil {
		log.Printf("  socket:   %d offered, %d dropped (buffer %d bytes), %d without kernel timestamp",
			l.Socket.KernelTotal, l.Socket.KernelDropped, l.Socket.RecvBuffer, l.Socket.FallbackStamps)

		if l.NICDelta != nil {
			log.Printf("  nic:      %d received, %d dropped, %d fifo errors (see run.json for driver counters)",
				l.NICDelta["dev.rx_packets"], l.NICDelta["dev.rx_drop"], l.NICDelta["dev.rx_fifo"])
		}

		for _, w := range l.NICWarnings {
			log.Printf("  nic:      %s", w)
		}
	}

	log.Printf("  windows:  %d closed, %d empty, %d evaluated, %d flagged", s.Window.Closed, s.Window.Empty, s.EvaluatedWindows, s.FlaggedWindows)
	log.Printf("  pauses:   %d jumps over %d epochs", s.Window.Jumps, s.Window.SkippedEpochs)
	log.Printf("  sources:  %d flagged IP rows, %d tracked, %d evicted (ip mode %s)",
		s.FlaggedIPRows, s.TrackedIPs, s.EvictedIPs, r.Config.IPMode)

	if s.Window.Late > 0 {
		log.Printf("warning: %d out-of-order packets were dropped; the input is not in time order", s.Window.Late)
	}
}
