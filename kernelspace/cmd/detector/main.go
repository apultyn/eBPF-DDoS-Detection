// Command detector runs the kernel-space detection pipeline and writes the
// results to an output directory:
//
//	windows.csv  one row per closed window
//	ips.csv      one row per evaluated candidate source
//	run.json     configuration, how the run ended, and a summary
//
// The packets are counted in the kernel by heavy_keeper.o, attached with
// XDP to the interface beforehand. The detector reads its pinned maps once
// per window and judges each window in user space (Linux, as root):
//
//	ip link set dev ens7 xdpgeneric obj heavy_keeper.o sec xdp
//	detector -iface ens7 -duration 10m -out results/live1
//
// -iface is optional and only used to read the interface's counters
// before and after the run; the maps are opened from -pin-dir.
//
// The number of packets sent is only known on the sender. Save the
// tcpreplay output next to run.json, since it is needed to find the
// capacity limit:
//
//	tcpreplay -i ens7 --pps 100000 attack.pcap 2>&1 | tee results/live1/tcpreplay.txt
//
// Every window row also carries the detector's own heap in use and the
// user and system CPU time it spent since the previous window.
//
// With -block, every source flagged by its per-IP verdict is added to the
// XDP program's blocklist, and its packets are dropped before they reach
// the sketch. A source stays blocked for -block-ttl after it was last
// flagged. Sources given with -allow are never blocked; include the host
// the experiment is run from. The blocklist is cleared at start whether
// or not -block is given, so an earlier run cannot skew this one:
//
//	detector -iface ens7 -block -block-ttl 30s -allow 192.0.2.10 -out results/live2
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/capture"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/heavykeeper"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/iqr"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/mitigate"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/report"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/resource"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

// progressInterval is how often a progress line is printed.
const progressInterval = 10 * time.Second

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
	pinDir   string
	iface    string
	duration time.Duration
	outDir   string
	force    bool
	quiet    bool

	// block turns on pushing flagged sources to the blocklist.
	block bool
}

func run() error {
	wcfg := window.DefaultConfig()
	dcfg := detector.DefaultConfig()
	mcfg := mitigate.DefaultConfig()

	var (
		opt    options
		mode   string
		ipMode string
		allow  string
	)

	flag.StringVar(&opt.pinDir, "pin-dir", heavykeeper.DefaultPinDir, "directory the XDP program's maps are pinned in")
	flag.StringVar(&opt.iface, "iface", "", "interface the XDP program is attached to, for reading its counters; optional")
	flag.DurationVar(&opt.duration, "duration", 0, "stop after this long; 0 runs until Ctrl-C")
	flag.StringVar(&opt.outDir, "out", "", "output directory for windows.csv, ips.csv and run.json")
	flag.BoolVar(&opt.force, "force", false, "overwrite existing output files")
	flag.BoolVar(&opt.quiet, "quiet", false, "do not print progress")

	flag.StringVar(&mode, "mode", dcfg.Mode.String(), "evaluation mode: combined or current")
	flag.IntVar(&wcfg.K, "k", wcfg.K, fmt.Sprintf("number of candidates per window, at most %d", heavykeeper.K))

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

	flag.BoolVar(&opt.block, "block", false, "add sources flagged by their per-IP verdict to the XDP blocklist")
	flag.DurationVar(&mcfg.TTL, "block-ttl", mcfg.TTL, "how long a source stays blocked after it was last flagged; 0 until the run ends")
	flag.StringVar(&allow, "allow", "", "comma-separated addresses that are never blocked")

	flag.Parse()

	if opt.outDir == "" {
		flag.Usage()
		return errors.New("-out is required")
	}

	var err error

	if dcfg.Mode, err = detector.ParseMode(mode); err != nil {
		return err
	}

	if dcfg.IQR.IPMode, err = iqr.ParseIPMode(ipMode); err != nil {
		return err
	}

	if mcfg.Allow, err = parseAllow(allow); err != nil {
		return err
	}

	mcfg.WindowLength = wcfg.Length

	if mcfg.TTL < 0 {
		return fmt.Errorf("-block-ttl %v is negative", mcfg.TTL)
	}

	if err := prepareOutput(opt.outDir, opt.force); err != nil {
		return err
	}

	return runKernel(opt, wcfg, dcfg, mcfg)
}

// parseAllow parses the -allow list.
func parseAllow(s string) ([]flow.Key, error) {
	var keys []flow.Key

	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}

		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("-allow: %w", err)
		}

		keys = append(keys, flow.FromAddr(a))
	}

	return keys, nil
}

// session is a run in progress: the pipeline and its accumulated stats.
type session struct {
	opt  options
	wcfg window.Config
	dcfg detector.Config

	ev   *detector.Evaluator
	agg  *window.Aggregator
	sink *report.CSVSink

	// mit pushes flagged sources to the blocklist; nil when blocking is
	// off.
	mit *mitigate.Mitigator

	// clock is CLOCK_TAI, the clock the blocklist's times are on.
	clock func() time.Time

	stats report.Stats

	// taiOffset is CLOCK_TAI minus the wall clock. Windows are numbered
	// on CLOCK_TAI; their bounds are reported on the wall clock, like the
	// other timestamps.
	taiOffset time.Duration

	// resources samples the process's memory and CPU once per window.
	resources *resource.Sampler

	stop    chan struct{}
	started time.Time
	next    time.Time
}

func newSession(opt options, wcfg window.Config, dcfg detector.Config, src window.Source, mit *mitigate.Mitigator, clock func() time.Time, taiOffset time.Duration) (*session, error) {
	s := &session{
		opt:       opt,
		wcfg:      wcfg,
		dcfg:      dcfg,
		mit:       mit,
		clock:     clock,
		taiOffset: taiOffset,
		stop:      make(chan struct{}),
		started:   time.Now(),
	}
	s.next = s.started.Add(progressInterval)

	var err error

	if s.ev, err = detector.NewEvaluator(dcfg); err != nil {
		return nil, err
	}

	if s.agg, err = window.NewAggregator(wcfg, src, clock, s.onClose); err != nil {
		return nil, err
	}

	if s.sink, err = report.NewCSVSink(opt.outDir, opt.force); err != nil {
		return nil, err
	}

	// The first window's figures run from here, after setup.
	s.resources = resource.NewSampler()

	return s, nil
}

// onClose evaluates a closed window and writes the result. An error ends
// the run.
func (s *session) onClose(c window.Closed) error {
	r, err := s.ev.Evaluate(c)
	if err != nil {
		return err
	}

	if s.mit != nil {
		s.block(&r)
	}

	// Sampled after the evaluation and blocking, so a window's figures
	// include the cost of judging it; writing the row falls to the next
	// window.
	r.Resources = s.resources.Sample()

	r.Start = r.Start.Add(-s.taiOffset)
	r.End = r.End.Add(-s.taiOffset)

	s.stats.Packets += r.Packets
	s.stats.BlockedPackets += r.BlockedPackets

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

	if r.SkippedBefore > 0 {
		log.Printf("warning: %d windows before window %d were not evaluated; the detector fell behind the kernel",
			r.SkippedBefore, r.Epoch)
	}

	return s.sink.Write(&r)
}

// block expires sources whose TTL has run out, then pushes the window's
// flagged sources to the blocklist. A failed map operation is logged but
// does not end the run: losing mitigation is better than losing the
// measurements.
func (s *session) block(r *detector.WindowResult) {
	now := s.clock()

	if err := s.mit.Expire(now); err != nil {
		log.Printf("warning: window %d: %v", r.Epoch, err)
	}

	var (
		flagged []flow.Key
		at      []int
	)

	for i, ip := range r.IPs {
		if ip.Verdict.IsMalicious {
			flagged = append(flagged, ip.IP)
			at = append(at, i)
		}
	}

	if len(flagged) == 0 {
		return
	}

	ok, err := s.mit.Block(flagged, now)
	r.BlockedAt = time.Now()

	if err != nil {
		log.Printf("warning: window %d: %v", r.Epoch, err)
	}

	for j, i := range at {
		r.IPs[i].Blocked = ok[j]
	}
}

func (s *session) loop(clock func() time.Time) *loop {
	return &loop{
		agg:   s.agg,
		clock: clock,
		wait:  s.wait,
		tick:  s.tick,
	}
}

// wait sleeps for d, or until the run is interrupted.
func (s *session) wait(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-t.C:
		return true
	case <-s.stop:
		return false
	}
}

func (s *session) tick() {
	if s.opt.quiet {
		return
	}

	if now := time.Now(); now.After(s.next) {
		st := s.agg.Stats()
		log.Printf("%v: %d packets, %d windows (%d flagged, %d discarded)",
			now.Sub(s.started).Round(time.Second), s.stats.Packets, st.Closed, s.stats.FlaggedWindows, st.Discarded)
		s.next = now.Add(progressInterval)
	}
}

// interruptOn makes Ctrl-C end the run cleanly: the windows closed so far
// are kept and run.json is still written.
func (s *session) interruptOn() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		signal.Stop(interrupt)
		close(s.stop)
	}()
}

// finish drops the incomplete last window, closes the CSV files and fills
// in the stats.
func (s *session) finish(finished time.Time) error {
	if d, ok := s.agg.Finish(); ok {
		d.Start = d.Start.Add(-s.taiOffset)
		d.End = d.End.Add(-s.taiOffset)

		s.stats.Dropped = &d
		log.Printf("dropped the incomplete last window %d (%d packets); it is not in windows.csv", d.Epoch, d.Packets)
	}

	err := s.sink.Close()

	s.stats.Window = s.agg.Stats()
	s.stats.TrackedIPs = uint64(s.ev.Detector().TrackedIPs())
	s.stats.EvictedIPs = s.ev.Detector().EvictedIPs()
	if s.mit != nil {
		st := s.mit.Stats()
		s.stats.Blocklist = &st
	}
	s.stats.WallSeconds = finished.Sub(s.started).Seconds()
	if s.stats.WallSeconds > 0 {
		s.stats.PacketsPerSecond = float64(s.stats.Packets) / s.stats.WallSeconds
	}

	return err
}

func runKernel(opt options, wcfg window.Config, dcfg detector.Config, mcfg mitigate.Config) error {
	clock, err := taiClock()
	if err != nil {
		return err
	}

	// The maps are opened before the output files are created, so a
	// missing XDP program leaves no half-written results behind.
	src, closer, err := openKernel(opt.pinDir)
	if err != nil {
		return err
	}
	defer closer.Close()

	// The blocklist is cleared even when blocking is off, so sources an
	// earlier run blocked do not have their packets dropped in this one.
	bl, blCloser, err := openBlocklist(opt.pinDir)
	if err != nil {
		return err
	}
	defer blCloser.Close()

	var mit *mitigate.Mitigator

	if opt.block {
		if mit, err = mitigate.New(mcfg, bl); err != nil {
			return err
		}
	}

	// CLOCK_TAI is ahead of the wall clock by a whole number of leap
	// seconds, or by zero when the kernel's TAI offset was never set.
	taiOffset := clock().Sub(time.Now()).Round(time.Second)

	s, err := newSession(opt, wcfg, dcfg, src, mit, clock, taiOffset)
	if err != nil {
		return err
	}

	info := &report.Live{
		Interface:        opt.iface,
		PinDir:           opt.pinDir,
		TAIOffsetSeconds: int64(taiOffset / time.Second),
	}
	if opt.duration > 0 {
		info.Duration = opt.duration.String()
	}

	var nicStart capture.NICCounters

	if opt.iface != "" {
		var warn error

		nicStart, warn, err = capture.ReadNICCounters(opt.iface)
		if err != nil {
			info.NICWarnings = append(info.NICWarnings, "start: "+err.Error())
		} else if warn != nil {
			info.NICWarnings = append(info.NICWarnings, "start: "+warn.Error())
		}
	}

	s.interruptOn()

	var end time.Time
	if opt.duration > 0 {
		end = clock().Add(opt.duration)
	}

	log.Printf("reading %s into %s (TAI offset %v)", opt.pinDir, opt.outDir, taiOffset)

	endReason, loopErr := s.loop(clock).run(end)
	finished := time.Now()

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

	finishErr := s.finish(finished)

	run := &report.Run{
		Tool:       "detector",
		Version:    report.CurrentVersion(),
		Args:       os.Args[1:],
		StartedAt:  s.started,
		FinishedAt: finished,
		EndReason:  endReason,
		Source:     "xdp",
		Config:     runConfig(wcfg, dcfg, mcfg, opt.block),
		Live:       info,
		Stats:      s.stats,
		Notes:      []string{report.TimingNote, report.ResourceNote, report.SentPacketsNote},
	}

	if opt.block {
		run.Notes = append(run.Notes, report.BlocklistNote)
	}

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

func runConfig(w window.Config, d detector.Config, m mitigate.Config, block bool) report.Config {
	c := report.Config{
		WindowLength: w.Length.String(),
		Mode:         d.Mode.String(),

		Depth: heavykeeper.Depth,
		Width: heavykeeper.Width,
		TopK:  heavykeeper.K,
		K:     w.K,

		BaseThreshold:    d.IQR.BaseThreshold,
		IQRMultiplier:    d.IQR.IQRMultiplier,
		OffsetMultiplier: d.IQR.OffsetMultiplier,
		MinSamples:       d.IQR.MinSamples,
		MaxHistorySize:   d.IQR.MaxHistorySize,
		MaxTrackedIPs:    d.IQR.MaxTrackedIPs,

		IPMode:               d.IQR.IPMode.String(),
		MaxSharedHistorySize: d.IQR.MaxSharedHistorySize,

		Block: block,
	}

	if block {
		c.BlockTTL = m.TTL.String()
		c.BlockCapacity = m.Capacity

		for _, k := range m.Allow {
			c.BlockAllow = append(c.BlockAllow, k.String())
		}
	}

	return c
}

func printSummary(r *report.Run) {
	s := r.Stats

	log.Printf("done in %.1fs (%.0f packets/s), ended: %s", s.WallSeconds, s.PacketsPerSecond, r.EndReason)
	log.Printf("  packets:  %d counted by XDP", s.Packets)

	if l := r.Live; l != nil {
		if l.NICDelta != nil {
			log.Printf("  nic:      %d received, %d dropped, %d fifo errors (see run.json for driver counters)",
				l.NICDelta["dev.rx_packets"], l.NICDelta["dev.rx_drop"], l.NICDelta["dev.rx_fifo"])
		}

		for _, w := range l.NICWarnings {
			log.Printf("  nic:      %s", w)
		}
	}

	log.Printf("  windows:  %d closed, %d empty, %d evaluated, %d flagged", s.Window.Closed, s.Window.Empty, s.EvaluatedWindows, s.FlaggedWindows)
	log.Printf("  behind:   %d windows discarded, %d jumps over %d epochs", s.Window.Discarded, s.Window.Jumps, s.Window.SkippedEpochs)
	log.Printf("  sources:  %d flagged IP rows, %d tracked, %d evicted (ip mode %s)",
		s.FlaggedIPRows, s.TrackedIPs, s.EvictedIPs, r.Config.IPMode)

	if b := s.Blocklist; b != nil {
		log.Printf("  blocked:  %d packets dropped; %d sources blocked, %d refreshed, %d expired, %d evicted, %d active at end (peak %d)",
			s.BlockedPackets, b.Blocked, b.Refreshed, b.Expired, b.Evicted, b.Active, b.Peak)

		if b.Errors > 0 {
			log.Printf("warning: %d blocklist operations failed; see the log above", b.Errors)
		}
	}

	// The start window is always discarded; more means the detector
	// could not keep up.
	if s.Window.Discarded > 1 || s.Window.Jumps > 0 {
		log.Printf("warning: windows were lost because the detector fell behind the kernel; see run.json")
	}
}
