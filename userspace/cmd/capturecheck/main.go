// Command capturecheck reads packets from a trace file or a live interface
// and reports what the capture layer sees. It is meant for checking a
// FABRIC node or a new trace before running the detector on it.
//
//	capturecheck -pcap equinix-chicago.dirA.20190117-130000.UTC.anon.pcap.gz
//	sudo capturecheck -iface ens7
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/capture"
)

func main() {
	pcapPath := flag.String("pcap", "", "read packets from this pcap file (.pcap or .pcap.gz)")
	iface := flag.String("iface", "", "capture live on this interface (Linux, needs root)")
	promisc := flag.Bool("promisc", false, "put the interface in promiscuous mode")
	flag.Parse()

	if (*pcapPath == "") == (*iface == "") {
		fmt.Fprintln(os.Stderr, "capturecheck: give exactly one of -pcap or -iface")
		os.Exit(2)
	}

	var (
		src capture.Source
		err error
	)

	if *pcapPath != "" {
		src, err = capture.OpenPcap(*pcapPath)
	} else {
		src, err = capture.OpenLive(capture.LiveConfig{Interface: *iface, Promiscuous: *promisc})
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "capturecheck:", err)
		os.Exit(1)
	}

	// Ctrl-C closes the source, which unblocks Next on a live capture.
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	go func() {
		<-interrupt
		src.Close()
	}()

	var (
		v4, v6      uint64
		bytes       uint64
		first, last time.Time
	)

	start := time.Now()

	for {
		p, err := src.Next()
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, capture.ErrClosed) {
				fmt.Fprintln(os.Stderr, "capturecheck:", err)
			}
			break
		}

		if first.IsZero() {
			first = p.Timestamp
		}
		last = p.Timestamp

		if p.Src.Is4() {
			v4++
		} else {
			v6++
		}

		bytes += uint64(p.Length)
	}

	src.Close()

	st := src.Stats()
	elapsed := time.Since(start)
	span := last.Sub(first)

	fmt.Printf("packets:   %d (ipv4 %d, ipv6 %d)\n", st.Packets, v4, v6)
	fmt.Printf("skipped:   %d non-IP or truncated frames\n", st.Skipped)
	fmt.Printf("bytes:     %d on the wire\n", bytes)
	fmt.Printf("time span: %v (%s to %s)\n", span, first.UTC().Format(time.RFC3339Nano), last.UTC().Format(time.RFC3339Nano))

	if span > 0 {
		fmt.Printf("rate:      %.0f packets/s in the capture\n", float64(st.Packets)/span.Seconds())
	}

	fmt.Printf("read in:   %v (%.0f packets/s)\n", elapsed, float64(st.Packets)/elapsed.Seconds())
}
