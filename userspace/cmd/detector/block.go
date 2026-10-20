package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/userspace/blocklist"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/detector"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/flow"
	"github.com/apultyn/eBPF-DDoS-Detection/userspace/mitigate"
)

// blocklistMap is the pinned blocklist of blocklist.c: the entries the
// Mitigator edits, the totals of what XDP dropped, and the maps' memory.
// On Linux it is a *blocklist.Blocklist.
type blocklistMap interface {
	mitigate.Map
	kernelMaps

	// Totals returns what XDP has dropped since blocklist.o was loaded.
	Totals() (blocklist.Totals, error)
}

// clearStaleBlocklist clears the XDP blocklist when -block is off, if it
// is pinned at all, and reports whether it was. Sources an earlier run
// blocked would otherwise go on being dropped in this one, while it
// reports no blocking.
func clearStaleBlocklist(pinDir string) (pinned bool, err error) {
	bl, err := openBlocklist(pinDir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	log.Printf("note: cleared the XDP blocklist in %s; -block is off, so nothing is added to it", pinDir)

	return true, bl.Close()
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

// countBlocked sets what XDP dropped since the previous window closed.
// The drops are counted when the window closes, not by the time of the
// dropped packets, so a window's figure can include packets dropped
// during the grace period after its end.
func (s *session) countBlocked(r *detector.WindowResult) {
	t, err := s.bl.Totals()
	if err != nil {
		log.Printf("warning: window %d: %v", r.Epoch, err)
		return
	}

	r.BlockedPackets = t.Packets - s.lastBlocked.Packets
	r.BlockedBytes = t.Bytes - s.lastBlocked.Bytes
	s.lastBlocked = t

	s.stats.BlockedPackets += r.BlockedPackets
}
