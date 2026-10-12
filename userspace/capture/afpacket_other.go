//go:build !linux

package capture

import (
	"errors"
	"time"
)

// LiveConfig configures a live capture.
type LiveConfig struct {
	Interface   string
	Promiscuous bool
	RecvBuffer  int
}

// LiveStats describes a live capture as seen from the kernel.
type LiveStats struct {
	RecvBuffer     int    `json:"recv_buffer_bytes"`
	KernelTotal    uint64 `json:"kernel_total"`
	KernelDropped  uint64 `json:"kernel_dropped"`
	KernelStamps   uint64 `json:"kernel_timestamps"`
	FallbackStamps uint64 `json:"fallback_timestamps"`
}

// LiveSource is only available on Linux. This stub lets the rest of the
// code build on a development machine, where trace files work as usual.
type LiveSource struct{}

var errNotLinux = errors.New("capture: live capture requires Linux")

// OpenLive always fails outside Linux.
func OpenLive(LiveConfig) (*LiveSource, error) {
	return nil, errNotLinux
}

func (*LiveSource) Next() (Packet, error)         { return Packet{}, ErrClosed }
func (*LiveSource) Stats() Stats                  { return Stats{} }
func (*LiveSource) Close() error                  { return nil }
func (*LiveSource) SetDeadline(time.Time) error   { return errNotLinux }
func (*LiveSource) LiveStats() (LiveStats, error) { return LiveStats{}, errNotLinux }
