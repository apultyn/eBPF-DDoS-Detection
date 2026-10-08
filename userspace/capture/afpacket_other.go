//go:build !linux

package capture

import "errors"

// LiveConfig configures a live capture.
type LiveConfig struct {
	Interface   string
	Promiscuous bool
}

// LiveSource is only available on Linux. This stub lets the rest of the
// code build on a development machine, where trace files work as usual.
type LiveSource struct{}

// OpenLive always fails outside Linux.
func OpenLive(LiveConfig) (*LiveSource, error) {
	return nil, errors.New("capture: live capture requires Linux")
}

func (*LiveSource) Next() (Packet, error) { return Packet{}, ErrClosed }
func (*LiveSource) Stats() Stats          { return Stats{} }
func (*LiveSource) Close() error          { return nil }
