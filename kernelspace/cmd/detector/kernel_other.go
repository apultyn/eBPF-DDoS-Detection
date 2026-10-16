//go:build !linux

package main

import (
	"errors"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/mitigate"
	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

var errNotLinux = errors.New("the kernel-space detector reads XDP maps and needs Linux")

func openKernel(string) (window.Source, kernelMaps, error) {
	return nil, nil, errNotLinux
}

func openBlocklist(string) (mitigate.Map, kernelMaps, error) {
	return nil, nil, errNotLinux
}

func taiClock() (func() time.Time, error) {
	return nil, errNotLinux
}
