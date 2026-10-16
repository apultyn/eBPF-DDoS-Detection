//go:build !linux

package main

import (
	"errors"
	"io"
	"time"

	"github.com/apultyn/eBPF-DDoS-Detection/kernelspace/window"
)

var errNotLinux = errors.New("the kernel-space detector reads XDP maps and needs Linux")

func openKernel(string) (window.Source, io.Closer, error) {
	return nil, nil, errNotLinux
}

func taiClock() (func() time.Time, error) {
	return nil, errNotLinux
}
