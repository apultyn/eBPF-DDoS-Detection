//go:build !linux

package main

import (
	"errors"
	"time"
)

var errNotLinux = errors.New("the XDP blocklist needs Linux")

func openBlocklist(string) (blocklistMap, error) {
	return nil, errNotLinux
}

func taiClock() (func() time.Time, error) {
	return nil, errNotLinux
}
