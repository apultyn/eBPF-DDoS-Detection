//go:build !linux

package resource

import "errors"

var errNotLinux = errors.New("resource: machine-wide CPU time is read from /proc/stat and needs Linux")

// readHostTimes always fails: the host columns are left empty.
func readHostTimes(*hostTimes) error {
	return errNotLinux
}
