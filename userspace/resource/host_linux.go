package resource

import "os"

// readHostTimes reads the machine's CPU times from /proc/stat into t.
func readHostTimes(t *hostTimes) error {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return err
	}
	defer f.Close()

	return parseProcStat(f, t)
}
