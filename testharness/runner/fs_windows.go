//go:build windows

package main

import "errors"

// The runner is the VM host. It runs on Linux (homebase) or macOS, never inside the guest. This stub
// exists so the package still builds on Windows for review; it does not pretend to measure anything.
func freeSpaceBytes(dir string) (int64, error) {
	return 0, errors.New("the runner is the VM host and is not supported on Windows")
}
