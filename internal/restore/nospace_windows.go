//go:build windows

package restore

import (
	"errors"
	"syscall"
)

// The restore runs on Linux. This file exists so that `GOOS=windows go vet
// ./...` — which CI runs, and which is the only thing that type-checks the
// Windows-tagged code in this repository — does not fail with "build
// constraints exclude all Go files".
const (
	errorHandleDiskFull = syscall.Errno(39)  // ERROR_HANDLE_DISK_FULL
	errorDiskFull       = syscall.Errno(112) // ERROR_DISK_FULL
)

func isNoSpace(err error) bool {
	return errors.Is(err, errorHandleDiskFull) ||
		errors.Is(err, errorDiskFull) ||
		errors.Is(err, syscall.ENOSPC)
}

func noSpaceErrno() error { return errorDiskFull }
