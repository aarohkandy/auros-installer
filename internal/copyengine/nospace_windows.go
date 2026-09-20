//go:build windows

package copyengine

import (
	"errors"
	"syscall"
)

// Win32 error codes for a full volume. Spelled as literals because the syscall
// package does not export every ERROR_* constant, and a disk-full that is not
// recognised as a disk-full becomes a generic write error that the retry logic
// then cheerfully retries onto a disk that is still full.
const (
	errorHandleDiskFull = syscall.Errno(39)  // ERROR_HANDLE_DISK_FULL
	errorDiskFull       = syscall.Errno(112) // ERROR_DISK_FULL
)

// isNoSpace reports whether err means the destination volume filled up.
func isNoSpace(err error) bool {
	return errors.Is(err, errorHandleDiskFull) ||
		errors.Is(err, errorDiskFull) ||
		errors.Is(err, syscall.ENOSPC)
}
