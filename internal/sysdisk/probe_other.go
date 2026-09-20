//go:build !windows

package sysdisk

import "context"

// probeBitLocker cannot answer off Windows. It says so rather than guessing, and
// Unknown is treated as protected.
func probeBitLocker(_ context.Context, _ string) (BitLocker, error) {
	return BitLockerUnknown, ErrProbeUnavailable
}
