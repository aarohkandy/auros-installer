//go:build !windows

package copyengine

import (
	"errors"
	"syscall"
)

// isNoSpace reports whether err means the destination volume filled up.
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}
