//go:build !windows

package restore

import (
	"errors"
	"syscall"
)

// isNoSpace reports whether err means the volume we are restoring ONTO filled
// up. It is the same predicate internal/copyengine uses for the Windows side,
// deliberately duplicated rather than shared: copyengine is a phase 1-5 package
// and this is phase 7, and a one-line predicate is not worth a dependency
// between the two halves of the product.
func isNoSpace(err error) bool {
	return errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT)
}

// noSpaceErrno is the errno a full volume reports on this platform. It exists
// so that the disk-full test can produce an error isNoSpace really recognises,
// rather than a string the test and the code agreed on between themselves.
func noSpaceErrno() error { return syscall.ENOSPC }
