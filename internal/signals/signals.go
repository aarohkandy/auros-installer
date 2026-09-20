// Package signals names the signals that stop a run, and nothing else.
//
// It exists for one reason. `syscall` is the package that can reach any Win32
// export — DeleteFileW, SetFirmwareEnvironmentVariableW — without importing
// internal/sysdisk and without importing os/exec, so
// internal/safety/wall_test.go confines it to the packages that genuinely need
// Win32. But the command still has to catch SIGTERM, and `syscall.SIGTERM` is
// the only name the standard library offers for it.
//
// Rather than punching a hole in the wall for cmd/auros-migrate, the hole is
// this package: one file, no state, no behaviour, whose entire content is a list
// of signal values. TestWall_ForbiddenImports allows `syscall` here and then
// checks that the only identifiers this package takes from it are signal names,
// so the exemption cannot quietly grow into a second path to the system disk.
package signals

import (
	"os"
	"syscall"
)

// Interrupting is the set of signals that mean "stop this run". A run stopped
// anywhere in phases 1-5 is a process exit that changed nothing; phase 6 unwinds
// its completed steps on a context that this cancellation cannot reach.
func Interrupting() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}
