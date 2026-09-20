//go:build !windows || !auros_arm_enabled

package sysdisk

import "context"

// execute is the compiled-out implementation. Every binary CI produces gets this
// one. It performs nothing and says so.
//
// Two conditions have to hold before the other implementation is reachable: the
// target must be Windows, and the binary must have been built with
// `-tags auros_arm_enabled`. A Linux CI runner and an ordinary `go build` both
// fail the second, so the tests in this repository — including the abort-path
// tests, which are the majority — run against a binary that is incapable of
// touching a system disk.
func execute(_ context.Context, _ Intent) (*Outcome, error) {
	return &Outcome{Err: ErrNotValidated}, ErrNotValidated
}
