//go:build !windows

package winenv

import (
	"os"
	"path/filepath"
)

// New returns the synthetic environment on non-Windows platforms.
//
// It is not a panic and not an error. The whole safety core has to be runnable
// and testable on Linux CI, and the tool's dry-run demonstration mode runs here
// too. What it must never do is pretend to be Windows: Platform() says
// "synthetic", and every caller that reports the mode to the user reports that.
func New() Env {
	base := os.TempDir()
	sys := filepath.Join(base, "auros-synth-system") + string(filepath.Separator)
	dest := filepath.Join(base, "auros-synth-dest") + string(filepath.Separator)
	return NewSynthetic(DefaultSynthetic(sys, dest))
}

// Available reports whether the real Windows surface is present.
func Available() bool { return false }
