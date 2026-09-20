//go:build !windows

package fault

import "errors"

// The guest half of the injector exists only on Windows.
//
// This build is what lets the catalogue, the pin arithmetic and `faultctl plan` be compiled, reviewed
// and exercised on the operator's macOS or Linux machine — which is useful, and is also the closest
// this harness ever gets to the operator's own machine. Everything that damages anything is Windows-only
// and refuses to exist here.

var errGuestUnavailable = errors.New(
	"fault: the guest fault executor is Windows-only. Nothing in this package damages anything on a " +
		"non-Windows host, by construction")

func NewGuestControl(destVolumeRoot string) (GuestControl, error) {
	return nil, errGuestUnavailable
}

func VolumeSerial(path string) (string, error) { return "", errGuestUnavailable }
