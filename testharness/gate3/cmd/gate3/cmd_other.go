//go:build !windows

package main

import "errors"

// Everything that touches a real machine is Windows-only and refuses to exist
// anywhere else, the same shape testharness/fault uses. `suite`, `plan` and
// `aggregate` are the commands that work on a laptop: the catalogue, the pin
// arithmetic and the verdict, none of which need a Windows machine to be
// reviewed or re-checked.
var errWindowsOnly = errors.New(
	"this command runs the installer against a real, disposable Windows machine and exists only on " +
		"Windows. `gate3 suite`, `gate3 plan` and `gate3 aggregate` work everywhere")

func cmdMintToken(_ []string) error         { return errWindowsOnly }
func cmdPrepare(_ []string) error           { return errWindowsOnly }
func cmdRun(_ []string) error               { return errWindowsOnly }
func cmdProveRed(_ []string) error          { return errWindowsOnly }
func cmdFormatDestination(_ []string) error { return errWindowsOnly }
