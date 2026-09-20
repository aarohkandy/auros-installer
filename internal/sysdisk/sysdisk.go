// Package sysdisk is the ONLY package in this repository permitted to touch the
// system disk or firmware variables.
//
// # The wall
//
// Nothing imports this package except internal/safety, and
// internal/safety/wall_test.go fails the build if anything else ever does. That
// test is the wall. It is not a comment, a lint rule or a convention: it is a
// test that parses every .go file in the repository and reports the file and
// line of any other importer.
//
// The single entry point into this package from the rest of the program is
// safety.Arm, which cannot be called without a safety.VerifiedArchive, which
// cannot be constructed without a successful phase 5.
//
// # Scope (DECISIONS.md D13)
//
// This package does NOT write boot media. SAFETY.md phase 6 step 2 says "write
// the boot medium"; D13 removed that from the Windows side, because doing it
// with no dependencies means an elevated raw handle on \\.\PhysicalDriveN,
// FSCTL_DISMOUNT_VOLUME on every child volume, a hand-rolled GPT and FAT32 ESP,
// and sector-aligned raw writes — irreversibly destructive, on a machine we do
// not own, with no undo. Install media is produced elsewhere.
//
// What is left is three things, each individually reversible:
//
//  1. Suspend BitLocker for exactly one boot. Unconditional, never optional.
//     On TPM 1.2 — common across 2012–2015 — changing firmware boot order
//     triggers a recovery-key prompt, and stranding a user at a recovery prompt
//     ON THE ABORT PATH is the worst outcome this tool can produce.
//  2. Point the next boot at media the user already made.
//  3. Restart.
//
// # Arming is disabled at compile time
//
// The privileged implementations are behind the `auros_arm_enabled` build tag.
// A binary built without it — which is every binary CI produces and every binary
// anyone gets by running `go build` — physically cannot execute them; Execute
// returns ErrNotValidated. Turning it on is a deliberate act recorded in a build
// command, not a flag someone flips at 2am.
//
// It stays off until SPEC §10 gate 3 is met: 100 clean migrations and 20 clean
// aborts against a Windows VM (SPEC §4.7 — never the operator's own machine).
package sysdisk

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	// ErrNotValidated is returned when a binary built without the
	// `auros_arm_enabled` tag is asked to perform a privileged step.
	ErrNotValidated = errors.New(
		"sysdisk: privileged steps are compiled out of this binary " +
			"(build tag auros_arm_enabled is not set); refusing to touch the system disk")

	// ErrNoSystemVolume is returned for an intent that does not name the volume
	// it intends to act on. Acting on "the C: drive" rather than on a specific
	// volume GUID is how a subst'd letter gets written to.
	ErrNoSystemVolume = errors.New("sysdisk: intent has no system volume GUID")

	// ErrNotCommitted is returned when Execute is called outside commit mode.
	// Defence in depth: safety.Arm already refuses, and so does this.
	ErrNotCommitted = errors.New("sysdisk: refusing to execute outside commit mode")

	// ErrBadMount is returned for a mount point that cannot be a single command
	// argument. A volume mounted at "C:\Program Files\Data" split on spaces
	// hands manage-bde "-disable C:\Program" and a stray "Files\Data", in the
	// middle of the one phase allowed to change the machine.
	ErrBadMount = errors.New("sysdisk: system mount point contains whitespace or quotes")
)

// BitLocker is the phase 1 finding about the system volume, as a tri-state.
//
// It is not a bool, and the zero value is not "off". A 2014 school laptop with
// TPM 1.2 is the machine this whole step exists for, and "we could not tell"
// must behave like "yes, it is on" — suspending BitLocker on a machine that is
// not using it is a no-op, while failing to suspend it on a machine that is
// leaves a user at a recovery prompt nobody has the key for. The asymmetry is
// total, so the default is total too.
type BitLocker int

const (
	// BitLockerUnknown is the zero value and is treated as PROTECTED.
	BitLockerUnknown BitLocker = iota
	// BitLockerOn means phase 1 established that BitLocker protects the system
	// volume.
	BitLockerOn
	// BitLockerOff means phase 1 established that it does not. This is the ONLY
	// value that omits the suspend step.
	BitLockerOff
)

func (b BitLocker) String() string {
	switch b {
	case BitLockerOn:
		return "on"
	case BitLockerOff:
		return "off"
	default:
		return "unknown (treated as on)"
	}
}

// SuspendNeeded reports whether the suspend step must be planned. It is written
// as "not positively off" rather than "on" on purpose.
func (b BitLocker) SuspendNeeded() bool { return b != BitLockerOff }

// Intent is a fully-resolved description of what crossing the wall will do. It
// is a plain value with no behaviour, so it can be printed, logged and shown to
// the user in dry-run mode without any risk of performing anything.
type Intent struct {
	// SystemVolumeGUID identifies the volume by GUID, never by drive letter.
	SystemVolumeGUID string

	// SystemMount is the mount point, for display and for the manage-bde
	// argument. Display only: identity is the GUID.
	SystemMount string

	// BitLocker is the phase 1 finding. The suspend step runs unless this is
	// positively BitLockerOff.
	BitLocker BitLocker

	// BootMediaGUID is the firmware boot entry for media THE USER ALREADY MADE
	// (D13). Empty means we do not touch the boot order at all and send the user
	// to the firmware menu instead, which is a first-class path rather than an
	// error case.
	BootMediaGUID string

	// Restart requests the final reboot.
	Restart bool

	// Commit must be true. Dry run never reaches this package.
	Commit bool
}

// Step is one reversible action. Reversal is not documentation: SAFETY.md
// requires every step to be individually reversible and the reversal to be
// tested more than the action, so the reversal is carried alongside the action
// and is what the abort path runs.
//
// The action is an ARGUMENT VECTOR, not a command line. The string shown in dry
// run is rendered from the argv, so what the user reads is derived from what the
// machine runs rather than re-parsed into it. Nothing anywhere splits a command
// string on spaces.
type Step struct {
	ID           string
	Description  string
	Argv         []string // exactly what runs
	ReversalArgv []string // exactly what undoes it
	Note         string   // human aside shown after the reversal, never executed
	Destructive  bool
}

// Command renders Argv for display and for the run log.
func (s Step) Command() string { return renderArgv(s.Argv) }

// Reversal renders ReversalArgv for display, with its human note appended.
func (s Step) Reversal() string {
	r := renderArgv(s.ReversalArgv)
	if s.Note != "" {
		r += "   (" + s.Note + ")"
	}
	return r
}

// renderArgv quotes any argument that needs it, so a mount point with a space in
// it is displayed as one argument because it IS one argument.
func renderArgv(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		if a == "" || strings.ContainsAny(a, " \t\"") {
			a = strconv.Quote(a)
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

// Steps computes the plan. It is pure: no I/O, no side effects, no privileges.
// Dry-run mode prints precisely this and performs none of it.
func (i Intent) Steps() []Step {
	var steps []Step
	if i.BitLocker.SuspendNeeded() {
		mount := i.SystemMount
		if mount == "" {
			mount = "C:"
		}
		steps = append(steps, Step{
			ID: "bitlocker-suspend",
			Description: "Suspend BitLocker for exactly one boot, so changing the boot order " +
				"does not strand you at a recovery-key prompt (TPM 1.2 machines). " +
				"Planned whenever BitLocker is not known to be off, including when it could not be checked.",
			Argv:         []string{"manage-bde", "-protectors", "-disable", mount, "-RebootCount", "1"},
			ReversalArgv: []string{"manage-bde", "-protectors", "-enable", mount},
			Destructive:  false,
		})
	}
	if i.BootMediaGUID != "" {
		steps = append(steps, Step{
			ID:           "boot-sequence",
			Description:  "Set a ONE-TIME next boot to the install media you already made. The saved boot order is not changed.",
			Argv:         []string{"bcdedit", "/set", "{fwbootmgr}", "bootsequence", i.BootMediaGUID},
			ReversalArgv: []string{"bcdedit", "/deletevalue", "{fwbootmgr}", "bootsequence"},
			Destructive:  false,
		})
	} else {
		steps = append(steps, Step{
			ID: "firmware-menu",
			Description: "No boot entry was given, so the next boot goes to the firmware menu and " +
				"you pick the USB stick yourself. This is the reliable path: BootNext is not " +
				"honoured by every vendor's firmware.",
			Argv:         []string{"shutdown", "/r", "/fw", "/t", "0"},
			ReversalArgv: []string{"shutdown", "/a"},
			Note:         "cancels a pending restart",
			Destructive:  false,
		})
	}
	if i.Restart {
		steps = append(steps, Step{
			ID:           "restart",
			Description:  "Restart the machine.",
			Argv:         []string{"shutdown", "/r", "/t", "0"},
			ReversalArgv: []string{"shutdown", "/a"},
			Note:         "only before the restart begins",
			Destructive:  false,
		})
	}
	return steps
}

// Describe renders the plan for a human. This is what dry-run mode shows.
func (i Intent) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "system volume : %s\n", i.SystemVolumeGUID)
	fmt.Fprintf(&b, "mounted at    : %s\n", i.SystemMount)
	fmt.Fprintf(&b, "BitLocker     : %s\n", i.BitLocker)
	if i.BootMediaGUID == "" {
		b.WriteString("boot media    : none given; firmware-menu fallback\n")
	} else {
		fmt.Fprintf(&b, "boot media    : %s (made by the user; this tool does not write boot media)\n", i.BootMediaGUID)
	}
	b.WriteString("\nsteps:\n")
	for n, s := range i.Steps() {
		fmt.Fprintf(&b, "  %d. %s\n     run:  %s\n     undo: %s\n", n+1, s.Description, s.Command(), s.Reversal())
	}
	return b.String()
}

// Validate refuses an intent that is not fully specified.
func (i Intent) Validate() error {
	if i.SystemVolumeGUID == "" {
		return ErrNoSystemVolume
	}
	if strings.ContainsAny(i.SystemMount, " \t\r\n\"'") {
		return fmt.Errorf("%w: %q", ErrBadMount, i.SystemMount)
	}
	if !i.Commit {
		return ErrNotCommitted
	}
	return nil
}

// Outcome records what actually happened, step by step, so the run log shows the
// exact point a failed arm stopped and therefore exactly what needs undoing.
type Outcome struct {
	Completed []string // step IDs that ran successfully
	Failed    string   // step ID that failed, if any
	Err       error
	Reversed  []string // step IDs whose reversal ran after the failure
}

// Execute performs the intent. The implementation is selected at compile time:
// without the `auros_arm_enabled` build tag it is a function that returns
// ErrNotValidated and does nothing.
func Execute(ctx context.Context, i Intent) (*Outcome, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	return execute(ctx, i)
}
