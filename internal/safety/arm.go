package safety

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/sysdisk"
	"github.com/aarohkandy/auros-installer/internal/verify"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// This file contains the two sides of the wall.
//
//	Verify  — the ONLY place a VerifiedArchive is constructed.
//	Arm     — the ONLY function permitted to touch the system disk, and the only
//	          importer of internal/sysdisk in the whole repository.
//
// internal/safety/wall_test.go fails if any other package ever imports
// internal/sysdisk. That test is the wall.

var (
	// ErrVerificationFailed means phase 5 found a disagreement. The report says
	// exactly which files.
	ErrVerificationFailed = errors.New("safety: verification failed; no VerifiedArchive issued")

	// ErrQuarantineNotEmpty means files could not be copied or verified.
	// SAFETY.md phase 5: the run does not proceed to phase 6 unless the
	// unresolved count is zero.
	ErrQuarantineNotEmpty = errors.New("safety: unresolved quarantined files remain; refusing to issue a VerifiedArchive")

	// ErrArchiveOnSystemVolume means the second copy is on the disk we are about
	// to change, which means there is no second copy.
	ErrArchiveOnSystemVolume = errors.New("safety: the archive is on the system volume; that is not a second copy")

	// ErrEmptyArchive means the manifest has no files. Arming on the strength of
	// a verification that verified nothing is the failure mode this catches.
	// There is no flag that turns it off: see verifyOption.
	ErrEmptyArchive = errors.New("safety: refusing to issue a VerifiedArchive for an empty manifest")

	// ErrWrongVolume means the steps about to run are aimed at a volume other
	// than the one the archive was verified against. The proof and the target
	// must be the same machine's system disk or the proof is about something
	// else.
	ErrWrongVolume = errors.New("safety: refusing to arm: the plan targets a volume the archive did not verify against")

	// ErrFirmwareUnknown means the run never established the firmware facts
	// SAFETY.md phase 1 requires. Arming on facts the tool admits it did not
	// check is arming blind, and the specific blindness that matters is
	// BitLocker: the suspend step exists to stop a TPM 1.2 machine landing at a
	// recovery prompt nobody has the key for.
	ErrFirmwareUnknown = errors.New("safety: refusing to arm: the firmware facts were never established (SAFETY.md phase 1)")

	// ErrBadSystemMount means the mount point carries whitespace or quotes and
	// cannot be rendered into a command line unambiguously.
	ErrBadSystemMount = errors.New("safety: refusing to arm: the system mount point is not a usable argument")
)

// VerifyRequest is the input to phase 5.
type VerifyRequest struct {
	// Dest is the destination, as PROVEN by a Resolver. It is not a path and a
	// GUID the caller supplies separately — those two can disagree, and a run
	// where they disagree is a run that verifies the system disk against itself
	// and calls it a second copy. A Destination carries a resolved path and the
	// identity of the volume that really holds it, and it cannot be constructed
	// outside this package.
	Dest Destination
	// System is the volume we must not have written to.
	System winenv.Volume
	// Manifest is what phase 4 says it wrote.
	Manifest *manifest.Manifest
	// Quarantine holds everything phase 4 could not copy. Phase 5 adds to it.
	Quarantine *quarantine.Set
	// Log is the run log on the destination volume.
	Log *runlog.Logger
	// BufSize, Progress and Clock are passed through to the verifier.
	BufSize  int
	Progress func(done, total int)
	Clock    func() time.Time

	// allowEmpty permits a zero-file archive. It is UNEXPORTED and settable only
	// through an unexported option inside this package, because it is the off
	// switch for ErrEmptyArchive and an exported off switch is not a rule. The
	// same technique copyengine uses for its hookDst.
	allowEmpty bool
}

// verifyOption is the in-package-only way to reach the unexported fields of a
// VerifyRequest. There is deliberately no exported option type: a caller in
// another package cannot name these, cannot set them, and cannot turn off a
// refusal.
type verifyOption func(*VerifyRequest)

// withAllowEmpty exists for tests of the machinery itself. A real run with
// nothing to copy has nothing to protect and must not arm anything.
func withAllowEmpty() verifyOption { return func(r *VerifyRequest) { r.allowEmpty = true } }

// Verify performs SAFETY.md phase 5 and, on complete success, issues the
// VerifiedArchive.
//
// This is the only function in the program that constructs a VerifiedArchive.
// Go enforces that for us: the struct's fields are unexported, so no other
// package can build one, and within this package this is the only composite
// literal that sets valid: true.
//
// It refuses to issue one when:
//   - verification could not run at all (returns the error),
//   - any file disagreed by count, size or digest,
//   - any quarantined file is still unresolved,
//   - the archive turns out to be on the system volume,
//   - the manifest is empty.
//
// On every one of those paths the system disk is untouched, because the code
// that can touch it is on the other side of a value this function did not
// return.
func Verify(ctx context.Context, m *Machine, req VerifyRequest, opts ...verifyOption) (VerifiedArchive, *verify.Report, error) {
	if m == nil {
		return VerifiedArchive{}, nil, errors.New("safety: no state machine")
	}
	for _, o := range opts {
		o(&req)
	}
	if err := m.Advance(PhaseVerify); err != nil {
		return VerifiedArchive{}, nil, err
	}
	clock := req.Clock
	if clock == nil {
		clock = time.Now
	}

	logf := func(kind string, f runlog.Fields) {
		if req.Log != nil {
			f["run_id"] = m.RunID()
			req.Log.Event(PhaseVerify.String(), kind, f)
		}
	}

	if req.Manifest == nil {
		return VerifiedArchive{}, nil, errors.New("safety: no manifest to verify against")
	}
	if req.Manifest.Len() == 0 && !req.allowEmpty {
		logf("refused", runlog.Fields{"reason": "empty-manifest"})
		return VerifiedArchive{}, nil, ErrEmptyArchive
	}

	// The archive must not be on the system volume. Phase 3 already established
	// this; checking again here is deliberate. This is the function that mints
	// the proof, and a proof should not depend on an earlier function having
	// been called correctly.
	//
	// "Again" means again from the disk, not again from the same two strings:
	// Reassert re-resolves the destination path and re-asks the operating system
	// which volume holds it. A junction swapped in after phase 3 changes the
	// answer here, and the run stops with no proof minted.
	if !req.Dest.Resolved() {
		logf("refused", runlog.Fields{"reason": "destination-not-resolved"})
		return VerifiedArchive{}, nil, ErrDestinationNotResolved
	}
	if err := req.Dest.Reassert(); err != nil {
		logf("refused", runlog.Fields{"reason": "destination-identity-changed", "error": err.Error()})
		return VerifiedArchive{}, nil, err
	}
	destRoot := req.Dest.Dir()
	dg, sg := normalizeGUID(req.Dest.Volume().GUID), normalizeGUID(req.System.GUID)
	if dg == "" || sg == "" {
		logf("refused", runlog.Fields{"reason": "volume-identity-unknown", "dest": dg, "system": sg})
		return VerifiedArchive{}, nil, ErrDestinationUnidentified
	}
	if dg == sg {
		logf("refused", runlog.Fields{"reason": "archive-on-system-volume", "volume": dg})
		return VerifiedArchive{}, nil, ErrArchiveOnSystemVolume
	}

	rep, err := verify.Run(ctx, verify.Options{
		DestRoot:   destRoot,
		Manifest:   req.Manifest,
		Quarantine: req.Quarantine,
		BufSize:    req.BufSize,
		Progress:   req.Progress,
		Clock:      clock,
	})
	if err != nil {
		logf("error", runlog.Fields{"error": err.Error()})
		return VerifiedArchive{}, rep, err
	}

	logf("report", runlog.Fields{
		"manifest_count":    rep.ManifestCount,
		"destination_count": rep.DestinationCount,
		"checked":           rep.Checked,
		"retried":           rep.Retried,
		"disagreements":     len(rep.Disagreements),
	})

	if !rep.Clean() {
		return VerifiedArchive{}, rep, fmt.Errorf("%w: %d disagreement(s)", ErrVerificationFailed, len(rep.Disagreements))
	}
	if req.Quarantine != nil && req.Quarantine.Unresolved() > 0 {
		n := req.Quarantine.Unresolved()
		logf("refused", runlog.Fields{"reason": "quarantine-not-empty", "unresolved": n})
		return VerifiedArchive{}, rep, fmt.Errorf("%w: %d file(s)", ErrQuarantineNotEmpty, n)
	}

	at := clock()
	va := VerifiedArchive{
		valid:            true, // the only place in the program this is set
		runID:            m.RunID(),
		destRoot:         destRoot,
		destVolumeGUID:   req.Dest.Volume().GUID,
		systemVolumeGUID: req.System.GUID,
		systemMount:      req.System.Mount,
		manifestDigest:   req.Manifest.Digest(),
		fileCount:        req.Manifest.Len(),
		totalBytes:       req.Manifest.TotalBytes(),
		verifiedAt:       at,
	}

	// SAFETY.md's "observable, logged moment where the data exists twice and the
	// original disk has not been touched". This is that line in the log.
	logf("verified", runlog.Fields{
		"file_count":            va.fileCount,
		"total_bytes":           va.totalBytes,
		"manifest_digest":       va.manifestDigest,
		"dest_volume":           va.destVolumeGUID,
		"dest_root":             va.destRoot,
		"system_volume":         va.systemVolumeGUID,
		"system_disk_untouched": !req.Dest.OnSystemVolume(),
		"note":                  "the data now exists in two places; system_disk_untouched above is measured, not asserted",
	})
	return va, rep, nil
}

// Step mirrors sysdisk.Step so that callers can display the arm plan without
// importing internal/sysdisk. That import is the thing the wall test forbids, so
// the type is re-declared here rather than re-exported.
type Step struct {
	ID          string
	Description string
	// Argv is exactly what runs, already split. Command below is rendered FROM
	// Argv for display, so the string the user reads cannot drift from the
	// argument vector the machine executes.
	Argv         []string
	ReversalArgv []string
	Command      string
	Reversal     string
}

// ArmRequest describes what crossing the wall will do. It deliberately has no
// "commit" field: the mode comes from the Machine, which took it at
// construction and has no setter.
type ArmRequest struct {
	// BitLocker is the phase 1 finding, as a tri-state. It is NOT a bool:
	// collapsing "we did not check" into "no" is how a TPM 1.2 laptop reaches a
	// recovery prompt with nobody holding the key. Unknown is the zero value and
	// is treated as PROTECTED, so a caller that forgets this field gets the
	// safe behaviour rather than the dangerous one.
	BitLocker winenv.TriState

	// FirmwareKnown records whether phase 1 actually established the firmware
	// facts. Commit mode refuses without it (ErrFirmwareUnknown).
	FirmwareKnown bool

	// BootMediaGUID is a firmware boot entry for media THE USER ALREADY MADE.
	// DECISIONS.md D13: this tool does not write boot media. Empty means the
	// firmware-menu path, which is a first-class route, not an error case.
	BootMediaGUID string
	Restart       bool
	Log           *runlog.Logger
}

// ArmResult is what happened, or what would have happened.
type ArmResult struct {
	Mode      Mode
	Steps     []Step
	Performed bool
	Completed []string
	Failed    string
	Reversed  []string
}

// Describe renders the result for the user, always stating the mode.
func (r *ArmResult) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mode: %s\n", r.Mode)
	switch {
	case r.Performed:
		b.WriteString("performed:\n")
	case r.Failed != "":
		// Something ran and then stopped. Saying "nothing was performed" here
		// would be the same class of lie this file spent a release removing.
		fmt.Fprintf(&b, "STOPPED at step %q. What had already run was reversed.\n", r.Failed)
	default:
		b.WriteString("no step below was performed; nothing on this machine was changed.\n")
		b.WriteString("this is what --commit would do:\n")
	}
	for n, s := range r.Steps {
		fmt.Fprintf(&b, "  %d. %s\n     run:  %s\n     undo: %s\n", n+1, s.Description, s.Command, s.Reversal)
	}
	if r.Failed != "" {
		fmt.Fprintf(&b, "\nFAILED at step %q. Reversed: %s\n", r.Failed, strings.Join(r.Reversed, ", "))
	}
	return b.String()
}

// Arm is the only function in this program permitted to write to the system disk
// or to firmware variables, and internal/safety is the only package permitted to
// import internal/sysdisk.
//
// It cannot be called without a VerifiedArchive. A VerifiedArchive cannot be
// obtained except from Verify. Verify does not return one unless every file was
// re-read from the destination and matched by count, size and SHA-256, and no
// quarantined file is unresolved. That chain is the invariant, expressed in
// types rather than in checks.
//
// In dry-run mode — the default — it computes and returns the plan and performs
// none of it, and the Machine does not record the wall as crossed.
//
// Even in commit mode, the privileged implementation is compiled out unless the
// binary was built with `-tags auros_arm_enabled`, which no CI build and no
// ordinary `go build` sets. See internal/sysdisk.
func Arm(ctx context.Context, m *Machine, va VerifiedArchive, req ArmRequest) (res *ArmResult, err error) {
	if m == nil {
		return nil, errors.New("safety: no state machine")
	}
	// Check the token before anything else, so the most important refusal is
	// also the first one and does not depend on any other state being right.
	if !va.ok() {
		return nil, ErrNotVerified
	}

	logf := func(kind string, f runlog.Fields) {
		if req.Log != nil {
			f["run_id"] = m.RunID()
			f["mode"] = m.Mode().String()
			req.Log.Event(PhaseArm.String(), kind, f)
		}
	}

	// The volume the steps will act on comes from the PROOF, not from the
	// caller. There is no field on ArmRequest that names a volume, so there is
	// no way to hand Arm a genuine archive and aim it at a different disk — in
	// particular at the disk holding the only second copy. What Verify checked
	// and what Arm changes are the same value by construction.
	systemGUID := normalizeGUID(va.systemVolumeGUID)
	if systemGUID == "" {
		return nil, ErrWrongVolume
	}
	if systemGUID == normalizeGUID(va.destVolumeGUID) {
		logf("refused", runlog.Fields{"reason": "archive-on-system-volume", "volume": systemGUID})
		return nil, ErrArchiveOnSystemVolume
	}
	if err := validMount(va.systemMount); err != nil {
		return nil, err
	}

	// SAFETY.md phase 1 requires all three firmware facts to be detected and
	// stated before the run begins. Crossing the wall on facts the tool never
	// checked is the failure this refuses; the BitLocker suspend step below is
	// generated whenever BitLocker is not positively known to be OFF, so a dry
	// run still shows the user what would happen.
	if m.Mode().Commits() && !req.FirmwareKnown {
		logf("refused", runlog.Fields{
			"reason":                "firmware-facts-unknown",
			"system_disk_untouched": true,
		})
		return nil, ErrFirmwareUnknown
	}

	// If phase 1 could not tell, ask the volume itself. This is a status read,
	// not a change, and it is the only way a stdlib-only binary can answer a
	// question SAFETY.md requires answered before anything is planned. It can
	// only turn Unknown into a fact; it is never consulted to overrule one.
	bl := bitLockerState(req.BitLocker)
	if bl == sysdisk.BitLockerUnknown {
		if probed, perr := sysdisk.ProbeBitLocker(ctx, va.systemMount); perr == nil {
			bl = probed
			logf("bitlocker-probed", runlog.Fields{"result": probed.String()})
		} else {
			logf("bitlocker-unknown", runlog.Fields{
				"error": perr.Error(),
				"note":  "BitLocker could not be established; the suspend step is planned anyway",
			})
		}
	}

	intent := sysdisk.Intent{
		SystemVolumeGUID: va.systemVolumeGUID,
		SystemMount:      va.systemMount,
		BitLocker:        bl,
		BootMediaGUID:    req.BootMediaGUID,
		Restart:          req.Restart,
		Commit:           m.Mode().Commits(),
	}
	// A last assertion that the plan is aimed where the proof looked. It is
	// trivially true today; it is here so that it stops being trivially true the
	// moment somebody reintroduces a caller-supplied target.
	if normalizeGUID(intent.SystemVolumeGUID) != systemGUID {
		return nil, ErrWrongVolume
	}
	steps := toSteps(intent.Steps())
	res = &ArmResult{Mode: m.Mode(), Steps: steps}

	if !m.Mode().Commits() {
		// Dry run. Reach the wall, record it, cross nothing.
		if err := m.DryRunWall(va); err != nil {
			return nil, err
		}
		logf("dry-run-plan", runlog.Fields{
			"steps":                 len(steps),
			"firmware_known":        req.FirmwareKnown,
			"bitlocker":             bl.String(),
			"system_disk_untouched": true,
		})
		return res, nil
	}

	if err := m.CrossWall(va); err != nil {
		logf("refused", runlog.Fields{"error": err.Error(), "system_disk_untouched": true})
		return nil, err
	}

	// From here the machine records the wall as crossed, so a panic must not
	// leave the run with no record of what had already been done. sysdisk
	// unwinds the steps themselves; this makes sure the run log says so.
	defer func() {
		if r := recover(); r != nil {
			logf("panicked", runlog.Fields{
				"panic":     fmt.Sprint(r),
				"completed": strings.Join(res.Completed, ","),
				"reversed":  strings.Join(res.Reversed, ","),
			})
			panic(r)
		}
	}()

	logf("executing", runlog.Fields{"steps": len(steps), "system_volume": va.systemVolumeGUID})
	out, eerr := sysdisk.Execute(ctx, intent)
	if out != nil {
		res.Completed, res.Failed, res.Reversed = out.Completed, out.Failed, out.Reversed
	}
	res.Performed = eerr == nil
	if eerr != nil {
		logf("failed", runlog.Fields{
			"error":     eerr.Error(),
			"completed": strings.Join(res.Completed, ","),
			"reversed":  strings.Join(res.Reversed, ","),
		})
		return res, eerr
	}
	logf("armed", runlog.Fields{"completed": strings.Join(res.Completed, ",")})
	return res, nil
}

// bitLockerState maps phase 1's tri-state onto the one sysdisk plans against.
// Unknown maps to Unknown, which sysdisk treats as protected. The mapping is
// total and has no default-to-false branch anywhere in it.
func bitLockerState(t winenv.TriState) sysdisk.BitLocker {
	switch t {
	case winenv.Yes:
		return sysdisk.BitLockerOn
	case winenv.No:
		return sysdisk.BitLockerOff
	default:
		return sysdisk.BitLockerUnknown
	}
}

// validMount refuses a mount point that cannot be rendered into a command line
// unambiguously. A volume mounted at "C:\Program Files\Data" is exactly the
// mount-point case SAFETY.md phase 3 warns about, and it must not turn into two
// arguments halfway through the one phase that changes the machine.
func validMount(mount string) error {
	if mount == "" {
		return nil // sysdisk substitutes C: and says so
	}
	if strings.ContainsAny(mount, " \t\r\n\"'") {
		return fmt.Errorf("%w: %q", ErrBadSystemMount, mount)
	}
	return nil
}

func toSteps(in []sysdisk.Step) []Step {
	out := make([]Step, 0, len(in))
	for _, s := range in {
		out = append(out, Step{
			ID:           s.ID,
			Description:  s.Description,
			Argv:         append([]string(nil), s.Argv...),
			ReversalArgv: append([]string(nil), s.ReversalArgv...),
			Command:      s.Command(),
			Reversal:     s.Reversal(),
		})
	}
	return out
}
