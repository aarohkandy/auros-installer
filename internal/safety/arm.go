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
	ErrEmptyArchive = errors.New("safety: refusing to issue a VerifiedArchive for an empty manifest")
)

// VerifyRequest is the input to phase 5.
type VerifyRequest struct {
	// DestRoot is the archive root on the destination volume.
	DestRoot string
	// DestVolumeGUID identifies the destination volume.
	DestVolumeGUID string
	// SystemVolumeGUID identifies the volume we must not have written to.
	SystemVolumeGUID string
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
	// AllowEmpty permits a zero-file archive. It exists for tests of the
	// machinery itself; a real run with nothing to copy has nothing to protect
	// and should not be arming anything.
	AllowEmpty bool
}

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
func Verify(ctx context.Context, m *Machine, req VerifyRequest) (VerifiedArchive, *verify.Report, error) {
	if m == nil {
		return VerifiedArchive{}, nil, errors.New("safety: no state machine")
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
	if req.Manifest.Len() == 0 && !req.AllowEmpty {
		logf("refused", runlog.Fields{"reason": "empty-manifest"})
		return VerifiedArchive{}, nil, ErrEmptyArchive
	}

	// The archive must not be on the system volume. Phase 3 already established
	// this; checking again here is deliberate. This is the function that mints
	// the proof, and a proof should not depend on an earlier function having
	// been called correctly.
	dg, sg := normalizeGUID(req.DestVolumeGUID), normalizeGUID(req.SystemVolumeGUID)
	if dg == "" || sg == "" {
		logf("refused", runlog.Fields{"reason": "volume-identity-unknown", "dest": dg, "system": sg})
		return VerifiedArchive{}, nil, ErrDestinationUnidentified
	}
	if dg == sg {
		logf("refused", runlog.Fields{"reason": "archive-on-system-volume", "volume": dg})
		return VerifiedArchive{}, nil, ErrArchiveOnSystemVolume
	}

	rep, err := verify.Run(ctx, verify.Options{
		DestRoot:   req.DestRoot,
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
		destRoot:         req.DestRoot,
		destVolumeGUID:   req.DestVolumeGUID,
		systemVolumeGUID: req.SystemVolumeGUID,
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
		"system_volume":         va.systemVolumeGUID,
		"system_disk_untouched": true,
		"note":                  "the data now exists in two places and the system disk has not been written to",
	})
	return va, rep, nil
}

// Step mirrors sysdisk.Step so that callers can display the arm plan without
// importing internal/sysdisk. That import is the thing the wall test forbids, so
// the type is re-declared here rather than re-exported.
type Step struct {
	ID          string
	Description string
	Command     string
	Reversal    string
}

// ArmRequest describes what crossing the wall will do. It deliberately has no
// "commit" field: the mode comes from the Machine, which took it at
// construction and has no setter.
type ArmRequest struct {
	SystemVolumeGUID   string
	SystemMount        string
	BitLockerProtected bool
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
	if !r.Performed {
		b.WriteString("nothing was written to the system disk.\n")
		b.WriteString("this is what --commit would do:\n")
	} else {
		b.WriteString("performed:\n")
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
func Arm(ctx context.Context, m *Machine, va VerifiedArchive, req ArmRequest) (*ArmResult, error) {
	if m == nil {
		return nil, errors.New("safety: no state machine")
	}
	// Check the token before anything else, so the most important refusal is
	// also the first one and does not depend on any other state being right.
	if !va.ok() {
		return nil, ErrNotVerified
	}

	intent := sysdisk.Intent{
		SystemVolumeGUID:   req.SystemVolumeGUID,
		SystemMount:        req.SystemMount,
		BitLockerProtected: req.BitLockerProtected,
		BootMediaGUID:      req.BootMediaGUID,
		Restart:            req.Restart,
		Commit:             m.Mode().Commits(),
	}
	steps := toSteps(intent.Steps())
	res := &ArmResult{Mode: m.Mode(), Steps: steps}

	logf := func(kind string, f runlog.Fields) {
		if req.Log != nil {
			f["run_id"] = m.RunID()
			f["mode"] = m.Mode().String()
			req.Log.Event(PhaseArm.String(), kind, f)
		}
	}

	if !m.Mode().Commits() {
		// Dry run. Reach the wall, record it, cross nothing.
		if err := m.DryRunWall(va); err != nil {
			return nil, err
		}
		logf("dry-run-plan", runlog.Fields{
			"steps":                 len(steps),
			"system_disk_untouched": true,
		})
		return res, nil
	}

	if err := m.CrossWall(va); err != nil {
		logf("refused", runlog.Fields{"error": err.Error(), "system_disk_untouched": true})
		return nil, err
	}

	logf("executing", runlog.Fields{"steps": len(steps), "system_volume": req.SystemVolumeGUID})
	out, err := sysdisk.Execute(ctx, intent)
	if out != nil {
		res.Completed, res.Failed, res.Reversed = out.Completed, out.Failed, out.Reversed
	}
	res.Performed = err == nil
	if err != nil {
		logf("failed", runlog.Fields{
			"error":     err.Error(),
			"completed": strings.Join(res.Completed, ","),
			"reversed":  strings.Join(res.Reversed, ","),
		})
		return res, err
	}
	logf("armed", runlog.Fields{"completed": strings.Join(res.Completed, ",")})
	return res, nil
}

func toSteps(in []sysdisk.Step) []Step {
	out := make([]Step, 0, len(in))
	for _, s := range in {
		out = append(out, Step{ID: s.ID, Description: s.Description, Command: s.Command, Reversal: s.Reversal})
	}
	return out
}
