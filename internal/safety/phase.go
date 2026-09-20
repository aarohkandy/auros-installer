package safety

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/aarohkandy/auros-installer/internal/runlog"
)

// Phase is SAFETY.md's phase list, in order.
//
//	┌──────────────── NON-DESTRUCTIVE ────────────────┐ ╎ ┌── DESTRUCTIVE ──┐
//	1 INVENTORY → 2 DISCLOSE → 3 DESTINATION → 4 COPY → 5 VERIFY →╎ 6 ARM → 7 RESTORE
//	                                                          THE WALL
//
// Phases 1–5 are read-only with respect to the system disk. An abort anywhere in
// them is a process exit, not a cleanup routine — which is precisely why the
// wall is after VERIFY and not after COPY.
type Phase int

const (
	// PhaseNone is the zero value: a Machine that has not started.
	PhaseNone Phase = iota
	PhaseInventory
	PhaseDisclose
	PhaseDestination
	PhaseCopy
	PhaseVerify
	PhaseArm
	PhaseRestore
)

var phaseNames = map[Phase]string{
	PhaseNone:        "none",
	PhaseInventory:   "1-inventory",
	PhaseDisclose:    "2-disclose",
	PhaseDestination: "3-destination",
	PhaseCopy:        "4-copy",
	PhaseVerify:      "5-verify",
	PhaseArm:         "6-arm",
	PhaseRestore:     "7-restore",
}

func (p Phase) String() string {
	if n, ok := phaseNames[p]; ok {
		return n
	}
	return fmt.Sprintf("phase(%d)", int(p))
}

// TouchesSystemDisk reports whether a phase is allowed to write to the system
// disk. Exactly one phase is.
func (p Phase) TouchesSystemDisk() bool { return p == PhaseArm }

// Mode is dry-run or commit. The zero value is DRY RUN, which is the default
// SAFETY.md rule 6 requires. A Mode nobody sets cannot commit.
type Mode int

const (
	// ModeDryRun performs every read, every copy to the destination and every
	// verification, and performs nothing at the wall. It is the zero value.
	ModeDryRun Mode = iota
	// ModeCommit is required to cross the wall. It comes from --commit.
	ModeCommit
)

func (m Mode) String() string {
	if m == ModeCommit {
		return "COMMIT"
	}
	return "DRY RUN"
}

// Commits reports whether this mode is permitted to cross the wall.
func (m Mode) Commits() bool { return m == ModeCommit }

// Errors returned by Machine. Each names a different way the ordering could have
// been broken, because "invalid state transition" is not something anyone can
// debug at 1am on a school's laptop.
var (
	ErrOutOfOrder    = errors.New("safety: phase transition out of order")
	ErrAborted       = errors.New("safety: run has aborted; no further phases")
	ErrAlreadyThere  = errors.New("safety: already in that phase")
	ErrUseCrossWall  = errors.New("safety: phase 6 (arm) is reached only through CrossWall with a VerifiedArchive")
	ErrNotVerified   = errors.New("safety: refusing to arm: no VerifiedArchive (verification did not succeed)")
	ErrWrongRun      = errors.New("safety: refusing to arm: the VerifiedArchive belongs to a different run")
	ErrAlreadyArmed  = errors.New("safety: the wall has already been crossed in this run")
	ErrNotCommitMode = errors.New("safety: refusing to arm: not in commit mode (--commit is required)")
)

// Machine enforces the ordering. It is safe for concurrent use; the copy engine
// reports progress from several goroutines.
//
// It is not a suggestion and it is not advisory. Arm cannot be entered by
// Advance at all: the only door into phase 6 is CrossWall, and CrossWall's
// signature requires a VerifiedArchive.
type Machine struct {
	mu      sync.Mutex
	runID   string
	cur     Phase
	mode    Mode
	crossed bool
	aborted bool
	reason  string
	log     *runlog.Logger
}

// NewMachine starts a run. log may be nil.
func NewMachine(mode Mode, log *runlog.Logger) *Machine {
	m := &Machine{runID: newRunID(), cur: PhaseNone, mode: mode, log: log}
	m.event("none", "run-start", runlog.Fields{"run_id": m.runID, "mode": mode.String()})
	return m
}

func newRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A run without a unique ID is still a run; it just cannot bind a
		// VerifiedArchive as tightly. Degrade, never fail the migration for it.
		return "run-norandom"
	}
	return hex.EncodeToString(b[:])
}

// RunID identifies this run. It appears in the run log and in any
// VerifiedArchive this Machine's Verify produces.
func (m *Machine) RunID() string { return m.runID }

// Mode is the run's mode. It never changes after construction: there is no
// setter, so nothing can promote a dry run to a commit halfway through.
func (m *Machine) Mode() Mode { return m.mode }

// Phase is the current phase.
func (m *Machine) Phase() Phase {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

// Crossed reports whether the wall has been crossed.
func (m *Machine) Crossed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.crossed
}

// Advance moves to the next phase. It moves forward by exactly one, it never
// moves backwards, and it refuses phase 6 outright.
func (m *Machine) Advance(p Phase) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aborted {
		return fmt.Errorf("%w (%s)", ErrAborted, m.reason)
	}
	if p == PhaseArm {
		return ErrUseCrossWall
	}
	if p == m.cur {
		return fmt.Errorf("%w: %s", ErrAlreadyThere, p)
	}
	if p != m.cur+1 {
		return fmt.Errorf("%w: %s -> %s (only %s is permitted next)", ErrOutOfOrder, m.cur, p, m.cur+1)
	}
	if p == PhaseRestore && !m.crossed {
		return fmt.Errorf("%w: restore before the wall was crossed", ErrOutOfOrder)
	}
	m.cur = p
	m.eventLocked(p.String(), "phase-enter", runlog.Fields{"run_id": m.runID, "mode": m.mode.String()})
	return nil
}

// CrossWall is the only way into phase 6. Its signature is the enforcement:
// there is no way to call it without a VerifiedArchive, and there is no way to
// obtain a VerifiedArchive except from a successful Verify on this Machine.
//
// It checks, in this order: the run has not aborted, we are standing at the end
// of phase 5, the archive is real, it belongs to this run, and we are in commit
// mode. The last of those means a dry run cannot cross even by accident.
func (m *Machine) CrossWall(v VerifiedArchive) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aborted {
		return fmt.Errorf("%w (%s)", ErrAborted, m.reason)
	}
	if m.crossed {
		return ErrAlreadyArmed
	}
	if m.cur != PhaseVerify {
		return fmt.Errorf("%w: the wall is crossed from %s, not from %s", ErrOutOfOrder, PhaseVerify, m.cur)
	}
	if !v.ok() {
		return ErrNotVerified
	}
	if v.runID != m.runID {
		return fmt.Errorf("%w: archive %s, run %s", ErrWrongRun, v.runID, m.runID)
	}
	if !m.mode.Commits() {
		return ErrNotCommitMode
	}
	m.cur = PhaseArm
	m.crossed = true
	m.eventLocked(PhaseArm.String(), "wall-crossed", runlog.Fields{
		"run_id":          m.runID,
		"file_count":      v.fileCount,
		"total_bytes":     v.totalBytes,
		"manifest_digest": v.manifestDigest,
		"dest_volume":     v.destVolumeGUID,
		"verified_at":     v.verifiedAt.UTC().Format("2006-01-02T15:04:05.000000000Z"),
	})
	return nil
}

// DryRunWall records that a dry run reached the wall and stopped. It is how a
// dry run reports "this is where I would have crossed" without any state change
// that could be mistaken for having crossed: cur does not move and crossed stays
// false.
func (m *Machine) DryRunWall(v VerifiedArchive) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aborted {
		return fmt.Errorf("%w (%s)", ErrAborted, m.reason)
	}
	if m.cur != PhaseVerify {
		return fmt.Errorf("%w: the wall is reached from %s, not from %s", ErrOutOfOrder, PhaseVerify, m.cur)
	}
	if !v.ok() {
		return ErrNotVerified
	}
	if v.runID != m.runID {
		return fmt.Errorf("%w: archive %s, run %s", ErrWrongRun, v.runID, m.runID)
	}
	m.eventLocked(PhaseVerify.String(), "wall-reached-dry-run", runlog.Fields{
		"run_id":     m.runID,
		"file_count": v.fileCount,
		"note":       "dry run: stopping at the wall; --commit is required to cross",
	})
	return nil
}

// Abort ends the run. Before the wall this is a process exit and changes
// nothing, which is the property the phase ordering exists to buy.
func (m *Machine) Abort(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.aborted {
		return
	}
	m.aborted = true
	m.reason = reason
	m.eventLocked(m.cur.String(), "abort", runlog.Fields{
		"run_id":                m.runID,
		"reason":                reason,
		"crossed_wall":          m.crossed,
		"system_disk_untouched": !m.crossed,
	})
}

// Aborted reports whether Abort has been called.
func (m *Machine) Aborted() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.aborted
}

// SystemDiskUntouched reports the property that matters on every abort path: if
// the wall was never crossed, nothing was written to the system disk, because
// the only code that can write to it is behind CrossWall.
func (m *Machine) SystemDiskUntouched() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.crossed
}

func (m *Machine) event(phase, kind string, f runlog.Fields) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.eventLocked(phase, kind, f)
}

func (m *Machine) eventLocked(phase, kind string, f runlog.Fields) {
	if m.log != nil {
		m.log.Event(phase, kind, f)
	}
}
