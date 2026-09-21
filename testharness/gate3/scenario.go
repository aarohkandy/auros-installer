package gate3

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE SUITE
//
// Spec §6C: 100 clean runs and 20 induced-failure runs, and the abort path is
// tested more than the happy path. This table is the induced-failure half.
//
// It is Go and not YAML for the reason testharness/fault/catalogue.go already
// gives: a typo in a YAML catalogue is a scenario that silently does not exist,
// and this is the one piece of software whose whole job is to be trustworthy
// about abort paths. Validate() runs at startup and in CI.
//
// WHAT CHANGED FROM testharness/fault/catalogue.go, AND WHY
//
// That catalogue was written before the installer existed — deliberately, so
// that the harness defined the interface rather than discovering it. The
// installer now exists and two of its properties make three of those scenarios
// mean something different:
//
//   - There is no progress protocol. The installer writes no NDJSON, so a
//     trigger cannot be read out of its log. Every trigger here is measured
//     from OUTSIDE the process instead (bytes the OS saw it write or read, and
//     files appearing on the destination), which is strictly better evidence
//     and needs nothing from the subject.
//   - The installer's manifest is written to the destination ONCE, at the end
//     of the copy, and phase 5 verifies against the in-memory manifest. So
//     "manifest truncated mid-copy" names a file that does not exist yet. Those
//     scenarios are re-pinned into VERIFY, where the file does exist — and
//     where damaging it is the more interesting question anyway: the manifest on
//     the destination is what the Linux-side restore reads, so a run that calls
//     itself verified while THAT file is damaged has verified something other
//     than what it is about to rely on.
//
// The three scenarios that expect the installer to SURVIVE are kept (S01-S03)
// and one is added (S04). A suite that only knows how to score aborts pushes an
// installer towards aborting on everything, and a tool that aborts on a clock
// jump is a tool a school works around by month two.
// ─────────────────────────────────────────────────────────────────────────────

// Action is what the harness does to the machine at the trigger point.
type Action string

const (
	// ActionNone is a run with no injected action: the clean runs, and the
	// scenarios whose "fault" is the configuration they start with.
	ActionNone Action = "none"
	// ActionKill is a power cut as faithfully as a hosted runner can produce
	// one: TerminateJobObject, so no signal handler, no deferred cleanup and no
	// flush of the installer's own buffers. See the honesty note in README.
	ActionKill Action = "kill_process"
	// ActionDismountDestination is the USB being pulled: FSCTL_DISMOUNT_VOLUME
	// on the destination volume, which invalidates every open handle, followed
	// by detaching the disk entirely.
	ActionDismountDestination Action = "dismount_destination"
	// ActionFillDestination consumes the destination's free space.
	ActionFillDestination Action = "fill_destination"
	// ActionMutateSource rewrites a source file, repeatedly, while the installer
	// is reading it.
	ActionMutateSource Action = "mutate_source"
	// ActionMutateSourceOnce rewrites a source file exactly once, after it has
	// been copied.
	ActionMutateSourceOnce Action = "mutate_source_once"
	// ActionDeleteSource removes a source file the installer has not reached.
	ActionDeleteSource Action = "delete_source"
	// ActionLockSource takes an exclusive, no-sharing handle on a source file,
	// which is what real-time antivirus looks like from the outside.
	ActionLockSource Action = "lock_source"
	// ActionLockArchive does the same to a file on the destination during verify.
	ActionLockArchive Action = "lock_archive"
	// ActionBitFlipArchive flips exactly one bit in a copied file. Not one byte.
	ActionBitFlipArchive Action = "bit_flip_archive"
	// ActionCorruptArchiveMany rewrites a run of bytes in many copied files.
	ActionCorruptArchiveMany Action = "corrupt_archive_many"
	// ActionTruncateManifest shortens the installer's own manifest.
	ActionTruncateManifest Action = "truncate_installer_manifest"
	// ActionBitFlipManifest flips one bit inside it.
	ActionBitFlipManifest Action = "bit_flip_installer_manifest"
	// ActionPlantExtra puts a file the manifest does not know about into the
	// archive: every hash is fine and the count is wrong.
	ActionPlantExtra Action = "plant_extra_archive_file"
	// ActionClockBackwards moves the system clock back.
	ActionClockBackwards Action = "clock_backwards"
)

// Trigger says how the harness knows the moment has arrived.
type Trigger string

const (
	// TriggerNone fires nothing.
	TriggerNone Trigger = "none"
	// TriggerBytes fires when the operating system has seen the installer move
	// BP basis points of the corpus in the named phase — written, for COPY; read
	// since the copy ended, for VERIFY.
	TriggerBytes Trigger = "phase_bytes"
	// TriggerPartial fires the instant the installer creates the partial file
	// for the pinned source file, which is the moment it starts reading it.
	TriggerPartial Trigger = "pin_file_in_flight"
)

// Expect is the behaviour a run must show to count.
type Expect string

const (
	// ExpectAbort: the installer must stop with a non-zero exit, must not claim
	// a verified archive, and must leave the system disk untouched.
	ExpectAbort Expect = "abort"
	// ExpectRefuse: the installer must refuse before it copies a single byte.
	ExpectRefuse Expect = "refuse-before-copy"
	// ExpectSurvive: the installer must complete, verify and report success.
	ExpectSurvive Expect = "survive"
)

// DestMode is how the destination is set up for a run. Three of the scenarios
// have no injected action at all: the fault IS the destination.
type DestMode string

const (
	// DestNormal is a freshly formatted volume with room.
	DestNormal DestMode = "normal"
	// DestSystemVolume points --dest at the system disk.
	DestSystemVolume DestMode = "system-volume"
	// DestTooSmall points --dest at a volume far too small for the corpus.
	DestTooSmall DestMode = "too-small"
	// DestJunctionToSystem points --dest at a directory on the destination
	// volume that is an NTFS junction onto the system disk. The letter says E:,
	// the bytes would land on C:. SAFETY.md phase 3 is mostly about this case.
	DestJunctionToSystem DestMode = "junction-onto-system-volume"
	// DestAuto passes no --dest at all and makes the installer choose.
	DestAuto DestMode = "auto"
)

// Scenario is one run.
type Scenario struct {
	ID     string
	Name   string
	Family string

	Dest    DestMode
	Trigger Trigger
	Phase   Phase
	BP      int
	Action  Action

	// TargetDeltaBytes selects the file the action applies to, as a byte
	// distance from the pin. See TargetFromPin.
	TargetDeltaBytes int64
	// Count is how many files a multi-file action touches.
	Count int
	// KeepBP is how much of a truncated file survives, in basis points.
	KeepBP int
	// Seconds is how far the clock moves.
	Seconds int64

	Expect Expect

	// AbortEvidence is what the installer must SAY, somewhere, for this run to
	// count as having aborted for this scenario's reason rather than for some
	// other one.
	//
	// It exists because "exit code is non-zero" is the weakest possible reading
	// of a clean abort. A suite in which every run aborts — for one unrelated
	// reason, on every scenario — is green and proves nothing, and that is not a
	// hypothetical: the first version of this harness left the account's
	// registry hive inside the corpus, and every single scenario aborted on it.
	//
	// The strings are matched against the installer's own quarantine reasons,
	// refusals and output, which are a closed set (internal/quarantine.Reason).
	// Scenarios that end with the process being killed have none, because a
	// process that no longer exists says nothing; those are covered by the fire
	// record and by the measurements instead.
	AbortEvidence []string

	// PlantSymlinkEscape asks the harness to put a symbolic link inside the
	// corpus that points outside it, before the run.
	PlantSymlinkEscape bool

	// PlantDeniedDir asks the harness to put a LocalAppData folder nobody can
	// list into the corpus, before the run.
	PlantDeniedDir bool

	// CloudFiles is the --cloud-files choice this run makes. Empty means
	// hydrate, which is what every other run uses.
	CloudFiles string

	// DeviatesSource / DeviatesArchive record that this scenario damages the
	// tree on purpose, so the post-run comparison expects the damage rather than
	// reporting the harness's own work as the installer's data loss. What
	// exactly was damaged is recorded AT FIRE TIME, by the injector, with the
	// bytes it left behind — never assumed from the scenario table.
	DeviatesSource  bool
	DeviatesArchive bool

	Why         string
	WrongReason string
}

// Suite is the induced-failure half of Gate 3: 24 runs that must abort or
// refuse, and 4 that must survive.
//
// Spec §6C asks for 20 aborts. There are 23 here because three cases the spec
// does not name are the ones this codebase argues about most in its own
// comments — a --dest that is the system disk, a --dest that is a junction onto
// it, and a symlink inside the source tree that leaves it — and a suite that
// does not test the refusals a file of safety comments is proudest of is
// testing the easy half.
func Suite() []Scenario {
	const (
		aheadFar   = 3 << 30   // far enough ahead that the installer has not planned past it yet
		ahead      = 256 << 20 // ~2 seconds of copying ahead on a hosted runner
		behind     = -64 << 20 // comfortably already copied
		holdTarget = 50
	)
	return []Scenario{
		// ── power cut ────────────────────────────────────────────────────────
		{
			ID: "F01", Family: "power_cut", Name: "Power cut at 7% of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 700, Action: ActionKill,
			Expect: ExpectAbort,
			Why: "The first few per cent are where a half-created destination tree exists and nothing " +
				"else. A tool that writes a completion marker optimistically writes it here.",
			WrongReason: "Windows survives a 7% cut for the trivial reason that almost nothing happened. " +
				"The run only counts if the harness saw the copy actually reach the pin.",
		},
		{
			ID: "F02", Family: "power_cut", Name: "Power cut at 43% of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 4300, Action: ActionKill,
			Expect: ExpectAbort,
			Why: "The ordinary case: the machine dies mid-write, inside a large file, with a partial " +
				"destination file whose size is not its final size.",
			WrongReason: "A partial archive later mistaken for a complete one is the Wubi failure. The " +
				"harness checks the installer never claimed verification, and re-hashes what is there.",
		},
		{
			ID: "F03", Family: "power_cut", Name: "Power cut at 94% of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 9400, Action: ActionKill,
			Expect: ExpectAbort,
			Why: "Near-complete is the most dangerous state there is, because it is the state a recovery " +
				"path is most tempted to round up to complete.",
			WrongReason: "An installer that silently resumed on the next start could reach a correct end " +
				"state having never aborted. This run requires the abort.",
		},
		{
			ID: "F04", Family: "power_cut", Name: "Power cut halfway through VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 5000, Action: ActionKill,
			Expect: ExpectAbort,
			Why: "VERIFY is the last thing between the user and the wall. A crash here leaves a " +
				"complete-looking archive that has been only half checked.",
			WrongReason: "Half-verified must not be recorded as verified anywhere on the destination — " +
				"if it can be, SAFETY.md rule 1's type-level guarantee is not real.",
		},

		// ── destination removed ──────────────────────────────────────────────
		{
			ID: "F05", Family: "dest_removed", Name: "Destination volume yanked at 38% of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 3800,
			Action: ActionDismountDestination, Expect: ExpectAbort,
			Why: "Someone walks past the trolley. The most common physical failure in a school, and not " +
				"an exotic test.",
			WrongReason: "A tool that buffers writes can keep succeeding for seconds after the device is " +
				"gone. The harness re-reads the destination afterwards rather than believing the log.",
		},
		{
			ID: "F06", Family: "dest_removed", Name: "Destination volume yanked during VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 4000,
			Action: ActionDismountDestination, Expect: ExpectAbort,
			AbortEvidence: []string{"missing-at-destination", "missing-from-destination", "read-error",
				"unreadable", "size-mismatch", "size-differs"},
			Why: "Verification reads from the destination. Losing it mid-verify must abort, not be " +
				"treated as 'the files we already checked were fine'.",
			WrongReason: "Counting the files verified so far as a pass satisfies a naive count check " +
				"while proving nothing about the rest.",
		},

		// ── destination fills ────────────────────────────────────────────────
		{
			ID: "F07", Family: "dest_full", Name: "Destination fills at 61% of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 6100,
			Action: ActionFillDestination, Expect: ExpectAbort,
			AbortEvidence: []string{"destination-full", "filled up", "not enough space on the disk"},
			Why: "The free-space check in phase 3 happens once, before the copy. Anything that eats space " +
				"during the copy defeats it — a Windows update, a second user, an underestimated " +
				"placeholder hydration.",
			WrongReason: "ENOSPC on one file must not be swallowed into a skip list. A skipped file " +
				"reported as copied is silent data loss at restore time.",
		},
		{
			ID: "F08", Family: "dest_full", Name: "Destination fills on the very last file",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 9950,
			Action: ActionFillDestination, Expect: ExpectAbort,
			AbortEvidence: []string{"destination-full", "filled up", "not enough space on the disk"},
			Why: "One file short of complete. The count check passes for 17,999 of 18,000 and the only " +
				"thing between the user and a lost file is that 18,000 != 17,999.",
			WrongReason: "A percentage-based success threshold would pass this. There is no threshold.",
		},

		// ── source mutated ───────────────────────────────────────────────────
		{
			ID: "F09", Family: "source_mutated", Name: "Source file rewritten repeatedly while it is copied",
			Dest: DestNormal, Trigger: TriggerPartial, Phase: PhaseCopy, BP: 2900,
			Action: ActionMutateSource, TargetDeltaBytes: 0, DeviatesSource: true, Expect: ExpectAbort,
			AbortEvidence: []string{"source-changed-during-copy", "changed during the copy"},
			Why: "A live machine: a document open in an application that saves every few seconds, or a " +
				"sync client rewriting a file under the copy. Phase 4 hashes DURING the copy for this " +
				"exact reason, and phase 5's one retry is allowed to fail here — the file never holds " +
				"still long enough to be captured, so it must end up quarantined and the run must stop.",
			WrongReason: "The dangerous pass is an archive holding a TORN file: the first half of one " +
				"version and the second half of another, with a digest that matches the mixture. The " +
				"harness re-hashes the copy against both versions that ever existed and calls anything " +
				"else corruption.",
		},

		// ── source deleted ───────────────────────────────────────────────────
		{
			ID: "F11", Family: "source_deleted", Name: "Source file deleted just ahead of the copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 3300,
			Action: ActionDeleteSource, TargetDeltaBytes: ahead, DeviatesSource: true, Expect: ExpectAbort,
			AbortEvidence: []string{"source-disappeared", "disappeared during the copy", "source file disappeared"},
			Why: "Temp files, browser cache, a user emptying Downloads while the tool runs. The inventory " +
				"is a snapshot; the disk is not.",
			WrongReason: "Treating a vanished source as 'nothing to copy' silently reduces the expected " +
				"count to match what was achieved, which makes the count check tautological.",
		},
		{
			ID: "F12", Family: "source_deleted", Name: "Source file deleted long before its copy begins",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 100,
			Action: ActionDeleteSource, TargetDeltaBytes: aheadFar, DeviatesSource: true, Expect: ExpectAbort,
			AbortEvidence: []string{"source-disappeared", "disappeared during the copy", "source file disappeared"},
			Why:           "Same family, widest possible gap between the acknowledged inventory and the copy.",
			WrongReason: "Re-enumerating at copy time instead of using the inventory the user " +
				"acknowledged would make this pass while quietly breaking phase 2.",
		},

		// ── manifest damaged ─────────────────────────────────────────────────
		{
			ID: "F13", Family: "manifest_damaged", Name: "Installer manifest truncated mid-record during VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 2000,
			Action: ActionTruncateManifest, KeepBP: 6000, Expect: ExpectAbort,
			Why: "The manifest on the destination is the only thing that makes the archive verifiable, " +
				"and it is what the Linux-side restore re-checks against. A run that reports a verified " +
				"archive while that file is truncated has verified something it is not going to use.",
			WrongReason: "A verifier that compares against its own in-memory copy cannot see this at " +
				"all, and will report success. That is the finding, not a pass.",
		},
		{
			ID: "F14", Family: "manifest_damaged", Name: "Installer manifest emptied during VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 2000,
			Action: ActionTruncateManifest, KeepBP: 0, Expect: ExpectAbort,
			Why: "An empty manifest verifies vacuously against anything: zero files compared, zero " +
				"mismatches, 100% success.",
			WrongReason: "This is the purest vacuous pass. Any verifier that accepts it would accept an " +
				"empty archive.",
		},

		// ── silent corruption ────────────────────────────────────────────────
		{
			ID: "F15", Family: "bit_flip", Name: "One bit flipped in an already-copied file",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 5500,
			Action: ActionBitFlipArchive, TargetDeltaBytes: behind, DeviatesArchive: true, Expect: ExpectAbort,
			AbortEvidence: []string{"hash-mismatch", "contents-differ"},
			Why: "Bad USB stick, bad cable, bad RAM. One bit. This is what per-file hashing is FOR, and " +
				"it is the check most likely to be quietly downgraded to a size comparison for speed.",
			WrongReason: "A verify that compares sizes, or that trusts the digest computed during the " +
				"copy instead of re-reading the destination, cannot see this and passes.",
		},
		{
			ID: "F16", Family: "manifest_damaged", Name: "One bit flipped inside the installer's manifest",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 2000,
			Action: ActionBitFlipManifest, Expect: ExpectAbort,
			Why: "Corrupting the record rather than the data. One flipped hex digit in one stored hash " +
				"and exactly one file appears corrupt that is not — or a corrupt one appears fine.",
			WrongReason: "If the manifest carries no integrity of its own AT THE PLACE IT IS STORED, the " +
				"restore inherits a record nobody checked.",
		},
		{
			ID: "F21", Family: "bit_flip", Name: "Fifty copied files corrupted before verify reaches them",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 1000,
			Action: ActionCorruptArchiveMany, TargetDeltaBytes: ahead, Count: holdTarget,
			DeviatesArchive: true, Expect: ExpectAbort,
			AbortEvidence: []string{"hash-mismatch", "contents-differ"},
			Why: "One bad file is a bad file. Fifty is a bad cable or a dying stick, and the case where a " +
				"verifier that gives up after the first disagreement reports one problem and hides " +
				"forty-nine.",
			WrongReason: "Aborting on the first mismatch would pass this run while telling the user a " +
				"fraction of the truth about their archive.",
		},
		{
			ID: "F22", Family: "count_mismatch", Name: "A file the manifest does not know about appears in the archive",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 9900,
			Action: ActionPlantExtra, DeviatesArchive: true, Expect: ExpectAbort,
			AbortEvidence: []string{"unexpected-file-at-destination", "unexpected-at-destination"},
			Why: "Every hash is fine and the count is wrong. The destination is not the archive the " +
				"manifest describes, and a restore would either copy a stranger's file onto the new " +
				"machine or silently ignore it.",
			WrongReason: "A verifier that only walks the manifest and never walks the destination cannot " +
				"see an extra file at all.",
		},

		// ── antivirus ────────────────────────────────────────────────────────
		{
			ID: "F19", Family: "av_lock", Name: "Exclusive handle on a source file the copy has not reached",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 2200,
			Action: ActionLockSource, TargetDeltaBytes: ahead, Expect: ExpectAbort,
			AbortEvidence: []string{"locked-or-in-use", "read-error", "being used by another process"},
			Why: "Real-time scanning opens files with no sharing at all. On the machines this product " +
				"exists for, the antivirus is the most aggressive thing installed.",
			WrongReason: "Silently skipping the file is the failure: a skipped file plus a reduced " +
				"expected count looks exactly like a clean run.",
		},
		{
			ID: "F20", Family: "av_lock", Name: "Exclusive handle on an archive file during VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 6600,
			Action: ActionLockArchive, TargetDeltaBytes: ahead, Expect: ExpectAbort,
			AbortEvidence: []string{"read-error", "locked-or-in-use", "unreadable", "being used by another process"},
			Why: "Verification re-reads every file from the destination. An antivirus scanning the " +
				"freshly written archive holds some of them, and a file that cannot be read cannot be " +
				"verified.",
			WrongReason: "Counting an unreadable destination file as verified, or retrying it forever, " +
				"are both ways this looks green.",
		},

		// ── the destination itself is the fault ──────────────────────────────
		{
			ID: "G01", Family: "bad_destination", Name: "--dest is a directory on the system disk",
			Dest: DestSystemVolume, Trigger: TriggerNone, Action: ActionNone, Expect: ExpectRefuse,
			AbortEvidence: []string{"destination is the system volume"},
			Why: "The archive is the second copy. On the system disk it is not a second copy of " +
				"anything, and phase 3 must refuse before it creates so much as a directory.",
			WrongReason: "Refusing AFTER creating the directory would still be a write to the system " +
				"disk during a phase that is defined as read-only with respect to it. The harness " +
				"watches C: through the change journal, so the directory would show up.",
		},
		{
			ID: "G02", Family: "bad_destination", Name: "--dest volume is far too small",
			Dest: DestTooSmall, Trigger: TriggerNone, Action: ActionNone, Expect: ExpectRefuse,
			AbortEvidence: []string{"room for the copy"},
			Why: "Phase 3 requires free space of at least the inventory plus ten per cent. A tool that " +
				"starts anyway and fills the stick has done work that has to be undone by hand.",
			WrongReason: "Copying until ENOSPC and calling that a clean abort tests the disk-full path " +
				"instead of the refusal, and leaves gigabytes on a volume the user has to clear.",
		},
		{
			ID: "G03", Family: "bad_destination", Name: "--dest is a junction onto the system disk",
			Dest: DestJunctionToSystem, Trigger: TriggerNone, Action: ActionNone, Expect: ExpectRefuse,
			AbortEvidence: []string{"system volume", "is a link"},
			Why: "E:\\backup can be an NTFS junction onto C:\\somewhere: the letter says E:, the bytes " +
				"land on C:. This is the exact aliasing internal/safety/destination.go exists to " +
				"defeat, and the one that would put the user's only copy on the disk about to be " +
				"repointed while printing the backup drive's GUID.",
			WrongReason: "Deriving the volume from the drive letter passes this test while doing the " +
				"worst thing the program can do. The harness watches the junction's TARGET on C:.",
		},
		{
			ID: "G04", Family: "path_escape", Name: "A link inside the source tree points outside it",
			Dest: DestNormal, Trigger: TriggerNone, Action: ActionNone, PlantSymlinkEscape: true,
			Expect:        ExpectAbort,
			AbortEvidence: []string{"path-escapes-source-root", "points outside the source tree"},
			Why: "A link in Documents pointing at C:\\Windows is how a copy of a user's files turns into " +
				"a copy of the operating system, or of a network share, or of itself.",
			WrongReason: "Following it 'because it resolves' is the failure. Quarantining it and then " +
				"proceeding to the wall anyway is the other one: an unresolved quarantine entry must " +
				"stop the run.",
		},

		{
			ID: "G05", Family: "appdata_hazard", Name: "A LocalAppData folder the user cannot list",
			Dest: DestNormal, Trigger: TriggerNone, Action: ActionNone, PlantDeniedDir: true,
			Expect:        ExpectAbort,
			AbortEvidence: []string{"read-error", "Access is denied"},
			Why: "SYSTEM-REVIEW §2.20: some real profiles carry a folder the user cannot read. Until " +
				"docs/APPDATA-SCOPE.md decides otherwise, the only honest outcome is to name it in the " +
				"quarantine and stop before the wall. It is a scenario of its own so that the clean runs " +
				"measure a clean machine instead of stopping here every time.",
			WrongReason: "Skipping the folder and issuing a verified archive is the failure: the user " +
				"is never told something was left behind. If APPDATA-SCOPE decides such folders are " +
				"out of scope, this expectation changes to survive-and-report, not disappears.",
		},

		// ── the installer must SURVIVE these ─────────────────────────────────
		{
			ID: "S01", Family: "source_mutated", Name: "Source file rewritten after it was copied, before verify",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 9900,
			Action: ActionMutateSourceOnce, TargetDeltaBytes: behind, DeviatesSource: true,
			Expect: ExpectSurvive,
			Why: "The window between COPY and VERIFY. A verify implemented as 'compare the destination " +
				"against a fresh read of the source' fails here on a file that was copied perfectly.",
			WrongReason: "This is one of the four runs where the correct behaviour is to CONTINUE. It " +
				"exists to stop the installer becoming so abort-happy that it is unusable on a live " +
				"machine, which is how a safety tool gets worked around.",
		},
		{
			ID: "S02", Family: "clock_backwards", Name: "System clock jumps back a day mid-copy",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseCopy, BP: 5000,
			Action: ActionClockBackwards, Seconds: 86400, Expect: ExpectSurvive,
			Why: "A dead CMOS battery on a 2013 laptop is not an edge case, it is the cohort: the clock " +
				"resets at every boot and NTP yanks it back seconds later.",
			WrongReason: "Anything computing a duration as end-minus-wall-start goes negative here, and " +
				"anything using mtime to decide whether a file changed gets a wrong answer. Being " +
				"unaffected is the pass.",
		},
		{
			ID: "S03", Family: "clock_backwards", Name: "Clock jumps back ten years at the start of VERIFY",
			Dest: DestNormal, Trigger: TriggerBytes, Phase: PhaseVerify, BP: 1000,
			Action: ActionClockBackwards, Seconds: 315360000, Expect: ExpectSurvive,
			Why: "Ten years backwards across the phase boundary. Any timestamp-based freshness logic " +
				"between copy and verify breaks here.",
			WrongReason: "Same as S02: a pass means the installer ignored the wall clock, which is what " +
				"it is supposed to do.",
		},
		{
			ID: "S05", Family: "cloud_files",
			Name: "--cloud-files=skip must leave the placeholders where they are",
			Dest: DestNormal, Trigger: TriggerNone, Action: ActionNone, CloudFiles: "skip",
			Expect: ExpectSurvive,
			Why: "SAFETY.md phase 1 makes this the user's choice, in plain words, before anything starts: " +
				"hydrate them (slow, and they have to fit) or leave them in the cloud. A school's uplink " +
				"is the reason the choice exists. A tool that asks and then does the other thing has " +
				"taken a decision the user was told they were making — and it sized the destination for " +
				"the answer it did not act on.",
			WrongReason: "The corpus's placeholders are attribute-only: their bytes are on the disk, so " +
				"reading them succeeds and nothing fails. The only way to tell whether the choice was " +
				"honoured is to look at whether those files are in the archive, which is what this run " +
				"does.",
		},
		{
			ID: "S04", Family: "auto_destination", Name: "No --dest at all: the installer must choose a volume that is not the system disk",
			Dest: DestAuto, Trigger: TriggerNone, Action: ActionNone, Expect: ExpectSurvive,
			Why: "Resolver.Choose is the path a real user takes — they do not type a path, they plug in " +
				"a stick. It has to be no weaker than the explicit one, and the harness checks where the " +
				"archive actually landed.",
			WrongReason: "Choosing the system disk, or choosing a volume it cannot identify, would be " +
				"caught here and nowhere else in this suite.",
		},
	}
}

// Lookup finds a scenario by id, case-insensitively.
func Lookup(id string) (Scenario, error) {
	for _, s := range Suite() {
		if strings.EqualFold(s.ID, id) {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("gate3: no such scenario %q", id)
}

// SuiteIDs lists every scenario id, in table order.
func SuiteIDs() []string {
	out := make([]string, 0, len(Suite()))
	for _, s := range Suite() {
		out = append(out, s.ID)
	}
	return out
}

// Validate is called at startup by everything that uses the suite. It is cheap
// and it catches the edit that silently removes a test.
func Validate() error {
	suite := Suite()
	seen := map[string]bool{}
	fams := map[string]int{}
	aborts, survives := 0, 0
	for _, s := range suite {
		if seen[s.ID] {
			return fmt.Errorf("gate3: duplicate scenario id %s", s.ID)
		}
		seen[s.ID] = true
		fams[s.Family]++
		switch s.Expect {
		case ExpectAbort, ExpectRefuse:
			aborts++
		case ExpectSurvive:
			survives++
		default:
			return fmt.Errorf("gate3: %s: unknown expectation %q", s.ID, s.Expect)
		}
		if s.Why == "" || s.WrongReason == "" {
			return fmt.Errorf("gate3: %s: every scenario must say why it exists and how it could pass "+
				"for the wrong reason", s.ID)
		}
		switch s.Trigger {
		case TriggerNone:
			if s.Action != ActionNone {
				return fmt.Errorf("gate3: %s: an action with no trigger would fire at an arbitrary "+
					"moment", s.ID)
			}
		case TriggerBytes, TriggerPartial:
			if s.Action == ActionNone {
				return fmt.Errorf("gate3: %s: a trigger that fires nothing is not a scenario", s.ID)
			}
			if s.BP < 0 || s.BP > 10000 {
				return fmt.Errorf("gate3: %s: trigger %d bp out of range", s.ID, s.BP)
			}
			if s.Phase != PhaseCopy && s.Phase != PhaseVerify {
				return fmt.Errorf("gate3: %s: unknown phase %q", s.ID, s.Phase)
			}
		default:
			return fmt.Errorf("gate3: %s: unknown trigger %q", s.ID, s.Trigger)
		}
		if s.Action == ActionClockBackwards && s.Seconds <= 0 {
			return fmt.Errorf("gate3: %s: a clock scenario that moves the clock zero seconds is not one", s.ID)
		}
		if s.Action == ActionCorruptArchiveMany && s.Count < 2 {
			return fmt.Errorf("gate3: %s: 'many files' means more than one", s.ID)
		}
	}
	// Spec §6C: 20 induced failures, and SAFETY.md rule 2: the abort path is
	// tested more than the happy path. The abort half must not shrink below the
	// number the spec names, whatever else is added.
	if aborts < 20 {
		return fmt.Errorf("gate3: only %d scenarios expect an abort or a refusal; spec §6C requires 20", aborts)
	}
	if survives < 1 {
		return errors.New("gate3: no scenario expects the installer to survive; a suite that only " +
			"scores aborts pushes a tool towards aborting on everything")
	}
	if aborts <= survives {
		return fmt.Errorf("gate3: %d abort scenarios and %d survival scenarios: the abort path is no "+
			"longer tested more than the happy path (SAFETY.md rule 2)", aborts, survives)
	}
	if len(fams) < 8 {
		names := make([]string, 0, len(fams))
		for f := range fams {
			names = append(names, f)
		}
		sort.Strings(names)
		return fmt.Errorf("gate3: only %d fault families (%s); the catalogue has drifted",
			len(fams), strings.Join(names, ", "))
	}
	return nil
}

// Describe renders the suite as the table README.md and the job summary quote.
func Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-5s %-16s %-28s %-14s %s\n", "ID", "FAMILY", "ACTION", "TRIGGER", "EXPECT")
	for _, s := range Suite() {
		trig := "—"
		if s.Trigger != TriggerNone {
			trig = fmt.Sprintf("%s@%d.%02d%%", s.Phase, s.BP/100, s.BP%100)
		}
		act := string(s.Action)
		if s.Action == ActionNone {
			act = "(" + string(s.Dest) + ")"
		}
		fmt.Fprintf(&b, "%-5s %-16s %-28s %-14s %s\n", s.ID, s.Family, act, trig, s.Expect)
	}
	return b.String()
}
