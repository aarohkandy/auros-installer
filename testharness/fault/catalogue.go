package fault

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE CATALOGUE
//
// Spec §6C: twenty runs with induced failure, twenty clean aborts, Windows still boots normally every
// time, zero data loss.
//
// Nine fault FAMILIES, twenty concrete SCENARIOS. The families are the failure modes a school laptop
// actually meets; the scenarios place each family at the trigger points where the installer's behaviour
// differs. A power cut at 7% and a power cut at 94% are not the same test: at 7% almost nothing has been
// written to the destination, at 94% the destination is nearly a complete archive and the temptation to
// treat it as one is at its maximum.
//
// WHY THIS IS GO AND NOT YAML. A YAML catalogue needs a third-party parser in the one piece of software
// whose entire job is to be trustworthy about abort paths, and a typo in it becomes a scenario that
// silently does not exist. Written as Go it compiles or it does not, `Validate` runs at startup, and
// `faultctl dump` emits the human-readable view that REPORT.md quotes.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// StandardSuite is the twenty runs that satisfy §6C. Order is fixed; run ids in REPORT.md refer to it.
func StandardSuite() []Scenario {
	return []Scenario{
		// ── family 1: hard power cut ──────────────────────────────────────────────────────────────
		{
			ID:      "F01", Family: "power_cut", Name: "Power cut very early in the copy",
			Site:    SiteHost, Action: ActionPowerCut,
			Trigger: Trigger{PhaseCopy, 700},
			Why: "The first few per cent are where a half-created destination directory tree exists and " +
				"nothing else. A tool that writes its 'archive complete' marker optimistically writes it here.",
			ExpectAbort: true,
			WrongReason: "Windows boots fine at 7% for the trivial reason that almost nothing happened. " +
				"The run only counts if the progress log proves the copy reached the pin.",
		},
		{
			ID:      "F02", Family: "power_cut", Name: "Power cut at 43% of copied bytes",
			Site:    SiteHost, Action: ActionPowerCut,
			Trigger: Trigger{PhaseCopy, 4300},
			Why: "The ordinary case: the machine dies in the middle of a large file, mid-write, with a " +
				"partially written destination file whose size on disk is not its final size.",
			ExpectAbort: true,
			WrongReason: "A partial destination that is later mistaken for a complete archive is exactly " +
				"the Wubi failure. P5 checks that no completion marker exists.",
		},
		{
			ID:      "F03", Family: "power_cut", Name: "Power cut at 94% — almost done",
			Site:    SiteHost, Action: ActionPowerCut,
			Trigger: Trigger{PhaseCopy, 9400},
			Why: "Near-complete is the most dangerous state there is, because it is the state a recovery " +
				"path is most tempted to round up to complete.",
			ExpectAbort: true,
			WrongReason: "An installer that resumes on restart could reach a correct end state while never " +
				"having aborted. That is a different product; P1 requires an abort.",
		},
		{
			ID:      "F04", Family: "power_cut", Name: "Power cut halfway through VERIFY",
			Site:    SiteHost, Action: ActionPowerCut,
			Trigger: Trigger{PhaseVerify, 5000},
			Why: "VERIFY is the last thing between the user and the wall (SAFETY.md phase 5). A crash here " +
				"leaves a complete-looking archive that has been only half checked.",
			ExpectAbort: true,
			WrongReason: "Half-verified must not be recorded as verified. If a VerifiedArchive value can " +
				"survive this, the type-level guarantee in SAFETY.md rule 1 is not real.",
		},

		// ── family 2: destination removed (the USB is pulled) ─────────────────────────────────────
		{
			ID:      "F05", Family: "dest_removed", Name: "USB destination yanked mid-copy",
			Site:    SiteHost, Action: ActionDetachDestination,
			Trigger: Trigger{PhaseCopy, 3800},
			Why: "Someone walks past the trolley. This is the most common physical failure in a school and " +
				"it is not an exotic test.",
			ExpectAbort: true,
			WrongReason: "A tool that buffers writes can keep 'succeeding' for several seconds after the " +
				"device is gone. P5 checks the destination, not the tool's opinion of the destination.",
		},
		{
			ID:      "F06", Family: "dest_removed", Name: "USB destination yanked during VERIFY",
			Site:    SiteHost, Action: ActionDetachDestination,
			Trigger: Trigger{PhaseVerify, 4000},
			Why: "Verification reads from the destination. Losing it mid-verify must abort, not be treated " +
				"as 'the files we already checked were fine'.",
			ExpectAbort: true,
			WrongReason: "Counting the files verified so far as a pass would satisfy a naive count check " +
				"while verifying nothing about the rest.",
		},

		// ── family 3: destination fills ───────────────────────────────────────────────────────────
		{
			ID:      "F07", Family: "dest_full", Name: "Destination volume fills at 61%",
			Site:    SiteGuest, Action: ActionFillDestination,
			Trigger: Trigger{PhaseCopy, 6100},
			Params:  map[string]string{"leave_bytes": "0"},
			Why: "The free-space check in SAFETY.md phase 3 is done once, before the copy. Anything that " +
				"consumes space during the copy — a Windows update, a second user, an over-optimistic " +
				"estimate of OneDrive placeholder hydration — defeats it.",
			ExpectAbort: true,
			WrongReason: "ENOSPC on one file must not be swallowed into a skip list. A skipped file that " +
				"is reported as copied is silent data loss at restore time.",
		},
		{
			ID:      "F08", Family: "dest_full", Name: "Destination fills on the very last file",
			Site:    SiteGuest, Action: ActionFillDestination,
			Trigger: Trigger{PhaseCopy, 9950},
			Params:  map[string]string{"leave_bytes": "0"},
			Why: "One file short of complete. The count check passes for 17,999 of 18,000 and the only " +
				"thing standing between the user and a lost file is that 18,000 != 17,999.",
			ExpectAbort: true,
			WrongReason: "A percentage-based success threshold ('99.99% copied') would pass this. There is " +
				"no threshold; the number is 18,000.",
		},

		// ── family 4: source mutated under us ─────────────────────────────────────────────────────
		{
			ID:      "F09", Family: "source_mutated", Name: "Source file rewritten while it is being copied",
			Site:    SiteGuest, Action: ActionMutateSource, TargetOffset: 0,
			Trigger: Trigger{PhaseCopy, 2900},
			Why: "A live machine. The user has a document open and saves it, or a sync client rewrites it. " +
				"SAFETY.md phase 4 hashes DURING the copy for this exact reason — hashing the source " +
				"afterwards would hash a file that is no longer the one we wrote.",
			ExpectAbort: true, DeviatesCorpus: true,
			WrongReason: "If the installer hashes the source after copying instead of streaming the hash, " +
				"this test passes for the wrong reason: source and destination disagree and it notices — " +
				"but it would also 'notice' on a file it had copied perfectly.",
		},
		{
			ID:      "F10", Family: "source_mutated", Name: "Source file rewritten after copy, before verify",
			Site:    SiteGuest, Action: ActionMutateSource, TargetOffset: -40,
			Trigger: Trigger{PhaseCopy, 9900},
			Why: "The window between COPY and VERIFY. A verify implemented as 'compare destination against " +
				"a fresh read of the source' fails here on a file that was copied correctly, and would " +
				"abort a good run. A verify implemented as SAFETY.md specifies — destination against the " +
				"manifest recorded during the copy — is unaffected.",
			ExpectAbort: false, DeviatesCorpus: true,
			WrongReason: "This is the one scenario where the correct behaviour is to CONTINUE. It is in the " +
				"suite to stop the installer from becoming so abort-happy that it is unusable on a live " +
				"machine, which is how a safety tool gets worked around.",
		},

		// ── family 5: source deleted under us ─────────────────────────────────────────────────────
		{
			ID:      "F11", Family: "source_deleted", Name: "Source file deleted just ahead of the copy",
			Site:    SiteGuest, Action: ActionDeleteSource, TargetOffset: 12,
			Trigger: Trigger{PhaseCopy, 3300},
			Why: "Temp files, browser cache, a user emptying Downloads while the tool runs. The inventory " +
				"is a snapshot; the disk is not.",
			ExpectAbort: true, DeviatesCorpus: true,
			WrongReason: "Treating a vanished source as 'nothing to copy' silently reduces the expected " +
				"count to match what was achieved, which makes the count check tautological.",
		},
		{
			ID:      "F12", Family: "source_deleted", Name: "Source file deleted before its copy begins",
			Site:    SiteGuest, Action: ActionDeleteSource, TargetOffset: 4000,
			Trigger: Trigger{PhaseCopy, 100},
			Why: "Same family, but the gap between inventory and copy is as wide as it gets. The installer " +
				"must report the discrepancy against the inventory it showed the user, not against what it " +
				"found later.",
			ExpectAbort: true, DeviatesCorpus: true,
			WrongReason: "Re-enumerating at copy time instead of using the acknowledged inventory would " +
				"make this pass while quietly breaking SAFETY.md phase 2's acknowledgement.",
		},

		// ── family 6: manifest damaged ────────────────────────────────────────────────────────────
		{
			ID:      "F13", Family: "manifest_damaged", Name: "Manifest truncated mid-record",
			Site:    SiteGuest, Action: ActionTruncateManifest,
			Trigger: Trigger{PhaseCopy, 8000},
			Params:  map[string]string{"keep_fraction_bp": "6000"},
			Why: "The manifest is the only thing that makes the archive verifiable. A truncated one must " +
				"abort — never be silently repaired, and never be treated as the shorter list it now is.",
			ExpectAbort: true,
			WrongReason: "A JSONL reader that skips the malformed last line would 'recover' from this and " +
				"verify a smaller corpus perfectly. That is the failure. LoadManifest rejects it on the " +
				"contiguous-index check instead.",
		},
		{
			ID:      "F14", Family: "manifest_damaged", Name: "Manifest truncated to zero bytes before verify",
			Site:    SiteGuest, Action: ActionTruncateManifest,
			Trigger: Trigger{PhaseCopy, 9990},
			Params:  map[string]string{"keep_fraction_bp": "0"},
			Why: "An empty manifest verifies vacuously against anything. Zero files compared, zero " +
				"mismatches, 100% success.",
			ExpectAbort: true,
			WrongReason: "This is the purest form of the vacuous pass, and any verifier that reports " +
				"success here would report success on an empty archive.",
		},

		// ── family 7: silent corruption ───────────────────────────────────────────────────────────
		{
			ID:      "F15", Family: "bit_flip", Name: "Single bit flipped in an already-copied file",
			Site:    SiteGuest, Action: ActionBitFlip, TargetOffset: -60,
			Trigger: Trigger{PhaseCopy, 5500},
			Why: "Bad USB stick, bad cable, bad RAM. One bit. This is what per-file hashing is FOR, and it " +
				"is the check most likely to be quietly downgraded to a size comparison for speed.",
			ExpectAbort: true,
			WrongReason: "A verify that compares sizes, or that trusts the hash computed during the copy " +
				"instead of re-reading from the destination, cannot see this at all and passes.",
		},
		{
			ID:      "F16", Family: "bit_flip", Name: "Single bit flipped inside the manifest",
			Site:    SiteGuest, Action: ActionBitFlip,
			Trigger: Trigger{PhaseCopy, 7700},
			Params:  map[string]string{"target": "manifest"},
			Why: "Corrupting the record rather than the data. One flipped hex digit in one stored hash and " +
				"exactly one file will appear corrupt that is not — or, worse, a corrupt file appears fine.",
			ExpectAbort: true,
			WrongReason: "If the manifest has no integrity of its own, the installer reports a file-level " +
				"problem and a user re-runs it forever on a file that is perfectly fine.",
		},

		// ── family 8: the clock ───────────────────────────────────────────────────────────────────
		{
			ID:      "F17", Family: "clock_backwards", Name: "System clock jumps backwards mid-copy",
			Site:    SiteGuest, Action: ActionClockBackwards,
			Trigger: Trigger{PhaseCopy, 5000},
			Params:  map[string]string{"seconds": "86400"},
			Why: "A dead CMOS battery on a 2013 laptop is not an edge case, it is the cohort. On these " +
				"machines the clock resets to the BIOS epoch on every boot and NTP corrects it seconds " +
				"later — backwards, by years.",
			ExpectAbort: false,
			WrongReason: "Anything that computes a duration as end-minus-start gets a negative number here, " +
				"and anything that uses mtime to decide whether a file changed gets a wrong answer. The " +
				"correct behaviour is to be unaffected, which is why this run expects NO abort: the " +
				"installer must use a monotonic clock and content hashes, not wall time.",
		},
		{
			ID:      "F18", Family: "clock_backwards", Name: "Clock jumps backwards across the COPY/VERIFY boundary",
			Site:    SiteGuest, Action: ActionClockBackwards,
			Trigger: Trigger{PhaseVerify, 1000},
			Params:  map[string]string{"seconds": "315360000"},
			Why: "Ten years backwards, at the moment verification starts. Any timestamp-based freshness " +
				"logic between the two phases breaks here.",
			ExpectAbort: false,
			WrongReason: "Same as F17. A pass means the installer ignored the clock, which is what it is " +
				"supposed to do.",
		},

		// ── family 9: antivirus ───────────────────────────────────────────────────────────────────
		{
			ID:      "F19", Family: "av_lock", Name: "Antivirus takes an exclusive handle on a file not yet copied",
			Site:    SiteGuest, Action: ActionExclusiveLock, TargetOffset: 25,
			Trigger: Trigger{PhaseCopy, 2200},
			Params:  map[string]string{"hold_ms": "120000"},
			Why: "Real-time scanning opens files with no sharing. On the machines we target, the antivirus " +
				"is usually the slowest and most aggressive thing installed.",
			ExpectAbort: true,
			WrongReason: "SAFETY.md phase 4 allows backup semantics and VSS to get past this. If neither " +
				"works the file must be QUARANTINED AND REPORTED. Silently skipping it is the failure, and " +
				"a skipped file plus a reduced expected count looks identical to a clean run.",
		},
		{
			ID:      "F20", Family: "av_lock", Name: "Antivirus locks a file on the destination during verify",
			Site:    SiteGuest, Action: ActionExclusiveLock, TargetOffset: -100,
			Trigger: Trigger{PhaseVerify, 6600},
			Params:  map[string]string{"hold_ms": "120000", "target": "destination"},
			Why: "Verification has to re-read every file from the destination. An antivirus scanning the " +
				"freshly written archive will hold some of them, and a file that cannot be read cannot be " +
				"verified.",
			ExpectAbort: true,
			WrongReason: "Counting an unreadable destination file as verified — or retrying it forever — " +
				"are both ways this looks green. SAFETY.md phase 5 allows exactly one retry, then " +
				"quarantine, then the unresolved count must be zero to proceed.",
		},
	}
}

// Families returns the nine failure modes, in catalogue order, for REPORT.md.
func Families() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range StandardSuite() {
		if !seen[s.Family] {
			seen[s.Family] = true
			out = append(out, s.Family)
		}
	}
	return out
}

// Lookup finds a scenario by id.
func Lookup(id string) (Scenario, error) {
	for _, s := range StandardSuite() {
		if strings.EqualFold(s.ID, id) {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("no such scenario %q (the suite is F01..F20)", id)
}

// Validate is called at startup by everything that uses the catalogue. It is cheap and it catches the
// edit that silently removes a test: a duplicated id, a trigger out of range, an action nobody
// implements, a family that lost its last member.
func Validate() error {
	suite := StandardSuite()
	if len(suite) != 20 {
		return fmt.Errorf("the suite has %d scenarios; spec §6C requires 20 induced-failure runs", len(suite))
	}
	known := map[Action]bool{
		ActionPowerCut:     true, ActionDetachDestination: true, ActionFillDestination: true,
		ActionMutateSource: true, ActionDeleteSource: true, ActionTruncateManifest: true,
		ActionBitFlip:      true, ActionClockBackwards: true, ActionExclusiveLock: true,
	}
	seen := map[string]bool{}
	fams := map[string]int{}
	for _, s := range suite {
		if seen[s.ID] {
			return fmt.Errorf("duplicate scenario id %s", s.ID)
		}
		seen[s.ID] = true
		if s.Trigger.BP < 0 || s.Trigger.BP > 10000 {
			return fmt.Errorf("%s: trigger %d bp out of range", s.ID, s.Trigger.BP)
		}
		if s.Trigger.Phase != PhaseCopy && s.Trigger.Phase != PhaseVerify {
			return fmt.Errorf("%s: unknown phase %q", s.ID, s.Trigger.Phase)
		}
		if !known[s.Action] {
			return fmt.Errorf("%s: action %q has no implementation", s.ID, s.Action)
		}
		if s.Site != SiteHost && s.Site != SiteGuest {
			return fmt.Errorf("%s: site must be host or guest", s.ID)
		}
		if s.Why == "" || s.WrongReason == "" {
			return fmt.Errorf("%s: every scenario must say why it exists and how it could pass for the "+
				"wrong reason", s.ID)
		}
		fams[s.Family]++
	}
	if len(fams) != 9 {
		names := make([]string, 0, len(fams))
		for f := range fams {
			names = append(names, f)
		}
		sort.Strings(names)
		return fmt.Errorf("expected 9 fault families, found %d: %s", len(fams), strings.Join(names, ", "))
	}
	// SAFETY.md rule 2: the abort path is tested more than the happy path. That ratio is checked by the
	// runner across the whole suite; here we only assert the abort-expecting scenarios still dominate
	// this file, because a catalogue that drifts to mostly-expect-success has stopped being this.
	aborts := 0
	for _, s := range suite {
		if s.ExpectAbort {
			aborts++
		}
	}
	if aborts < 12 {
		return errors.New("fewer than 12 of the 20 scenarios expect an abort: the fault catalogue has " +
			"drifted away from testing the abort path")
	}
	return nil
}

// Describe renders the catalogue as the table REPORT.md and README.md quote. Plain text on purpose:
// the moment this needs a template engine it will stop being regenerated.
func Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%-5s %-16s %-6s %-22s %-14s %s\n", "ID", "FAMILY", "SITE", "ACTION", "TRIGGER", "EXPECT")
	for _, s := range StandardSuite() {
		expect := "abort"
		if !s.ExpectAbort {
			expect = "CONTINUE (see Why)"
		}
		fmt.Fprintf(&b, "%-5s %-16s %-6s %-22s %-14s %s\n",
			s.ID, s.Family, s.Site, s.Action, s.Trigger.String(), expect)
	}
	return b.String()
}
