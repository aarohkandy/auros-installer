package gate3

import (
	"fmt"
	"sort"
	"strings"
)

// MaxOvershootBytes bounds how far past its pin a fault may fire and still count
// as having fired AT that pin.
//
// The harness polls the job object's I/O counters every couple of milliseconds
// and the installer writes through a 1 MiB buffer, so a few megabytes of
// overshoot is the measurement, not a drift. Sixteen is four doublings of
// headroom and still three orders of magnitude below an 8 GB corpus: a fault
// pinned at 43% cannot quietly become one that fired at 99%.
const MaxOvershootBytes int64 = 16 << 20

// Evaluate turns the run's measurements into checks. It adds every check the
// run owes and never omits one: a check that did not run is a check that failed,
// and Recompute enforces that from the other side.
func (r *Result) Evaluate(sc *Scenario, expectedFiles int) {
	// ── C1: the invariant (D27). Nothing was written to the system disk. ──
	sys := r.SystemDisk
	switch {
	case sys == nil:
		r.Add(CheckSystemDisk, false, "the system disk was never measured")
	case sys.Error != "":
		r.Add(CheckSystemDisk, false, "the system disk could not be measured: %s", sys.Error)
	case sys.Wrapped:
		r.Add(CheckSystemDisk, false,
			"the change journal wrapped during the run, so the window cannot be accounted for")
	case len(sys.Unexplained) > 0:
		r.Add(CheckSystemDisk, false, "%d change(s) to C: that the noise list does not explain, first: %s",
			len(sys.Unexplained), sys.Unexplained[0])
	default:
		r.Add(CheckSystemDisk, true, "%d change-journal records examined between USN %d and %d; "+
			"%d matched the published noise list; nothing else touched C:",
			sys.Records, sys.StartUSN, sys.EndUSN, sys.Excluded)
	}

	// ── C2: the user's own files are byte-identical afterwards. ──
	if r.Source == nil {
		r.Add(CheckSourceIntact, false, "the source was never re-hashed")
	} else {
		s := r.Source
		bad := len(s.Missing) + len(s.Corrupt) + len(s.Unreadable) + len(s.DeviationsLost) + len(s.Extra)
		if bad == 0 {
			r.Add(CheckSourceIntact, true,
				"%d of %d source files re-hashed against the golden manifest, byte-identical (%d deliberate deviation(s))",
				s.HashMatches, s.Expected, len(s.DeviationsSeen))
		} else {
			r.Add(CheckSourceIntact, false,
				"DATA LOSS OR DAMAGE IN THE SOURCE: %d lost, %d corrupted, %d unreadable, %d unexpected new files, "+
					"%d deliberate deviations not in the state the harness left them in%s",
				len(s.Missing), len(s.Corrupt), len(s.Unreadable), len(s.Extra), len(s.DeviationsLost),
				firstOf(s.Missing, s.Extra)+firstProblem(s.Corrupt))
		}
	}

	// ── C3: nothing in the archive is silently wrong. ──
	if r.Archive == nil {
		r.Add(CheckArchiveSound, false, "the archive was never re-hashed")
	} else {
		a := r.Archive
		bad := len(a.Corrupt) + len(a.Unreadable) + len(a.DeviationsLost) + len(a.Extra)
		if bad == 0 {
			r.Add(CheckArchiveSound, true,
				"%d file(s) present on the destination, every one byte-identical to the golden manifest "+
					"(%d partial file(s) left behind, which is debris and not an archive entry)",
				a.Present, len(a.Partials))
		} else {
			r.Add(CheckArchiveSound, false,
				"CORRUPTION IN THE ARCHIVE: %d corrupted, %d unreadable, %d unexpected, %d deliberate "+
					"deviations not as injected%s",
				len(a.Corrupt), len(a.Unreadable), len(a.Extra), len(a.DeviationsLost),
				firstProblem(a.Corrupt))
		}
	}

	// ── C4: the installer did what the scenario requires. ──
	r.evaluateOutcome(sc, expectedFiles)

	// ── C5: the fault fired, at its pin. ──
	if sc != nil && sc.Trigger != TriggerNone {
		switch {
		case r.Fire == nil:
			r.Add(CheckFaultFired, false, "no fire record: this run is not evidence about %s", sc.ID)
		case !r.Fire.Fired:
			r.Add(CheckFaultFired, false, "the fault never fired (%s): a scenario that did not happen "+
				"is not a scenario that passed", r.Fire.NotFired)
		case r.Fire.ActionError != "":
			r.Add(CheckFaultFired, false, "the fault fired but the action failed: %s", r.Fire.ActionError)
		case sc.Trigger == TriggerBytes && r.Fire.OvershootBytes > MaxOvershootBytes:
			r.Add(CheckFaultFired, false, "fired %d bytes past its pin, over the %d-byte ceiling: the pin "+
				"was nominal, not real", r.Fire.OvershootBytes, MaxOvershootBytes)
		case sc.Trigger == TriggerBytes && r.Fire.ObservedBytes <= 0:
			r.Add(CheckFaultFired, false, "fired with zero bytes moved: that is before the installer did "+
				"anything, not at %d%%", sc.BP/100)
		case sc.Phase == PhaseCopy && r.Fire.DestBytesAtFire <= 0 && r.Pin != nil && r.Pin.CumulativeBytes > 0:
			// The one cross-check that does not come from the installer at all:
			// the operating system said it had written bytes, so the destination
			// volume must have less free space than it started with. An
			// installer that reports a copy it is not performing fails here.
			r.Add(CheckFaultFired, false, "the OS had seen %d bytes written but the destination volume "+
				"had gained nothing when the trigger fired", r.Fire.ObservedBytes)
		default:
			r.Add(CheckFaultFired, true, "fired at %d bytes (%+d from the pin), with %d bytes really on "+
				"the destination at that instant; target %s",
				r.Fire.ObservedBytes, r.Fire.OvershootBytes, r.Fire.DestBytesAtFire,
				orNone(r.Fire.TargetPath))
		}
	}

	// ── C6: the wall was never crossed. Every run here is a dry run. ──
	switch {
	case r.Claims == nil:
		r.Add(CheckWallNotCrossed, false, "the installer's run log was never read")
	case r.Claims.CrossedWall:
		r.Add(CheckWallNotCrossed, false,
			"THE RUN LOG SAYS THE WALL WAS CROSSED in a dry run with the privileged steps compiled out")
	default:
		r.Add(CheckWallNotCrossed, true, "the run log records no wall crossing (dry run, %d events)",
			r.Claims.Events)
	}

	// ── C7: on a run that claims success, everything is actually there. ──
	if r.Kind == KindClean || (sc != nil && sc.Expect == ExpectSurvive) {
		a := r.Archive
		switch {
		case a == nil:
			r.Add(CheckArchiveFull, false, "the archive was never walked")
		case len(a.Missing) > 0:
			r.Add(CheckArchiveFull, false, "FILES LOST: %d of %d golden files are not in the archive, first: %s",
				len(a.Missing), a.Expected, a.Missing[0])
		case len(a.Partials) > 0:
			r.Add(CheckArchiveFull, false, "%d unfinished .auros-partial file(s) in an archive that claims "+
				"to be complete, first: %s", len(a.Partials), a.Partials[0])
		case a.HashMatches+len(a.DeviationsSeen) < a.Expected:
			r.Add(CheckArchiveFull, false, "only %d of %d files matched by hash", a.HashMatches, a.Expected)
		default:
			r.Add(CheckArchiveFull, true, "all %d files exist in two places and the second copy was "+
				"re-hashed here, file by file", a.Expected)
		}
	}

	// ── C8: the manifest the RESTORE will read agrees with what is on disk. ──
	if r.Kind == KindClean || (sc != nil && sc.Expect == ExpectSurvive) {
		m := r.Manifest
		switch {
		case m == nil || !m.Exists:
			r.Add(CheckManifestSound, false,
				"no manifest on the destination: the archive cannot be re-verified by the restore")
		case !m.Parses:
			r.Add(CheckManifestSound, false, "the manifest on the destination does not parse: %s", m.ParseError)
		case m.Count != expectedFiles:
			r.Add(CheckManifestSound, false, "the manifest on the destination lists %d files, the corpus has %d",
				m.Count, expectedFiles)
		default:
			if bad := r.manifestDisagrees(); bad != "" {
				r.Add(CheckManifestSound, false, "the manifest on the destination disagrees with the bytes "+
					"that are there: %s", bad)
			} else {
				r.Add(CheckManifestSound, true, "%d entries, trailer digest intact, every entry agrees with "+
					"the harness's own hash of the file it names", m.Count)
			}
		}
	}

	// ── C9: the installer looked where the user's files actually are. ──
	r.evaluateKnownFolders()

	// ── C10: the installer finished on its own. ──
	switch {
	case r.TimedOut:
		r.Add(CheckEndedItself, false,
			"the harness had to kill the installer on its timeout after %.0fs: a run that never ended is "+
				"not an abort", r.DurationSec)
	case r.KilledByUs && (sc == nil || sc.Action != ActionKill):
		r.Add(CheckEndedItself, false, "the harness killed the installer and this scenario did not ask it to")
	case r.KilledByUs:
		r.Add(CheckEndedItself, true, "ended when the scenario killed it, which is the scenario")
	default:
		r.Add(CheckEndedItself, true, "exited by itself after %.1fs with code %d", r.DurationSec, r.ExitCode)
	}
}

func (r *Result) evaluateOutcome(sc *Scenario, expectedFiles int) {
	expect := Expect(ExpectSurvive)
	if sc != nil {
		expect = sc.Expect
	}
	c := r.Claims
	if c == nil {
		r.Add(CheckOutcome, false, "the installer's run log was never read, so its claims are unknown")
		return
	}
	switch expect {
	case ExpectAbort:
		switch {
		case r.ExitCode == 0:
			r.Add(CheckOutcome, false, "the installer exited 0: this scenario requires it to stop")
		case c.ClaimedVerified:
			r.Add(CheckOutcome, false,
				"THE INSTALLER CLAIMED A VERIFIED ARCHIVE (%d files) on a run that was supposed to abort",
				c.VerifiedCount)
		default:
			r.Add(CheckOutcome, true, "stopped with exit %d and never claimed a verified archive%s",
				r.ExitCode, abortReason(c))
		}
	case ExpectRefuse:
		copied := 0
		partials := 0
		if r.Archive != nil {
			copied = r.Archive.Present
			partials = len(r.Archive.Partials)
		}
		switch {
		case r.ExitCode == 0:
			r.Add(CheckOutcome, false, "the installer exited 0: it was supposed to refuse")
		case c.ClaimedVerified:
			r.Add(CheckOutcome, false, "the installer claimed a verified archive on a run it should have refused")
		case copied > 0 || partials > 0:
			r.Add(CheckOutcome, false,
				"the installer copied %d file(s) (%d partial) before refusing: phase 3 must refuse before "+
					"anything is written", copied, partials)
		default:
			r.Add(CheckOutcome, true, "refused with exit %d before copying a single file%s", r.ExitCode, abortReason(c))
		}
	default: // ExpectSurvive, and every clean run
		switch {
		case r.ExitCode != 0:
			r.Add(CheckOutcome, false, "the installer exited %d on a run that had to succeed", r.ExitCode)
		case !c.ClaimedVerified:
			r.Add(CheckOutcome, false, "the installer exited 0 without ever recording a verified archive")
		case c.VerifiedCount != expectedFiles:
			r.Add(CheckOutcome, false, "the installer says it verified %d files; the corpus has %d",
				c.VerifiedCount, expectedFiles)
		case !c.ReachedWall:
			r.Add(CheckOutcome, false,
				"the installer never recorded reaching the wall: a dry run must say where it stopped")
		default:
			r.Add(CheckOutcome, true, "succeeded, recorded a verified archive of %d files, and stopped at "+
				"the wall as a dry run must", c.VerifiedCount)
		}
	}
}

func (r *Result) evaluateKnownFolders() {
	if len(r.Inventory) == 0 {
		r.Add(CheckKnownFolders, false,
			"the installer printed no known folders: phase 1 found nowhere to look, and a run that "+
				"copied nothing from nowhere would otherwise look like a run with nothing to copy")
		return
	}
	root := strings.ToLower(strings.TrimRight(r.CorpusRoot, `\`))
	var wrong []string
	for _, kf := range knownFolderRoots {
		got, ok := r.Inventory[kf.Label]
		if !ok {
			wrong = append(wrong, kf.Label+": not inventoried at all")
			continue
		}
		want := strings.ToLower(root + `\` + strings.ReplaceAll(kf.Corpus, "/", `\`))
		if strings.ToLower(strings.TrimRight(got, `\`)) != want {
			wrong = append(wrong, fmt.Sprintf("%s: the installer resolved %s, the corpus is at %s",
				kf.Label, got, want))
		}
	}
	sort.Strings(wrong)
	if len(wrong) > 0 {
		r.Add(CheckKnownFolders, false, "known-folder redirection did not take: %s", strings.Join(wrong, "; "))
		return
	}
	r.Add(CheckKnownFolders, true, "all %d known folders resolved into the corpus, through "+
		"SHGetKnownFolderPath rather than by assuming %%USERPROFILE%%", len(knownFolderRoots))
}

// manifestDisagrees compares the installer's manifest against the harness's own
// hashes. It returns "" when they agree.
func (r *Result) manifestDisagrees() string {
	if r.Manifest == nil || r.manifestGolden == nil {
		return "the harness did not load a corpus to compare it against"
	}
	var bad []string
	for _, rec := range r.manifestGolden.ByCopy {
		e, ok := r.Manifest.Entry(rec.Archive)
		if !ok {
			bad = append(bad, rec.Archive+" is not in the manifest at all")
		} else if e.SHA256 != rec.SHA256 || e.Size != rec.Size {
			bad = append(bad, fmt.Sprintf("%s: manifest says %s (%d bytes), the corpus is %s (%d bytes)",
				rec.Archive, e.SHA256, e.Size, rec.SHA256, rec.Size))
		}
		if len(bad) >= 5 {
			break
		}
	}
	return strings.Join(bad, "; ")
}

// manifestGolden is set by the runner so Evaluate can compare the installer's
// manifest against the corpus. It is not serialised.
func (r *Result) attachGolden(g *Golden) { r.manifestGolden = g }

func firstOf(lists ...[]string) string {
	for _, l := range lists {
		if len(l) > 0 {
			return " — first: " + l[0]
		}
	}
	return ""
}

func firstProblem(ps []Problem) string {
	if len(ps) == 0 {
		return ""
	}
	return fmt.Sprintf(" — first: %s (%s: wanted %s, found %s)", ps[0].Path, ps[0].Kind, ps[0].Want, ps[0].Got)
}

func abortReason(c *Claims) string {
	if c.AbortReason != "" {
		return " (" + c.AbortReason + ")"
	}
	if len(c.Refusals) > 0 {
		return " (" + c.Refusals[0] + ")"
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
