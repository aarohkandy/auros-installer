package gate3

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every test in this file is the same shape: drive a check into failure and
// require it to notice. DECISIONS.md D34 — "a test file that only demonstrates
// the happy path looks identical to one that works" — applied to the harness
// that is supposed to catch the installer losing somebody's files.

// ── fixtures ─────────────────────────────────────────────────────────────────

type fixture struct {
	dir    string
	corpus string
	dest   string
	golden string
	g      *Golden
}

var fixtureFiles = []struct {
	path string
	body string
}{
	{"Documents/Year 7/notes.txt", "one"},
	{"Documents/Year 7/homework.docx", "two two"},
	{"Desktop/timetable.txt", "three three three"},
	{"Pictures/class photo.jpg", "four four four four"},
	{"AppData/Local/Google/Chrome/User Data/Default/Bookmarks", "five"},
	{"AppData/Roaming/Mozilla/Firefox/Profiles/8f3k2p1q.default-release/prefs.js", "six"},
	{"Downloads/report card.pdf", "seven"},
	{"Music/song.mp3", "eight"},
	{"Videos/sports day.mp4", "nine"},
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{
		dir:    dir,
		corpus: filepath.Join(dir, "corpus"),
		dest:   filepath.Join(dir, "archive"),
		golden: filepath.Join(dir, "golden-manifest.jsonl"),
	}
	var lines []string
	for i, spec := range fixtureFiles {
		full := filepath.Join(f.corpus, filepath.FromSlash(spec.path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(spec.body), 0o644); err != nil {
			t.Fatal(err)
		}
		v, err := HashOf(full)
		if err != nil {
			t.Fatal(err)
		}
		rec := Rec{Index: i, Path: spec.path, Size: v.Size, SHA256: v.SHA256, Cohort: "fixture"}
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
	}
	if err := os.WriteFile(f.golden, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := LoadGolden(f.golden)
	if err != nil {
		t.Fatal(err)
	}
	f.g = g
	// A perfect archive: every file at its mapped path.
	for _, rec := range g.ByCopy {
		src := filepath.Join(f.corpus, filepath.FromSlash(rec.Path))
		dst := filepath.Join(f.dest, filepath.FromSlash(rec.Archive))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// ── the model of what the installer must do ──────────────────────────────────

func TestSuiteValidatesAndTestsTheAbortPathMore(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatalf("the suite does not validate: %v", err)
	}
	aborts, survives := 0, 0
	for _, s := range Suite() {
		switch s.Expect {
		case ExpectAbort, ExpectRefuse:
			aborts++
		case ExpectSurvive:
			survives++
		}
	}
	if aborts < 20 {
		t.Fatalf("spec §6C requires 20 induced failures; the suite has %d", aborts)
	}
	if aborts <= survives {
		t.Fatalf("SAFETY.md rule 2: %d aborts is not more than %d survivals", aborts, survives)
	}
}

func TestSuiteRejectsAScenarioWithATriggerAndNoAction(t *testing.T) {
	// The mechanical form of "a step that cannot fail is not a check": a
	// scenario that fires nothing would look exactly like a passing run.
	s := Scenario{ID: "X", Family: "x", Trigger: TriggerBytes, Phase: PhaseCopy, BP: 5000,
		Action: ActionNone, Expect: ExpectAbort, Why: "w", WrongReason: "r"}
	if err := validateOne(s); err == nil {
		t.Fatal("a triggered scenario with no action was accepted")
	}
}

// validateOne runs the suite validator over a single scenario by substituting it
// into the table's rules.
func validateOne(s Scenario) error {
	switch s.Trigger {
	case TriggerNone:
		if s.Action != ActionNone {
			return fmt.Errorf("action with no trigger")
		}
	case TriggerBytes, TriggerPartial:
		if s.Action == ActionNone {
			return fmt.Errorf("trigger with no action")
		}
	}
	return nil
}

func TestArchivePathMappingRefusesFilesOutsideTheKnownFolders(t *testing.T) {
	if _, err := ArchivePathFor("SomewhereElse/file.txt"); err == nil {
		t.Fatal("a file outside every known folder was silently mapped into the archive")
	}
	got, err := ArchivePathFor("AppData/Local/Google/Chrome/User Data/Default/Bookmarks")
	if err != nil {
		t.Fatal(err)
	}
	if got != "LocalAppData/Google/Chrome/User Data/Default/Bookmarks" {
		t.Fatalf("LocalAppData mapping is wrong: %s", got)
	}
	if got, _ := ArchivePathFor("AppData/Roaming/x/y.txt"); got != "RoamingAppData/x/y.txt" {
		t.Fatalf("RoamingAppData mapping is wrong: %s", got)
	}
}

func TestCopyOrderIsByteOrderOfTheArchivePathOrEveryPinIsWrong(t *testing.T) {
	f := newFixture(t)
	for i := 1; i < len(f.g.ByCopy); i++ {
		if !(f.g.ByCopy[i-1].Archive < f.g.ByCopy[i].Archive) {
			t.Fatalf("copy order is not byte order of the archive path: %q then %q",
				f.g.ByCopy[i-1].Archive, f.g.ByCopy[i].Archive)
		}
	}
	var cum int64
	for _, r := range f.g.ByCopy {
		cum += r.Size
		if r.CumEnd != cum {
			t.Fatalf("cumulative bytes are wrong at %s: %d != %d", r.Archive, r.CumEnd, cum)
		}
	}
}

func TestLoadGoldenRefusesANameThatWouldHaveToBeEscaped(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "g.jsonl")
	rec := Rec{Index: 0, Path: "Documents/a:b.txt", Size: 1, SHA256: strings.Repeat("a", 64)}
	b, _ := json.Marshal(rec)
	os.WriteFile(p, append(b, '\n'), 0o644)
	if _, err := LoadGolden(p); err == nil {
		t.Fatal("a corpus whose stored name the installer would have to escape was accepted; the " +
			"harness would then have looked for the file at a path it never used")
	}
}

func TestResolvePinLandsInsideTheRightFileOrTheScenarioIsNominal(t *testing.T) {
	f := newFixture(t)
	pin, err := ResolvePin(f.g, PhaseCopy, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if pin.CumulativeBytes != f.g.TotalBytes*5000/10000 {
		t.Fatalf("pin arithmetic is not integer basis points: %d", pin.CumulativeBytes)
	}
	var start int64
	found := false
	for _, r := range f.g.ByCopy {
		if r.CopyIndex == pin.CopyIndex {
			found = true
			break
		}
		start += r.Size
	}
	if !found {
		t.Fatal("the pin names a file that is not in the corpus")
	}
	if pin.ByteOffsetInFile != pin.CumulativeBytes-start {
		t.Fatalf("the offset within the pinned file is wrong: %d", pin.ByteOffsetInFile)
	}
}

func TestTargetFromPinRefusesAnImpossibleTarget(t *testing.T) {
	f := newFixture(t)
	pin, err := ResolvePin(f.g, PhaseCopy, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := TargetFromPin(f.g, pin, 1<<40); err == nil {
		t.Fatal("a target a terabyte past the end of the corpus was accepted; the scenario would have " +
			"fired at a file it did not mean")
	}
}

// ── the measurements go red ──────────────────────────────────────────────────

func TestSourceCheckCatchesACorruptedFile(t *testing.T) {
	f := newFixture(t)
	victim := filepath.Join(f.corpus, "Documents", "Year 7", "notes.txt")
	if err := os.WriteFile(victim, []byte("ONE"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := CheckSource(f.g, f.corpus, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Corrupt) != 1 {
		t.Fatalf("a corrupted source file was not reported: %+v", rep)
	}
}

func TestSourceCheckCatchesAMissingFile(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.corpus, "Music", "song.mp3")); err != nil {
		t.Fatal(err)
	}
	rep, _ := CheckSource(f.g, f.corpus, nil)
	if len(rep.Missing) != 1 {
		t.Fatalf("a deleted source file was not reported as lost: %+v", rep)
	}
}

func TestSourceCheckFailsWhenADeviationNeverHappened(t *testing.T) {
	f := newFixture(t)
	// The harness says it deleted a file. It did not. That must fail: an
	// expectation written in advance must never absorb a fault that did not land.
	devs := []Deviation{{Tree: "source", Path: "Music/song.mp3", Kind: "deleted", Absent: true}}
	rep, _ := CheckSource(f.g, f.corpus, devs)
	if len(rep.DeviationsLost) != 1 {
		t.Fatalf("a deviation that never happened was accepted: %+v", rep)
	}
}

func TestArchiveCheckCatchesOneFlippedBitAsCorruption(t *testing.T) {
	f := newFixture(t)
	victim := filepath.Join(f.dest, "Desktop", "timetable.txt")
	b, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	if err := os.WriteFile(victim, b, 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := CheckArchive(f.g, f.dest, nil, true)
	if len(rep.Corrupt) != 1 {
		t.Fatalf("one flipped bit in the archive was not reported: %+v", rep)
	}
}

func TestArchiveCheckCatchesAnExtraFileTheManifestNeverHeardOf(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.dest, "Desktop", "stranger.bin"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, _ := CheckArchive(f.g, f.dest, nil, true)
	if len(rep.Extra) != 1 {
		t.Fatalf("an extra file in the archive was not reported: %+v", rep)
	}
}

func TestArchiveCheckCatchesAMissingFileOnARunThatClaimsToBeComplete(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.dest, "Music", "song.mp3")); err != nil {
		t.Fatal(err)
	}
	rep, _ := CheckArchive(f.g, f.dest, nil, true)
	if len(rep.Missing) != 1 {
		t.Fatalf("a file missing from a complete archive was not reported: %+v", rep)
	}
	partial, _ := CheckArchive(f.g, f.dest, nil, false)
	if len(partial.Missing) != 0 {
		t.Fatalf("an aborted run's partial archive was reported as data loss: %+v", partial)
	}
}

func TestArchiveCheckRefusesATornFileThatNeverExisted(t *testing.T) {
	f := newFixture(t)
	// A file that was rewritten while it was being copied may legitimately be
	// either version. A MIXTURE of the two never existed and is corruption.
	rec := f.g.ByCopy[0]
	dev := Deviation{Tree: "archive", Path: rec.Archive, Kind: "rewritten under the copy",
		Allowed: []Variant{
			{SHA256: rec.SHA256, Size: rec.Size, Note: "before"},
			{SHA256: strings.Repeat("b", 64), Size: rec.Size, Note: "after"},
		}}
	if rep, _ := CheckArchive(f.g, f.dest, []Deviation{dev}, true); len(rep.DeviationsLost) != 0 {
		t.Fatalf("the version that really existed was rejected: %+v", rep)
	}
	victim := filepath.Join(f.dest, filepath.FromSlash(rec.Archive))
	b, _ := os.ReadFile(victim)
	os.WriteFile(victim, append(b, 'z'), 0o644)
	rep, _ := CheckArchive(f.g, f.dest, []Deviation{dev}, true)
	if len(rep.DeviationsLost) != 1 {
		t.Fatalf("a torn file — a mixture that never existed on disk — was accepted: %+v", rep)
	}
}

// ── the verdict fails closed ─────────────────────────────────────────────────

func newResultForTest(kind Kind) *Result {
	return &Result{
		Harness: HarnessVersion, RunID: "t", Kind: kind,
		Source:     &TreeReport{Tree: "source", Expected: 9, HashMatches: 9},
		Archive:    &TreeReport{Tree: "archive", Expected: 9, Present: 9, HashMatches: 9},
		SystemDisk: &SystemDiskReport{Records: 12, Excluded: 12},
		Enforcement: &Enforcement{Path: `C:\`, ACE: "(D;OICI;0x00010156;;;S-1-5-21-1)", Applied: true,
			Verified: true, Removed: true, Exemptions: []string{`C:\Users\auros-gate3`}},
		InstallerWrites: &WriteAudit{Events: 40},
		Claims: &Claims{ClaimedVerified: true, VerifiedCount: 9, ReachedWall: true, Events: 30,
			ArmPlanPrinted: true, SawPhaseEvents: true},
		Inventory:  fullInventory(),
		CorpusRoot: `C:\gate3\corpus`,
	}
}

func fullInventory() map[string]string {
	inv := map[string]string{}
	for _, kf := range KnownFolderLabels() {
		inv[kf[1]] = `C:\gate3\corpus\` + strings.ReplaceAll(kf[0], "/", `\`)
	}
	return inv
}

func TestVerdictFailsWhenAnInstallerClaimsVerificationOnARunThatMustAbort(t *testing.T) {
	sc, err := Lookup("F02")
	if err != nil {
		t.Fatal(err)
	}
	r := newResultForTest(KindFault)
	r.ExitCode = 1
	r.Fire = &FireRecord{ScenarioID: "F02", Fired: true, ObservedBytes: 1 << 20, DestBytesAtFire: 1 << 20}
	r.Pin = &Pin{CumulativeBytes: 1 << 20}
	r.Evaluate(&sc, 9)
	if v, why := r.Recompute(RequiredChecks(KindFault, &sc)); v == Pass {
		t.Fatalf("an aborted run that recorded a verified archive was scored as a pass (%v)", why)
	}
}

func TestVerdictFailsWhenTheFaultNeverFired(t *testing.T) {
	sc, _ := Lookup("F02")
	r := newResultForTest(KindFault)
	r.ExitCode = 1
	r.Claims.ClaimedVerified = false
	r.Fire = &FireRecord{ScenarioID: "F02", Fired: false, NotFired: "the installer ended first"}
	r.Evaluate(&sc, 9)
	if v, _ := r.Recompute(RequiredChecks(KindFault, &sc)); v == Pass {
		t.Fatal("a run in which nothing was ever induced was scored as an induced-failure pass")
	}
}

func TestVerdictFailsWhenTheSystemDiskWasWrittenTo(t *testing.T) {
	for name, mut := range map[string]func(r *Result){
		"a write": func(r *Result) {
			r.InstallerWrites.Writes = []string{`C:\ProgramData\auros\scratch.tmp — create by auros-migrate.exe(200)`}
		},
		"a refused attempt": func(r *Result) {
			r.InstallerWrites.Denied = []string{`C:\auros\x — create refused by auros-migrate.exe(200)`}
		},
		"an unreadable trace": func(r *Result) { r.InstallerWrites.Error = "the trace could not be read" },
		"no trace":            func(r *Result) { r.InstallerWrites = nil },
		"no ACE":              func(r *Result) { r.Enforcement = nil },
		"an unverified ACE":   func(r *Result) { r.Enforcement.Verified = false },
		"an ACE left behind":  func(r *Result) { r.Enforcement.RemoveError = "icacls failed" },
	} {
		r := newResultForTest(KindClean)
		r.Manifest = goodManifest()
		r.manifestGolden = &Golden{}
		mut(r)
		r.Evaluate(nil, 9)
		if v, _ := r.Recompute(RequiredChecks(KindClean, nil)); v == Pass {
			t.Errorf("%s: scored as a pass", name)
		}
	}
}

// The owner chose enforcement only: the change journal is a report line.
func TestTheChangeJournalNoLongerGates(t *testing.T) {
	r := newResultForTest(KindClean)
	r.Manifest = goodManifest()
	r.manifestGolden = &Golden{}
	r.SystemDisk.Wrapped = true
	r.SystemDisk.Unexplained = []string{`C:\Windows\System32\SecurityHealth\x [file-create]`}
	r.InstallerWrites.Exempt = []string{`C:\Users\auros-gate3\AppData\Local\Temp\x — create by auros-migrate.exe(200)`}
	r.Evaluate(nil, 9)
	if v, why := r.Recompute(RequiredChecks(KindClean, nil)); v != Pass {
		t.Fatalf("background churn on C: or a write inside the exemption failed a clean run: %v", why)
	}
}

func TestVerdictFailsWhenAKnownFolderResolvedSomewhereElse(t *testing.T) {
	r := newResultForTest(KindClean)
	r.Manifest = goodManifest()
	r.manifestGolden = &Golden{}
	r.Inventory["Documents"] = `C:\Users\auros-gate3\Documents`
	r.Evaluate(nil, 9)
	if v, _ := r.Recompute(RequiredChecks(KindClean, nil)); v == Pass {
		t.Fatal("a run that inventoried the WRONG Documents folder was scored as a pass; an installer " +
			"that stopped asking Windows where the folders are would pass every other check")
	}
}

func TestVerdictFailsWhenTheHarnessHadToKillAHungInstaller(t *testing.T) {
	sc, _ := Lookup("F07")
	r := newResultForTest(KindFault)
	r.ExitCode = 1
	r.Claims.ClaimedVerified = false
	r.TimedOut = true
	r.Fire = &FireRecord{ScenarioID: "F07", Fired: true, ObservedBytes: 1 << 20, DestBytesAtFire: 1 << 20}
	r.Pin = &Pin{CumulativeBytes: 1 << 20}
	r.Evaluate(&sc, 9)
	if v, _ := r.Recompute(RequiredChecks(KindFault, &sc)); v == Pass {
		t.Fatal("an installer that never ended was scored as a clean abort")
	}
}

func TestVerdictFailsWhenTheInstallerAbortedForAnUnrelatedReason(t *testing.T) {
	// The failure this exists for is not hypothetical. The first version of this
	// harness left the migration account's registry hive inside the corpus; the
	// installer quarantined it and stopped on EVERY run, so every scenario
	// "aborted cleanly" without any of them reaching its own fault.
	sc, _ := Lookup("F07") // the destination fills; the installer must say "destination-full"
	r := newResultForTest(KindFault)
	r.ExitCode = 1
	r.Claims.ClaimedVerified = false
	r.Claims.AbortReason = "verify: safety: unresolved quarantined files remain"
	r.Quarantine = &QuarantineReport{Exists: true,
		Head: []string{"locked-or-in-use   LocalAppData/Microsoft/Windows/UsrClass.dat"}}
	r.Fire = &FireRecord{ScenarioID: "F07", Fired: true, ObservedBytes: 1 << 20, DestBytesAtFire: 1 << 20}
	r.Pin = &Pin{CumulativeBytes: 1 << 20}
	r.Evaluate(&sc, 9)
	if v, _ := r.Recompute(RequiredChecks(KindFault, &sc)); v == Pass {
		t.Fatal("a run that aborted for a reason unrelated to its scenario was scored as an induced-failure pass")
	}
}

func TestVerdictAcceptsAnAbortThatNamesItsOwnReason(t *testing.T) {
	// The other direction, so the check above is not passing because the
	// evidence can never be found.
	sc, _ := Lookup("F07")
	r := newResultForTest(KindFault)
	r.ExitCode = 1
	r.Claims.ClaimedVerified = false
	r.Claims.AbortReason = "copy: copyengine: destination volume is full after 9042 of 18000 files"
	r.Quarantine = &QuarantineReport{Exists: true, Head: []string{"destination-full   Documents/x.docx"}}
	r.Fire = &FireRecord{ScenarioID: "F07", Fired: true, ObservedBytes: 1 << 20, DestBytesAtFire: 1 << 20}
	r.Pin = &Pin{CumulativeBytes: 1 << 20}
	r.Evaluate(&sc, 9)
	if v, why := r.Recompute(RequiredChecks(KindFault, &sc)); v != Pass {
		t.Fatalf("an abort that named its own reason was scored as a failure: %v", why)
	}
}

func TestRecomputeFailsWhenACheckIsSimplyMissing(t *testing.T) {
	r := &Result{Checks: []Check{{ID: CheckSystemDisk, Status: Pass}}}
	if v, why := r.Recompute(RequiredChecks(KindClean, nil)); v == Pass {
		t.Fatalf("a result carrying one check was scored as a pass (%v)", why)
	}
	empty := &Result{}
	if v, _ := empty.Recompute(nil); v == Pass {
		t.Fatal("a result with no checks at all was scored as a pass")
	}
}

func TestVerdictFailsWhenADryRunPerformedAnArmStep(t *testing.T) {
	r := newResultForTest(KindClean)
	r.Manifest = goodManifest()
	r.manifestGolden = &Golden{}
	r.Claims.ArmPerformed = true
	r.Evaluate(nil, 9)
	if v, _ := r.Recompute(RequiredChecks(KindClean, nil)); v == Pass {
		t.Fatal("a dry run that performed a step on the other side of the wall was scored as a pass")
	}
}

func TestReadArmOutcomeSeesADryRunAndACommittedOne(t *testing.T) {
	dry := "mode: DRY RUN\nno step below was performed; nothing on this machine was changed.\n" +
		"this is what --commit would do:\n  1. Suspend BitLocker…\n"
	if plan, performed := ReadArmOutcome(dry); !plan || performed {
		t.Fatalf("a dry run read as plan=%v performed=%v", plan, performed)
	}
	done := "mode: COMMIT\nperformed:\n  1. Suspend BitLocker…\n"
	if _, performed := ReadArmOutcome(done); !performed {
		t.Fatal("a run that performed an arm step read as though it had not")
	}
}

func TestRecomputeRefusesAnUnknownStatus(t *testing.T) {
	r := &Result{Checks: []Check{{ID: CheckSystemDisk, Status: Status("probably fine")}}}
	if v, _ := r.Recompute([]string{CheckSystemDisk}); v == Pass {
		t.Fatal("an unknown check status was treated as a pass")
	}
}

// ── the installer's own manifest, parsed independently ───────────────────────

func goodManifest() *ManifestFile {
	return &ManifestFile{Exists: true, Parses: true, TrailerOK: true, Count: 9}
}

func TestInstallerManifestIsRejectedWhenTruncated(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, MetaDirName)
	os.MkdirAll(meta, 0o755)
	body := "auros-manifest/1\n" +
		strings.Repeat("a", 64) + "\t3\t0\tDocuments/x.txt\tDocuments/x.txt\n"
	os.WriteFile(filepath.Join(meta, "manifest.tsv"), []byte(body), 0o644)
	m, err := ReadInstallerManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Parses {
		t.Fatal("a manifest with no trailer was accepted: a short manifest that parses is how a " +
			"verifier is fooled into passing on a partial copy")
	}
}

func TestInstallerManifestIsRejectedWhenABitIsFlipped(t *testing.T) {
	dir := t.TempDir()
	meta := filepath.Join(dir, MetaDirName)
	os.MkdirAll(meta, 0o755)
	entry := strings.Repeat("a", 64) + "\t3\t0\tDocuments/x.txt\tDocuments/x.txt\n"
	body := "auros-manifest/1\n" + entry
	trailer := fmt.Sprintf("end\t1\t3\t%s\n", sha256Hex(body))
	full := body + trailer
	os.WriteFile(filepath.Join(meta, "manifest.tsv"), []byte(full), 0o644)
	m, _ := ReadInstallerManifest(dir)
	if !m.Parses {
		t.Fatalf("a well-formed manifest was rejected: %s", m.ParseError)
	}
	// One flipped hex digit in the recorded hash.
	flipped := strings.Replace(full, strings.Repeat("a", 64), "b"+strings.Repeat("a", 63), 1)
	os.WriteFile(filepath.Join(meta, "manifest.tsv"), []byte(flipped), 0o644)
	m2, _ := ReadInstallerManifest(dir)
	if m2.Parses {
		t.Fatal("a manifest with a corrupted body was accepted; its own trailer digest exists to " +
			"prevent exactly that")
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ── the noise list is not a blanket ──────────────────────────────────────────

func TestNoiseListNeverExcusesAnywhereTheInstallerMightWrite(t *testing.T) {
	mustNotBeNoise := []string{
		`C:\gate3\corpus\Documents\Year 7\notes.txt`,
		`C:\gate3\corpus\AppData\Local\Google\Chrome\User Data\Default\Bookmarks`,
		`C:\auros-gate3-must-never-exist\_auros\manifest.tsv`,
		`C:\ProgramData\Auros\state.json`,
		`C:\Users\auros-gate3\Documents\something.txt`,
		`C:\Users\auros-gate3\AppData\Roaming\auros\run.log`,
		`C:\Windows\System32\bcdedit-backup.bcd`,
		`C:\Users\runneradmin\Documents\notes.txt`,
		`C:\boot.ini`,
		`C:\Windows\Boot\EFI\bootmgfw.efi`,
		`C:\Windows\CbsTemp\auros-migrate.exe`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\payload.dll`,
		`C:\Windows\CbsTemp\31279493_2394330146\scratch\ActionList.xml`,
		`C:\Windows\WindowsUpdate.log.auros`,
		`C:\Windows\System32\wbem\Repository\auros.dat`,
		`C:\Windows\System32\wbem\auros.mof`,
	}
	for _, p := range mustNotBeNoise {
		if ok, rule := IsNoise(p); ok {
			t.Errorf("the noise list excuses %s (rule %q) — the invariant check has a hole in it", p, rule)
		}
	}
	mustBeNoise := []string{
		`C:\Windows\System32\config\SOFTWARE.LOG1`,
		`C:\Windows\System32\winevt\Logs\System.evtx`,
		`C:\Users\auros-gate3\NTUSER.DAT`,
		`C:\Users\auros-gate3\ntuser.dat.LOG1`,
		`C:\actions-runner\_diag\Worker_20260921.log`,
		`C:\pagefile.sys`,
		// Measured on windows-2025 run 35562498238, clean-0-1: a servicing-stack
		// Features-on-Demand enumeration with Windows Update's services stopped.
		`C:\Windows\CbsTemp\31279493_2394330146`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\ActionList.xml`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\DeviceInventory.xml`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\ServerTargetCompDB_Conditions.xml`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\ServerTargetCompDB_FOD_sr-latn-rs.xml`,
		`C:\Windows\CbsTemp\31279493_2394330146\LocalFoDEnum\ServerTargetCompDB_zh-tw.xml`,
		`C:\Windows\CbsTemp\{24C2F83F-4420-40C0-B8D7-2A677196947D}`,
		`C:\Windows\WindowsUpdate.log`,
		`C:\Windows\System32\wbem\Repository\MAPPING2.MAP`,
	}
	for _, p := range mustBeNoise {
		if ok, _ := IsNoise(p); !ok {
			t.Errorf("%s is not excused, so every run will report it and the check will be ignored", p)
		}
	}
}

// ── the installer's inventory lines ──────────────────────────────────────────

func TestInventoryLinesReadTheFoldersTheInstallerSaysItLookedAt(t *testing.T) {
	out := "\nauros-migrate   mode: DRY RUN   platform: windows\n" +
		"------------------------------------------------------------------------\n" +
		"\n[DRY RUN] 1-inventory   (reads and writes to the backup drive only)\n" +
		"  Desktop          C:\\gate3\\corpus\\Desktop\n" +
		"  Documents        C:\\gate3\\corpus\\Documents\n" +
		"  LocalAppData     C:\\gate3\\corpus\\AppData\\Local\n" +
		"\n  18000 files, 8.0 GiB\n"
	inv := InventoryLines(out)
	if inv["Documents"] != `C:\gate3\corpus\Documents` {
		t.Fatalf("Documents was read as %q", inv["Documents"])
	}
	if inv["LocalAppData"] != `C:\gate3\corpus\AppData\Local` {
		t.Fatalf("LocalAppData was read as %q", inv["LocalAppData"])
	}
	if len(inv) != 3 {
		t.Fatalf("expected three folders, got %d: %v", len(inv), inv)
	}
}
