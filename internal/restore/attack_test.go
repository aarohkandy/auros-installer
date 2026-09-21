package restore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This file is the record of ten attacks against the Linux restore, every one
// of which succeeded against the code as it stood. Each test is written to go
// red against the original defect and green against the fix, and the message it
// prints on failure names the consequence rather than the assertion, because
// the consequence is somebody's payroll spreadsheet.
//
// The rule these exist to serve: a check that cannot fail is not a check. Every
// one of these was watched failing before the fix that makes it pass.

// ---- FATAL 1: the finder never looked where the archive actually is ----

// The Windows half puts the archive at <volume>/auros-backup, because
// cmd/auros-migrate asks safety.Resolver.Choose for that subdirectory and
// copyengine then writes _auros/manifest.tsv under it. The path below is
// spelled as a LITERAL on purpose: a fixture built out of the same constant the
// finder reads would move when the constant moves, and would agree with the bug
// instead of with the stick in somebody's pocket.
func TestFinder_FindsTheArchiveWhereTheWindowsHalfActuallyPutsIt(t *testing.T) {
	mount := t.TempDir()
	buildArchive(t, filepath.Join(mount, "auros-backup"), map[string]string{
		"Documents/payroll.xlsx": "everyone's salary",
	})

	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: mount, FSType: "vfat"}}, nil },
		ExtraRoots: []string{},
	}
	found, err := f.Find()
	if err != nil {
		t.Fatalf("the archive is on the stick at %s/auros-backup and the finder did not see it: %v\n"+
			"The Windows disk is already overwritten by now; this is the user being told "+
			"there is nothing to restore while their only copy sits unread.",
			mount, err)
	}
	if len(found) != 1 {
		t.Fatalf("found %d archives, want 1", len(found))
	}
	if got, want := found[0].Root, filepath.Join(mount, "auros-backup"); got != want {
		t.Errorf("archive root = %s, want %s", got, want)
	}
}

// --archive <mount> is the operator pointing at the stick, not at the folder on
// it. It has to find the same thing.
func TestFinder_ExplicitMountPointDescendsToTheArchiveFolder(t *testing.T) {
	mount := t.TempDir()
	buildArchive(t, filepath.Join(mount, "auros-backup"), map[string]string{
		"Documents/payroll.xlsx": "everyone's salary",
	})
	f := &Finder{Explicit: mount}
	found, err := f.Find()
	if err != nil {
		t.Fatalf("--archive %s did not find the archive one level down: %v", mount, err)
	}
	if got, want := found[0].Root, filepath.Join(mount, "auros-backup"); got != want {
		t.Errorf("archive root = %s, want %s", got, want)
	}
}

// ---- MINOR: an explicit --archive that is wrong is not "no backup attached" ----

func TestFinder_AnExplicitArchiveThatIsNotThereIsNotAnAbsenceOfBackups(t *testing.T) {
	dir := t.TempDir()
	f := &Finder{Explicit: dir}
	_, err := f.Find()
	if err == nil {
		t.Fatal("an explicit --archive with no manifest under it returned no error")
	}
	if errors.Is(err, ErrNoArchive) {
		t.Fatalf("--archive %s could not be honoured, and the caller is told that no backup drive "+
			"is attached (exit 0, nothing to do). The user typed a path; the tool decided for them.\n  got: %v",
			dir, err)
	}
	if !errors.Is(err, ErrExplicitArchiveMissing) {
		t.Fatalf("err = %v, want ErrExplicitArchiveMissing", err)
	}
	// It must say what it looked for, not merely that it did not find it.
	for _, want := range []string{dir, "_auros", "auros-backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q:\n%v", want, err)
		}
	}
}

// A removable drive that was searched and held nothing is a different fact
// from "nothing is attached", and the caller must be able to tell them apart.
func TestFinder_ADriveThatIsAttachedButEmptyIsNotNothingAttached(t *testing.T) {
	stick := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stick, "Holiday photos"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: stick, FSType: "exfat"}}, nil },
		ExtraRoots: []string{},
	}
	_, err := f.Find()
	if !errors.Is(err, ErrNoArchiveOnAttachedMedia) {
		t.Fatalf("err = %v, want ErrNoArchiveOnAttachedMedia", err)
	}
	if errors.Is(err, ErrNoArchive) {
		t.Fatalf("an attached, searched drive also matches ErrNoArchive, so a caller would exit 0: %v", err)
	}
	if !strings.Contains(err.Error(), stick) {
		t.Errorf("the refusal does not name the drive it looked at:\n%v", err)
	}

	// And the internal disk alone is still the quiet case.
	sys := t.TempDir()
	f = &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: sys, FSType: "btrfs"}}, nil },
		ExtraRoots: []string{},
	}
	if _, err := f.Find(); !errors.Is(err, ErrNoArchive) {
		t.Fatalf("a machine with only its own disk: err = %v, want ErrNoArchive", err)
	}
}

// The archive one folder down under a name that is NOT the agreed one — a
// stick where somebody renamed the folder — is still found, because the
// finder lists one level rather than trusting the name alone.
func TestFinder_FindsARenamedArchiveFolderOneLevelDown(t *testing.T) {
	mount := t.TempDir()
	buildArchive(t, filepath.Join(mount, "Mrs Patel laptop"), map[string]string{"Documents/a.txt": "aaa"})
	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: mount, FSType: "vfat"}}, nil },
		ExtraRoots: []string{},
	}
	found, err := f.Find()
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got, want := found[0].Root, filepath.Join(mount, "Mrs Patel laptop"); got != want {
		t.Errorf("root = %s, want %s", got, want)
	}
}

// ---- FATAL 2: a Wi-Fi refusal did not make the run unclean ----

type fakeHandler struct {
	rep *HandlerReport
	err error
}

func (f *fakeHandler) Handle(context.Context, []*Item) (*HandlerReport, error) { return f.rep, f.err }

// The exact Problem internal/netprofile produces when a keyfile comes out
// world-readable: it deletes the file and does not add the network.
const wifiRefusal = "REFUSED: the Wi-Fi password file came out as 0644 instead of 0600 on this " +
	"filesystem. The file was deleted and the network was not added."

func TestSummary_AWiFiProblemMakesTheRunUnclean(t *testing.T) {
	cases := []struct {
		name string
		sink Handler
	}{
		{"a refusal from the handler", &fakeHandler{rep: &HandlerReport{
			Title: "Wi-Fi networks", Skipped: 1, Problems: []string{wifiRefusal}}}},
		{"a profile that could not be parsed", &fakeHandler{rep: &HandlerReport{
			Title: "Wi-Fi networks", Skipped: 1,
			Problems: []string{"Home.xml is not a wireless profile this can read: unexpected EOF"}}}},
		{"no handler in this build at all", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, l := newHome(t)
			root := t.TempDir()
			buildArchive(t, root, map[string]string{
				"Documents/report.txt": "quarterly numbers",
				"WiFi/Home.xml":        "<WLANProfile/>",
			})
			s := runIt(t, context.Background(), root, l, Options{WiFiSink: tc.sink})

			if s.Clean() {
				t.Errorf("the run is CLEAN with a Wi-Fi problem in it: %q\n"+
					"the report is called %q and the popup says %q — so the user deletes the archive",
					s.WiFi.Problems, ReportName(s), mustNotify(s))
			}
			if got := ReportName(s); got != ReportNameProblem {
				t.Errorf("report filename = %q, want %q", got, ReportNameProblem)
			}
			if _, _, urgent := NotifyBody(s); !urgent {
				t.Error("the desktop popup is not marked urgent")
			}
			if !strings.Contains(RenderReport(s, l), "WI-FI") {
				t.Error("the report does not carry the Wi-Fi section")
			}
		})
	}
}

func mustNotify(s *Summary) string {
	sum, _, _ := NotifyBody(s)
	return sum
}

// A network that was named on the old machine but whose password was not in the
// backup is EXPECTED, not a failure. It is skipped, it is reported by name, and
// it must not turn a perfect file restore into "PLEASE READ".
func TestSummary_ASkippedNetworkWithNoProblemIsStillACleanRun(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/report.txt": "quarterly numbers",
		"WiFi/Home.xml":        "<WLANProfile/>",
	})
	s := runIt(t, context.Background(), root, l, Options{WiFiSink: &fakeHandler{rep: &HandlerReport{
		Title:   "Wi-Fi networks",
		Skipped: 1,
		Lines:   []string{"Staffroom                    NOT added — the password was not in the backup"},
	}}})
	if !s.Clean() {
		t.Fatalf("a network with no saved password made the whole run unclean:\n%s", RenderReport(s, l))
	}
	if !strings.Contains(RenderReport(s, l), "NOT added") {
		t.Error("the skipped network is not named in the report")
	}
}

// ---- MAJOR: a symlinked user directory carried a file out of the home ----

// A dual-drive 2012 laptop with /data mounted separately is the ordinary reason
// ~/Documents is a link. A pre-placed link is the hostile one. Neither may put
// the user's file outside the account the restore is running as.
func TestExecute_ASymlinkedDocumentsFolderCannotCarryAFileOutOfTheHome(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n"
	if err := os.WriteFile(filepath.Join(cfg, "user-dirs.dirs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "Documents")); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/payroll.xlsx": "everyone's salary"})

	escaped := filepath.Join(outside, "payroll.xlsx")
	l, err := NewLayout(home, cfg, noEnv)
	if err == nil {
		p, perr := BuildPlan(a, l)
		if perr == nil {
			s, _ := Execute(context.Background(), p, Options{})
			if s != nil && s.Clean() {
				if _, statErr := os.Lstat(escaped); statErr == nil {
					t.Fatalf("payroll.xlsx was written to %s, outside the home directory, and the run "+
						"reported itself CLEAN. ~/Documents was a symlink and every check was lexical.",
						escaped)
				}
			}
		}
	}
	if _, statErr := os.Lstat(escaped); statErr == nil {
		t.Fatalf("a file was written outside the home directory, at %s", escaped)
	}
}

// ---- MAJOR: a root run left the user locked out of their own files ----

func TestExecute_ARootRunLeavesEveryFileOwnedByThePersonWhoseHomeItIs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("this is the failure mode of a run started by an administrator; it needs uid 0 to drive")
	}
	const uid, gid = 1000, 1000
	home, l := newHome(t)
	if err := filepath.Walk(home, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"RoamingAppData/Mozilla/Firefox/Profiles/x.default/logins.json": "the user's own passwords",
		"Documents/report.txt": "quarterly numbers",
	})
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}

	var wrong []string
	if err := filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		st, ok := ownerOf(info)
		if !ok {
			return nil
		}
		if st.uid != uid || st.gid != gid {
			wrong = append(wrong, p)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(wrong) > 0 {
		t.Fatalf("%d path(s) under a home owned by %d:%d are owned by someone else, the first of them %s\n"+
			"Every 0600 file (the whole Firefox profile) is now unreadable by the person it belongs to, "+
			"and the run called itself clean because root could read it all back.",
			len(wrong), uid, gid, wrong[0])
	}
}

// ---- MAJOR: the second run stopped saying the file had been renamed ----

// Running the restore again is the documented recovery from any interruption,
// and it is what happens at every login until a run is clean. The disclosure
// must not exist only on the run least likely to be read.
func TestExecute_TheSecondRunStillSaysTheFileWasRenamed(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/notes.txt": "from the old computer"})

	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "notes.txt"), []byte("this machine's own notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	s1 := runIt(t, context.Background(), root, l, Options{})
	if got := len(renamedFiles(s1)); got != 1 {
		t.Fatalf("first run: %d renamed files, want 1", got)
	}
	s2 := runIt(t, context.Background(), root, l, Options{})
	if got := len(renamedFiles(s2)); got != 1 {
		t.Errorf("second run: %d renamed files, want 1 — the user is told 1 file came across and is "+
			"never told that the notes.txt under its own name is not theirs", got)
	}
	if !strings.Contains(RenderReport(s2, l), "RENAMED") {
		t.Error("second run: the report has no RENAMED section at all")
	}
}

// ---- MAJOR: a thumbnail cache was called a damaged archive ----

// Thumbs.db is what Windows Explorer leaves behind whenever anyone opens the
// folder. desktop.ini, ._ files from a Mac and .Trash-1000 from a Linux box are
// the same thing. None of them is evidence that the user's backup is damaged.
func TestExecute_LitterBesideTheArchiveIsNotADamagedArchive(t *testing.T) {
	for _, name := range []string{"Thumbs.db", "desktop.ini", "._report.txt", ".DS_Store"} {
		t.Run(name, func(t *testing.T) {
			_, l := newHome(t)
			root := t.TempDir()
			buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
			if err := os.WriteFile(filepath.Join(root, name), []byte("\x00cache"), 0o644); err != nil {
				t.Fatal(err)
			}
			s := runIt(t, context.Background(), root, l, Options{})
			rep := RenderReport(s, l)
			if !s.Clean() {
				t.Fatalf("one %s beside the archive stopped the restore and told a school their only "+
					"copy is damaged:\n%s", name, rep)
			}
			if !strings.Contains(rep, name) {
				t.Errorf("%s was ignored silently; it has to be named", name)
			}
		})
	}
}

// A file that is genuinely not in the manifest and is not litter still stops
// the run. The demotion above must not become "extras do not matter".
func TestExecute_AnUnexplainedExtraFileStillStopsTheRun(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	if err := os.WriteFile(filepath.Join(root, "Documents", "stranger.txt"), []byte("not in the list"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := runIt(t, context.Background(), root, l, Options{})
	if s.Clean() {
		t.Fatal("a file at the destination that the manifest does not describe was accepted")
	}
	if n := countFilesUnder(t, home); n != 1 {
		// only the user-dirs.dirs the fixture wrote
		t.Errorf("%d files under the home directory; the refusal was supposed to write nothing", n)
	}
}

// ---- MINOR: two entries with identical bytes collapsed into one file ----

func TestExecute_TwoEntriesWithTheSameBytesCannotCollapseIntoOneFile(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/notes.txt":                "the same bytes",
		"Documents/notes (from Windows).txt": "the same bytes",
	})
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "notes.txt"), []byte("this machine's own notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run twice: the second run is where an aside name meets its own earlier
	// copy, which is the other way the same collision can arise.
	for run := 1; run <= 2; run++ {
		s := runIt(t, context.Background(), root, l, Options{})
		finals := map[string]string{}
		for _, r := range s.Results {
			if prev, dup := finals[r.Final]; dup {
				t.Fatalf("run %d: %s and %s are both reported as the file at %s — two entries, "+
					"one file on disk, and every hash matched because it is the same file hashed twice.\n%s",
					run, prev, r.Path, r.Final, RenderReport(s, l))
			}
			finals[r.Final] = r.Path
		}
		if !s.Clean() {
			t.Fatalf("run %d: not clean:\n%s", run, RenderReport(s, l))
		}
		// Both of the user's files exist, and the machine's own notes.txt is
		// untouched.
		if got := mustRead(t, filepath.Join(docs, "notes.txt")); got != "this machine's own notes" {
			t.Fatalf("run %d: the machine's own notes.txt was changed to %q", run, got)
		}
		onDisk := 0
		for f := range finals {
			if mustRead(t, f) == "the same bytes" {
				onDisk++
			}
		}
		if onDisk != 2 {
			t.Errorf("run %d: %d of the 2 restored files are on disk", run, onDisk)
		}
		if got := len(renamedFiles(s)); got != 1 {
			t.Errorf("run %d: %d renamed, want 1 (notes.txt, which had to move aside)", run, got)
		}
	}
}

// The identity check itself, behind the construction above: two accounted
// entries claiming one file is a disagreement, always. Driven directly, since
// the fix above means Execute no longer produces the collision — and a check
// that nothing can reach is a check nobody has watched fail.
func TestReVerify_TwoEntriesClaimingOneFileIsADisagreement(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Documents/a.txt": "the same bytes",
		"Documents/b.txt": "the same bytes",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	one := filepath.Join(l.Home, "Documents", "a.txt")
	if err := os.MkdirAll(filepath.Dir(one), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(one, []byte("the same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	results := []Result{
		{Path: "Documents/a.txt", Outcome: OutWritten, Final: one},
		{Path: "Documents/b.txt", Outcome: OutAlreadyPresent, Final: one},
	}
	rep := reVerify(context.Background(), results, p, false, make([]byte, 4096))
	if rep.Clean() {
		t.Fatalf("two entries both claimed %s and the re-check called it clean: %+v", one, rep)
	}
	joined := strings.Join(rep.Disagreements, "\n")
	if !strings.Contains(joined, "Documents/a.txt") || !strings.Contains(joined, "Documents/b.txt") {
		t.Errorf("the disagreement does not name both entries:\n%s", joined)
	}
}

// ---- MINOR: the report was written twice, the second time with O_TRUNC ----

func TestWriteReport_WritesOnceAndRecordsThePathItWroteTo(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	s := runIt(t, context.Background(), root, l, Options{})

	p, err := WriteReport(s, l)
	if err != nil {
		t.Fatal(err)
	}
	if s.ReportFilePath != p {
		t.Errorf("WriteReport wrote %s and left Summary.ReportFilePath as %q, so the caller has to "+
			"render and write the file a SECOND time to fix it up — with O_TRUNC, on the run whose "+
			"cause is a full disk", p, s.ReportFilePath)
	}
	if got, want := mustRead(t, p), RenderReport(s, l); got != want {
		t.Error("the file on the desktop is not what RenderReport produces for this summary")
	}
}

// ---- MINOR: a stale .part from a killed run lived in Documents forever ----

func TestExecute_SweepsAStalePartialFromAnInterruptedRun(t *testing.T) {
	home, l := newHome(t)
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(docs, ".auros-restore-987654321.part")
	if err := os.WriteFile(stale, []byte("half a file from a run that was killed"), 0o644); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	if _, err := os.Lstat(stale); err == nil {
		t.Errorf("%s survived a full clean run. A defer does not run on a power cut, so one of these "+
			"accumulates in the user's own folder for every interruption, forever.", stale)
	}
}

// The plan is checked with links resolved, but a directory can be swapped for
// a link between planning and writing. The write path checks again, on the
// directory that exists at the moment the temporary file is created.
func TestExecute_ADirectorySwappedForALinkAfterPlanningIsNotFollowed(t *testing.T) {
	home, l := newHome(t)
	outside := t.TempDir()
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/payroll.xlsx": "everyone's salary"})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	// Now, after the plan was checked, ~/Documents becomes a link.
	if err := os.Symlink(outside, filepath.Join(home, "Documents")); err != nil {
		t.Fatal(err)
	}
	s, _ := Execute(context.Background(), p, Options{})
	if _, err := os.Lstat(filepath.Join(outside, "payroll.xlsx")); err == nil {
		t.Fatalf("the file followed a link swapped in after planning, out of the home to %s", outside)
	}
	if s.Clean() {
		t.Fatalf("the run is clean although the file could not be placed:\n%s", RenderReport(s, l))
	}
	if s.Counts[OutFailed] != 1 {
		t.Errorf("FAILED = %d, want 1", s.Counts[OutFailed])
	}
}

// Fedora Atomic ships /home as a link to /var/home. Resolving links on one side
// of the comparison and not the other would refuse every machine we sell, so
// this is the other half of the symlink fix: a home reached THROUGH a link is
// an ordinary home.
func TestExecute_AHomeReachedThroughALinkIsAnOrdinaryHome(t *testing.T) {
	base := t.TempDir()
	realHome := filepath.Join(base, "var", "home", "pupil")
	if err := os.MkdirAll(filepath.Join(realHome, ".config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "var", "home"), filepath.Join(base, "home")); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home", "pupil")
	if err := os.WriteFile(filepath.Join(home, ".config", "user-dirs.dirs"),
		[]byte("XDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := NewLayout(home, filepath.Join(home, ".config"), noEnv)
	if err != nil {
		t.Fatalf("a home reached through /home -> /var/home was refused: %v", err)
	}
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	if got := mustRead(t, filepath.Join(realHome, "Documents", "report.txt")); got != "quarterly numbers" {
		t.Errorf("content = %q", got)
	}
}

// The layout itself refuses a user directory that is a link out of the home,
// and says what the link really points at.
func TestNewLayout_AUserDirectoryThatIsALinkOutOfHomeIsRefused(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "user-dirs.dirs"),
		[]byte("XDG_PICTURES_DIR=\"$HOME/Pictures\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "Pictures")); err != nil {
		t.Fatal(err)
	}
	_, err := NewLayout(home, cfg, noEnv)
	if !errors.Is(err, ErrDirOutsideHome) {
		t.Fatalf("err = %v, want ErrDirOutsideHome", err)
	}
	if !strings.Contains(err.Error(), outside) {
		t.Errorf("the refusal does not say where the link really goes:\n%v", err)
	}
}

// ---- the handover, watchable without root ----

type chownRecorder struct{ got map[string][2]int }

func (c *chownRecorder) chown(p string, uid, gid int) error {
	c.got[p] = [2]int{uid, gid}
	return nil
}

// Every directory the run CREATES and every file it commits is handed to the
// home's owner. Directories that already existed are not. Driven through the
// unexported seam, so this runs on any machine as any user; the test above
// drives the real thing as root.
func TestExecute_HandsEveryCreatedPathToTheHomeOwner(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"RoamingAppData/Mozilla/Firefox/Profiles/x.default/logins.json": "the user's own passwords",
		"Documents/sub/report.txt":                                      "quarterly numbers",
	})
	rec := &chownRecorder{got: map[string][2]int{}}
	own := &Ownership{UID: 4242, GID: 4343, chown: rec.chown}
	s := runIt(t, context.Background(), root, l, Options{ownership: own})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	want := []string{
		filepath.Join(home, ".mozilla"),
		filepath.Join(home, ".mozilla", "firefox"),
		filepath.Join(home, ".mozilla", "firefox", "Profiles"),
		filepath.Join(home, ".mozilla", "firefox", "Profiles", "x.default"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Documents", "sub"),
	}
	for _, p := range want {
		if got, ok := rec.got[p]; !ok || got != [2]int{4242, 4343} {
			t.Errorf("created directory %s was not handed over (got %v, %v)", p, got, ok)
		}
	}
	// The files were handed over under their TEMPORARY names, before the
	// rename, so there is no instant at which the real name is root's.
	var files int
	for p, ids := range rec.got {
		if isPartial(filepath.Base(p)) {
			files++
			if ids != [2]int{4242, 4343} {
				t.Errorf("%s handed to %v", p, ids)
			}
		}
	}
	if files != 2 {
		t.Errorf("%d temporary files were handed over before their rename, want 2: %v", files, rec.got)
	}
	if _, touched := rec.got[home]; touched {
		t.Error("the home directory itself was re-owned; it already existed and is not the restore's to change")
	}
}

func TestOwnershipFor_OnlyARootRunHandsAnythingOver(t *testing.T) {
	home := t.TempDir()
	st, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	me, ok := ownerOf(st)
	if !ok {
		t.Skip("this platform does not report file owners")
	}
	if own, err := ownershipFor(home, me.uid+1); err != nil || own != nil {
		t.Fatalf("a non-root run decided to hand files over: %+v, %v", own, err)
	}
	own, err := ownershipFor(home, 0)
	if err != nil {
		t.Fatal(err)
	}
	if me.uid == 0 && me.gid == 0 {
		if own != nil {
			t.Fatalf("root restoring into root's own home decided to hand over: %+v", own)
		}
		return
	}
	if own == nil || own.UID != me.uid || own.GID != me.gid {
		t.Fatalf("a root run into a home owned by %d:%d decided %+v", me.uid, me.gid, own)
	}
}

// The report and the Wi-Fi staging are in the home directory too.
func TestWriteReport_HandsTheReportToTheHomeOwner(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	rec := &chownRecorder{got: map[string][2]int{}}
	s := runIt(t, context.Background(), root, l, Options{ownership: &Ownership{UID: 7, GID: 8, chown: rec.chown}})
	before := len(rec.got)
	if _, err := WriteReport(s, l); err != nil {
		t.Fatal(err)
	}
	if len(rec.got) == before {
		t.Fatal("the report was written into the home directory and never handed over")
	}
}

// ---- the sweep does not reach beyond what it owns ----

func TestSweepPartials_TouchesOnlyItsOwnPatternInItsOwnDirectories(t *testing.T) {
	home, l := newHome(t)
	docs := filepath.Join(home, "Documents")
	elsewhere := filepath.Join(home, "Projects")
	for _, d := range []string{docs, elsewhere} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	keep := map[string]string{
		filepath.Join(docs, "my.part"):                       "a user's file that ends in .part",
		filepath.Join(docs, ".auros-restore-.part"):          "the pattern with nothing in the middle",
		filepath.Join(elsewhere, ".auros-restore-1234.part"): "our pattern, in a directory this plan does not write to",
	}
	for p, c := range keep {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	s := runIt(t, context.Background(), root, l, Options{})
	for p := range keep {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("the sweep removed %s, which was not its to remove", p)
		}
	}
	if len(s.PartialsSwept) != 0 {
		t.Errorf("swept %v, want nothing", s.PartialsSwept)
	}
}

// And a dry run writes nothing, including deletions.
func TestSweepPartials_ADryRunDeletesNothing(t *testing.T) {
	home, l := newHome(t)
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(docs, ".auros-restore-55.part")
	if err := os.WriteFile(stale, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "quarterly numbers"})
	runIt(t, context.Background(), root, l, Options{DryRun: true})
	if _, err := os.Lstat(stale); err != nil {
		t.Errorf("a dry run deleted %s", stale)
	}
}

// The layout checks the user directories themselves. A link one level INSIDE
// one of them — ~/Documents/Finance pointing at another disk — is the plan's
// to catch, with its links resolved, before anything is written.
func TestPlan_ALinkInsideAUserDirectoryIsRefusedBeforeAnyWrite(t *testing.T) {
	home, l := newHome(t)
	outside := t.TempDir()
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(docs, "Finance")); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/Finance/payroll.xlsx": "everyone's salary"})
	_, err := BuildPlan(a, l)
	if !errors.Is(err, ErrPathEscape) {
		t.Fatalf("a link inside ~/Documents was planned: BuildPlan returned %v, want ErrPathEscape", err)
	}
	if !strings.Contains(err.Error(), outside) {
		t.Errorf("the refusal does not say where the link really goes:\n%v", err)
	}
	if n := countFilesUnder(t, outside); n != 0 {
		t.Errorf("%d file(s) written outside the home", n)
	}
}
