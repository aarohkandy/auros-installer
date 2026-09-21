package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fullDisk accepts a fixed number of bytes and then reports the platform's
// out-of-space errno, which is what a volume that fills up mid-file does. The
// budget is shared across every file, so the run genuinely runs out part-way
// through one rather than at a convenient boundary.
type fullDisk struct {
	w      io.Writer
	budget *int64
}

func (f *fullDisk) Write(p []byte) (int, error) {
	if *f.budget <= 0 {
		return 0, &os.PathError{Op: "write", Path: "destination", Err: noSpaceErrno()}
	}
	n := int64(len(p))
	short := false
	if n > *f.budget {
		n, short = *f.budget, true
	}
	written, err := f.w.Write(p[:n])
	*f.budget -= int64(written)
	if err != nil {
		return written, err
	}
	if short {
		return written, &os.PathError{Op: "write", Path: "destination", Err: noSpaceErrno()}
	}
	return written, nil
}

// runIt is the whole pipeline: find, plan, execute.
func runIt(t *testing.T, ctx context.Context, archiveRoot string, l *Layout, o Options) *Summary {
	t.Helper()
	a := loadForTest(t, archiveRoot)
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	s, err := Execute(ctx, p, o)
	if err != nil && s == nil {
		t.Fatalf("Execute: %v", err)
	}
	return s
}

// countFilesUnder counts every regular file under root, so a test can assert
// that a refusal really wrote NOTHING rather than merely reporting that it
// wrote nothing.
func countFilesUnder(t *testing.T, root string) int {
	t.Helper()
	n := 0
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Mode().IsRegular() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestExecute_TheHappyPathRestoresAndRechecksEveryFile(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/report.txt":  "quarterly numbers",
		"Documents/sub/old.doc": "older numbers",
		"Desktop/note.txt":      "remember the milk",
		"Pictures/cat.jpg":      "\x89PNG not really",
	})
	s := runIt(t, context.Background(), root, l, Options{})

	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	if s.FilesRestored() != 4 {
		t.Errorf("restored %d, want 4", s.FilesRestored())
	}
	if got := mustRead(t, filepath.Join(home, "Documents", "report.txt")); got != "quarterly numbers" {
		t.Errorf("content = %q", got)
	}
	if s.ReVerify.Matched != 4 {
		t.Errorf("re-check matched %d, want 4", s.ReVerify.Matched)
	}
	if s.ReVerify.Accounted != s.ReVerify.Manifest {
		t.Errorf("accounted %d of %d", s.ReVerify.Accounted, s.ReVerify.Manifest)
	}
}

func TestExecute_AWrongHashInTheArchiveAbortsBeforeAnythingIsWritten(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/a.txt": "aaa",
		"Documents/b.txt": "bbb",
		"Documents/c.txt": "ccc",
	})
	// Corrupt one file's CONTENT on the stick, leaving the manifest intact.
	// This is a USB stick with a bad block, which is the exact case the
	// pre-verification exists for.
	if err := os.WriteFile(filepath.Join(root, "Documents", "b.txt"), []byte("XXX"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := countFilesUnder(t, home)
	s := runIt(t, context.Background(), root, l, Options{})

	if s.Clean() {
		t.Fatal("a damaged archive was reported as a clean restore")
	}
	if s.PreVerify.Clean() {
		t.Fatal("the pre-check passed on a corrupted archive")
	}
	if after := countFilesUnder(t, home); after != before {
		t.Fatalf("%d file(s) were written despite a damaged archive; the rule is that NOTHING is written",
			after-before)
	}
	report := RenderReport(s, l)
	if !strings.Contains(report, "b.txt") {
		t.Errorf("the report does not name the damaged file:\n%s", report)
	}
	if !strings.Contains(report, "NOT been changed") {
		t.Errorf("the report does not tell the user their backup is untouched:\n%s", report)
	}
}

func TestExecute_AMissingFileInTheArchiveAbortsBeforeAnythingIsWritten(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/a.txt": "aaa", "Documents/b.txt": "bbb",
	})
	if err := os.Remove(filepath.Join(root, "Documents", "b.txt")); err != nil {
		t.Fatal(err)
	}
	before := countFilesUnder(t, home)
	s := runIt(t, context.Background(), root, l, Options{})
	if s.Clean() {
		t.Fatal("an incomplete archive was reported as clean")
	}
	if after := countFilesUnder(t, home); after != before {
		t.Fatalf("%d file(s) written from an incomplete archive", after-before)
	}
}

func TestExecute_AnExtraFileAtTheArchiveAbortsOnTheCountAlone(t *testing.T) {
	// Every hash matches. The count does not. This is the case a per-file
	// check alone cannot catch, and it means the directory is not the archive
	// the manifest describes.
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "aaa"})
	if err := os.WriteFile(filepath.Join(root, "Documents", "stranger.txt"), []byte("?"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := countFilesUnder(t, home)
	s := runIt(t, context.Background(), root, l, Options{})
	if s.Clean() {
		t.Fatal("an archive with an unexpected file in it was reported as clean")
	}
	if after := countFilesUnder(t, home); after != before {
		t.Fatalf("%d file(s) written", after-before)
	}
	if !strings.Contains(RenderReport(s, l), "stranger.txt") {
		t.Errorf("the report does not name the unexpected file:\n%s", RenderReport(s, l))
	}
}

func TestExecute_RerunningIsIdempotentAndWritesNothingTwice(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/a.txt": "aaa", "Documents/b.txt": "bbb", "Desktop/c.txt": "ccc",
	})
	first := runIt(t, context.Background(), root, l, Options{})
	if !first.Clean() || first.Counts[OutWritten] != 3 {
		t.Fatalf("first run: clean=%v written=%d", first.Clean(), first.Counts[OutWritten])
	}
	second := runIt(t, context.Background(), root, l, Options{})
	if !second.Clean() {
		t.Fatalf("second run is not clean:\n%s", RenderReport(second, l))
	}
	if second.Counts[OutWritten] != 0 {
		t.Errorf("second run wrote %d file(s); a re-run must write nothing", second.Counts[OutWritten])
	}
	if second.Counts[OutAlreadyPresent] != 3 {
		t.Errorf("second run found %d already there, want 3", second.Counts[OutAlreadyPresent])
	}
	if second.FilesRestored() != 3 {
		t.Errorf("the count shown to the user changed between runs: %d", second.FilesRestored())
	}
}

func TestExecute_AnInterruptedRunIsFinishedByRunningItAgain(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("Documents/f%02d.txt", i)] = fmt.Sprintf("contents of %d", i)
	}
	buildArchive(t, root, files)

	// Pull the power out after five files.
	ctx, cancel := context.WithCancel(context.Background())
	stopAfter := 5
	o := Options{Progress: func(done, _ int, _ string) {
		if done >= stopAfter {
			cancel()
		}
	}}
	first := runIt(t, ctx, root, l, o)
	cancel()
	if first.Clean() {
		t.Fatal("an interrupted run reported itself clean")
	}
	if first.StoppedEarly == "" {
		t.Error("an interrupted run did not record that it stopped early")
	}
	partial := countFilesUnder(t, filepath.Join(home, "Documents"))
	if partial == 0 || partial >= 20 {
		t.Fatalf("after the interruption %d of 20 files exist; the test needs a genuine partial state", partial)
	}
	// No half-written file may be left behind: every file present must be
	// complete, because the write is a rename of a fully hashed temporary.
	if n := countPartFiles(t, home); n != 0 {
		t.Errorf("%d .part file(s) left behind", n)
	}

	second := runIt(t, context.Background(), root, l, Options{})
	if !second.Clean() {
		t.Fatalf("the resumed run is not clean:\n%s", RenderReport(second, l))
	}
	if second.FilesRestored() != 20 {
		t.Errorf("after resuming, %d of 20 files are here", second.FilesRestored())
	}
	if second.Counts[OutAlreadyPresent] != partial {
		t.Errorf("the resumed run re-wrote files it did not need to: already-there=%d, want %d",
			second.Counts[OutAlreadyPresent], partial)
	}
}

func countPartFiles(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && strings.HasSuffix(p, ".part") {
			n++
		}
		return nil
	})
	return n
}

func TestExecute_AFileAlreadyThereIsNeverOverwritten(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/notes.txt": "from the old computer"})

	// The user has already made a file with that name on the new machine.
	// Overwriting it would destroy work that was never backed up anywhere.
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(docs, "notes.txt")
	if err := os.WriteFile(mine, []byte("written on the NEW computer this morning"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := runIt(t, context.Background(), root, l, Options{})
	if got := mustRead(t, mine); got != "written on the NEW computer this morning" {
		t.Fatalf("the user's own file was overwritten; it now reads %q", got)
	}
	if s.Counts[OutPlacedAside] != 1 {
		t.Fatalf("placed-aside = %d, want 1", s.Counts[OutPlacedAside])
	}
	aside := filepath.Join(docs, "notes (from Windows).txt")
	if got := mustRead(t, aside); got != "from the old computer" {
		t.Errorf("the restored copy is not at %s", aside)
	}
	if !s.Clean() {
		t.Errorf("placing a file alongside is a normal outcome, not a failure:\n%s", RenderReport(s, l))
	}
	report := RenderReport(s, l)
	if !strings.Contains(report, "from Windows") {
		t.Errorf("the report does not tell the user about the renamed copy:\n%s", report)
	}
}

func TestExecute_RerunAfterPlacingAsideDoesNotKeepMakingCopies(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/notes.txt": "from the old computer"})
	docs := filepath.Join(home, "Documents")
	if err := os.MkdirAll(docs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	runIt(t, context.Background(), root, l, Options{})
	second := runIt(t, context.Background(), root, l, Options{})
	if second.Counts[OutWritten] != 0 {
		t.Errorf("the second run wrote %d more copies", second.Counts[OutWritten])
	}
	ents, err := os.ReadDir(docs)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		names := []string{}
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("Documents holds %d files after two runs: %v", len(ents), names)
	}
}

func TestExecute_AZeroByteFileIsAnOrdinaryFile(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/empty.txt":    "",
		"Documents/notempty.txt": "x",
	})
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	st, err := os.Stat(filepath.Join(home, "Documents", "empty.txt"))
	if err != nil {
		t.Fatalf("the empty file is missing: %v", err)
	}
	if st.Size() != 0 {
		t.Errorf("size = %d, want 0", st.Size())
	}
}

func TestExecute_NamesLegalOnNTFSAndAwkwardOnExtFourRoundTrip(t *testing.T) {
	// The stored name on the stick is percent-encoded by manifest.Sanitize so
	// it can live on an exFAT volume. The RESTORED name must be the original
	// one — ext4 is happy with a colon and a trailing space, and the user's
	// file is called what it was called.
	home, l := newHome(t)
	root := t.TempDir()
	// NOT tested here: a backslash in a name. manifest.CleanRel turns "\\" into
	// "/" because on Windows a backslash IS a path separator and can never be
	// part of a filename, so "Documents/back\\slash.txt" is the file
	// "slash.txt" in the folder "back". Asserting otherwise would be asserting
	// a Windows path is a Linux one.
	names := []string{
		"Documents/meeting 2014-05-06 10:30.txt",
		"Documents/trailing space .txt",
		"Documents/CON.txt",
		"Documents/ünïcode ✔.txt",
		"Documents/pct%20literal.txt",
	}
	files := map[string]string{}
	for i, n := range names {
		files[n] = fmt.Sprintf("body %d", i)
	}
	buildArchive(t, root, files)

	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	for i, n := range names {
		rel := strings.TrimPrefix(n, "Documents/")
		p := filepath.Join(home, "Documents", rel)
		got, err := os.ReadFile(p)
		if err != nil {
			listDir(t, filepath.Join(home, "Documents"))
			t.Fatalf("%s is not at %s: %v", n, p, err)
		}
		if string(got) != fmt.Sprintf("body %d", i) {
			t.Errorf("%s has the wrong contents", n)
		}
	}
	// And the encoded name must NOT survive into the home directory.
	if _, err := os.Stat(filepath.Join(home, "Documents", "meeting 2014-05-06 10%3A30.txt")); err == nil {
		t.Error("the percent-encoded name was restored instead of the real one")
	}
}

func listDir(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Logf("cannot list %s: %v", dir, err)
		return
	}
	t.Logf("what IS in %s:", dir)
	for _, e := range ents {
		t.Logf("  %q", e.Name())
	}
}

func TestExecute_TheDiskFillingUpStopsTheRunAndSaysSo(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	files := map[string]string{}
	for i := 0; i < 20; i++ {
		files[fmt.Sprintf("Documents/f%02d.bin", i)] = strings.Repeat("x", 1000)
	}
	buildArchive(t, root, files)

	budget := int64(4500)
	o := Options{BufSize: 256}
	o.hookWriter = func(_ string, w io.Writer) io.Writer { return &fullDisk{w: w, budget: &budget} }

	s := runIt(t, context.Background(), root, l, o)
	if s.Clean() {
		t.Fatal("a run that ran out of disk reported itself clean")
	}
	if s.StoppedEarly == "" {
		t.Fatal("the run did not record that it stopped")
	}
	if !strings.Contains(s.StoppedEarly, "again") {
		t.Errorf("the message does not tell the user what to do: %q", s.StoppedEarly)
	}
	if n := countPartFiles(t, home); n != 0 {
		t.Errorf("%d half-written file(s) were left behind", n)
	}
	// Everything that IS on disk must be complete and correct: that is what
	// makes the re-run after freeing space safe.
	a := loadForTest(t, root)
	for _, e := range a.Manifest.Entries() {
		rel := strings.TrimPrefix(e.Path, "Documents/")
		p := filepath.Join(home, "Documents", rel)
		b, err := os.ReadFile(p)
		if err != nil {
			continue // never written, which is fine
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			t.Errorf("%s exists on disk and does not match the archive", p)
		}
	}
	// Free the space and finish.
	budget = 1 << 30
	second := runIt(t, context.Background(), root, l, Options{})
	if !second.Clean() {
		t.Fatalf("the run after freeing space is not clean:\n%s", RenderReport(second, l))
	}
	if second.FilesRestored() != 20 {
		t.Errorf("restored %d of 20 after freeing space", second.FilesRestored())
	}
}

func TestExecute_EighteenThousandFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("18,000 files")
	}
	_, l := newHome(t)
	root := t.TempDir()
	files := make(map[string]string, 18000)
	for i := 0; i < 18000; i++ {
		files[fmt.Sprintf("Documents/d%03d/f%05d.txt", i%180, i)] = fmt.Sprintf("file number %d", i)
	}
	buildArchive(t, root, files)
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean over 18,000 files: %s", s.ReVerify.Describe())
	}
	if s.FilesRestored() != 18000 {
		t.Fatalf("restored %d of 18000", s.FilesRestored())
	}
	if s.ReVerify.Checked != 18000 {
		t.Errorf("re-checked %d of 18000", s.ReVerify.Checked)
	}
}

func TestExecute_ADryRunIsNeverReportedAsAFinishedRestore(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "aaa"})
	before := countFilesUnder(t, home)
	s := runIt(t, context.Background(), root, l, Options{DryRun: true})
	if after := countFilesUnder(t, home); after != before {
		t.Fatalf("a dry run wrote %d file(s)", after-before)
	}
	if s.Clean() {
		t.Fatal("a dry run reported itself as a completed restore, which is the worst possible " +
			"false positive: nothing is on disk and the user has been told it is")
	}
	if !strings.Contains(RenderReport(s, l), "practice run") {
		t.Errorf("the report does not say it was a practice run:\n%s", RenderReport(s, l))
	}
}

func TestReVerify_AFileChangedAfterTheWriteIsCaught(t *testing.T) {
	// The third check, demonstrated going RED. Without this, "we checked
	// again afterwards" is a sentence nobody has ever watched fail.
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "aaa", "Documents/b.txt": "bbb"})
	a := loadForTest(t, root)
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := false
	s, err := Execute(context.Background(), p, Options{
		Progress: func(_, _ int, _ string) {
			// Rewrite a restored file behind the engine's back, exactly as a
			// dying disk would.
			if corrupted {
				return
			}
			target := filepath.Join(home, "Documents", "a.txt")
			if _, serr := os.Stat(target); serr == nil {
				_ = os.WriteFile(target, []byte("XXX"), 0o644)
				corrupted = true
			}
		},
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !corrupted {
		t.Fatal("the test never managed to corrupt a file, so it proves nothing")
	}
	if s.Clean() {
		t.Fatal("the re-check passed over a file that was changed after it was written")
	}
	if len(s.ReVerify.Disagreements) == 0 {
		t.Fatal("the re-check reported no disagreement")
	}
	if !strings.Contains(RenderReport(s, l), "a.txt") {
		t.Errorf("the report does not name the file:\n%s", RenderReport(s, l))
	}
}

func TestSummary_AnEmptyRunIsNeverClean(t *testing.T) {
	// 0 == 0 == 0 satisfies every equality in Clean, which is how a perfect
	// restore of nothing becomes the most convincing evidence in the program.
	s := &Summary{Counts: map[Outcome]int{}}
	if s.Clean() {
		t.Fatal("a summary over zero files reported itself clean")
	}
	var nilSummary *Summary
	if nilSummary.Clean() {
		t.Fatal("a nil summary reported itself clean")
	}
	r := &ReVerifyReport{Reconciled: true}
	if r.Clean() {
		t.Fatal("a re-check over zero files reported itself clean")
	}
}

func TestExecute_AWithheldFileIsNeverWrittenAnywhere(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/a.txt": "aaa",
		"LocalAppData/Google/Chrome/User Data/Default/Login Data": "SUPER SECRET PASSWORD BLOB",
	})
	s := runIt(t, context.Background(), root, l, Options{})
	if !s.Clean() {
		t.Fatalf("not clean:\n%s", RenderReport(s, l))
	}
	// Nowhere in the home directory may that blob appear.
	found := ""
	_ = filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(b), "SUPER SECRET PASSWORD BLOB") {
			found = p
		}
		return nil
	})
	if found != "" {
		t.Fatalf("D15 BREACH: the Chrome password blob was written to %s", found)
	}
	if s.Counts[OutWithheld] != 1 {
		t.Errorf("withheld = %d, want 1", s.Counts[OutWithheld])
	}
	if !strings.Contains(RenderReport(s, l), "ON PURPOSE") {
		t.Errorf("the report does not explain what was left behind:\n%s", RenderReport(s, l))
	}
}

func TestExecute_ACountThatDoesNotReconcileIsNeverClean(t *testing.T) {
	// Directly exercise the accounting arm of the re-check: if an entry falls
	// out of the results, the run must not be clean even though every file on
	// disk is perfect.
	r := &ReVerifyReport{Expected: 3, Checked: 3, Matched: 3, Accounted: 3, Manifest: 4}
	r.Reconciled = r.Accounted == r.Manifest
	if r.Clean() {
		t.Fatal("a re-check that lost an entry reported itself clean")
	}
	s := &Summary{
		ManifestCount: 4,
		Counts:        map[Outcome]int{},
		ReVerify:      r,
	}
	if s.Clean() {
		t.Fatal("the summary is clean with an unreconciled count")
	}
	if !strings.Contains(strings.Join(problems(s), " "), "accounted for") {
		t.Errorf("the problem list does not explain the shortfall: %v", problems(s))
	}
}
