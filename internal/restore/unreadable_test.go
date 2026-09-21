package restore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lockDir makes dir unlistable for the rest of the test, the way ext4's
// root-owned lost+found is to the user the restore runs as.
func lockDir(t *testing.T, dir string) { lockDirMode(t, dir, 0) }

// lockDirMode with 0o311 leaves a directory's files openable by name but the
// directory itself unlistable.
func lockDirMode(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 directory; this needs an ordinary user")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })
}

// Found by running the real binary against an ext4 stick: lost+found is root
// 0700, the pre-verify's walk stopped on it, the whole restore aborted, and the
// report said the drive held 0 files — about a drive holding every one of them.
// A folder no manifest entry is inside cannot hold the user's files.
func TestExecute_AnUnreadableFolderBesideTheArchiveDoesNotStopTheRestore(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "numbers", "Pictures/cat.jpg": "cat"})
	lockDir(t, filepath.Join(root, "lost+found"))

	s := runIt(t, context.Background(), root, l, Options{})
	rep := RenderReport(s, l)
	if !s.Clean() {
		t.Fatalf("an unreadable lost+found beside the archive stopped the restore:\n%s", rep)
	}
	if got := mustRead(t, filepath.Join(home, "Documents", "report.txt")); got != "numbers" {
		t.Errorf("content = %q", got)
	}
	if !strings.Contains(rep, "lost+found") {
		t.Errorf("the folder that could not be opened is not named:\n%s", rep)
	}
}

// The other side: a folder the backup's own files are in, which cannot be
// opened. That is not ignorable — it is named, nothing is written, and the
// report never claims the drive holds zero files.
func TestExecute_AnUnreadableFolderInsideTheBackupIsNamedNotCountedAsZero(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/report.txt":   "numbers",
		"Documents/term/old.doc": "older",
		"Pictures/cat.jpg":       "cat",
	})
	lockDir(t, filepath.Join(root, "Documents", "term"))

	s := runIt(t, context.Background(), root, l, Options{})
	rep := RenderReport(s, l)
	if s.Clean() {
		t.Fatalf("a backup folder that could not be read was called clean:\n%s", rep)
	}
	if !strings.Contains(rep, "Documents/term") {
		t.Errorf("the unreadable folder inside the backup is not named:\n%s", rep)
	}
	if strings.Contains(rep, "the drive holds 0") || strings.Contains(rep, "0 checked") {
		t.Errorf("FALSE STATEMENT: the report says the drive holds nothing:\n%s", rep)
	}
	if n := countFilesUnder(t, filepath.Join(home, "Documents")); n != 0 {
		t.Errorf("%d file(s) were written from a backup that did not check out", n)
	}
}

// A backup folder whose files open by name but which cannot be LISTED: every
// listed file verifies, and what else is in there cannot be known. Named as a
// problem, and the count is not wrongly reported as short — the files were
// there and were checked.
func TestExecute_ABackupFolderThatCannotBeListedIsNamedEvenIfItsFilesRead(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/report.txt":   "numbers",
		"Documents/term/old.doc": "older",
	})
	lockDirMode(t, filepath.Join(root, "Documents", "term"), 0o311)

	s := runIt(t, context.Background(), root, l, Options{})
	rep := RenderReport(s, l)
	if s.Clean() {
		t.Fatalf("a backup folder that could not be listed was treated as outside the backup:\n%s", rep)
	}
	if !strings.Contains(rep, "Documents/term/") {
		t.Errorf("the unlistable folder is not named:\n%s", rep)
	}
	if strings.Contains(rep, "the drive holds") {
		t.Errorf("FALSE STATEMENT: every file was there and checked, and the report says the count is short:\n%s", rep)
	}
}

// The archive's own top folder cannot be listed, so the check cannot finish.
// The report says it stopped; it does not print the unfinished check's zeroes
// as a count of what is on the drive.
func TestExecute_ACheckThatCouldNotFinishPrintsNoCounts(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "numbers"})
	lockDirMode(t, root, 0o311)

	s := runIt(t, context.Background(), root, l, Options{})
	rep := RenderReport(s, l)
	if s.Clean() {
		t.Fatalf("clean over an archive that could not be listed:\n%s", rep)
	}
	if strings.Contains(rep, "the drive holds 0") || strings.Contains(rep, "0 checked") {
		t.Errorf("FALSE STATEMENT: an unfinished check is printed as a count:\n%s", rep)
	}
}
