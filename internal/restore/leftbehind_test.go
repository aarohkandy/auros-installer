package restore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
)

// writeLeftBehind writes _auros/quarantine.txt the way the Windows half does:
// quarantine.Set.WriteReport, under quarantine.ReportFile.
func writeLeftBehind(t *testing.T, root string, recs ...quarantine.Record) {
	t.Helper()
	q := quarantine.NewSet(nil)
	for _, r := range recs {
		q.Add(r)
	}
	f, err := os.Create(filepath.Join(root, manifest.MetaDir, quarantine.ReportFile))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := q.WriteReport(f); err != nil {
		t.Fatal(err)
	}
}

// SYSTEM-REVIEW §2.22 / H11: the list of files Windows could not copy was on
// the stick and nothing read it, so a green report covered a real gap.
func TestExecute_TheReportNamesWhatWindowsLeftBehind(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/report.txt": "numbers"})
	lost := `C:\Users\pat\Documents\open all term.xlsx`
	writeLeftBehind(t, root, quarantine.Record{Path: lost, Reason: quarantine.ReasonLocked, Waived: true, WaivedBy: "pat"})

	s := runIt(t, context.Background(), root, l, Options{})
	rep := RenderReport(s, l)
	for _, want := range []string{lost, "NOT EVERYTHING WAS IN THE BACKUP", "KEEP THE BACKUP DRIVE"} {
		if !strings.Contains(rep, want) {
			t.Errorf("the report does not say %q: Windows left a file behind and the user is not told.\n%s", want, rep)
		}
	}
}

func TestReport_TheCleanBranchTellsTheUserToKeepTheStick(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, manifest.MetaDir), 0o755); err != nil {
		t.Fatal(err)
	}
	writeLeftBehind(t, root) // nothing left behind
	s := cleanSummary()
	s.LeftBehind = ReadLeftBehind(root)
	rep := RenderReport(s, mustLayout(t))
	if !strings.Contains(rep, "KEEP THE BACKUP DRIVE") {
		t.Errorf("a clean report does not tell the user to keep the USB stick:\n%s", rep)
	}
	if strings.Contains(rep, "NOT EVERYTHING WAS IN THE BACKUP") {
		t.Errorf("an empty quarantine list was reported as files left behind:\n%s", rep)
	}
}

func TestReport_AMissingListAndAMissingTotalAreSaidNotInvented(t *testing.T) {
	s := cleanSummary()
	s.LeftBehind = ReadLeftBehind(t.TempDir())
	rep := RenderReport(s, mustLayout(t))
	for _, want := range []string{"cannot say whether any were", "not recorded in the backup"} {
		if !strings.Contains(rep, want) {
			t.Errorf("the report does not say %q:\n%s", want, rep)
		}
	}
}

func TestReadLeftBehind_ALinkOnTheStickIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, manifest.MetaDir), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "shadow")
	if err := os.WriteFile(secret, []byte("root:$6$secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, manifest.MetaDir, quarantine.ReportFile)); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	lb := ReadLeftBehind(root)
	if strings.Contains(lb.Text, "secret") || lb.Err == "" {
		t.Fatalf("followed a link on the stick into the report: %+v", lb)
	}
}
