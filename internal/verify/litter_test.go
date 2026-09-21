package verify

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Operating-system litter beside a perfect archive is named, not counted, and
// is not a disagreement. The first version treated one Thumbs.db exactly like a
// stranger's file: a COUNT MISMATCH, a quarantine record, and — on the Linux
// side — "THE ARCHIVE IS DAMAGED" on the only copy of somebody's work.
func TestVerify_LitterBesideAPerfectArchiveIsNamedNotCounted(t *testing.T) {
	litter := []string{
		"Thumbs.db",
		"Documents/desktop.ini",
		"Documents/._a.txt",
		".DS_Store",
		".Trash-1000/files/old.txt",
		"System Volume Information/IndexerVolumeGuid",
		"$RECYCLE.BIN/S-1-5-21/desktop.ini",
	}
	dest, m, q := fixture(t, three())
	for _, rel := range litter {
		full := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("noise"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() {
		t.Fatalf("litter made a perfect archive fail:\n%s", rep.Describe())
	}
	if len(rep.Litter) != len(litter) {
		t.Errorf("named %d litter files, want %d: %v", len(rep.Litter), len(litter), rep.Litter)
	}
	if rep.DestinationCount != 3+len(litter) || rep.Counted() != 3 {
		t.Errorf("destination=%d counted=%d; want %d and 3 — the raw count is kept, the litter is subtracted in the open",
			rep.DestinationCount, rep.Counted(), 3+len(litter))
	}
	if q.Unresolved() != 0 {
		t.Errorf("litter reached the quarantine set: %d record(s)", q.Unresolved())
	}
	desc := rep.Describe()
	for _, rel := range litter {
		if !strings.Contains(desc, rel) {
			t.Errorf("Describe does not name %s", rel)
		}
	}
}

// A Thumbs.db that IS in the manifest — the user's Pictures folder had one —
// is a file like any other, and a damaged one fails like any other. Litter is
// only ever what is left over after the manifest has been checked.
func TestVerify_ALitterNamedFileInTheManifestIsStillVerified(t *testing.T) {
	dest, m, q := fixture(t, map[string]string{
		"Pictures/Thumbs.db": "the user's own thumbnail cache",
		"Pictures/cat.jpg":   "a cat",
	})
	if err := os.WriteFile(filepath.Join(dest, "Pictures", "Thumbs.db"), []byte("the user's own thumbnail cachX"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("a corrupted manifest entry named Thumbs.db was waved through as litter")
	}
	if len(rep.Litter) != 0 {
		t.Errorf("a manifest entry was classed as litter: %v", rep.Litter)
	}
	found := false
	for _, d := range rep.Disagreements {
		if d.Stored == "Pictures/Thumbs.db" && d.Kind == KindHash {
			found = true
		}
	}
	if !found {
		t.Errorf("the damaged Thumbs.db was not reported as a hash mismatch: %+v", rep.Disagreements)
	}
}

// The count stays exact. Litter plus a MISSING file must not add up to a pass
// by coincidence: 3 in the list, 2 real files and 1 Thumbs.db at the
// destination is a missing file, not a match.
func TestVerify_LitterCannotStandInForAMissingFile(t *testing.T) {
	dest, m, q := fixture(t, three())
	if err := os.Remove(filepath.Join(dest, "Documents", "b.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "Documents", "Thumbs.db"), []byte("noise"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatalf("a missing file was covered by a Thumbs.db:\n%s", rep.Describe())
	}
	if rep.Counted() != 2 {
		t.Errorf("counted %d, want 2", rep.Counted())
	}
}

func TestIsLitter_IsNarrow(t *testing.T) {
	for _, tc := range []struct {
		stored string
		want   bool
	}{
		{"Thumbs.db", true},
		{"a/b/THUMBS.DB", true},
		{"desktop.ini", true},
		{"._x", true},
		{"._", false},                  // nothing after the prefix
		{"Documents/_notes.txt", false}, // one underscore, not AppleDouble
		{"Documents/thumbs.db.bak", false},
		{"Documents/My Trash-1000/x", false},
		{".Trash-1000/files/x", true},
		{"Documents/Thumbs/a.jpg", false},
		{"Documents/report.docx", false},
	} {
		if got := isLitter(tc.stored); got != tc.want {
			t.Errorf("isLitter(%q) = %v, want %v", tc.stored, got, tc.want)
		}
	}
}
