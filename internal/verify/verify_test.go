package verify

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

func fixture(t *testing.T, files map[string]string) (dest string, m *manifest.Manifest, q *quarantine.Set) {
	t.Helper()
	dest = t.TempDir()
	m = manifest.New()
	for rel, content := range files {
		full := filepath.Join(dest, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		e := manifest.Entry{}
		e.Path = rel
		e.Stored = rel
		e.Size = int64(len(content))
		e.ModTimeUnixNano = 1700000000
		e.SHA256 = testsupport.SHA256(content)
		if content == "" {
			e.SHA256 = manifest.EmptySHA256
		}
		if err := m.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	q = quarantine.NewSet(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	return dest, m, q
}

func opts(dest string, m *manifest.Manifest, q *quarantine.Set) Options {
	o := Options{}
	o.DestRoot = dest
	o.Manifest = m
	o.Quarantine = q
	o.BufSize = 32
	return o
}

func three() map[string]string {
	return map[string]string{
		"Documents/a.txt": "alpha",
		"Documents/b.txt": "bravo",
		"Desktop/e.txt":   "",
	}
}

func TestVerify_CleanArchive(t *testing.T) {
	dest, m, q := fixture(t, three())
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() {
		t.Fatalf("not clean:\n%s", rep.Describe())
	}
	if rep.Checked != 3 || rep.ManifestCount != 3 || rep.DestinationCount != 3 {
		t.Errorf("checked=%d manifest=%d destination=%d", rep.Checked, rep.ManifestCount, rep.DestinationCount)
	}
	if q.Unresolved() != 0 {
		t.Errorf("a clean archive quarantined something: %+v", q.Records())
	}
}

func TestVerify_OneHashDiffers(t *testing.T) {
	dest, m, q := fixture(t, three())
	if err := os.WriteFile(filepath.Join(dest, "Documents", "a.txt"), []byte("ALPHA"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("a corrupted file verified clean")
	}
	if len(rep.Disagreements) != 1 || rep.Disagreements[0].Kind != KindHash {
		t.Fatalf("disagreements = %+v, want exactly one contents-differ", rep.Disagreements)
	}
	if !rep.Disagreements[0].Retried {
		t.Error("the mismatching file was not retried; SAFETY.md phase 5 requires one retry")
	}
	if q.Unresolved() != 1 {
		t.Errorf("unresolved = %d, want 1", q.Unresolved())
	}
}

func TestVerify_ManyHashesDiffer(t *testing.T) {
	dest, m, q := fixture(t, three())
	for _, rel := range []string{"Documents/a.txt", "Documents/b.txt"} {
		if err := os.WriteFile(filepath.Join(dest, filepath.FromSlash(rel)), []byte("wrong"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 2 {
		t.Fatalf("disagreements = %d, want 2:\n%s", len(rep.Disagreements), rep.Describe())
	}
	// The report names files. "Verification failed" is not actionable.
	for _, d := range rep.Disagreements {
		if d.Path == "" || d.Want == "" || d.Got == "" {
			t.Errorf("disagreement is not specific enough to act on: %+v", d)
		}
	}
}

func TestVerify_SizeDiffersWithoutReadingTheWholeFile(t *testing.T) {
	dest, m, q := fixture(t, three())
	if err := os.WriteFile(filepath.Join(dest, "Documents", "a.txt"), []byte("alpha-and-then-some"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Disagreements) != 1 || rep.Disagreements[0].Kind != KindSize {
		t.Fatalf("disagreements = %+v, want one size-differs", rep.Disagreements)
	}
}

func TestVerify_MissingFile(t *testing.T) {
	dest, m, q := fixture(t, three())
	if err := os.Remove(filepath.Join(dest, "Documents", "b.txt")); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("a missing file verified clean")
	}
	if rep.Disagreements[0].Kind != KindMissing {
		t.Errorf("kind = %s, want %s", rep.Disagreements[0].Kind, KindMissing)
	}
	if rep.DestinationCount != 2 {
		t.Errorf("DestinationCount = %d, want 2", rep.DestinationCount)
	}
}

func TestVerify_CountMismatchWithEveryHashCorrect(t *testing.T) {
	// The case a hash-only check passes: every file the manifest names is byte
	// perfect, and there is one more file at the destination than there should
	// be. SPEC §6C: count AND hash.
	dest, m, q := fixture(t, three())
	if err := os.WriteFile(filepath.Join(dest, "Documents", "stowaway.txt"), []byte("extra"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("an archive with an unaccounted file verified clean")
	}
	if rep.ManifestCount != 3 || rep.DestinationCount != 4 {
		t.Errorf("manifest=%d destination=%d, want 3 and 4", rep.ManifestCount, rep.DestinationCount)
	}
	found := false
	for _, d := range rep.Disagreements {
		if d.Kind == KindExtra && d.Stored == "Documents/stowaway.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("the extra file was not named: %+v", rep.Disagreements)
	}
	if q.Unresolved() == 0 {
		t.Error("the extra file did not reach the quarantine set")
	}
}

func TestVerify_IgnoresTheMetadataDirectory(t *testing.T) {
	dest, m, q := fixture(t, three())
	meta := filepath.Join(dest, manifest.MetaDir)
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{manifest.FileName, "run-x.jsonl", "quarantine.txt"} {
		if err := os.WriteFile(filepath.Join(meta, n), []byte("metadata"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Clean() {
		t.Fatalf("the metadata directory was counted as archive content:\n%s", rep.Describe())
	}
}

func TestVerify_DirectoryWhereAFileShouldBe(t *testing.T) {
	dest, m, q := fixture(t, three())
	p := filepath.Join(dest, "Documents", "a.txt")
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("a directory passed as a file")
	}
	if rep.Disagreements[0].Kind != KindNotRegular {
		t.Errorf("kind = %s, want %s", rep.Disagreements[0].Kind, KindNotRegular)
	}
}

func TestVerify_Cancelled(t *testing.T) {
	dest, m, q := fixture(t, three())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Run(ctx, opts(dest, m, q))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestVerify_RefusesWithoutAManifest(t *testing.T) {
	dest := t.TempDir()
	o := Options{}
	o.DestRoot = dest
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("verification ran with no manifest")
	}
}

func TestVerify_RefusesWithoutADestination(t *testing.T) {
	o := Options{}
	o.Manifest = manifest.New()
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("verification ran with no destination")
	}
}

func TestVerify_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permissions are not enforced")
	}
	dest, m, q := fixture(t, three())
	p := filepath.Join(dest, "Documents", "a.txt")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Skipf("cannot remove permissions: %v", err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o644) })
	rep, err := Run(context.Background(), opts(dest, m, q))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Clean() {
		t.Fatal("an unreadable file verified clean")
	}
	if rep.Disagreements[0].Kind != KindUnreadable {
		t.Errorf("kind = %s, want %s", rep.Disagreements[0].Kind, KindUnreadable)
	}
}

func TestReport_CleanRequiresCountAndChecksToAgree(t *testing.T) {
	// A report that found no disagreements but checked fewer files than the
	// manifest holds is not clean. That combination is how a verifier that
	// silently stopped early would otherwise pass.
	r := &Report{ManifestCount: 10, DestinationCount: 10, Checked: 9}
	if r.Clean() {
		t.Fatal("a report that checked 9 of 10 files reported clean")
	}
	r2 := &Report{ManifestCount: 10, DestinationCount: 11, Checked: 10}
	if r2.Clean() {
		t.Fatal("a report with a count mismatch reported clean")
	}
}
