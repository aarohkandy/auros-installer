package copyengine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// Ratio of abort tests to happy tests in this file: 16 to 3. SAFETY.md rule 2.
//
// Every test builds a stand-in SYSTEM DISK alongside the source and the
// destination, fingerprints it, and asserts it is byte-identical afterwards.
// Phase 4 writes only to the destination, and this is where that is proven
// rather than asserted in a comment.

type env struct {
	base      string
	src       string
	dest      string
	sys       string
	sysBefore testsupport.Fingerprint
	q         *quarantine.Set
}

func newEnv(t *testing.T, files map[string]string) *env {
	t.Helper()
	base := t.TempDir()
	e := &env{base: base}
	e.src = filepath.Join(base, "source")
	e.dest = filepath.Join(base, "usb")
	e.sys = filepath.Join(base, "systemdisk")
	for _, d := range []string{e.src, e.dest, e.sys} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testsupport.Tree(t, e.sys, map[string]string{
		"Windows/System32/config/SYSTEM": "registry hive",
		"Users/pat/thesis.odt":           "the only copy",
		"bootmgr":                        "boot manager",
	})
	testsupport.Tree(t, e.src, files)
	e.sysBefore = testsupport.Snapshot(t, e.sys)
	e.q = quarantine.NewSet(func() time.Time { return time.Unix(1700000000, 0).UTC() })
	return e
}

func (e *env) opts() Options {
	o := Options{}
	o.Sources = []Source{{Root: e.src, Label: "Documents"}}
	o.DestRoot = e.dest
	o.Quarantine = e.q
	o.BufSize = 64
	return o
}

func (e *env) assertSystemDiskUntouched(t *testing.T) {
	t.Helper()
	testsupport.AssertUnchanged(t, e.sys, e.sysBefore)
}

func sample() map[string]string {
	return map[string]string{
		"a.txt":       "alpha",
		"sub/b.txt":   "bravo",
		"sub/c/d.txt": "delta",
	}
}

// ---------- the happy paths (three) ----------

func TestCopy_WritesEveryFileAndHashesTheBytesItWrote(t *testing.T) {
	e := newEnv(t, sample())
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 3 || res.Quarantined != 0 {
		t.Fatalf("copied=%d quarantined=%d, want 3 and 0\n%s", res.Copied, res.Quarantined, res.Describe())
	}
	for rel, content := range sample() {
		got := testsupport.MustRead(t, filepath.Join(e.dest, "Documents", filepath.FromSlash(rel)))
		if got != content {
			t.Errorf("%s = %q, want %q", rel, got, content)
		}
		entry, ok := res.Manifest.Lookup("Documents/" + rel)
		if !ok {
			t.Errorf("%s is not in the manifest", rel)
			continue
		}
		if entry.SHA256 != testsupport.SHA256(content) {
			t.Errorf("%s digest = %s, want %s", rel, entry.SHA256, testsupport.SHA256(content))
		}
	}
	if _, err := os.Stat(res.ManifestPath); err != nil {
		t.Errorf("the manifest was not written to the destination: %v", err)
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_ZeroByteFileIsOrdinary(t *testing.T) {
	e := newEnv(t, map[string]string{"empty.txt": "", "nonempty.txt": "x"})
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 2 {
		t.Fatalf("copied = %d, want 2", res.Copied)
	}
	entry, _ := res.Manifest.Lookup("Documents/empty.txt")
	if entry.Size != 0 || entry.SHA256 != manifest.EmptySHA256 {
		t.Errorf("empty file entry = %+v", entry)
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_FileLargerThanTheBufferStreams(t *testing.T) {
	// 2 MiB through a 64-byte buffer. Nothing anywhere reads a whole file into
	// memory, so a file larger than available RAM is not a special case.
	big := strings.Repeat("auros-", 349525) // 2,097,150 bytes
	e := newEnv(t, map[string]string{"big.bin": big})
	o := e.opts()
	o.BufSize = 64
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, ok := res.Manifest.Lookup("Documents/big.bin")
	if !ok {
		t.Fatal("the large file is not in the manifest")
	}
	if entry.Size != int64(len(big)) {
		t.Errorf("size = %d, want %d", entry.Size, len(big))
	}
	if entry.SHA256 != testsupport.SHA256(big) {
		t.Error("the digest does not match the content")
	}
	e.assertSystemDiskUntouched(t)
}

// ---------- abort paths ----------

func TestCopy_RefusesDestinationInsideASource(t *testing.T) {
	e := newEnv(t, sample())
	o := e.opts()
	o.DestRoot = filepath.Join(e.src, "backup") // copying a tree into itself
	_, err := Run(context.Background(), o)
	if !errors.Is(err, ErrDestinationInsideSource) {
		t.Fatalf("err = %v, want ErrDestinationInsideSource", err)
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_RefusesNoDestination(t *testing.T) {
	e := newEnv(t, sample())
	o := e.opts()
	o.DestRoot = ""
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_RefusesNoSources(t *testing.T) {
	e := newEnv(t, sample())
	o := e.opts()
	o.Sources = nil
	if _, err := Run(context.Background(), o); !errors.Is(err, ErrNoSources) {
		t.Fatalf("err = %v, want ErrNoSources", err)
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_RefusesALabelThatEscapes(t *testing.T) {
	e := newEnv(t, sample())
	for _, label := range []string{"..", "../escape", "/abs", ""} {
		o := e.opts()
		o.Sources = []Source{{Root: e.src, Label: label}}
		if _, err := Run(context.Background(), o); !errors.Is(err, ErrBadLabel) {
			t.Errorf("label %q: err = %v, want ErrBadLabel", label, err)
		}
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SymlinkEscapingTheRootIsQuarantinedNotFollowed(t *testing.T) {
	e := newEnv(t, map[string]string{"ok.txt": "fine"})
	// A link out of the source tree and onto the system disk.
	target := filepath.Join(e.sys, "Users", "pat", "thesis.odt")
	link := filepath.Join(e.src, "escape.lnk")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 1 {
		t.Errorf("copied = %d, want 1 (only the real file)", res.Copied)
	}
	if _, ok := res.Manifest.Lookup("Documents/escape.lnk"); ok {
		t.Error("the escaping link was copied into the archive")
	}
	if !hasReason(e.q, "Documents/escape.lnk", quarantine.ReasonPathEscape) {
		t.Errorf("the escaping link was not quarantined as a path escape: %+v", e.q.Records())
	}
	if e.q.Unresolved() == 0 {
		t.Error("an unfollowed link must leave an unresolved record, so the run cannot reach the wall")
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SymlinkInsideTheRootIsReportedNotFollowed(t *testing.T) {
	e := newEnv(t, map[string]string{"real.txt": "content"})
	link := filepath.Join(e.src, "alias.txt")
	if err := os.Symlink(filepath.Join(e.src, "real.txt"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 1 {
		t.Errorf("copied = %d, want 1", res.Copied)
	}
	if !hasReason(e.q, "Documents/alias.txt", quarantine.ReasonUnsupportedType) {
		t.Errorf("the link was not reported: %+v", e.q.Records())
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SourceDisappearsBeforeItIsCopied(t *testing.T) {
	e := newEnv(t, sample())
	o := e.opts()
	victim := filepath.Join(e.src, "sub", "b.txt")
	o.hookBeforeCopy = func(src string) {
		if src == victim {
			os.Remove(victim)
		}
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 2 {
		t.Errorf("copied = %d, want 2: one bad file must not abort the run", res.Copied)
	}
	if !hasReason(e.q, "Documents/sub/b.txt", quarantine.ReasonSourceDisappeared) {
		t.Errorf("not quarantined as disappeared: %+v", e.q.Records())
	}
	if e.q.Unresolved() != 1 {
		t.Errorf("unresolved = %d, want 1 (the run must not reach the wall)", e.q.Unresolved())
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SourceDisappearsMidCopy(t *testing.T) {
	e := newEnv(t, map[string]string{"a.txt": strings.Repeat("x", 4096), "b.txt": "fine"})
	o := e.opts()
	victim := filepath.Join(e.src, "a.txt")
	o.hookAfterOpen = func(src string) {
		if src == victim {
			os.Remove(victim)
		}
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := res.Manifest.Lookup("Documents/a.txt"); ok {
		t.Error("a file that vanished mid-copy is in the manifest")
	}
	if e.q.Unresolved() == 0 {
		t.Errorf("nothing was quarantined: %+v", e.q.Records())
	}
	assertNoPartials(t, e.dest)
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SourceChangesMidCopy(t *testing.T) {
	// The bytes written would be a mixture of two versions of the file, so the
	// digest would describe nothing. Quarantine, never record.
	e := newEnv(t, map[string]string{"a.txt": strings.Repeat("x", 8192), "b.txt": "fine"})
	o := e.opts()
	victim := filepath.Join(e.src, "a.txt")
	o.hookAfterOpen = func(src string) {
		if src != victim {
			return
		}
		f, err := os.OpenFile(victim, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		f.WriteString("appended while the copy was running")
		f.Close()
		os.Chtimes(victim, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, ok := res.Manifest.Lookup("Documents/a.txt"); ok {
		t.Error("a file that changed mid-copy is in the manifest")
	}
	if !hasReason(e.q, "Documents/a.txt", quarantine.ReasonSourceChanged) {
		t.Errorf("not quarantined as changed: %+v", e.q.Records())
	}
	if rec := find(e.q, "Documents/a.txt"); rec.Attempts < 2 {
		t.Errorf("attempts = %d, want at least 2 (retry once, then quarantine)", rec.Attempts)
	}
	assertNoPartials(t, e.dest)
	e.assertSystemDiskUntouched(t)
}

func TestCopy_RetrySucceedsAndTheFileIsNotQuarantined(t *testing.T) {
	// The other half of the retry rule: a transient failure must not condemn a
	// file. Antivirus touching a file once is not data loss.
	e := newEnv(t, map[string]string{"a.txt": strings.Repeat("y", 4096)})
	o := e.opts()
	victim := filepath.Join(e.src, "a.txt")
	fired := false
	o.hookAfterOpen = func(src string) {
		if src != victim || fired {
			return
		}
		fired = true
		os.Chtimes(victim, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	}
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 1 {
		t.Errorf("copied = %d, want 1", res.Copied)
	}
	if e.q.Unresolved() != 0 {
		t.Errorf("a file that succeeded on retry is still quarantined: %+v", e.q.Records())
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_ContextCancelledBeforeAnythingHappens(t *testing.T) {
	e := newEnv(t, sample())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := Run(ctx, e.opts())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if res.Copied != 0 {
		t.Errorf("copied = %d after a cancelled start", res.Copied)
	}
	assertNoPartials(t, e.dest)
	e.assertSystemDiskUntouched(t)
}

func TestCopy_ContextCancelledMidRunLeavesAKnowableDestination(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 40; i++ {
		files[string(rune('a'+i%26))+string(rune('a'+i/26))+".txt"] = strings.Repeat("z", 512)
	}
	e := newEnv(t, files)
	ctx, cancel := context.WithCancel(context.Background())
	o := e.opts()
	seen := 0
	o.hookBeforeCopy = func(string) {
		seen++
		if seen == 5 {
			cancel()
		}
	}
	res, err := Run(ctx, o)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if !res.Cancelled {
		t.Error("the result does not report cancellation")
	}
	// Knowable: no partials, and the manifest on disk describes exactly the
	// files that are complete.
	assertNoPartials(t, e.dest)
	f, oerr := os.Open(res.ManifestPath)
	if oerr != nil {
		t.Fatalf("no manifest was written on the cancel path: %v", oerr)
	}
	defer f.Close()
	m, rerr := manifest.Read(f)
	if rerr != nil {
		t.Fatalf("the manifest written on the cancel path does not parse: %v", rerr)
	}
	onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir)
	if m.Len() != onDisk {
		t.Errorf("manifest lists %d files, destination holds %d", m.Len(), onDisk)
	}
	if e.q.Unresolved() == 0 {
		t.Error("the files that were never copied must be quarantined, not silently missing")
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_FileTooLargeIsQuarantinedNotSkipped(t *testing.T) {
	e := newEnv(t, map[string]string{"small.txt": "ok", "huge.bin": strings.Repeat("h", 4096)})
	o := e.opts()
	o.MaxFileBytes = 1024
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 1 {
		t.Errorf("copied = %d, want 1", res.Copied)
	}
	if !hasReason(e.q, "Documents/huge.bin", quarantine.ReasonTooLarge) {
		t.Errorf("the oversized file was not quarantined: %+v", e.q.Records())
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_NamesLegalOnNTFSAreStoredPortablyAndRecordedBothWays(t *testing.T) {
	// Written straight into the source with names an exFAT stick would refuse.
	names := []string{"report:2024.txt", "what?.txt", "trailing dot.", "CON", "a|b.txt"}
	e := newEnv(t, map[string]string{"plain.txt": "ordinary"})
	for _, n := range names {
		p := filepath.Join(e.src, n)
		if err := os.WriteFile(p, []byte("content of "+n), 0o644); err != nil {
			t.Skipf("this filesystem will not hold %q: %v", n, err)
		}
	}
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != len(names)+1 {
		t.Fatalf("copied = %d, want %d\n%s", res.Copied, len(names)+1, res.Describe())
	}
	for _, n := range names {
		entry, ok := res.Manifest.Lookup("Documents/" + n)
		if !ok {
			t.Errorf("%q is not in the manifest under its original name", n)
			continue
		}
		// The ORIGINAL name is recorded, so restore can put it back...
		if entry.Path != "Documents/"+n {
			t.Errorf("Path = %q, want the original name", entry.Path)
		}
		// ...and the STORED name is portable.
		if strings.ContainsAny(entry.Stored, `<>:"|?*\`) {
			t.Errorf("stored name %q is not portable", entry.Stored)
		}
		if got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored))); got != "content of "+n {
			t.Errorf("%q: content = %q", n, got)
		}
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_DuplicatePathsDifferingOnlyInCaseBothSurvive(t *testing.T) {
	e := newEnv(t, map[string]string{"plain.txt": "ordinary"})
	if err := os.WriteFile(filepath.Join(e.src, "Report.txt"), []byte("upper"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.src, "report.txt"), []byte("lower"), 0o644); err != nil {
		t.Skipf("this filesystem is case-insensitive: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(e.src, "Report.txt")); string(b) != "upper" {
		t.Skip("this filesystem is case-insensitive; the two files collapsed into one")
	}

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	upper, okU := res.Manifest.Lookup("Documents/Report.txt")
	lower, okL := res.Manifest.Lookup("Documents/report.txt")
	if !okU || !okL {
		t.Fatalf("both files must be in the manifest: upper=%v lower=%v", okU, okL)
	}
	if manifest.FoldKey(upper.Stored) == manifest.FoldKey(lower.Stored) {
		t.Fatalf("both stored at %q and %q, which collide on a case-insensitive volume",
			upper.Stored, lower.Stored)
	}
	if upper.SHA256 == lower.SHA256 {
		t.Fatal("the two files have the same digest: one overwrote the other")
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_SweepsPartialsLeftByAnEarlierRun(t *testing.T) {
	e := newEnv(t, sample())
	debris := filepath.Join(e.dest, "Documents", "stale.txt"+partialSuffix)
	if err := os.MkdirAll(filepath.Dir(debris), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(debris, []byte("half a file from a run that was killed"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.PartialsSwept) != 1 {
		t.Errorf("swept %d partials, want 1", len(res.PartialsSwept))
	}
	if _, err := os.Stat(debris); !os.IsNotExist(err) {
		t.Error("the stale partial is still on the destination")
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_ResumeReusesCompleteFilesAndStillRecordsThem(t *testing.T) {
	e := newEnv(t, sample())
	first, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if first.Copied != 3 {
		t.Fatalf("first run copied %d", first.Copied)
	}

	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o := e2.opts()
	o.Resume = true
	second, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if second.Resumed != 3 || second.Copied != 0 {
		t.Errorf("resumed=%d copied=%d, want 3 and 0", second.Resumed, second.Copied)
	}
	if second.Manifest.Digest() != first.Manifest.Digest() {
		t.Error("a resumed run produced a different manifest")
	}
	e.assertSystemDiskUntouched(t)
}

func TestCopy_UnreadableDirectoryIsQuarantinedAndTheRunContinues(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permissions are not enforced")
	}
	e := newEnv(t, map[string]string{"readable.txt": "fine", "locked/secret.txt": "hidden"})
	locked := filepath.Join(e.src, "locked")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot remove permissions: %v", err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied < 1 {
		t.Errorf("copied = %d, want at least the readable file", res.Copied)
	}
	if e.q.Unresolved() == 0 {
		t.Error("the unreadable directory was silently skipped")
	}
	e.assertSystemDiskUntouched(t)
}

// ---------- helpers ----------

func hasReason(q *quarantine.Set, path string, want quarantine.Reason) bool {
	for _, r := range q.Records() {
		if r.Path == path && r.Reason == want {
			return true
		}
	}
	return false
}

func find(q *quarantine.Set, path string) quarantine.Record {
	for _, r := range q.Records() {
		if r.Path == path {
			return r
		}
	}
	return quarantine.Record{}
}

func assertNoPartials(t *testing.T, dest string) {
	t.Helper()
	err := filepath.Walk(dest, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(p, partialSuffix) {
			t.Errorf("a partial file was left behind: %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the destination: %v", err)
	}
}
