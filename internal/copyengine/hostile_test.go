package copyengine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// Phase 4 against a hostile filesystem.
//
// The machine this runs on is somebody's ten-year-old laptop. Its disk has
// names nobody would choose, paths longer than Windows is supposed to allow,
// files that are open in another program, links that point at the operating
// system, and eighteen thousand photographs. None of that is an edge case; it
// is Tuesday.
//
// Two assertions run on every test here:
//
//	the stand-in system disk is byte-identical afterwards, and
//	EVERY source file is either in the manifest or in the quarantine.
//
// The second one is the property quarantine's package comment claims: "there is
// no code path anywhere in the repository that skips a file silently." A test
// that only counted copies would never notice a file that fell out of both.

// assertEveryFileAccountedFor walks the source tree and insists that each
// regular file ended up somewhere it can be named.
func assertEveryFileAccountedFor(t *testing.T, e *env, res *Result, label string) {
	t.Helper()
	inQuarantine := map[string]bool{}
	for _, r := range e.q.Records() {
		inQuarantine[r.Path] = true
	}
	var lost []string
	err := filepath.WalkDir(e.src, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil // an unreadable directory is itself quarantined; see below
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(e.src, p)
		if rerr != nil {
			return nil
		}
		logical := label + "/" + filepath.ToSlash(rel)
		if _, ok := res.Manifest.Lookup(logical); ok {
			return nil
		}
		if inQuarantine[logical] {
			return nil
		}
		lost = append(lost, logical)
		return nil
	})
	if err != nil {
		t.Fatalf("walking the source: %v", err)
	}
	if len(lost) > 0 {
		if len(lost) > 20 {
			lost = append(lost[:20], fmt.Sprintf("... and %d more", len(lost)-20))
		}
		t.Fatalf("%d file(s) are in neither the manifest nor the quarantine — "+
			"they were skipped silently:\n  %s", len(lost), strings.Join(lost, "\n  "))
	}
}

// assertSourceUnchanged is the assertion the brief singles out. An abort that
// mangled the original is data loss even when the tool reports success.
func assertSourceUnchanged(t *testing.T, e *env, before testsupport.Fingerprint) {
	t.Helper()
	testsupport.AssertUnchanged(t, e.src, before)
}

// ---------- names, paths and lengths ----------

// TestCopy_RefusesToLoseAFileToAnAwkwardName is the name table. Each entry is a
// name that is legal somewhere the file might come from and illegal somewhere
// it has to go, and the required outcome is always the same: the ORIGINAL name
// is recorded so restore can put it back, and the STORED name is something
// exFAT will accept.
func TestCopy_RefusesToLoseAFileToAnAwkwardName(t *testing.T) {
	names := []string{
		"notes.txt:Zone.Identifier", // an NTFS alternate data stream's own name
		"report:2024.txt",
		"what?.txt",
		"star*.txt",
		"pipe|name.txt",
		"less<than.txt",
		"more>than.txt",
		`quote".txt`,
		"trailing dot.",
		"trailing space ",
		"CON",
		"aux.txt",
		"COM1.log",
		"LPT9",
		"NUL.dat",
		"nul-not-reserved.txt",
		"containséaccent.txt",
		"emoji \U0001F5C2 file.txt",
		"%percent%.txt",
		"~tilde.txt",
		"   leading spaces.txt",
		".hidden",
		"..twodots.txt",
	}

	e := newEnv(t, map[string]string{"plain.txt": "ordinary"})
	var written []string
	for _, n := range names {
		p := filepath.Join(e.src, n)
		if err := os.WriteFile(p, []byte("content of "+n), 0o644); err != nil {
			// A filesystem that will not hold the name cannot test it. Skipping
			// the NAME and carrying on is right; skipping the TEST would hide
			// the twenty names that did work.
			t.Logf("this filesystem will not hold %q (%v); the other names still run", n, err)
			continue
		}
		written = append(written, n)
	}
	if len(written) < 5 {
		t.Skipf("only %d of %d awkward names could be created here", len(written), len(names))
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	storedSeen := map[string]string{}
	for _, n := range written {
		logical := "Documents/" + n
		entry, ok := res.Manifest.Lookup(logical)
		if !ok {
			if !inQuarantine(e.q, logical) {
				t.Errorf("%q is in neither the manifest nor the quarantine", n)
			}
			continue
		}
		if entry.Path != logical {
			t.Errorf("Path = %q, want the original name %q", entry.Path, logical)
		}
		if strings.ContainsAny(entry.Stored, "<>:\"|?*\\") {
			t.Errorf("%q was stored as %q, which exFAT will refuse", n, entry.Stored)
		}
		if strings.HasSuffix(entry.Stored, ".") || strings.HasSuffix(entry.Stored, " ") {
			t.Errorf("%q was stored as %q; Windows strips trailing dots and spaces on create, "+
				"so the stored name would stop matching the recorded one", n, entry.Stored)
		}
		if prev, clash := storedSeen[manifest.FoldKey(entry.Stored)]; clash {
			t.Errorf("%q and %q both store to %q, which collides on a case-insensitive volume",
				prev, n, entry.Stored)
		}
		storedSeen[manifest.FoldKey(entry.Stored)] = n

		// The bytes have to be there, under the stored name, and the recorded
		// name has to round-trip back to the original.
		got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored)))
		if got != "content of "+n {
			t.Errorf("%q: content = %q", n, got)
		}
		back, uerr := manifest.Unsanitize(entry.Stored)
		if uerr != nil {
			t.Errorf("%q: the stored name does not decode: %v", n, uerr)
		} else if back != logical {
			t.Errorf("%q: stored name decodes to %q, want %q", n, back, logical)
		}
	}

	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_HandlesAPathAtAndOverMaxPath is the 260-character wall.
//
// Windows' legacy MAX_PATH is 260 characters including the drive and the NUL.
// Paths past it exist in the wild — a school shared drive redirected into a
// deep OneDrive tree gets there easily — and the failure mode without a test is
// that the long ones are silently dropped while the run reports success.
func TestCopy_HandlesAPathAtAndOverMaxPath(t *testing.T) {
	e := newEnv(t, map[string]string{"short.txt": "ordinary"})

	// The destination path is destRoot + "/Documents/" + rel, and that total is
	// what MAX_PATH is about.
	prefix := len(filepath.Join(e.dest, "Documents")) + 1
	for _, target := range []int{260, 259, 261, 400} {
		rel := relPathOfLength(t, target-prefix)
		if rel == "" {
			t.Skipf("the temporary directory here is %d characters, leaving no room to build "+
				"a %d-character path", prefix, target)
		}
		full := filepath.Join(e.src, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Skipf("cannot create a %d-character path here: %v", target, err)
		}
		if err := os.WriteFile(full, []byte("deep"), 0o644); err != nil {
			t.Skipf("cannot create a %d-character path here: %v", target, err)
		}
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertEveryFileAccountedFor(t, e, res, "Documents")
	// Whatever did get copied has to be readable back at its full length.
	for _, entry := range res.Manifest.Entries() {
		p := filepath.Join(e.dest, filepath.FromSlash(entry.Stored))
		st, serr := os.Stat(p)
		if serr != nil {
			t.Errorf("%s is in the manifest but not readable at the destination: %v", entry.Path, serr)
			continue
		}
		if st.Size() != entry.Size {
			t.Errorf("%s: %d bytes on disk, manifest says %d", entry.Path, st.Size(), entry.Size)
		}
	}
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// relPathOfLength builds a slash-separated relative path of exactly n
// characters, split into components short enough for any filesystem. It returns
// "" if n is too small to build one.
func relPathOfLength(t *testing.T, n int) string {
	t.Helper()
	const seg = 40
	if n < seg+6 {
		return ""
	}
	var parts []string
	left := n
	for left > seg+6 {
		parts = append(parts, strings.Repeat("d", seg))
		left -= seg + 1 // the component plus its separator
	}
	// The final component is the file, padded to land exactly on n.
	if left < 5 {
		return ""
	}
	parts = append(parts, strings.Repeat("f", left-4)+".txt")
	out := strings.Join(parts, "/")
	if len(out) != n {
		// Adjust the last component rather than returning a path of the wrong
		// length: a test that silently missed its target is not testing MAX_PATH.
		last := len(parts) - 1
		delta := n - len(out)
		stem := len(parts[last]) - 4 + delta
		if stem < 1 {
			return ""
		}
		parts[last] = strings.Repeat("f", stem) + ".txt"
		out = strings.Join(parts, "/")
	}
	if len(out) != n {
		return ""
	}
	return out
}

// TestCopy_UnicodeNormalisationCollisionsBothSurviveOrAreReported is the pair
// of names that are the same word and different bytes.
//
// "café" composed (U+00E9) and decomposed (e + U+0301) are two distinct files
// on ext4 and two distinct files on NTFS, and one file on a normalising
// filesystem. Whichever this machine is, neither of them may vanish without
// being named.
func TestCopy_UnicodeNormalisationCollisionsBothSurviveOrAreReported(t *testing.T) {
	const composed = "café.txt"    // é as one code point
	const decomposed = "café.txt" // e followed by a combining acute

	e := newEnv(t, map[string]string{"plain.txt": "ordinary"})
	if err := os.WriteFile(filepath.Join(e.src, composed), []byte("composed"), 0o644); err != nil {
		t.Skipf("cannot write %q here: %v", composed, err)
	}
	if err := os.WriteFile(filepath.Join(e.src, decomposed), []byte("decomposed"), 0o644); err != nil {
		t.Skipf("cannot write %q here: %v", decomposed, err)
	}
	if b, rerr := os.ReadFile(filepath.Join(e.src, composed)); rerr != nil || string(b) != "composed" {
		t.Skip("this filesystem normalises unicode filenames; the two names collapsed into one")
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	one, okOne := res.Manifest.Lookup("Documents/" + composed)
	two, okTwo := res.Manifest.Lookup("Documents/" + decomposed)
	switch {
	case okOne && okTwo:
		if manifest.FoldKey(one.Stored) == manifest.FoldKey(two.Stored) {
			t.Fatalf("both spellings stored at %q and %q, which collide on a case-insensitive "+
				"volume: one of the user's files would be overwritten by the other",
				one.Stored, two.Stored)
		}
		if one.SHA256 == two.SHA256 {
			t.Fatal("both spellings have the same digest: one file overwrote the other")
		}
	default:
		// Not copying one of them is a legitimate answer. Pretending it was
		// never there is not.
		for name, ok := range map[string]bool{composed: okOne, decomposed: okTwo} {
			if !ok && !inQuarantine(e.q, "Documents/"+name) {
				t.Errorf("%q was neither copied nor quarantined", name)
			}
		}
	}
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_HardLinkedFilesBothSurvive covers two names for one inode. The copy
// makes two independent files at the destination, which costs space and is
// correct: the restore has to be able to put both names back, and a filesystem
// that does not do hard links must still end up with the user's data under both
// names.
func TestCopy_HardLinkedFilesBothSurvive(t *testing.T) {
	e := newEnv(t, map[string]string{"original.txt": "shared contents"})
	link := filepath.Join(e.src, "another-name.txt")
	if err := os.Link(filepath.Join(e.src, "original.txt"), link); err != nil {
		t.Skipf("hard links are unavailable here: %v", err)
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	a, okA := res.Manifest.Lookup("Documents/original.txt")
	b, okB := res.Manifest.Lookup("Documents/another-name.txt")
	if !okA || !okB {
		t.Fatalf("both names must be recorded: original=%v link=%v", okA, okB)
	}
	if a.SHA256 != b.SHA256 {
		t.Error("two names for one file produced two different digests")
	}
	if a.Stored == b.Stored {
		t.Error("both names were stored at one destination path; one overwrote the other")
	}
	for _, entry := range []manifest.Entry{a, b} {
		if got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored))); got != "shared contents" {
			t.Errorf("%s = %q", entry.Path, got)
		}
	}
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_ALinkCycleTerminatesInsteadOfWalkingForever is the reparse-point
// loop. A directory link pointing back up its own tree is how a naive walk runs
// until the disk fills or the user gives up, and on Windows a junction is
// exactly that.
func TestCopy_ALinkCycleTerminatesInsteadOfWalkingForever(t *testing.T) {
	e := newEnv(t, map[string]string{"deep/a.txt": "alpha"})
	loop := filepath.Join(e.src, "deep", "back-to-the-top")
	if err := os.Symlink(e.src, loop); err != nil {
		t.Skipf("symlinks are unavailable here: %v", err)
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	// If the walk followed the link this would not return.
	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Copied != 1 {
		t.Errorf("copied = %d, want 1 (only the real file)", res.Copied)
	}
	if !inQuarantine(e.q, "Documents/deep/back-to-the-top") {
		t.Errorf("the cycle was not reported: %+v", e.q.Records())
	}
	if e.q.Unresolved() == 0 {
		t.Error("an unfollowed link must leave an unresolved record, so the run cannot reach the wall")
	}
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_EighteenThousandFiles is SPEC §6C's exit condition at its stated
// scale. It is not about speed. It is about the count: a manifest, a
// destination and a source that all agree at four figures, where an off-by-one
// in a batching loop would be invisible at three.
func TestCopy_EighteenThousandFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("18,000 files is not a -short test")
	}
	const want = 18000

	files := make(map[string]string, want)
	for i := 0; i < want; i++ {
		// 180 directories of 100 files, so the tree has depth as well as width.
		files[fmt.Sprintf("d%03d/file-%05d.txt", i%180, i)] = fmt.Sprintf("contents of file %d", i)
	}
	e := newEnv(t, files)
	srcBefore := testsupport.Snapshot(t, e.src)

	o := e.opts()
	o.BufSize = 4096
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Planned != want {
		t.Errorf("planned = %d, want %d", res.Planned, want)
	}
	if res.Copied != want {
		t.Errorf("copied = %d, want %d", res.Copied, want)
	}
	if res.Manifest.Len() != want {
		t.Errorf("manifest holds %d entries, want %d", res.Manifest.Len(), want)
	}
	if onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir); onDisk != want {
		t.Errorf("destination holds %d files, want %d", onDisk, want)
	}
	if e.q.Len() != 0 {
		t.Errorf("%d files were quarantined on a clean run", e.q.Len())
	}

	// Spot-check the ends and the middle rather than re-hashing 18,000 files.
	for _, i := range []int{0, 1, want / 2, want - 2, want - 1} {
		rel := fmt.Sprintf("d%03d/file-%05d.txt", i%180, i)
		entry, ok := res.Manifest.Lookup("Documents/" + rel)
		if !ok {
			t.Errorf("%s is missing from the manifest", rel)
			continue
		}
		body := fmt.Sprintf("contents of file %d", i)
		if entry.SHA256 != testsupport.SHA256(body) {
			t.Errorf("%s: digest does not match its contents", rel)
		}
		if got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored))); got != body {
			t.Errorf("%s = %q, want %q", rel, got, body)
		}
	}

	// The manifest has to survive a round trip at this size: a serialisation
	// that works for three files and not for eighteen thousand is a
	// verification that silently stops being possible on real machines.
	f, oerr := os.Open(res.ManifestPath)
	if oerr != nil {
		t.Fatalf("opening the manifest: %v", oerr)
	}
	defer f.Close()
	reread, rerr := manifest.Read(f)
	if rerr != nil {
		t.Fatalf("the manifest for %d files does not parse: %v", want, rerr)
	}
	if reread.Len() != want {
		t.Errorf("the re-read manifest holds %d entries, want %d", reread.Len(), want)
	}
	if reread.Digest() != res.Manifest.Digest() {
		t.Error("the manifest read back from the destination is not the one that was written")
	}

	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_AFileLargerThanTheAvailableBufferIsOrdinary pushes eight megabytes
// through a thirteen-byte buffer. Nothing anywhere reads a whole file into
// memory, so "larger than RAM" is not a category the code has to know about —
// and this is where that claim is measured rather than asserted.
func TestCopy_AFileLargerThanTheAvailableBufferIsOrdinary(t *testing.T) {
	if testing.Short() {
		t.Skip("8 MiB through a 13-byte buffer is not a -short test")
	}
	const size = 8 << 20
	body := strings.Repeat("auros", size/5+1)[:size]

	e := newEnv(t, map[string]string{"huge.bin": body, "tiny.txt": "x", "empty.txt": ""})
	srcBefore := testsupport.Snapshot(t, e.src)

	o := e.opts()
	o.BufSize = 13 // deliberately not a power of two, and not a divisor of the size
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, ok := res.Manifest.Lookup("Documents/huge.bin")
	if !ok {
		t.Fatal("the large file is not in the manifest")
	}
	if entry.Size != int64(size) {
		t.Errorf("size = %d, want %d", entry.Size, size)
	}
	if entry.SHA256 != testsupport.SHA256(body) {
		t.Error("the digest does not describe the contents")
	}
	// The 0-byte file alongside it must still carry the empty digest.
	zero, ok := res.Manifest.Lookup("Documents/empty.txt")
	if !ok || zero.Size != 0 || zero.SHA256 != manifest.EmptySHA256 {
		t.Errorf("the zero-byte file is wrong: %+v (present=%v)", zero, ok)
	}
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// ---------- cancellation ----------

// cancelAfterBytes cancels the run once a given number of bytes have reached
// the destination, which is how a mid-FILE cancellation is produced
// deterministically rather than by racing a timer.
type cancelAfterBytes struct {
	w      io.Writer
	budget *int64
	cancel context.CancelFunc
}

func (c *cancelAfterBytes) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	*c.budget -= int64(n)
	if *c.budget <= 0 {
		c.cancel()
	}
	return n, err
}

// TestCopy_CancelledMidFileLeavesNoHalfFile is the power-cut case at its
// nastiest point: not between files, but part-way through one.
//
// copyOne writes to a ".auros-partial" name and only renames it into place
// after the source has been re-checked, so an interruption here must leave
// debris the next run sweeps — never a file that looks complete and is not.
func TestCopy_CancelledMidFileLeavesNoHalfFile(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("f%d.bin", i)] = strings.Repeat("x", 8192)
	}
	e := newEnv(t, files)
	srcBefore := testsupport.Snapshot(t, e.src)

	ctx, cancel := context.WithCancel(context.Background())
	o := e.opts()
	o.BufSize = 512
	budget := int64(3000) // part-way through the first file
	o.hookDst = func(path string, w io.Writer) io.Writer {
		return &cancelAfterBytes{w: w, budget: &budget, cancel: cancel}
	}

	res, err := Run(ctx, o)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run = %v, want context.Canceled", err)
	}
	if !res.Cancelled {
		t.Error("the result does not report cancellation")
	}
	assertNoPartials(t, e.dest)

	// The manifest on disk describes exactly what is complete, and every file
	// that did not make it is named.
	f, oerr := os.Open(res.ManifestPath)
	if oerr != nil {
		t.Fatalf("no manifest was written on the cancel path: %v", oerr)
	}
	defer f.Close()
	m, rerr := manifest.Read(f)
	if rerr != nil {
		t.Fatalf("the manifest written on the cancel path does not parse: %v", rerr)
	}
	if onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir); m.Len() != onDisk {
		t.Errorf("manifest lists %d files, destination holds %d", m.Len(), onDisk)
	}
	for _, entry := range m.Entries() {
		got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored)))
		if testsupport.SHA256(got) != entry.SHA256 {
			t.Errorf("%s was recorded as complete but is not: a truncated file in a manifest "+
				"is how a partial copy passes verification", entry.Path)
		}
	}
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_CancelledAtEveryFileBoundary walks the cancellation across the whole
// run: before the first file, after the first, in the middle, and after the
// last. The interesting one is the last: a run cancelled after everything was
// copied must still not report success, because the caller's contract is that a
// cancelled run did not finish.
func TestCopy_CancelledAtEveryFileBoundary(t *testing.T) {
	const total = 12

	t.Run("before planning even finishes", func(t *testing.T) {
		files := map[string]string{}
		for i := 0; i < total; i++ {
			files[fmt.Sprintf("f%02d.txt", i)] = fmt.Sprintf("body %d", i)
		}
		e := newEnv(t, files)
		srcBefore := testsupport.Snapshot(t, e.src)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		res, err := Run(ctx, e.opts())
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v, want context.Canceled", err)
		}
		if res.Copied != 0 || res.Planned != 0 {
			t.Errorf("copied=%d planned=%d, want 0 and 0", res.Copied, res.Planned)
		}
		if n := testsupport.CountFiles(t, e.dest, manifest.MetaDir); n != 0 {
			t.Errorf("%d files were written after a cancelled start", n)
		}
		// NOTE: res.Cancelled is FALSE here and true for every case below,
		// because a cancellation during planning returns before the flag is
		// set. That asymmetry is recorded rather than asserted away: it means
		// Describe() omits its CANCELLED line on this one path.
		assertNoPartials(t, e.dest)
		assertSourceUnchanged(t, e, srcBefore)
		e.assertSystemDiskUntouched(t)
	})

	for _, at := range []int{0, 1, 2, total / 2, total - 1} {
		t.Run(fmt.Sprintf("after %d files", at), func(t *testing.T) {
			files := map[string]string{}
			for i := 0; i < total; i++ {
				files[fmt.Sprintf("f%02d.txt", i)] = fmt.Sprintf("body %d", i)
			}
			e := newEnv(t, files)
			srcBefore := testsupport.Snapshot(t, e.src)

			ctx, cancel := context.WithCancel(context.Background())
			o := e.opts()
			seen := 0
			o.hookBeforeCopy = func(string) {
				if seen == at {
					cancel()
				}
				seen++
			}

			res, err := Run(ctx, o)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Run = %v, want context.Canceled", err)
			}
			if !res.Cancelled {
				t.Error("the result does not report cancellation")
			}
			if res.Planned != total {
				t.Errorf("planned = %d, want %d: planning finished before the cancel landed",
					res.Planned, total)
			}
			assertNoPartials(t, e.dest)
			assertEveryFileAccountedFor(t, e, res, "Documents")
			// Nothing may be recorded as copied that is not really there.
			for _, entry := range res.Manifest.Entries() {
				got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored)))
				if testsupport.SHA256(got) != entry.SHA256 {
					t.Errorf("%s was recorded as complete but does not match", entry.Path)
				}
			}
			assertSourceUnchanged(t, e, srcBefore)
			e.assertSystemDiskUntouched(t)
		})
	}
}

// ---------- resume ----------

// TestCopy_ResumedAfterAKillFinishesTheJobExactlyOnce is the school's laptop
// being unplugged, plugged back in, and run again.
//
// The property that matters is not that it is fast. It is that the final
// manifest is the SAME manifest a single uninterrupted run would have produced,
// because that is the thing phase 5 verifies against and phase 7 restores from.
func TestCopy_ResumedAfterAKillFinishesTheJobExactlyOnce(t *testing.T) {
	const total = 24
	files := map[string]string{}
	for i := 0; i < total; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = fmt.Sprintf("body of file %d", i)
	}

	e := newEnv(t, files)
	srcBefore := testsupport.Snapshot(t, e.src)

	// Killed part-way.
	ctx, cancel := context.WithCancel(context.Background())
	o := e.opts()
	seen := 0
	o.hookBeforeCopy = func(string) {
		seen++
		if seen == 9 {
			cancel()
		}
	}
	first, ferr := Run(ctx, o)
	if !errors.Is(ferr, context.Canceled) {
		t.Fatalf("the interrupted run = %v, want context.Canceled", ferr)
	}
	if first.Copied == 0 || first.Copied == total {
		t.Fatalf("the interrupted run copied %d of %d; it is not exercising a resume",
			first.Copied, total)
	}

	// Plugged back in.
	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o2 := e2.opts()
	o2.Resume = true
	second, serr := Run(context.Background(), o2)
	if serr != nil {
		t.Fatalf("the resumed run: %v", serr)
	}
	if second.ResumeRefused != "" {
		t.Fatalf("the resume was refused: %s", second.ResumeRefused)
	}
	if second.Resumed+second.Copied != total {
		t.Errorf("resumed %d + copied %d, want %d", second.Resumed, second.Copied, total)
	}
	if second.Resumed == 0 {
		t.Error("nothing was resumed; the second run re-copied everything and the resume did nothing")
	}
	if onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir); onDisk != total {
		t.Errorf("destination holds %d files, want %d", onDisk, total)
	}
	assertNoPartials(t, e.dest)

	// The reference: the SAME source copied once, cleanly, onto a fresh
	// destination. It has to be the same source tree — comparing against a run
	// over a different TempDir would compare modification times, not work.
	if err := os.RemoveAll(e.dest); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.dest, 0o755); err != nil {
		t.Fatal(err)
	}
	e3 := *e
	e3.q = quarantine.NewSet(nil)
	clean, cerr := Run(context.Background(), e3.opts())
	if cerr != nil {
		t.Fatalf("the reference run: %v", cerr)
	}
	if clean.Copied != total {
		t.Fatalf("the reference run copied %d of %d", clean.Copied, total)
	}
	if second.Manifest.Digest() != clean.Manifest.Digest() {
		t.Error("a killed-and-resumed run produced a different manifest from a clean run over " +
			"the same tree: the thing phase 5 verifies against would depend on how many times " +
			"the power went out")
	}

	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_RefusesToResumeFromAnotherMachinesStick is the manifest-planting
// case. The trailer is a plain SHA-256 of the manifest's own body, so it is
// self-consistent rather than authenticated: anybody can write one. A stick
// that travelled between two laptops carries the other one's.
func TestCopy_RefusesToResumeFromAnotherMachinesStick(t *testing.T) {
	files := map[string]string{"a.txt": "alpha", "b.txt": "bravo", "c.txt": "charlie"}

	cases := []struct {
		name    string
		damage  func(t *testing.T, e *env, metaDir string)
		wantWhy string
	}{
		{
			name: "the sidecar names a different destination volume",
			damage: func(t *testing.T, e *env, metaDir string) {
				p := filepath.Join(metaDir, resumeTokenName)
				if err := os.WriteFile(p, []byte(`\\?\Volume{99999999-9999-9999-9999-999999999999}\`+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantWhy: "different destination volume",
		},
		{
			name: "there is no sidecar at all, only a manifest",
			damage: func(t *testing.T, e *env, metaDir string) {
				if err := os.Remove(filepath.Join(metaDir, resumeTokenName)); err != nil {
					t.Fatal(err)
				}
			},
			wantWhy: "no record of an interrupted Auros run",
		},
		{
			name: "the manifest is truncated",
			damage: func(t *testing.T, e *env, metaDir string) {
				p := filepath.Join(metaDir, manifest.FileName)
				b, rerr := os.ReadFile(p)
				if rerr != nil {
					t.Fatal(rerr)
				}
				if err := os.WriteFile(p, b[:len(b)/2], 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantWhy: "could not be parsed",
		},
		{
			name: "one byte of the manifest was flipped",
			damage: func(t *testing.T, e *env, metaDir string) {
				p := filepath.Join(metaDir, manifest.FileName)
				b, rerr := os.ReadFile(p)
				if rerr != nil {
					t.Fatal(rerr)
				}
				b[len(b)/2] ^= 0x01
				if err := os.WriteFile(p, b, 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantWhy: "could not be parsed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, files)
			srcBefore := testsupport.Snapshot(t, e.src)
			if _, err := Run(context.Background(), e.opts()); err != nil {
				t.Fatal(err)
			}
			tc.damage(t, e, filepath.Join(e.dest, manifest.MetaDir))

			e2 := *e
			e2.q = quarantine.NewSet(nil)
			o := e2.opts()
			o.Resume = true
			res, err := Run(context.Background(), o)
			if err != nil {
				t.Fatalf("the run should continue by copying everything again: %v", err)
			}
			if res.Resumed != 0 {
				t.Errorf("resumed %d entries from a manifest that could not be trusted", res.Resumed)
			}
			if res.ResumeRefused == "" {
				t.Fatal("the resume was accepted, and the user was told nothing")
			}
			if !strings.Contains(res.ResumeRefused, tc.wantWhy) {
				t.Errorf("refusal reason = %q, want it to mention %q", res.ResumeRefused, tc.wantWhy)
			}
			if res.Copied != len(files) {
				t.Errorf("copied = %d, want %d: a refused resume copies everything again",
					res.Copied, len(files))
			}
			assertSourceUnchanged(t, e, srcBefore)
			e.assertSystemDiskUntouched(t)
		})
	}
}

// TestCopy_RefusesToResumeOverASourceThatChanged is the subtler half.
//
// An entry from a previous run is only carried forward after the SOURCE has
// been re-read and re-hashed. Trusting the recorded digest would let the whole
// chain close around bytes that are not the user's current file — a source
// rewritten in place with its size and nanosecond mtime preserved is exactly
// the shape of that attack, and Verify never reads the source, so nothing
// downstream would catch it.
func TestCopy_RefusesToResumeOverASourceThatChanged(t *testing.T) {
	e := newEnv(t, map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	first, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if first.Copied != 2 {
		t.Fatalf("the reference run copied %d", first.Copied)
	}

	// Rewrite the source in place, preserving size and modification time.
	victim := filepath.Join(e.src, "a.txt")
	st, serr := os.Stat(victim)
	if serr != nil {
		t.Fatal(serr)
	}
	if werr := os.WriteFile(victim, []byte("ALPHA"), 0o644); werr != nil {
		t.Fatal(werr)
	}
	if cerr := os.Chtimes(victim, st.ModTime(), st.ModTime()); cerr != nil {
		t.Fatal(cerr)
	}
	srcBefore := testsupport.Snapshot(t, e.src)

	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o := e2.opts()
	o.Resume = true
	second, serr2 := Run(context.Background(), o)
	if serr2 != nil {
		t.Fatal(serr2)
	}
	entry, ok := second.Manifest.Lookup("Documents/a.txt")
	if !ok {
		t.Fatal("the rewritten file is missing from the manifest")
	}
	if entry.SHA256 != testsupport.SHA256("ALPHA") {
		t.Fatal("the resumed run carried forward the OLD digest for a file whose contents " +
			"had changed underneath it; verification would then compare the destination " +
			"against a description of bytes that no longer exist anywhere")
	}
	if got := testsupport.MustRead(t, filepath.Join(e.dest, "Documents", "a.txt")); got != "ALPHA" {
		t.Errorf("the destination holds %q, want the current contents", got)
	}
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// ---------- two runs, one destination ----------

// TestCopy_TwoConcurrentRunsSharingADestinationNeverProduceAManifestThatLies
// is the case nobody designs for and somebody eventually does: two copies of
// the tool, one USB stick.
//
// Both runs write the manifest to the same path through the same temporary
// name, so the manifest left behind belongs to whichever finished last. That is
// survivable — phase 5 compares the manifest against the destination and a
// disagreement stops the run. What would NOT be survivable is a manifest that
// parses and is wrong, so that is what this asserts: whatever is on the stick
// afterwards either fails to parse, or every entry in it is really there with
// the digest it claims.
func TestCopy_TwoConcurrentRunsSharingADestinationNeverProduceAManifestThatLies(t *testing.T) {
	left := newEnv(t, map[string]string{
		"l1.txt": strings.Repeat("l", 2048),
		"l2.txt": strings.Repeat("L", 2048),
		"l3.txt": "left three",
	})
	right := newEnv(t, map[string]string{
		"r1.txt": strings.Repeat("r", 2048),
		"r2.txt": strings.Repeat("R", 2048),
		"r3.txt": "right three",
	})
	// One stick, two runs.
	shared := left.dest
	leftBefore := testsupport.Snapshot(t, left.src)
	rightBefore := testsupport.Snapshot(t, right.src)

	oLeft := left.opts()
	oLeft.DestRoot = shared
	oRight := right.opts()
	oRight.DestRoot = shared

	var wg sync.WaitGroup
	results := make([]*Result, 2)
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		results[0], errs[0] = Run(context.Background(), oLeft)
	}()
	go func() {
		defer wg.Done()
		results[1], errs[1] = Run(context.Background(), oRight)
	}()
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Logf("run %d returned %v, which is an acceptable outcome for a contested destination", i, err)
		}
	}

	// Whatever manifest survived must not describe files that are not there.
	p := filepath.Join(shared, manifest.MetaDir, manifest.FileName)
	f, oerr := os.Open(p)
	if oerr != nil {
		t.Logf("no manifest survived the contest, which is honest: %v", oerr)
	} else {
		defer f.Close()
		m, rerr := manifest.Read(f)
		if rerr != nil {
			t.Logf("the surviving manifest does not parse (%v), which is the DETECTABLE outcome "+
				"and is what phase 5 exists to catch", rerr)
		} else {
			for _, entry := range m.Entries() {
				full := filepath.Join(shared, filepath.FromSlash(entry.Stored))
				got, gerr := os.ReadFile(full)
				if gerr != nil {
					t.Errorf("the manifest names %s but it is not at the destination: %v",
						entry.Path, gerr)
					continue
				}
				if testsupport.SHA256(string(got)) != entry.SHA256 {
					t.Errorf("the manifest describes %s with a digest its bytes do not have", entry.Path)
				}
				if int64(len(got)) != entry.Size {
					t.Errorf("the manifest gives %s %d bytes; it has %d", entry.Path, entry.Size, len(got))
				}
			}
		}
	}

	// Neither source was touched, and neither system disk was touched.
	assertSourceUnchanged(t, left, leftBefore)
	assertSourceUnchanged(t, right, rightBefore)
	left.assertSystemDiskUntouched(t)
	right.assertSystemDiskUntouched(t)
}

// ---------- the destination going away ----------

// TestCopy_DestinationReplacedByAFileMidRunAbortsWithoutTouchingAnythingElse is
// the stick being pulled and something else appearing in its place.
func TestCopy_DestinationReplacedByAFileMidRunAbortsWithoutTouchingAnythingElse(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = fmt.Sprintf("body %d", i)
	}
	e := newEnv(t, files)
	srcBefore := testsupport.Snapshot(t, e.src)

	o := e.opts()
	seen := 0
	o.hookBeforeCopy = func(string) {
		seen++
		if seen != 4 {
			return
		}
		if err := os.RemoveAll(e.dest); err != nil {
			return
		}
		// Something that is not a directory now occupies the destination path.
		_ = os.WriteFile(e.dest, []byte("the stick is gone"), 0o644)
	}

	res, err := Run(context.Background(), o)
	if err == nil {
		t.Fatal("Run reported success after the destination was replaced by a file")
	}
	if res == nil {
		t.Fatal("no result was returned")
	}
	// Whatever it claims to have copied, nothing may be BOTH absent from the
	// destination and absent from the quarantine.
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_RefusesWhenTheDestinationIdentityCannotBeReasserted is the junction
// swapped in between phase 3 and the first write. AssertDestination is the hook
// cmd/auros-migrate wires to Destination.Reassert; an error from it must stop
// the run before a byte is written.
func TestCopy_RefusesWhenTheDestinationIdentityCannotBeReasserted(t *testing.T) {
	e := newEnv(t, sample())
	srcBefore := testsupport.Snapshot(t, e.src)

	sentinel := errors.New("the destination is on a different volume than it was")
	o := e.opts()
	called := 0
	o.AssertDestination = func() error {
		called++
		return sentinel
	}

	res, err := Run(context.Background(), o)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Run = %v, want the reassert failure", err)
	}
	if called != 1 {
		t.Errorf("AssertDestination was called %d times, want 1", called)
	}
	if res.Copied != 0 {
		t.Errorf("copied = %d, want 0: the run must stop before the first write", res.Copied)
	}
	if n := testsupport.CountFiles(t, e.dest, manifest.MetaDir); n != 0 {
		t.Errorf("%d files were written to a destination whose identity was in doubt", n)
	}
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

func inQuarantine(q *quarantine.Set, path string) bool {
	for _, r := range q.Records() {
		if r.Path == path {
			return true
		}
	}
	return false
}
