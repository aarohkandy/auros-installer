//go:build !windows

package copyengine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// Files that will not open, and a destination that will not accept writes.
//
// SAFETY.md phase 4: "Locked and in-use files are normal on a live machine …
// if a VSS snapshot cannot be taken, that file is quarantined and reported,
// never silently skipped." On the synthetic environment CI runs, a file with
// no permissions stands in for a file Outlook has open — the code path is the
// same one: the open fails, and the question is whether the tool says so.

func TestCopy_ALockedFileIsQuarantinedAndTheRestOfTheRunFinishes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permissions are not enforced, so nothing here would be locked")
	}
	e := newEnv(t, map[string]string{
		"readable-one.txt":   "fine",
		"outlook.pst":        "somebody's entire mail archive",
		"readable-two.txt":   "also fine",
		"sub/readable-3.txt": "still fine",
	})
	locked := filepath.Join(e.src, "outlook.pst")
	// The source fingerprint is taken BEFORE the file is locked. Snapshot hashes
	// the contents of every file, so taken afterwards it failed with "permission
	// denied" on the one file this test exists to lock — before Run was ever
	// called. That went unseen because a root container skips this test above;
	// a non-root CI runner is the first place it ever executed.
	srcBefore := testsupport.Snapshot(t, e.src)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot remove permissions here: %v", err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o644) })
	if f, oerr := os.Open(locked); oerr == nil {
		f.Close()
		t.Skip("this filesystem ignores permissions; the file is not actually locked")
	}

	res, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatalf("Run: %v — one unreadable file must not abort a forty-minute copy", err)
	}
	if res.Copied != 3 {
		t.Errorf("copied = %d, want 3 (everything except the locked file)", res.Copied)
	}
	if _, ok := res.Manifest.Lookup("Documents/outlook.pst"); ok {
		t.Error("a file that could not be read is in the manifest")
	}
	if !hasReason(e.q, "Documents/outlook.pst", quarantine.ReasonLocked) {
		t.Errorf("the locked file was not quarantined as locked: %+v", e.q.Records())
	}
	if rec := find(e.q, "Documents/outlook.pst"); rec.Attempts < 2 {
		t.Errorf("attempts = %d, want at least 2: the retry rule is one retry, then quarantine",
			rec.Attempts)
	}
	// And the run cannot reach the wall while it is unresolved.
	if e.q.Unresolved() != 1 {
		t.Errorf("unresolved = %d, want 1", e.q.Unresolved())
	}
	// The report the user reads has to name the file, not count it.
	var report bytes.Buffer
	if werr := e.q.WriteReport(&report); werr != nil {
		t.Fatal(werr)
	}
	for _, want := range []string{"outlook.pst", string(quarantine.ReasonLocked)} {
		if !strings.Contains(report.String(), want) {
			t.Errorf("the quarantine report does not mention %q:\n%s", want, report.String())
		}
	}

	assertNoPartials(t, e.dest)
	assertEveryFileAccountedFor(t, e, res, "Documents")
	// Unlock before comparing, so the comparison can READ the locked file. The
	// fingerprint records content, not mode, so this hides nothing the tool did;
	// what it adds is proof that the one file the tool failed to open — the
	// mail archive — is byte-for-byte what it was.
	if err := os.Chmod(locked, 0o644); err != nil {
		t.Fatalf("restoring permissions to compare the source: %v", err)
	}
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// TestCopy_ADestinationThatGoesReadOnlyMidRunLosesNothingSilently is the stick
// remounting read-only part-way through, which is what a failing USB controller
// on a ten-year-old laptop actually does.
func TestCopy_ADestinationThatGoesReadOnlyMidRunLosesNothingSilently(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permissions are not enforced")
	}
	files := map[string]string{}
	for i := 0; i < 10; i++ {
		files[fmt.Sprintf("f%02d.txt", i)] = fmt.Sprintf("body %d", i)
	}
	e := newEnv(t, files)
	srcBefore := testsupport.Snapshot(t, e.src)

	target := filepath.Join(e.dest, "Documents")
	o := e.opts()
	seen := 0
	o.hookBeforeCopy = func(string) {
		seen++
		if seen == 4 {
			_ = os.Chmod(target, 0o555)
		}
	}
	t.Cleanup(func() { os.Chmod(target, 0o755) })

	res, err := Run(context.Background(), o)
	// Either outcome is acceptable — what is not acceptable is a file going
	// missing from both the manifest and the quarantine.
	if err != nil {
		t.Logf("Run returned %v, which is an honest answer for a read-only destination", err)
	}
	if res.Copied == 0 {
		t.Skip("the permission change landed before anything was copied; nothing to check")
	}
	if res.Copied == res.Planned {
		t.Skip("this filesystem ignores directory permissions; the destination never went read-only")
	}

	assertNoPartials(t, e.dest)
	assertEveryFileAccountedFor(t, e, res, "Documents")
	if e.q.Unresolved() == 0 {
		t.Error("the files that could not be written are not blocking the wall")
	}
	// Nothing recorded as copied may be missing or wrong.
	if cerr := os.Chmod(target, 0o755); cerr != nil {
		t.Fatal(cerr)
	}
	for _, entry := range res.Manifest.Entries() {
		got, rerr := os.ReadFile(filepath.Join(e.dest, filepath.FromSlash(entry.Stored)))
		if rerr != nil {
			t.Errorf("%s is in the manifest but not at the destination: %v", entry.Path, rerr)
			continue
		}
		if testsupport.SHA256(string(got)) != entry.SHA256 {
			t.Errorf("%s was recorded as complete but does not match", entry.Path)
		}
	}
	if onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir); onDisk != res.Manifest.Len() {
		t.Errorf("destination holds %d files, manifest lists %d", onDisk, res.Manifest.Len())
	}

	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}
