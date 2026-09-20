//go:build !windows

package copyengine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// fullVolume is a writer that accepts a fixed number of bytes and then reports
// ENOSPC, which is exactly what a USB stick does when it runs out partway
// through a file.
type fullVolume struct {
	w      io.Writer
	budget *int64 // shared across every file, as a real volume's free space is
}

func (f *fullVolume) Write(p []byte) (int, error) {
	if *f.budget <= 0 {
		return 0, &os.PathError{Op: "write", Path: "destination", Err: syscall.ENOSPC}
	}
	n := int64(len(p))
	short := false
	if n > *f.budget {
		n = *f.budget
		short = true
	}
	written, err := f.w.Write(p[:n])
	*f.budget -= int64(written)
	if err != nil {
		return written, err
	}
	if short {
		return written, &os.PathError{Op: "write", Path: "destination", Err: syscall.ENOSPC}
	}
	return written, nil
}

func TestCopy_DestinationFillsUpMidCopy(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 10; i++ {
		files[string(rune('a'+i))+".txt"] = strings.Repeat("x", 1000)
	}
	e := newEnv(t, files)

	o := e.opts()
	o.BufSize = 256
	// One shared budget, so the volume genuinely runs out part-way through the
	// fourth file rather than at a convenient file boundary.
	budget := int64(3500)
	o.hookDst = func(path string, w io.Writer) io.Writer {
		return &fullVolume{w: w, budget: &budget}
	}

	res, err := Run(context.Background(), o)
	if err == nil {
		t.Fatal("Run succeeded on a full destination")
	}
	if !res.DestinationFull {
		t.Fatalf("the result does not report a full destination: %v\n%s", err, res.Describe())
	}
	if res.Copied == 0 {
		t.Error("nothing was copied before the volume filled: the test is not exercising the mid-copy case")
	}
	if res.Copied == res.Planned {
		t.Error("everything was copied: the volume never filled")
	}

	// Nothing partially written is left behind...
	assertNoPartials(t, e.dest)

	// ...every file that did not make it is quarantined, not silently absent...
	accounted := res.Copied + res.Resumed + e.q.Unresolved()
	if accounted < res.Planned {
		t.Errorf("%d files planned but only %d accounted for (copied %d, quarantined %d)",
			res.Planned, accounted, res.Copied, e.q.Unresolved())
	}
	if !hasAnyReason(e.q, quarantine.ReasonDestinationFull) {
		t.Errorf("nothing was quarantined as destination-full: %+v", e.q.Records())
	}

	// ...the manifest describes exactly what is complete...
	onDisk := testsupport.CountFiles(t, e.dest, manifest.MetaDir)
	if res.Manifest.Len() != onDisk {
		t.Errorf("manifest lists %d files, destination holds %d", res.Manifest.Len(), onDisk)
	}
	for _, entry := range res.Manifest.Entries() {
		got := testsupport.MustRead(t, filepath.Join(e.dest, filepath.FromSlash(entry.Stored)))
		if int64(len(got)) != entry.Size {
			t.Errorf("%s: %d bytes on disk, manifest says %d", entry.Path, len(got), entry.Size)
		}
		if testsupport.SHA256(got) != entry.SHA256 {
			t.Errorf("%s: a truncated file was recorded as complete", entry.Path)
		}
	}

	// ...and, most importantly:
	e.assertSystemDiskUntouched(t)
}

func TestCopy_DiskFullIsNotRetried(t *testing.T) {
	// Retrying onto a volume that is still full cannot succeed and costs the
	// user battery they may not have.
	e := newEnv(t, map[string]string{"a.txt": strings.Repeat("x", 500)})
	o := e.opts()
	attempts := 0
	o.hookBeforeCopy = func(string) { attempts++ }
	none := int64(0)
	o.hookDst = func(path string, w io.Writer) io.Writer {
		return &fullVolume{w: w, budget: &none}
	}
	if _, err := Run(context.Background(), o); err == nil {
		t.Fatal("Run succeeded with no room at all")
	}
	if attempts != 1 {
		t.Errorf("attempted %d times, want 1: a full disk is not a transient failure", attempts)
	}
	e.assertSystemDiskUntouched(t)
}

func TestIsNoSpace(t *testing.T) {
	if !isNoSpace(&os.PathError{Op: "write", Path: "x", Err: syscall.ENOSPC}) {
		t.Error("ENOSPC was not recognised as a full volume")
	}
	if isNoSpace(&os.PathError{Op: "write", Path: "x", Err: syscall.EACCES}) {
		t.Error("EACCES was misread as a full volume")
	}
}

func hasAnyReason(q *quarantine.Set, want quarantine.Reason) bool {
	for _, r := range q.Records() {
		if r.Reason == want {
			return true
		}
	}
	return false
}
