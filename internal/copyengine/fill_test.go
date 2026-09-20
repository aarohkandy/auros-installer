//go:build !windows

package copyengine

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// The destination filling up, at every point in the run.
//
// A USB stick that runs out at 1% is a mistake the user can recover from in
// thirty seconds. One that runs out at 99% is the dangerous one: almost
// everything is there, the tool is nearly finished, and the temptation to
// treat "nearly" as "done" is at its highest. SAFETY.md phase 5 does not care
// how close it got — the unresolved count has to be zero.
//
// What must be true at every percentage:
//
//	the run does not report success,
//	no partially written file is left behind,
//	the manifest describes exactly the files that are really complete,
//	every file that did not make it is NAMED, and
//	the system disk and the source are byte-identical.

func TestCopy_DestinationFillsUpAtEveryPointInTheRun(t *testing.T) {
	const files = 20
	const each = 1000
	const totalBytes = files * each

	for _, pct := range []int{0, 1, 25, 50, 75, 99} {
		t.Run(fmt.Sprintf("%d percent of the way through", pct), func(t *testing.T) {
			tree := map[string]string{}
			for i := 0; i < files; i++ {
				tree[fmt.Sprintf("d%d/f%02d.bin", i%4, i)] = repeat(byte('a'+i%26), each)
			}
			e := newEnv(t, tree)
			srcBefore := testsupport.Snapshot(t, e.src)

			o := e.opts()
			o.BufSize = 128
			budget := int64(totalBytes) * int64(pct) / 100
			o.hookDst = func(path string, w io.Writer) io.Writer {
				return &fullVolume{w: w, budget: &budget}
			}

			res, err := Run(context.Background(), o)
			if err == nil {
				t.Fatal("Run reported success on a destination that ran out of room")
			}
			if !res.DestinationFull {
				t.Fatalf("the result does not report a full destination: %v\n%s", err, res.Describe())
			}
			if res.Planned != files {
				t.Fatalf("planned = %d, want %d", res.Planned, files)
			}
			if res.Copied >= res.Planned {
				t.Fatalf("copied %d of %d: the volume never actually filled, so this case is "+
					"not testing anything", res.Copied, res.Planned)
			}
			if pct >= 25 && res.Copied == 0 {
				t.Errorf("copied = 0 with %d%% of the space available: the fill is landing "+
					"before the first file rather than part-way through the run", pct)
			}

			assertNoPartials(t, e.dest)
			assertEveryFileAccountedFor(t, e, res, "Documents")
			if !hasAnyReason(e.q, quarantine.ReasonDestinationFull) {
				t.Errorf("nothing was quarantined as destination-full: %+v", e.q.Records())
			}

			// The manifest must describe exactly what is complete — no more,
			// and nothing truncated recorded as whole.
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
					t.Errorf("%s: a truncated file was recorded as complete, which is how a "+
						"partial copy passes verification", entry.Path)
				}
			}

			// And the accounting adds up, file for file.
			accounted := res.Copied + res.Resumed + e.q.Unresolved()
			if accounted != res.Planned {
				t.Errorf("%d files planned, %d accounted for (copied %d, resumed %d, quarantined %d)",
					res.Planned, accounted, res.Copied, res.Resumed, e.q.Unresolved())
			}

			assertSourceUnchanged(t, e, srcBefore)
			e.assertSystemDiskUntouched(t)
		})
	}
}

// TestCopy_AFullDestinationStopsTheRunRatherThanShrinkingTheJob is the rule
// SAFETY.md phase 3 states for the destination CHOICE, held to at copy time as
// well: "We do not offer a smaller subset." A run that filled up must not come
// back looking like a success with fewer files in it.
func TestCopy_AFullDestinationStopsTheRunRatherThanShrinkingTheJob(t *testing.T) {
	tree := map[string]string{}
	for i := 0; i < 6; i++ {
		tree[fmt.Sprintf("f%d.bin", i)] = repeat('z', 500)
	}
	e := newEnv(t, tree)
	srcBefore := testsupport.Snapshot(t, e.src)

	o := e.opts()
	o.BufSize = 100
	budget := int64(1200) // two files and a bit
	o.hookDst = func(path string, w io.Writer) io.Writer {
		return &fullVolume{w: w, budget: &budget}
	}

	res, err := Run(context.Background(), o)
	if err == nil {
		t.Fatal("Run succeeded on a full destination")
	}
	if e.q.Unresolved() == 0 {
		t.Fatal("the files that did not fit are not blocking the wall")
	}
	// The user-facing description must say what did NOT happen, not only what
	// did. A report that reads like a success is how a partial copy becomes a
	// wipe.
	desc := res.Describe()
	for _, want := range []string{"THE DESTINATION FILLED UP", "not copied"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the description does not mention %q:\n%s", want, desc)
		}
	}
	assertNoPartials(t, e.dest)
	assertEveryFileAccountedFor(t, e, res, "Documents")
	assertSourceUnchanged(t, e, srcBefore)
	e.assertSystemDiskUntouched(t)
}

// repeat builds n bytes of one value. strings.Repeat would do, but a distinct
// byte per file makes a mixed-up destination obvious in a failure message.
func repeat(b byte, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return string(out)
}
