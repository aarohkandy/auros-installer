package copyengine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
)

// A resumed entry used to be carried forward on size and mtime alone, with its
// recorded digest trusted. That digest describes whatever is at the DESTINATION,
// and phase 5 checks the destination against it, so the whole chain could close
// around bytes that are not the user's files. verify never reads the source by
// design, so nothing downstream could catch it.

func TestResume_RefusesAManifestPlantedByAnotherMachine(t *testing.T) {
	// The attack: plant a manifest and matching files on the backup drive — or
	// just reuse a stick that carries another laptop's run — and ask for
	// --resume. The entries are carried forward with their planted digests.
	e := newEnv(t, sample())

	meta := filepath.Join(e.dest, manifest.MetaDir)
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	planted := manifest.New()
	for rel, content := range sample() {
		full := filepath.Join(e.dest, "Documents", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		// The planted file's contents are NOT the user's file's contents.
		body := "planted:" + content
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(filepath.Join(e.src, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		ent := manifest.Entry{
			Path:            "Documents/" + rel,
			Stored:          "Documents/" + rel,
			Size:            int64(len(body)),
			ModTimeUnixNano: st.ModTime().UnixNano(),
			SHA256:          strings.Repeat("ab", 32),
		}
		if err := planted.Add(ent); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(meta, manifest.FileName), planted.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	// A manifest with no matching identity token: written by someone else.
	o := e.opts()
	o.Resume = true
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Resumed != 0 {
		t.Errorf("resumed %d entries from a manifest this destination has no record of", res.Resumed)
	}
	if res.ResumeRefused == "" {
		t.Error("the run did not say why the resume was refused")
	}
	if res.Copied != 3 {
		t.Errorf("copied %d, want 3: every file should have been copied for real", res.Copied)
	}
	for _, ent := range res.Manifest.Entries() {
		if ent.SHA256 == strings.Repeat("ab", 32) {
			t.Errorf("a planted digest survived into the manifest: %s", ent.Path)
		}
	}
	e.assertSystemDiskUntouched(t)
}

func TestResume_RefusesAManifestWrittenForADifferentVolume(t *testing.T) {
	e := newEnv(t, sample())
	if _, err := Run(context.Background(), e.opts()); err != nil {
		t.Fatal(err)
	}
	// Same files, same manifest, different destination volume: a stick that
	// travelled between two laptops.
	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o := e2.opts()
	o.Resume = true
	o.ResumeIdentity = `\\?\Volume{99999999-9999-9999-9999-999999999999}\`
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resumed != 0 {
		t.Errorf("resumed %d entries bound to another volume", res.Resumed)
	}
	if !strings.Contains(res.ResumeRefused, "different destination volume") {
		t.Errorf("ResumeRefused = %q", res.ResumeRefused)
	}
}

func TestResume_RecopiesWhenTheSourceChangedBehindItsBack(t *testing.T) {
	// No attacker needed: a file rewritten in place with its size and its
	// nanosecond mtime preserved was silently archived as its old version.
	e := newEnv(t, sample())
	first, err := Run(context.Background(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(e.src, "a.txt")
	st, err := os.Stat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("ALPHA"), 0o644); err != nil { // same 5 bytes
		t.Fatal(err)
	}
	if err := os.Chtimes(src, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}

	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o := e2.opts()
	o.Resume = true
	second, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if second.Copied < 1 {
		t.Fatal("the changed file was carried forward instead of being copied again")
	}
	if second.Manifest.Digest() == first.Manifest.Digest() {
		t.Error("the manifest is unchanged although the source changed")
	}
	got, err := os.ReadFile(filepath.Join(e.dest, "Documents", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "ALPHA" {
		t.Errorf("the destination holds %q, not the file the user has now", got)
	}
	e.assertSystemDiskUntouched(t)
}

func TestResume_CarriedForwardEntriesAreLoggedAsSuch(t *testing.T) {
	// A post-mortem has to be able to tell copied files from assumed ones.
	e := newEnv(t, sample())
	if _, err := Run(context.Background(), e.opts()); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	e2 := *e
	e2.q = quarantine.NewSet(nil)
	o := e2.opts()
	o.Resume = true
	o.Log = newTestLogger(&sb)
	res, err := Run(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Resumed != 3 {
		t.Fatalf("resumed = %d, want 3", res.Resumed)
	}
	if !strings.Contains(sb.String(), `"kind":"resumed"`) {
		t.Errorf("resumed files are not distinguishable in the run log:\n%s", sb.String())
	}
}

// ---------- the destination identity is re-checked before the first write ----------

func TestCopy_AssertDestinationRunsBeforeAnythingIsWritten(t *testing.T) {
	// Phase 3's answer has a shelf life: a junction swapped in after the check
	// would redirect every write without changing anything already looked at.
	e := newEnv(t, sample())
	called := false
	o := e.opts()
	o.AssertDestination = func() error {
		called = true
		return errTestIdentity
	}
	res, err := Run(context.Background(), o)
	if err == nil {
		t.Fatal("the run continued after the destination identity check failed")
	}
	if !called {
		t.Fatal("the destination was never re-checked")
	}
	if res.Copied != 0 {
		t.Errorf("copied %d files after the identity check failed", res.Copied)
	}
	if entries, derr := os.ReadDir(filepath.Join(e.dest, "Documents")); derr == nil && len(entries) > 0 {
		t.Errorf("files were written despite the refusal: %v", entries)
	}
	e.assertSystemDiskUntouched(t)
}

var errTestIdentity = &identityError{}

type identityError struct{}

func (*identityError) Error() string { return "the destination is not the volume it was" }

func newTestLogger(sb *strings.Builder) *runlog.Logger {
	return runlog.NewWriter(sb, func() time.Time { return time.Unix(1700000000, 0).UTC() })
}
