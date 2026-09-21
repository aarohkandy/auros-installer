package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/safety"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// This command had no test file at all, which is how volumeFor and
// resolveDestination — the two functions the junction attack went through —
// were shipped untested.

const (
	sysGUID  = `\\?\Volume{11111111-1111-1111-1111-111111111111}\`
	destGUID = `\\?\Volume{22222222-2222-2222-2222-222222222222}\`
)

func machine(t *testing.T) (*safety.Resolver, string, string) {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	sys := filepath.Join(base, "C")
	dest := filepath.Join(base, "D")
	for _, d := range []string{sys, dest} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := winenv.SyntheticConfig{}
	cfg.Vols = []winenv.Volume{
		{GUID: sysGUID, Mount: sys, FreeBytes: 100 << 30, TotalBytes: 200 << 30, IsSystem: true},
		{GUID: destGUID, Mount: dest, FreeBytes: 100 << 30, TotalBytes: 200 << 30},
	}
	env := winenv.NewSynthetic(cfg)
	sysVol, err := env.SystemVolume()
	if err != nil {
		t.Fatal(err)
	}
	return safety.NewResolver(env, sysVol), sys, dest
}

func TestResolveDestination_RefusesAJunctionOntoTheSystemVolume(t *testing.T) {
	// --dest D:\backup, where D:\backup is a junction onto C:\AurosBackup.
	r, sys, dest := machine(t)
	if err := os.MkdirAll(filepath.Join(sys, "AurosBackup"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dest, "backup")
	if err := os.Symlink(filepath.Join(sys, "AurosBackup"), link); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}

	d, err := resolveDestination(r, link, 1<<20)
	if !errors.Is(err, safety.ErrDestinationIsSystemVolume) {
		t.Fatalf("err = %v, want ErrDestinationIsSystemVolume", err)
	}
	if d.Resolved() {
		t.Fatal("a destination on the system volume was accepted")
	}
	// Nothing may have been created through the link either.
	entries, rerr := os.ReadDir(filepath.Join(sys, "AurosBackup"))
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(entries) != 0 {
		t.Errorf("the run created %v on the system volume before refusing", entries)
	}
}

func TestResolveDestination_RefusesWhenEveryDriveIsTheSystemDisk(t *testing.T) {
	// The no-flag path: with no qualifying drive the run stops rather than
	// falling back to the system disk.
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		base = real
	}
	sys := filepath.Join(base, "C")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := winenv.SyntheticConfig{}
	cfg.Vols = []winenv.Volume{{GUID: sysGUID, Mount: sys, FreeBytes: 100 << 30, IsSystem: true}}
	env := winenv.NewSynthetic(cfg)
	sysVol, _ := env.SystemVolume()
	r := safety.NewResolver(env, sysVol)

	if _, err := resolveDestination(r, "", 1<<20); !errors.Is(err, safety.ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
}

func TestResolveDestination_AcceptsARealDirectoryOnTheBackupDrive(t *testing.T) {
	r, _, dest := machine(t)
	d, err := resolveDestination(r, filepath.Join(dest, "auros-backup"), 1<<20)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if d.Volume().GUID != destGUID {
		t.Errorf("volume = %s, want the backup drive", d.Volume().GUID)
	}
	if d.OnSystemVolume() {
		t.Error("a destination on the backup drive measured as being on the system volume")
	}
}

// The automatic choice puts the archive in the folder the Linux restore looks
// in. The expected path is spelled as a LITERAL: sticks already in the field
// carry exactly this name, so a change to it is a change the restore on those
// sticks has to survive, and the person making it should have to edit this line
// and read why. internal/manifest pins the constant; this pins the call site,
// which is where the two halves drifted apart the first time — the migrate
// side passed its own "auros-backup" and the restore never looked inside it.
func TestResolveDestination_TheAutomaticChoiceIsTheFolderTheRestoreLooksIn(t *testing.T) {
	r, _, dest := machine(t)
	d, err := resolveDestination(r, "", 1<<20)
	if err != nil {
		t.Fatalf("resolveDestination: %v", err)
	}
	if got, want := d.Dir(), filepath.Join(dest, "auros-backup"); got != want {
		t.Fatalf("the archive goes to %s; the restore on the new machine looks for %s", got, want)
	}
	if got := filepath.Base(d.Dir()); got != manifest.ArchiveSubdir {
		t.Errorf("the migrate side chose %q and manifest.ArchiveSubdir is %q: the two halves disagree", got, manifest.ArchiveSubdir)
	}
}

// ---------- phase 1: OneDrive Files On-Demand ----------

func TestPlaceholderChoice_RefusesToStartUntilTheUserHasChosen(t *testing.T) {
	// SAFETY.md phase 1: counted, told, and the choice made BEFORE the run
	// starts. The old command never called CloudPlaceholders at all, and sized
	// the space check for a hydration nobody agreed to.
	ph := winenv.PlaceholderStats{Count: 4210, LogicalSize: 180 << 30, OnDiskSize: 12 << 20}
	if _, err := placeholderChoice(ph, ""); err == nil {
		t.Fatal("the run continued with 4210 unresolved cloud placeholders")
	}
	if _, err := placeholderChoice(ph, "maybe"); err == nil {
		t.Fatal("an unrecognised choice was accepted")
	}
	for _, want := range []string{"hydrate", "skip"} {
		got, err := placeholderChoice(ph, want)
		if err != nil || got != want {
			t.Errorf("placeholderChoice(%q) = %q, %v", want, got, err)
		}
	}
}

func TestPlaceholderChoice_NoPlaceholdersNeedsNoChoice(t *testing.T) {
	got, err := placeholderChoice(winenv.PlaceholderStats{}, "")
	if err != nil {
		t.Fatalf("a machine with no placeholders was asked to choose: %v", err)
	}
	if got != "none-found" {
		t.Errorf("choice = %q", got)
	}
}

func TestAdjustForPlaceholders_SkipDoesNotReserveSpaceForFilesItWillNotCopy(t *testing.T) {
	ph := winenv.PlaceholderStats{Count: 10, LogicalSize: 100 << 30, OnDiskSize: 1 << 20}
	if got := adjustForPlaceholders(200<<30, ph, "skip"); got != 100<<30 {
		t.Errorf("skip = %d, want the logical size deducted", got)
	}
	if got := adjustForPlaceholders(200<<30, ph, "hydrate"); got != 200<<30 {
		t.Errorf("hydrate = %d, want the full size", got)
	}
	if got := adjustForPlaceholders(1<<20, ph, "skip"); got != 0 {
		t.Errorf("a deduction below zero produced %d", got)
	}
}

func TestCountPlaceholders_SumsEverySourceRoot(t *testing.T) {
	cfg := winenv.SyntheticConfig{Placeholders: winenv.PlaceholderStats{Count: 3, LogicalSize: 30, OnDiskSize: 3}}
	env := winenv.NewSynthetic(cfg)
	got, err := countPlaceholders(env, []copyengine.Source{{Root: "a"}, {Root: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Count != 6 || got.LogicalSize != 60 {
		t.Errorf("got %+v, want two roots summed", got)
	}
}

func TestUsage_SaysDryRunIsTheDefault(t *testing.T) {
	if !strings.Contains(usage, "DRY RUN IS THE DEFAULT") {
		t.Error("the usage text no longer states that dry run is the default")
	}
}
