package safety

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/testsupport"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// SAFETY.md phase 3, exhaustively.
//
// Every case in this file is a REFUSAL except the handful marked as controls,
// and the controls are not decoration: a refusal test whose setup silently
// stopped reaching the code under test would pass forever. "What would make
// this go red?" has to have an answer, so each family of refusals is paired
// with the nearest-neighbour input that must be ACCEPTED. If the accept case
// starts failing, the refusals below it are no longer proving anything.
//
// Every case asserts two things beyond the error:
//
//	the stand-in system disk is byte-identical afterwards, and
//	the source tree is byte-identical afterwards.
//
// The second one matters on its own. An abort that mangled the original is
// data loss even when the tool reports success.

// altGUID is a third volume identity, for the cases that need one that is
// neither the system disk nor the fixture's backup drive.
const altGUID = `\\?\Volume{33333333-3333-3333-3333-333333333333}\`

// destFixture is a machine with a system disk, a backup drive, and a source
// tree that lives — as it really would — on the system disk.
type destFixture struct {
	base      string
	sysDir    string
	backupDir string
	srcDir    string
	sysVol    winenv.Volume
	backupVol winenv.Volume
	res       *Resolver
	sysBefore testsupport.Fingerprint
	srcBefore testsupport.Fingerprint
}

func newDestFixture(t *testing.T, backupFree uint64) *destFixture {
	t.Helper()
	base := t.TempDir()
	if real, err := filepath.EvalSymlinks(base); err == nil {
		// The resolver deals in RESOLVED paths. macOS puts TempDir under a
		// symlinked /var, so a fixture that skipped this would be testing a
		// mismatch of its own making rather than the code.
		base = real
	}
	f := &destFixture{base: base}
	f.sysDir = filepath.Join(base, "systemdisk")
	f.backupDir = filepath.Join(base, "usb")
	f.srcDir = filepath.Join(f.sysDir, "Users", "pat", "Documents")
	for _, d := range []string{f.sysDir, f.backupDir, f.srcDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	testsupport.Tree(t, f.sysDir, map[string]string{
		"Windows/System32/config/SYSTEM": "registry hive",
		"bootmgr":                        "boot manager",
	})
	testsupport.Tree(t, f.srcDir, map[string]string{
		"thesis.odt":      "the only copy of somebody's work",
		"photos/gran.jpg": "a photograph nobody else has",
	})

	f.sysVol = vol(sysGUID, f.sysDir, 100<<30, true)
	f.backupVol = vol(destGUID, f.backupDir, backupFree, false)
	cfg := winenv.SyntheticConfig{Vols: []winenv.Volume{f.sysVol, f.backupVol}}
	f.res = NewResolver(winenv.NewSynthetic(cfg), f.sysVol)

	f.sysBefore = testsupport.Snapshot(t, f.sysDir)
	f.srcBefore = testsupport.Snapshot(t, f.srcDir)
	return f
}

// assertNothingTouched is the assertion every case in this file ends with.
func (f *destFixture) assertNothingTouched(t *testing.T) {
	t.Helper()
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
	testsupport.AssertUnchanged(t, f.srcDir, f.srcBefore)
}

// ---------- CheckDestination: every alias of the system disk ----------

// TestDestination_RefusesEveryAliasOfTheSystemDisk is the drive-letter table.
//
// SAFETY.md phase 3: "Verified by volume GUID, not by drive letter — a mount
// point or a subst'd letter can alias the system volume." Every row below is a
// way the same physical volume can present itself as something else, plus the
// normalisation cases where an identity check that compared raw strings would
// conclude two spellings of one volume were two volumes.
func TestDestination_RefusesEveryAliasOfTheSystemDisk(t *testing.T) {
	const bigEnough = 900 << 30
	sys := vol(sysGUID, `C:\`, bigEnough, true)

	cases := []struct {
		name    string
		v       winenv.Volume
		dir     string
		system  winenv.Volume
		inv     int64
		wantErr error
	}{
		{
			name:    "same GUID behind another drive letter",
			v:       vol(sysGUID, `D:\`, bigEnough, false),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "same GUID in different capitalisation",
			v:       vol(`\\?\VOLUME{11111111-1111-1111-1111-111111111111}\`, `D:\`, bigEnough, false),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "same GUID without the trailing separator",
			v:       vol(`\\?\Volume{11111111-1111-1111-1111-111111111111}`, `D:\`, bigEnough, false),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "same GUID with a forward-slash separator",
			v:       vol(`\\?\Volume{11111111-1111-1111-1111-111111111111}/`, `D:\`, bigEnough, false),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "same GUID with surrounding whitespace",
			v:       vol("  "+sysGUID+"  ", `D:\`, bigEnough, false),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "different GUID but flagged as the system volume",
			v:       vol(destGUID, `D:\`, bigEnough, true),
			dir:     `D:\auros`,
			system:  sys,
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "different GUID but the path is inside the system mount point",
			v:       vol(destGUID, `C:\mounted-elsewhere`, bigEnough, false),
			dir:     `C:\mounted-elsewhere\auros`,
			system:  vol(sysGUID, `C:\`, bigEnough, true),
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "different GUID but the path IS the system mount point",
			v:       vol(destGUID, `C:\`, bigEnough, false),
			dir:     `C:\`,
			system:  vol(sysGUID, `C:\`, bigEnough, true),
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name:    "destination volume has no identity at all",
			v:       vol("", `E:\`, bigEnough, false),
			dir:     `E:\auros`,
			system:  sys,
			wantErr: ErrDestinationUnidentified,
		},
		{
			name:    "destination identity is only whitespace",
			v:       vol("   ", `E:\`, bigEnough, false),
			dir:     `E:\auros`,
			system:  sys,
			wantErr: ErrDestinationUnidentified,
		},
		{
			name:    "the SYSTEM volume has no identity, so nothing can be ruled out",
			v:       vol(destGUID, `E:\`, bigEnough, false),
			dir:     `E:\auros`,
			system:  vol("", `C:\`, bigEnough, true),
			wantErr: ErrDestinationUnidentified,
		},
		{
			// CONTROL. A path that merely shares a prefix with the system
			// mount, segment-wise, is a different place. If this row starts
			// refusing, the two rows above it stopped meaning anything.
			name:    "control: a sibling path with a shared prefix is not inside the system mount",
			v:       vol(destGUID, `C:\Users2`, bigEnough, false),
			dir:     `C:\Users2\auros`,
			system:  vol(sysGUID, `C:\Users`, bigEnough, true),
			wantErr: nil,
		},
		{
			// CONTROL. The ordinary case: a genuinely different volume.
			name:    "control: a different volume with room is accepted",
			v:       vol(destGUID, `E:\`, bigEnough, false),
			dir:     `E:\auros`,
			system:  sys,
			wantErr: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckDestination(tc.v, tc.dir, tc.system, tc.inv)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckDestination = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CheckDestination = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestDestination_RefusesWhenShortByOneByte is the boundary, from both sides.
//
// A size check with an off-by-one is a size check that passes a destination one
// byte too small, and the file that does not fit is the last one — which is the
// one the user is most likely to have been working on.
func TestDestination_RefusesWhenShortByOneByte(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 900<<30, true)
	inventories := []int64{0, 1, 4096, 1 << 20, 1 << 30, 7 << 30}

	for _, inv := range inventories {
		need := RequiredBytes(inv)
		t.Run(fmt.Sprintf("inventory %d short by one byte", inv), func(t *testing.T) {
			v := vol(destGUID, `E:\`, uint64(need)-1, false)
			if err := CheckDestination(v, `E:\auros`, sys, inv); !errors.Is(err, ErrDestinationTooSmall) {
				t.Fatalf("inventory %d, free %d: err = %v, want ErrDestinationTooSmall", inv, need-1, err)
			}
		})
		t.Run(fmt.Sprintf("control: inventory %d with exactly enough room", inv), func(t *testing.T) {
			v := vol(destGUID, `E:\`, uint64(need), false)
			if err := CheckDestination(v, `E:\auros`, sys, inv); err != nil {
				t.Fatalf("inventory %d, free %d: err = %v, want nil "+
					"(if this fails the short-by-one case above proves nothing)", inv, need, err)
			}
		})
	}

	// The headroom is not decoration: a destination with room for exactly the
	// bytes and nothing else must be refused, because the manifest, the run log
	// and the quarantine report all have to fit afterwards. A copy that cannot
	// be described cannot be verified.
	inv := int64(10) << 30
	exact := vol(destGUID, `E:\`, uint64(inv), false)
	if err := CheckDestination(exact, `E:\auros`, sys, inv); !errors.Is(err, ErrDestinationTooSmall) {
		t.Fatalf("a destination with room for the bytes but not the manifest was accepted: %v", err)
	}
}

func TestRequiredBytes_RefusesToWrapAround(t *testing.T) {
	// A negative or absurd inventory size must not wrap into a small
	// requirement that then passes every check.
	if got := RequiredBytes(-1); got != MetadataReserveBytes {
		t.Errorf("RequiredBytes(-1) = %d, want %d", got, MetadataReserveBytes)
	}
	for _, n := range []int64{1 << 40, 1 << 55, 1 << 62, 1<<63 - 1} {
		if got := RequiredBytes(n); got <= 0 {
			t.Errorf("RequiredBytes(%d) = %d: a wrapped requirement passes every check", n, got)
		}
	}
}

// ---------- Resolver.Resolve: links, junctions, and paths that lie ----------

// TestDestination_ResolveRefusesPathsThatLie is the junction table.
//
// SAFETY.md phase 3: "D:\backup can be an NTFS junction onto C:\AurosBackup:
// the letter says D:, the bytes land on C:." Go's EvalSymlinks resolves NTFS
// junctions and directory symlinks alike, and on the synthetic environment CI
// runs, a POSIX symlink stands in for both. The property under test is the
// same one either way: the volume is derived from the RESOLVED path, never from
// the string the user typed.
func TestDestination_ResolveRefusesPathsThatLie(t *testing.T) {
	cases := []struct {
		name string
		// setup returns the path to hand to Resolve.
		setup   func(t *testing.T, f *destFixture) string
		inv     int64
		wantErr error
		// check runs only on the accept cases.
		check func(t *testing.T, f *destFixture, d Destination)
	}{
		{
			name: "a plain directory on the backup drive",
			setup: func(t *testing.T, f *destFixture) string {
				return filepath.Join(f.backupDir, "auros-backup")
			},
			check: func(t *testing.T, f *destFixture, d Destination) {
				if d.Volume().GUID != destGUID {
					t.Errorf("volume = %q, want the backup drive", d.Volume().GUID)
				}
				if !d.Resolved() {
					t.Error("the destination carries no proof")
				}
			},
		},
		{
			name: "a directory that is plainly on the system disk",
			setup: func(t *testing.T, f *destFixture) string {
				return filepath.Join(f.sysDir, "AurosBackup")
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "the system mount point itself",
			setup: func(t *testing.T, f *destFixture) string {
				return f.sysDir
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "the user's own documents folder",
			setup: func(t *testing.T, f *destFixture) string {
				return f.srcDir
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "a junction on the backup drive pointing at the system disk",
			setup: func(t *testing.T, f *destFixture) string {
				target := filepath.Join(f.sysDir, "AurosBackup")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				// The fixture put that directory there, not the code under
				// test; re-baseline so the final assertion still means
				// "Resolve changed nothing".
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				link := filepath.Join(f.backupDir, "looks-like-a-usb-stick")
				mustSymlink(t, target, link)
				return link
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "a junction three directories up from the destination",
			setup: func(t *testing.T, f *destFixture) string {
				target := filepath.Join(f.sysDir, "AurosBackup")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				link := filepath.Join(f.backupDir, "alias")
				mustSymlink(t, target, link)
				// Nothing below the link exists yet: the ancestor walk has to
				// find it before MkdirAll creates anything THROUGH it.
				return filepath.Join(link, "a", "b", "c")
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "a junction onto the user's documents folder",
			setup: func(t *testing.T, f *destFixture) string {
				link := filepath.Join(f.backupDir, "docs-alias")
				mustSymlink(t, f.srcDir, link)
				return link
			},
			wantErr: ErrDestinationIsSystemVolume,
		},
		{
			name: "a dangling link",
			setup: func(t *testing.T, f *destFixture) string {
				link := filepath.Join(f.backupDir, "dangling")
				mustSymlink(t, filepath.Join(f.base, "nothing-is-here"), link)
				return link
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			name: "a link that points at itself",
			setup: func(t *testing.T, f *destFixture) string {
				link := filepath.Join(f.backupDir, "ouroboros")
				mustSymlink(t, link, link)
				return link
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			name: "a two-step link cycle",
			setup: func(t *testing.T, f *destFixture) string {
				a := filepath.Join(f.backupDir, "a-link")
				b := filepath.Join(f.backupDir, "b-link")
				mustSymlink(t, b, a)
				mustSymlink(t, a, b)
				return a
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			name: "an existing regular file where a directory should be",
			setup: func(t *testing.T, f *destFixture) string {
				p := filepath.Join(f.backupDir, "not-a-directory")
				if err := os.WriteFile(p, []byte("a file"), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			name: "a directory underneath a regular file",
			setup: func(t *testing.T, f *destFixture) string {
				p := filepath.Join(f.backupDir, "blocker")
				if err := os.WriteFile(p, []byte("a file"), 0o644); err != nil {
					t.Fatal(err)
				}
				return filepath.Join(p, "child")
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			// CONTROL, and the important one. A link is not automatically
			// sinister. A link to somewhere legitimate is accepted — and the
			// path carried forward is the RESOLVED one, because every writer
			// downstream must use a path that has been proven to mean what it
			// says.
			name: "control: a link to a legitimate directory is accepted, resolved",
			setup: func(t *testing.T, f *destFixture) string {
				target := filepath.Join(f.backupDir, "real-backup-dir")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(f.backupDir, "friendly-alias")
				mustSymlink(t, target, link)
				return link
			},
			check: func(t *testing.T, f *destFixture, d Destination) {
				want := filepath.Join(f.backupDir, "real-backup-dir")
				if d.Dir() != want {
					t.Errorf("Dir() = %q, want the resolved path %q: "+
						"every writer downstream uses this string", d.Dir(), want)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDestFixture(t, 900<<30)
			dir := tc.setup(t, f)
			d, err := f.res.Resolve(dir, tc.inv)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Resolve(%s) = %v, want nil", dir, err)
				}
				if tc.check != nil {
					tc.check(t, f, d)
				}
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Resolve(%s) = %v, want %v", dir, err, tc.wantErr)
				}
				if d.Resolved() {
					t.Fatal("a refused Resolve still handed back a proof")
				}
			}
			f.assertNothingTouched(t)
		})
	}
}

func TestDestination_ResolveRefusesWhenTheDriveIsTooSmall(t *testing.T) {
	inv := int64(4) << 30
	need := RequiredBytes(inv)

	t.Run("short by one byte", func(t *testing.T) {
		f := newDestFixture(t, uint64(need)-1)
		_, err := f.res.Resolve(filepath.Join(f.backupDir, "auros"), inv)
		if !errors.Is(err, ErrDestinationTooSmall) {
			t.Fatalf("err = %v, want ErrDestinationTooSmall", err)
		}
		// The refusal must happen BEFORE anything is created. A tool that
		// makes the directory and then says no has written to a drive it has
		// just declared unusable.
		if _, serr := os.Stat(filepath.Join(f.backupDir, "auros")); !os.IsNotExist(serr) {
			t.Error("the destination directory was created before the size check refused")
		}
		f.assertNothingTouched(t)
	})

	t.Run("control: exactly enough is accepted", func(t *testing.T) {
		f := newDestFixture(t, uint64(need))
		if _, err := f.res.Resolve(filepath.Join(f.backupDir, "auros"), inv); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
		f.assertNothingTouched(t)
	})
}

func TestDestination_ResolveRefusesWithoutAnEnvironment(t *testing.T) {
	// A Resolver with no environment cannot ask which volume holds anything,
	// so it cannot prove a destination is not the system disk.
	var r *Resolver
	if _, err := r.Resolve("anywhere", 0); !errors.Is(err, ErrDestinationNotResolved) {
		t.Errorf("nil resolver: err = %v, want ErrDestinationNotResolved", err)
	}
	empty := &Resolver{}
	if _, err := empty.Resolve("anywhere", 0); !errors.Is(err, ErrDestinationNotResolved) {
		t.Errorf("empty resolver: err = %v, want ErrDestinationNotResolved", err)
	}
	if _, _, err := empty.Choose("auros", 0); !errors.Is(err, ErrDestinationNotResolved) {
		t.Errorf("empty resolver Choose: err = %v, want ErrDestinationNotResolved", err)
	}
}

// ---------- the zero-value Destination ----------

// TestDestination_ZeroValueProvesNothing is the Destination half of the same
// argument verified.go makes about VerifiedArchive. A value a caller declared
// rather than obtained carries no proof, and every method that could be read as
// a safety claim has to answer accordingly.
func TestDestination_ZeroValueProvesNothing(t *testing.T) {
	var d Destination
	if d.Resolved() {
		t.Error("the zero Destination claims to be resolved")
	}
	if !d.OnSystemVolume() {
		t.Error("the zero Destination claims not to be on the system volume: " +
			"unknown must never read as no")
	}
	if err := d.Reassert(); !errors.Is(err, ErrDestinationNotResolved) {
		t.Errorf("Reassert = %v, want ErrDestinationNotResolved", err)
	}
	if d.Dir() != "" {
		t.Errorf("Dir() = %q, want empty", d.Dir())
	}
	o := d.RunlogOptions()
	if !o.DestIsSystemVolume {
		t.Error("the run log would open on a destination that proved nothing")
	}
}

// ---------- Reassert: the junction swapped in mid-run ----------

// TestDestination_ReassertCatchesAnIdentitySwappedInMidRun covers the TOCTOU
// window. Phase 3's answer has a shelf life: a junction swapped in after the
// destination was chosen redirects every subsequent write without changing
// anything the program has already looked at. The copy engine calls Reassert
// before its first write and safety.Verify calls it before minting the proof,
// so the window is closed at both ends — and these are the cases that must
// close it.
func TestDestination_ReassertCatchesAnIdentitySwappedInMidRun(t *testing.T) {
	cases := []struct {
		name string
		// mutate happens after the destination has been resolved.
		mutate  func(t *testing.T, f *destFixture, dir string)
		wantErr error
		// onSystemAfter is what OnSystemVolume must answer afterwards. It is
		// stated per case rather than assumed: an identity that cannot be
		// established must answer TRUE (unknown is not "no"), but a junction
		// that moved the destination elsewhere on the SAME drive genuinely has
		// not landed on the system disk, and a test that demanded "true" there
		// would be demanding a wrong answer.
		onSystemAfter bool
	}{
		{
			name:   "control: nothing changed",
			mutate: func(t *testing.T, f *destFixture, dir string) {},
		},
		{
			name: "the destination directory was deleted",
			mutate: func(t *testing.T, f *destFixture, dir string) {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
			},
			wantErr:       ErrDestinationUnresolvable,
			onSystemAfter: true,
		},
		{
			name: "the destination was replaced by a file",
			mutate: func(t *testing.T, f *destFixture, dir string) {
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(dir, []byte("not a directory any more"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantErr:       ErrDestinationUnresolvable,
			onSystemAfter: true,
		},
		{
			name: "the destination was replaced by a junction onto the system disk",
			mutate: func(t *testing.T, f *destFixture, dir string) {
				target := filepath.Join(f.sysDir, "AurosBackup")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, target, dir)
			},
			wantErr:       ErrDestinationMoved,
			onSystemAfter: true,
		},
		{
			name: "the destination was replaced by a junction elsewhere on the same drive",
			mutate: func(t *testing.T, f *destFixture, dir string) {
				// Same VOLUME, different PLACE. The volume check alone would
				// wave this through, and the bytes would land somewhere the
				// user never chose.
				target := filepath.Join(f.backupDir, "somewhere-else")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, target, dir)
			},
			wantErr:       ErrDestinationMoved,
			onSystemAfter: false,
		},
		{
			name: "a parent directory became a junction onto the system disk",
			mutate: func(t *testing.T, f *destFixture, dir string) {
				parent := filepath.Dir(dir)
				target := filepath.Join(f.sysDir, "AurosBackup")
				if err := os.MkdirAll(filepath.Join(target, filepath.Base(dir)), 0o755); err != nil {
					t.Fatal(err)
				}
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				if err := os.RemoveAll(parent); err != nil {
					t.Fatal(err)
				}
				mustSymlink(t, target, parent)
			},
			wantErr:       ErrDestinationMoved,
			onSystemAfter: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDestFixture(t, 900<<30)
			// Resolve something two levels down so a parent can be swapped.
			want := filepath.Join(f.backupDir, "auros", "archive")
			d, err := f.res.Resolve(want, 0)
			if err != nil {
				t.Fatalf("setting up the destination: %v", err)
			}
			if err := d.Reassert(); err != nil {
				t.Fatalf("Reassert failed before the mutation: %v", err)
			}
			tc.mutate(t, f, d.Dir())

			err = d.Reassert()
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Reassert = %v, want nil", err)
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Reassert = %v, want %v", err, tc.wantErr)
			}
			// OnSystemVolume is a MEASUREMENT taken on demand, not a cached
			// answer from phase 3. Where the identity can no longer be
			// established it must say true, because unknown is not "no".
			if got := d.OnSystemVolume(); got != tc.onSystemAfter {
				t.Errorf("OnSystemVolume() = %v, want %v", got, tc.onSystemAfter)
			}
			f.assertNothingTouched(t)
		})
	}
}

// ---------- Choose: no qualifying destination ----------

// TestDestination_ChooseRefusesRatherThanImprovising is SAFETY.md phase 3's
// last paragraph: "If no qualifying destination exists, we refuse to continue.
// We do not offer a smaller subset, we do not offer to skip verification, and
// we do not offer to use the system disk."
func TestDestination_ChooseRefusesRatherThanImprovising(t *testing.T) {
	inv := int64(10) << 30

	t.Run("the only drive with room is the system disk", func(t *testing.T) {
		f := newDestFixture(t, 1<<20) // the backup stick is far too small
		_, rejected, err := f.res.Choose("auros-backup", inv)
		if !errors.Is(err, ErrNoDestination) {
			t.Fatalf("err = %v, want ErrNoDestination", err)
		}
		if len(rejected) == 0 {
			t.Error("the user was given no reason for any drive")
		}
		// Every drive the user can see must be named with its real reason.
		if s := DescribeRejections(rejected); s == "" {
			t.Error("no explanation was produced")
		}
		sawSystem := false
		for _, r := range rejected {
			if errors.Is(r.Err, ErrDestinationIsSystemVolume) {
				sawSystem = true
			}
		}
		if !sawSystem {
			t.Errorf("the system disk was not rejected as the system disk: %+v", rejected)
		}
		f.assertNothingTouched(t)
	})

	t.Run("there are no volumes at all", func(t *testing.T) {
		f := newDestFixture(t, 900<<30)
		bare := NewResolver(winenv.NewSynthetic(winenv.SyntheticConfig{}), f.sysVol)
		if _, _, err := bare.Choose("auros-backup", inv); !errors.Is(err, ErrNoDestination) {
			t.Fatalf("err = %v, want ErrNoDestination", err)
		}
		f.assertNothingTouched(t)
	})

	t.Run("control: one drive qualifies and is chosen", func(t *testing.T) {
		f := newDestFixture(t, uint64(RequiredBytes(inv)))
		d, _, err := f.res.Choose("auros-backup", inv)
		if err != nil {
			t.Fatalf("err = %v, want nil (if this fails the refusals above prove nothing)", err)
		}
		if d.Volume().GUID != destGUID {
			t.Errorf("chose %q, want the backup drive", d.Volume().GUID)
		}
		f.assertNothingTouched(t)
	})
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this environment cannot create symlinks, so the junction cases "+
			"cannot run here: %v", err)
	}
}
