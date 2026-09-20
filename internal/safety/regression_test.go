package safety

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/testsupport"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// Every test in this file is a specific attack that once worked. They are here
// so that the attack has to be re-invented rather than merely re-introduced.

// ---------- FATAL: a destination that is a link onto the system volume ----------

// linkFixture builds a machine with a system volume and a backup volume, both
// mounted at real directories, and returns a resolver over it.
func linkFixture(t *testing.T) (*Resolver, string, string) {
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
	sysVol := vol(sysGUID, sys, 100<<30, true)
	return NewResolver(syntheticEnvFor(sys, dest), sysVol), sys, dest
}

func TestResolver_RefusesADestinationThatIsALinkOntoTheSystemVolume(t *testing.T) {
	// The attack: --dest D:\backup, where D:\backup is an NTFS junction onto
	// C:\AurosBackup. The old code lowercased the string, matched the prefix
	// "D:\", and reported the backup drive's GUID while every byte landed on C:.
	r, sys, dest := linkFixture(t)
	target := filepath.Join(sys, "AurosBackup")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dest, "backup")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}
	before := testsupport.Snapshot(t, sys)

	d, err := r.Resolve(link, 1<<20)
	if !errors.Is(err, ErrDestinationIsSystemVolume) {
		t.Fatalf("Resolve through a junction onto the system volume: err = %v, want ErrDestinationIsSystemVolume", err)
	}
	if d.Resolved() {
		t.Fatal("a Destination was issued for a path on the system volume")
	}
	testsupport.AssertUnchanged(t, sys, before)
}

func TestResolver_RefusesADestinationReachedThroughALinkedParent(t *testing.T) {
	// The nastier variant: the LEAF is an ordinary directory, reached through a
	// junctioned parent. Verification then succeeds — against the system disk —
	// and a VerifiedArchive is minted whose destVolumeGUID is a lie.
	r, sys, dest := linkFixture(t)
	real := filepath.Join(sys, "AurosBackup", "backup")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(sys, "AurosBackup"), filepath.Join(dest, "link")); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}
	before := testsupport.Snapshot(t, sys)

	_, err := r.Resolve(filepath.Join(dest, "link", "backup"), 1<<20)
	if !errors.Is(err, ErrDestinationIsSystemVolume) {
		t.Fatalf("err = %v, want ErrDestinationIsSystemVolume", err)
	}
	testsupport.AssertUnchanged(t, sys, before)
}

func TestResolver_CreatesNothingThroughALinkOntoTheSystemVolume(t *testing.T) {
	// The no-flag path used to MkdirAll straight onto a junction that already
	// existed. Nothing may be created through one.
	r, sys, dest := linkFixture(t)
	if err := os.Symlink(sys, filepath.Join(dest, "auros-backup")); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}
	before := testsupport.Snapshot(t, sys)

	_, rejected, err := r.Choose("auros-backup", 1<<20)
	if err == nil {
		t.Fatal("Choose accepted a candidate that is a link onto the system volume")
	}
	if len(rejected) == 0 {
		t.Error("the user is told nothing about why the drive was refused")
	}
	testsupport.AssertUnchanged(t, sys, before)
}

func TestResolver_CarriesTheResolvedPathNotTheOneThatWasTyped(t *testing.T) {
	// A link that stays on the backup drive is fine — but every writer must be
	// handed the path it resolves to, because that is the path whose volume was
	// identified.
	r, _, dest := linkFixture(t)
	real := filepath.Join(dest, "real-backup")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dest, "shortcut")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}

	d, err := r.Resolve(link, 1<<20)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Dir() != real {
		t.Errorf("Dir() = %q, want the resolved path %q", d.Dir(), real)
	}
	if d.RunlogOptions().DestRoot != real {
		t.Errorf("the run log would be written to %q, not to the resolved path", d.RunlogOptions().DestRoot)
	}
	if d.RunlogOptions().DestIsSystemVolume {
		t.Error("a destination on the backup volume was reported as the system volume")
	}
}

func TestVerify_RefusesWhenTheDestinationBecomesALinkMidRun(t *testing.T) {
	// TOCTOU: phase 3 checked a real directory; between then and phase 5 it was
	// replaced with a link onto the system volume. The proof must not be minted.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)

	elsewhere := filepath.Join(f.sysDir, "swapped")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.destDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, f.destDir); err != nil {
		t.Skipf("cannot create a link on this filesystem: %v", err)
	}
	f.sysBefore = testsupport.Snapshot(t, f.sysDir)

	va, _, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrDestinationMoved) && !errors.Is(err, ErrDestinationIsSystemVolume) {
		t.Fatalf("err = %v, want the destination-changed refusal", err)
	}
	if va.IsVerified() {
		t.Fatal("a VerifiedArchive was minted for a destination that moved under the run")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestDestination_ReportsWhereItActuallyIsRatherThanAsserting(t *testing.T) {
	// The three "system_disk_untouched: true" literals were printed whether or
	// not they were true. The claim is now a measurement.
	f := newFixture(t, sampleFiles())
	if f.dest.OnSystemVolume() {
		t.Error("a destination on the backup volume measured as being on the system volume")
	}
	onSys := f.dest
	onSys.dir = f.sysDir
	onSys.vol = f.sysVol
	if !onSys.OnSystemVolume() {
		t.Error("a destination on the system volume measured as not being on it")
	}
	var unresolved Destination
	if !unresolved.OnSystemVolume() {
		t.Error("an unresolved destination answered 'not the system volume'; unknown must never read as no")
	}
}

// ---------- MAJOR: Arm aimed at a volume the archive never verified ----------

func TestArm_TargetsOnlyTheVolumeTheArchiveVerified(t *testing.T) {
	// The attack: a genuine VerifiedArchive plus an ArmRequest naming the
	// DESTINATION volume, so that `manage-bde -protectors -disable` runs against
	// the drive holding the only second copy. There is now no field on
	// ArmRequest that names a volume at all: the target comes from the proof.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeDryRun, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if va.SystemVolumeGUID() != sysGUID {
		t.Fatalf("the archive names %q as the system volume", va.SystemVolumeGUID())
	}
	res, err := Arm(context.Background(), m, va, armReq(f.log))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Steps {
		for _, a := range s.Argv {
			if a == f.destDir || strings.Contains(a, destGUID) {
				t.Errorf("step %q is aimed at the backup drive: %v", s.ID, s.Argv)
			}
		}
	}
	if len(res.Steps) == 0 || !strings.Contains(res.Steps[0].Command, f.sysVol.Mount) {
		t.Errorf("the plan does not act on the verified system volume: %+v", res.Steps)
	}
}

func TestArm_RefusesAnArchiveWhoseArchiveIsOnTheSystemVolume(t *testing.T) {
	// A proof whose two volumes are the same is not a proof of a second copy.
	// Both CrossWall and Arm refuse it, so neither the state machine nor the
	// function that touches the disk depends on the other having checked.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	va.destVolumeGUID = va.systemVolumeGUID // in-package surgery; no caller can do this

	if err := m.CrossWall(va); !errors.Is(err, ErrArchiveOnSystemVolume) {
		t.Errorf("CrossWall: err = %v, want ErrArchiveOnSystemVolume", err)
	}
	if _, err := Arm(context.Background(), m, va, armReq(f.log)); !errors.Is(err, ErrArchiveOnSystemVolume) {
		t.Errorf("Arm: err = %v, want ErrArchiveOnSystemVolume", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with an archive on the system volume")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestArm_RefusesAnArchiveThatNamesNoSystemVolume(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	va.systemVolumeGUID = ""
	if _, err := Arm(context.Background(), m, va, armReq(f.log)); !errors.Is(err, ErrWrongVolume) {
		t.Fatalf("err = %v, want ErrWrongVolume", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with an archive that names no system volume")
	}
}

func TestArm_RefusesASystemMountThatIsNotOneArgument(t *testing.T) {
	// "C:\Program Files\Data" is the mount-point case SAFETY.md phase 3 warns
	// about. Split on spaces it hands manage-bde a truncated target.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	va.systemMount = `C:\Program Files\Data`
	if _, err := Arm(context.Background(), m, va, armReq(f.log)); !errors.Is(err, ErrBadSystemMount) {
		t.Fatalf("err = %v, want ErrBadSystemMount", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with an unusable mount point")
	}
}

// ---------- MAJOR: BitLocker unknown must mean protected ----------

func TestArm_PlansTheSuspendWhenBitLockerWasNeverChecked(t *testing.T) {
	// winEnv.Firmware() returns Known:false on real Windows today, so every
	// TriState is Unknown. The old wiring computed `== winenv.Yes`, which is
	// false, and no suspend step was ever generated on the machine this tool was
	// built for. Unknown now plans the step.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeDryRun, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	req := ArmRequest{Log: f.log} // BitLocker unset: the zero value is Unknown
	res, err := Arm(context.Background(), m, va, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Steps) == 0 || res.Steps[0].ID != "bitlocker-suspend" {
		t.Fatalf("no BitLocker suspend was planned for an unchecked machine: %+v", res.Steps)
	}
}

func TestArm_RefusesToCommitOnFirmwareItNeverChecked(t *testing.T) {
	// SAFETY.md phase 1 requires all three firmware facts before the run begins.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	req := ArmRequest{Log: f.log, BitLocker: winenv.Unknown, FirmwareKnown: false}
	if _, err := Arm(context.Background(), m, va, req); !errors.Is(err, ErrFirmwareUnknown) {
		t.Fatalf("err = %v, want ErrFirmwareUnknown", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed on firmware facts the tool admits it never checked")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- MAJOR: no exported way to allow an empty archive ----------

func TestVerify_EmptyArchiveCannotBeAllowedFromOutsideThisPackage(t *testing.T) {
	// `VerifyRequest.AllowEmpty` was an exported bool that turned off
	// ErrEmptyArchive — the refusal whose own doc comment names this as the
	// failure mode it catches. It is gone. This test asserts the API has no
	// exported escape hatch of any kind on the two request types.
	root := repoRoot(t)
	suspicious := regexp.MustCompile(`^(Allow|Skip|Force|Bypass|Ignore|Disable|Unsafe|Override)`)
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, filepath.Join(root, "internal", "safety"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	guarded := map[string]bool{"VerifyRequest": true, "ArmRequest": true, "VerifiedArchive": true}
	checked := 0
	for _, p := range pkg {
		ast.Inspect(p, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !guarded[ts.Name.Name] {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			checked++
			for _, fld := range st.Fields.List {
				for _, nm := range fld.Names {
					if nm.IsExported() && suspicious.MatchString(nm.Name) {
						t.Errorf("%s has an exported escape hatch %q: a refusal with an "+
							"exported off switch is not a refusal", ts.Name.Name, nm.Name)
					}
				}
			}
			return true
		})
	}
	if checked < 3 {
		t.Fatalf("examined %d of the 3 guarded types: this test is vacuous", checked)
	}
}

func TestVerify_EvenTheInternalEscapeHatchCannotMintAnEmptyArchive(t *testing.T) {
	// The in-package option exists for tests of the machinery. It gets past the
	// empty-manifest refusal and still cannot produce a proof, because a report
	// over zero files is no longer clean.
	f := newFixture(t, map[string]string{})
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, rep, err := Verify(context.Background(), m, f.req(), withAllowEmpty())
	if err == nil {
		t.Fatal("an empty archive was verified")
	}
	if rep != nil && rep.Clean() {
		t.Error("a report over zero files reported itself clean")
	}
	if va.IsVerified() {
		t.Fatal("a VerifiedArchive was minted for zero files")
	}
	if err := m.CrossWall(va); err == nil {
		t.Fatal("the wall was crossed on a verification that verified nothing")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_EmptyManifestIsRefusedByDefault(t *testing.T) {
	f := newFixture(t, map[string]string{})
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrEmptyArchive) {
		t.Fatalf("err = %v, want ErrEmptyArchive", err)
	}
	assertCannotArm(t, m, va, f)
}
