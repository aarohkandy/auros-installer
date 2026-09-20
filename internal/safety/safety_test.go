package safety

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// The abort path is tested more than the happy path (SPEC §6C, SAFETY.md rule 2).
// In this file there is one test of a successful verification and fifteen of
// refusals, and every refusal asserts that the stand-in system disk is
// byte-identical afterwards.

const (
	sysGUID  = `\\?\Volume{11111111-1111-1111-1111-111111111111}\`
	destGUID = `\\?\Volume{22222222-2222-2222-2222-222222222222}\`
)

type fixture struct {
	sysDir    string
	destDir   string
	sysBefore testsupport.Fingerprint
	man       *manifest.Manifest
	q         *quarantine.Set
	log       *runlog.Logger
	logBuf    *bytes.Buffer
}

// newFixture builds a stand-in system disk with files on it, and a destination
// holding a correct copy of a small tree.
func newFixture(t *testing.T, files map[string]string) *fixture {
	t.Helper()
	base := t.TempDir()
	sys := filepath.Join(base, "systemdisk")
	dest := filepath.Join(base, "usb")
	if err := os.MkdirAll(sys, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	// Something on the system disk that must survive every test in this file.
	testsupport.Tree(t, sys, map[string]string{
		"Windows/System32/config/SYSTEM": "registry hive",
		"Users/pat/Documents/thesis.odt": "the only copy of somebody's work",
		"bootmgr":                        "boot manager",
	})

	man := manifest.New()
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
		if len(content) == 0 {
			e.SHA256 = manifest.EmptySHA256
		}
		if err := man.Add(e); err != nil {
			t.Fatal(err)
		}
	}

	buf := &bytes.Buffer{}
	fixed := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }

	f := &fixture{}
	f.sysDir = sys
	f.destDir = dest
	f.sysBefore = testsupport.Snapshot(t, sys)
	f.man = man
	f.q = quarantine.NewSet(clock)
	f.logBuf = buf
	f.log = runlog.NewWriter(buf, clock)
	return f
}

func (f *fixture) req() VerifyRequest {
	return VerifyRequest{
		DestRoot:         f.destDir,
		DestVolumeGUID:   destGUID,
		SystemVolumeGUID: sysGUID,
		Manifest:         f.man,
		Quarantine:       f.q,
		Log:              f.log,
	}
}

// run drives a machine from the start of the run to the end of phase 4, which is
// where every test in this file picks up.
func atVerifyBoundary(t *testing.T, mode Mode, log *runlog.Logger) *Machine {
	t.Helper()
	m := NewMachine(mode, log)
	for _, p := range []Phase{PhaseInventory, PhaseDisclose, PhaseDestination, PhaseCopy} {
		if err := m.Advance(p); err != nil {
			t.Fatalf("advance to %s: %v", p, err)
		}
	}
	return m
}

func sampleFiles() map[string]string {
	return map[string]string{
		"Documents/a.txt":     "alpha",
		"Documents/sub/b.txt": "bravo",
		"Desktop/empty.txt":   "",
	}
}

// ---------- the one happy path ----------

func TestVerify_IssuesArchiveWhenEverythingMatches(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeDryRun, f.log)

	va, rep, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatalf("Verify: %v\n%s", err, rep.Describe())
	}
	if !va.IsVerified() {
		t.Fatal("Verify returned a VerifiedArchive that is not verified")
	}
	if va.FileCount() != 3 {
		t.Errorf("FileCount = %d, want 3", va.FileCount())
	}
	if va.RunID() != m.RunID() {
		t.Errorf("archive run %q, machine run %q", va.RunID(), m.RunID())
	}
	if !rep.Clean() {
		t.Errorf("report not clean: %s", rep.Describe())
	}
	// SAFETY.md's observable moment must appear in the log.
	if !bytes.Contains(f.logBuf.Bytes(), []byte(`"kind":"verified"`)) {
		t.Errorf("the verification moment was not logged:\n%s", f.logBuf.String())
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- refusals: the archive ----------

func TestVerify_RefusesWhenOneHashDiffers(t *testing.T) {
	f := newFixture(t, sampleFiles())
	if err := os.WriteFile(filepath.Join(f.destDir, "Documents", "a.txt"), []byte("ALPHA"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, rep, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
	if va.IsVerified() {
		t.Fatal("a VerifiedArchive was issued for a mismatching archive")
	}
	if len(rep.Disagreements) != 1 {
		t.Errorf("disagreements = %d, want 1", len(rep.Disagreements))
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesWhenManyHashesDiffer(t *testing.T) {
	f := newFixture(t, sampleFiles())
	for _, rel := range []string{"Documents/a.txt", "Documents/sub/b.txt"} {
		if err := os.WriteFile(filepath.Join(f.destDir, filepath.FromSlash(rel)), []byte("xxxxx"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, rep, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
	if len(rep.Disagreements) != 2 {
		t.Errorf("disagreements = %d, want 2:\n%s", len(rep.Disagreements), rep.Describe())
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesOnCountMismatchWithEveryHashCorrect(t *testing.T) {
	// The subtle one: every file the manifest names is present and correct, but
	// the destination holds one more than it should. Hash checking alone passes
	// this. SPEC §6C requires count AND hash, and this is why.
	f := newFixture(t, sampleFiles())
	if err := os.WriteFile(filepath.Join(f.destDir, "Documents", "stowaway.txt"), []byte("not in the manifest"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, rep, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
	if rep.ManifestCount == rep.DestinationCount {
		t.Errorf("counts should differ: manifest %d, destination %d", rep.ManifestCount, rep.DestinationCount)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesWhenAFileIsMissing(t *testing.T) {
	f := newFixture(t, sampleFiles())
	if err := os.Remove(filepath.Join(f.destDir, "Desktop", "empty.txt")); err != nil {
		t.Fatal(err)
	}
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("err = %v, want ErrVerificationFailed", err)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesWhenQuarantineIsNotEmpty(t *testing.T) {
	// Every file that WAS copied verifies perfectly. One file never made it.
	// SAFETY.md phase 5: the run does not proceed unless the unresolved count is
	// zero.
	f := newFixture(t, sampleFiles())
	f.q.Add(quarantine.Record{
		Path:   "Documents/locked.pst", Reason: quarantine.ReasonLocked,
		Detail: "in use by Outlook", Attempts: 2,
	})
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, rep, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrQuarantineNotEmpty) {
		t.Fatalf("err = %v, want ErrQuarantineNotEmpty", err)
	}
	if !rep.Clean() {
		t.Errorf("the files that were copied should still verify cleanly: %s", rep.Describe())
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesEmptyManifest(t *testing.T) {
	f := newFixture(t, map[string]string{})
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(context.Background(), m, f.req())
	if !errors.Is(err, ErrEmptyArchive) {
		t.Fatalf("err = %v, want ErrEmptyArchive", err)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesWhenArchiveIsOnTheSystemVolume(t *testing.T) {
	f := newFixture(t, sampleFiles())
	req := f.req()
	req.DestVolumeGUID = sysGUID // the "second copy" is on the disk we would wipe
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(context.Background(), m, req)
	if !errors.Is(err, ErrArchiveOnSystemVolume) {
		t.Fatalf("err = %v, want ErrArchiveOnSystemVolume", err)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_RefusesWhenVolumeIdentityIsUnknown(t *testing.T) {
	f := newFixture(t, sampleFiles())
	req := f.req()
	req.DestVolumeGUID = "" // a drive letter is not an identity
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(context.Background(), m, req)
	if !errors.Is(err, ErrDestinationUnidentified) {
		t.Fatalf("err = %v, want ErrDestinationUnidentified", err)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestVerify_CancelledContext(t *testing.T) {
	f := newFixture(t, sampleFiles())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(ctx, m, f.req())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	assertCannotArm(t, m, va, f)
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- refusals: the wall itself ----------

func TestArm_RefusesTheZeroValueVerifiedArchive(t *testing.T) {
	// The declaration this whole design exists to defeat.
	f := newFixture(t, sampleFiles())
	var forged VerifiedArchive

	m := atVerifyBoundary(t, ModeCommit, f.log)
	if _, _, err := Verify(context.Background(), m, f.req()); err != nil {
		t.Fatal(err)
	}
	if forged.IsVerified() {
		t.Fatal("the zero value claims to be verified")
	}
	_, err := Arm(context.Background(), m, forged, ArmRequest{SystemVolumeGUID: sysGUID, Log: f.log})
	if !errors.Is(err, ErrNotVerified) {
		t.Fatalf("err = %v, want ErrNotVerified", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with a zero-value archive")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestArm_RefusesAnArchiveFromAnotherRun(t *testing.T) {
	f := newFixture(t, sampleFiles())
	other := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), other, f.req())
	if err != nil {
		t.Fatal(err)
	}

	// A different Machine: a fresh run, a stale proof.
	f2 := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f2.log)
	if _, _, err := Verify(context.Background(), m, f2.req()); err != nil {
		t.Fatal(err)
	}
	if _, err := Arm(context.Background(), m, va, ArmRequest{SystemVolumeGUID: sysGUID, Log: f2.log}); !errors.Is(err, ErrWrongRun) {
		t.Fatalf("err = %v, want ErrWrongRun", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with another run's archive")
	}
	testsupport.AssertUnchanged(t, f2.sysDir, f2.sysBefore)
}

func TestArm_DryRunIsTheDefaultAndDoesNotCross(t *testing.T) {
	f := newFixture(t, sampleFiles())
	var mode Mode // the zero value must be DRY RUN
	if mode.Commits() {
		t.Fatal("the zero Mode commits; the default must be dry run")
	}
	m := atVerifyBoundary(t, mode, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}

	res, err := Arm(context.Background(), m, va, ArmRequest{
		SystemVolumeGUID: sysGUID, SystemMount: "C:", BitLockerProtected: true, Restart: true, Log: f.log,
	})
	if err != nil {
		t.Fatalf("dry-run Arm: %v", err)
	}
	if res.Performed {
		t.Fatal("dry run reports having performed the arm")
	}
	if m.Crossed() {
		t.Fatal("dry run crossed the wall")
	}
	if !m.SystemDiskUntouched() {
		t.Fatal("dry run did not leave the system disk untouched")
	}
	if len(res.Steps) == 0 {
		t.Fatal("dry run produced no plan to show the user")
	}
	if got := res.Describe(); !bytes.Contains([]byte(got), []byte("DRY RUN")) {
		t.Errorf("the mode is not stated in the output:\n%s", got)
	}
	// SAFETY.md: BitLocker suspension is unconditional when BitLocker is on.
	if res.Steps[0].ID != "bitlocker-suspend" {
		t.Errorf("first step = %q, want bitlocker-suspend", res.Steps[0].ID)
	}
	if res.Steps[0].Reversal == "" {
		t.Error("the BitLocker step has no reversal")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestArm_CommitModeIsStillCompiledOut(t *testing.T) {
	// Proof that the default build cannot touch a system disk even when
	// everything else is in order: a clean verification, commit mode, a real
	// intent — and the privileged implementation is not in the binary.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Arm(context.Background(), m, va, ArmRequest{
		SystemVolumeGUID: sysGUID, SystemMount: "C:", BitLockerProtected: true, Log: f.log,
	})
	if err == nil {
		t.Fatal("commit-mode Arm succeeded: the privileged steps are NOT compiled out")
	}
	if !m.Crossed() {
		t.Error("commit mode should have recorded the wall crossing before attempting the steps")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- refusals: phase ordering ----------

func TestPhase_RefusesOutOfOrderTransitions(t *testing.T) {
	m := NewMachine(ModeCommit, nil)
	if err := m.Advance(PhaseCopy); !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("skipping to copy: err = %v, want ErrOutOfOrder", err)
	}
	if err := m.Advance(PhaseInventory); err != nil {
		t.Fatal(err)
	}
	if err := m.Advance(PhaseInventory); !errors.Is(err, ErrAlreadyThere) {
		t.Errorf("repeating a phase: err = %v, want ErrAlreadyThere", err)
	}
	if err := m.Advance(PhaseVerify); !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("skipping disclose and destination: err = %v, want ErrOutOfOrder", err)
	}
}

func TestPhase_ArmIsUnreachableByAdvance(t *testing.T) {
	// There is no door into phase 6 except CrossWall, whose signature demands a
	// VerifiedArchive.
	m := atVerifyBoundary(t, ModeCommit, nil)
	if err := m.Advance(PhaseVerify); err != nil {
		t.Fatal(err)
	}
	if err := m.Advance(PhaseArm); !errors.Is(err, ErrUseCrossWall) {
		t.Fatalf("Advance(PhaseArm) = %v, want ErrUseCrossWall", err)
	}
	if m.Crossed() {
		t.Fatal("Advance reached phase 6")
	}
}

func TestPhase_RestoreRequiresTheWall(t *testing.T) {
	m := atVerifyBoundary(t, ModeCommit, nil)
	if err := m.Advance(PhaseVerify); err != nil {
		t.Fatal(err)
	}
	if err := m.Advance(PhaseRestore); err == nil {
		t.Fatal("restore was allowed without crossing the wall")
	}
}

func TestPhase_AbortStopsEverything(t *testing.T) {
	m := atVerifyBoundary(t, ModeCommit, nil)
	m.Abort("user pulled the USB stick")
	if err := m.Advance(PhaseVerify); !errors.Is(err, ErrAborted) {
		t.Errorf("err = %v, want ErrAborted", err)
	}
	if !m.SystemDiskUntouched() {
		t.Error("an abort before the wall must report the system disk untouched")
	}
}

func TestPhase_CannotCrossTwice(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CrossWall(va); err != nil {
		t.Fatal(err)
	}
	if err := m.CrossWall(va); !errors.Is(err, ErrAlreadyArmed) {
		t.Fatalf("second crossing: err = %v, want ErrAlreadyArmed", err)
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestPhase_DryRunCannotCrossEvenWithAValidArchive(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeDryRun, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CrossWall(va); !errors.Is(err, ErrNotCommitMode) {
		t.Fatalf("err = %v, want ErrNotCommitMode", err)
	}
	if m.Crossed() {
		t.Fatal("a dry run crossed the wall")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// assertCannotArm is the assertion every refusal test ends with: whatever went
// wrong, the value that came back cannot be used to touch the system disk.
func assertCannotArm(t *testing.T, m *Machine, va VerifiedArchive, f *fixture) {
	t.Helper()
	if va.IsVerified() {
		t.Fatal("a VerifiedArchive was issued on a refusal path")
	}
	if _, err := Arm(context.Background(), m, va, ArmRequest{SystemVolumeGUID: sysGUID, Log: f.log}); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("Arm with the refused archive: err = %v, want ErrNotVerified", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed on a refusal path")
	}
	if !m.SystemDiskUntouched() {
		t.Fatal("the machine does not report the system disk as untouched")
	}
}

// ---------- phase 3: the destination ----------

func vol(guid, mount string, free uint64, isSystem bool) winenv.Volume {
	return winenv.Volume{GUID: guid, Mount: mount, FreeBytes: free, TotalBytes: free * 2, IsSystem: isSystem}
}

func TestDestination_RefusesTheSystemDisk(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	d := Destination{Volume: vol(sysGUID, `D:\`, 100<<30, false), Dir: `D:\auros`}
	// Same GUID, different letter: a mount point or a subst'd letter aliasing C:.
	if err := CheckDestination(d, sys, 1<<20); !errors.Is(err, ErrDestinationIsSystemVolume) {
		t.Fatalf("err = %v, want ErrDestinationIsSystemVolume", err)
	}
}

func TestDestination_RefusesWhenTooSmall(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	// 10 GB of data needs 11 GB plus metadata; offer 10.5 GB.
	d := Destination{Volume: vol(destGUID, `E:\`, 10<<30+512<<20, false)}
	if err := CheckDestination(d, sys, 10<<30); !errors.Is(err, ErrDestinationTooSmall) {
		t.Fatalf("err = %v, want ErrDestinationTooSmall", err)
	}
}

func TestDestination_RefusesWhenIdentityIsUnknown(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	d := Destination{Volume: vol("", `E:\`, 100<<30, false)}
	if err := CheckDestination(d, sys, 1<<20); !errors.Is(err, ErrDestinationUnidentified) {
		t.Fatalf("err = %v, want ErrDestinationUnidentified", err)
	}
}

func TestDestination_RefusesWhenNothingQualifies(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	candidates := []Destination{
		{Volume: vol(sysGUID, `C:\`, 100<<30, true)},
		{Volume: vol(destGUID, `E:\`, 1<<20, false)},
		{Volume: vol("", `F:\`, 900<<30, false)},
	}
	_, rejected, err := ChooseDestination(candidates, sys, 10<<30)
	if !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
	if len(rejected) != 3 {
		t.Errorf("rejected %d, want 3 (the user is told about every drive)", len(rejected))
	}
	if s := DescribeRejections(rejected); s == "" {
		t.Error("no explanation was produced for the user")
	}
}

func TestDestination_RefusesWithNoCandidatesAtAll(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	if _, _, err := ChooseDestination(nil, sys, 1<<20); !errors.Is(err, ErrNoDestination) {
		t.Fatalf("err = %v, want ErrNoDestination", err)
	}
}

func TestDestination_PicksTheLargestQualifyingVolume(t *testing.T) {
	sys := vol(sysGUID, `C:\`, 100<<30, true)
	big := `\\?\Volume{33333333-3333-3333-3333-333333333333}\`
	candidates := []Destination{
		{Volume: vol(destGUID, `E:\`, 20<<30, false)},
		{Volume: vol(big, `F:\`, 64<<30, false)},
	}
	got, _, err := ChooseDestination(candidates, sys, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if got.Volume.GUID != big {
		t.Errorf("chose %s, want the larger volume", got.Volume.Mount)
	}
}

func TestRequiredBytes_IncludesHeadroomAndDoesNotOverflow(t *testing.T) {
	if got := RequiredBytes(1000); got != 1100+MetadataReserveBytes {
		t.Errorf("RequiredBytes(1000) = %d, want %d", got, 1100+MetadataReserveBytes)
	}
	if got := RequiredBytes(1 << 62); got <= 0 {
		t.Errorf("RequiredBytes overflowed to %d; a wrapped requirement passes every check", got)
	}
}

func TestSameVolume_UnknownIsNeverEqual(t *testing.T) {
	a := winenv.Volume{GUID: ""}
	if SameVolume(a, a) {
		t.Fatal("two unidentified volumes compared equal; unknown must never read as different or as same")
	}
	x := winenv.Volume{GUID: `\\?\Volume{ABCDEF01-0000-0000-0000-000000000000}\`}
	y := winenv.Volume{GUID: `\\?\volume{abcdef01-0000-0000-0000-000000000000}`}
	if !SameVolume(x, y) {
		t.Fatal("the same volume in different capitalisation compared unequal")
	}
}
