package safety

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/testsupport"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// The wall, from both sides.
//
// SAFETY.md: "Phase 6 (ARM) is the only place we cross. It refuses to run
// unless it is handed a VerifiedArchive." Everything below is an attempt to
// reach phase 6 without one, or with one that does not mean what the caller
// wants it to mean. Every case asserts the stand-in system disk is
// byte-identical afterwards.

// ---------- phase 5 refusals ----------

// TestVerify_RefusalTable walks every way a verification can fail to produce a
// proof. The point of the table is exhaustiveness: a refusal that exists in the
// code and in no test is a refusal nobody will notice deleting.
func TestVerify_RefusalTable(t *testing.T) {
	cases := []struct {
		name    string
		prepare func(t *testing.T, f *fixture, req *VerifyRequest)
		wantErr error
		// wantAny accepts any non-nil error, for the paths whose failure is not
		// a named sentinel. It is used sparingly and never for a safety rule.
		wantAny bool
	}{
		{
			name: "a file at the destination is one byte short",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				writeDest(t, f, "Documents/a.txt", "alph")
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a file at the destination is one byte long",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				writeDest(t, f, "Documents/a.txt", "alphas")
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a file's contents changed but its length did not",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				// The case a count check and a size check both pass. Only the
				// hash catches it, which is why SPEC §6C.4 demands both.
				writeDest(t, f, "Documents/a.txt", "ALPHA")
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a file at the destination became a directory",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				p := filepath.Join(f.destDir, "Documents", "a.txt")
				if err := os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(p, 0o755); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a zero-byte file at the destination is no longer empty",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				// A 0-byte file is ordinary, not an error, and it has to be
				// verified like any other or it is a free pass.
				writeDest(t, f, "Desktop/empty.txt", "x")
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a file the manifest names was deleted from the destination",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				if err := os.Remove(filepath.Join(f.destDir, "Documents", "sub", "b.txt")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "the whole destination directory was emptied",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				for _, rel := range []string{"Documents/a.txt", "Documents/sub/b.txt", "Desktop/empty.txt"} {
					if err := os.Remove(filepath.Join(f.destDir, filepath.FromSlash(rel))); err != nil {
						t.Fatal(err)
					}
				}
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "a stowaway file appeared at the destination",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				writeDest(t, f, "Documents/stowaway.txt", "not in the manifest")
			},
			wantErr: ErrVerificationFailed,
		},
		{
			name: "the destination was unmounted before verification",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				if err := os.RemoveAll(f.destDir); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: ErrDestinationUnresolvable,
		},
		{
			name: "the destination became a junction onto the system disk",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				target := filepath.Join(f.sysDir, "AurosBackup")
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				if err := os.RemoveAll(f.destDir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, f.destDir); err != nil {
					t.Skipf("this environment cannot create symlinks: %v", err)
				}
			},
			wantErr: ErrDestinationMoved,
		},
		{
			name: "the destination carries no proof at all",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				req.Dest = Destination{}
			},
			wantErr: ErrDestinationNotResolved,
		},
		{
			name: "the destination volume has no identity",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				req.Dest = f.destWithVolume(winenv.Volume{Mount: f.destDir, FreeBytes: 100 << 30})
			},
			wantErr: ErrDestinationUnidentified,
		},
		{
			name: "the SYSTEM volume has no identity, so nothing can be ruled out",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				req.System = winenv.Volume{Mount: f.sysDir}
			},
			wantErr: ErrDestinationUnidentified,
		},
		{
			name: "the archive is on the system volume under a different capitalisation",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				// The second copy is on the disk we are about to change, and
				// the only thing hiding it is the case of a GUID. An identity
				// check that compared raw strings would call this a second copy
				// and cross the wall.
				onSys := filepath.Join(f.sysDir, "pretend-usb")
				if err := os.MkdirAll(onSys, 0o755); err != nil {
					t.Fatal(err)
				}
				f.sysBefore = testsupport.Snapshot(t, f.sysDir)
				d := f.dest
				d.dir = onSys
				d.vol = vol(strings.ToUpper(sysGUID), onSys, 100<<30, false)
				req.Dest = d
				req.System = vol(strings.ToLower(sysGUID), f.sysDir, 100<<30, true)
			},
			wantErr: ErrArchiveOnSystemVolume,
		},
		{
			name: "there is no manifest to verify against",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				req.Manifest = nil
			},
			wantAny: true,
		},
		{
			name: "the manifest is empty, so verification verified nothing",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				req.Manifest = manifest.New()
			},
			wantErr: ErrEmptyArchive,
		},
		{
			name: "one file could not be copied at all",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				f.q.Add(quarantine.Record{
					Path:     "Documents/outlook.pst",
					Reason:   quarantine.ReasonLocked,
					Detail:   "in use by Outlook",
					Attempts: 2,
				})
			},
			wantErr: ErrQuarantineNotEmpty,
		},
		{
			name: "several files could not be copied",
			prepare: func(t *testing.T, f *fixture, req *VerifyRequest) {
				for _, p := range []string{"a.pst", "b.pst", "c.pst"} {
					f.q.Add(quarantine.Record{Path: p, Reason: quarantine.ReasonLocked, Attempts: 1})
				}
			},
			wantErr: ErrQuarantineNotEmpty,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, sampleFiles())
			req := f.req()
			tc.prepare(t, f, &req)
			m := atVerifyBoundary(t, ModeCommit, f.log)

			va, _, err := Verify(context.Background(), m, req)
			switch {
			case tc.wantAny:
				if err == nil {
					t.Fatal("Verify succeeded where it had to refuse")
				}
			default:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Verify = %v, want %v", err, tc.wantErr)
				}
			}
			assertCannotArm(t, m, va, f)
			testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
		})
	}
}

// TestVerify_WaivedQuarantineIsTheOneWayThroughAndItIsRecorded is the control
// for the two quarantine refusals above. Without it, a bug that made
// Unresolved() always return zero would leave those two cases passing for the
// wrong reason, and a bug that made it always return non-zero would be
// invisible.
func TestVerify_WaivedQuarantineIsTheOneWayThroughAndItIsRecorded(t *testing.T) {
	f := newFixture(t, sampleFiles())
	f.q.Add(quarantine.Record{
		Path:     "Documents/outlook.pst",
		Reason:   quarantine.ReasonLocked,
		Attempts: 2,
	})
	if err := f.q.Waive("Documents/outlook.pst", "pat, who was shown the file and said go ahead"); err != nil {
		t.Fatal(err)
	}
	m := atVerifyBoundary(t, ModeCommit, f.log)

	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatalf("Verify = %v, want nil after an attributed waiver", err)
	}
	if !va.IsVerified() {
		t.Fatal("no archive was issued after the only blocker was waived")
	}
	// An unattributed waiver is not a waiver.
	if werr := f.q.Waive("Documents/outlook.pst", "   "); werr == nil {
		t.Error("an unattributed waiver was accepted")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- phase 6 refusals ----------

// TestArm_RefusalTable is the other side of the wall. Every case starts from a
// GENUINE VerifiedArchive — one this package's own Verify produced — and then
// breaks exactly one thing about it. Starting from a real proof is deliberate:
// a table built out of hand-made zero values would only ever re-test
// ErrNotVerified.
func TestArm_RefusalTable(t *testing.T) {
	cases := []struct {
		name    string
		mode    Mode
		damage  func(va *VerifiedArchive)
		request func(r *ArmRequest)
		wantErr error
	}{
		{
			name:    "the archive names no system volume",
			damage:  func(va *VerifiedArchive) { va.systemVolumeGUID = "" },
			wantErr: ErrWrongVolume,
		},
		{
			name:    "the archive's system volume is only whitespace",
			damage:  func(va *VerifiedArchive) { va.systemVolumeGUID = "   " },
			wantErr: ErrWrongVolume,
		},
		{
			name: "the archive's second copy is on the system volume",
			damage: func(va *VerifiedArchive) {
				va.destVolumeGUID = va.systemVolumeGUID
			},
			wantErr: ErrArchiveOnSystemVolume,
		},
		{
			name: "the second copy is on the system volume in different capitalisation",
			damage: func(va *VerifiedArchive) {
				va.destVolumeGUID = strings.ToUpper(va.systemVolumeGUID)
			},
			wantErr: ErrArchiveOnSystemVolume,
		},
		{
			name: "the second copy is on the system volume without the trailing separator",
			damage: func(va *VerifiedArchive) {
				va.destVolumeGUID = strings.TrimSuffix(va.systemVolumeGUID, `\`)
			},
			wantErr: ErrArchiveOnSystemVolume,
		},
		{
			name:    "the system mount point contains a space",
			damage:  func(va *VerifiedArchive) { va.systemMount = `C:\Program Files\Data` },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "the system mount point contains a tab",
			damage:  func(va *VerifiedArchive) { va.systemMount = "C:\tData" },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "the system mount point contains a newline",
			damage:  func(va *VerifiedArchive) { va.systemMount = "C:\nshutdown /r" },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "the system mount point contains a carriage return",
			damage:  func(va *VerifiedArchive) { va.systemMount = "C:\rshutdown /r" },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "the system mount point contains a double quote",
			damage:  func(va *VerifiedArchive) { va.systemMount = `C:\"quoted"` },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "the system mount point contains a single quote",
			damage:  func(va *VerifiedArchive) { va.systemMount = `C:\'quoted'` },
			wantErr: ErrBadSystemMount,
		},
		{
			name:    "commit mode with firmware facts that were never established",
			mode:    ModeCommit,
			damage:  func(va *VerifiedArchive) {},
			request: func(r *ArmRequest) { r.FirmwareKnown = false },
			wantErr: ErrFirmwareUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, sampleFiles())
			m := atVerifyBoundary(t, tc.mode, f.log)
			va, _, err := Verify(context.Background(), m, f.req())
			if err != nil {
				t.Fatalf("setting up a genuine archive: %v", err)
			}
			if !va.IsVerified() {
				t.Fatal("the setup did not produce a real archive; the table proves nothing")
			}
			tc.damage(&va)
			req := armReq(f.log)
			if tc.request != nil {
				tc.request(&req)
			}

			res, err := Arm(context.Background(), m, va, req)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Arm = %v, want %v", err, tc.wantErr)
			}
			if res != nil && res.Performed {
				t.Fatal("a refused Arm reports having performed its steps")
			}
			if m.Crossed() {
				t.Fatal("the wall was crossed on a refusal path")
			}
			if !m.SystemDiskUntouched() {
				t.Fatal("the machine does not report the system disk as untouched")
			}
			testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
		})
	}
}

// TestArm_RefusesWithoutAStateMachine covers the argument nobody thinks about.
func TestArm_RefusesWithoutAStateMachine(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if _, aerr := Arm(context.Background(), nil, va, armReq(f.log)); aerr == nil {
		t.Fatal("Arm with no state machine succeeded")
	}
	if _, _, verr := Verify(context.Background(), nil, f.req()); verr == nil {
		t.Fatal("Verify with no state machine succeeded")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// TestArm_PlansTheBitLockerSuspendUnlessItIsKnownToBeOff is the asymmetry
// SAFETY.md phase 6 step 1 insists on. Suspending BitLocker on a machine that
// is not using it is a no-op. Failing to suspend it on a machine that is leaves
// a user at a recovery prompt nobody has the key for — and on the ABORT path,
// which is the worst outcome this tool can produce. So "we could not tell" has
// to behave like "yes".
func TestArm_PlansTheBitLockerSuspendUnlessItIsKnownToBeOff(t *testing.T) {
	cases := []struct {
		name        string
		state       winenv.TriState
		wantSuspend bool
	}{
		{name: "BitLocker is on", state: winenv.Yes, wantSuspend: true},
		{name: "BitLocker could not be checked", state: winenv.Unknown, wantSuspend: true},
		{name: "the zero TriState, which is a caller who forgot the field", state: 0, wantSuspend: true},
		{name: "BitLocker is known to be off", state: winenv.No, wantSuspend: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, sampleFiles())
			m := atVerifyBoundary(t, ModeDryRun, f.log)
			va, _, err := Verify(context.Background(), m, f.req())
			if err != nil {
				t.Fatal(err)
			}
			req := armReq(f.log)
			req.BitLocker = tc.state
			res, err := Arm(context.Background(), m, va, req)
			if err != nil {
				t.Fatalf("dry-run Arm: %v", err)
			}
			got := hasStep(res, "bitlocker-suspend")
			if got != tc.wantSuspend {
				t.Fatalf("bitlocker-suspend planned = %v, want %v", got, tc.wantSuspend)
			}
			if got {
				s := stepByID(res, "bitlocker-suspend")
				if len(s.ReversalArgv) == 0 || s.Reversal == "" {
					t.Error("the BitLocker step carries no reversal; SAFETY.md requires every step to be reversible")
				}
				if s.Argv[0] != "manage-bde" {
					t.Errorf("suspend runs %q", s.Argv[0])
				}
			}
			if m.Crossed() {
				t.Fatal("a dry run crossed the wall")
			}
			testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
		})
	}
}

// TestArm_PlanNeverWritesBootMedia is DECISIONS.md D13 as a test rather than a
// paragraph. The customer-facing page says in as many words that the Windows
// program does not write your USB stick. If a step ever appears that opens a
// raw device handle, that promise and the code have come apart, and the one the
// customer read is the one that matters.
func TestArm_PlanNeverWritesBootMedia(t *testing.T) {
	// Command names are matched exactly; a substring test would trip over
	// "bcdedit" and teach whoever hits it to loosen the check.
	forbiddenCommands := map[string]bool{
		"diskpart": true, "dd": true, "format": true, "mkfs": true,
		"bootsect": true, "fsutil": true, "dism": true, "wbadmin": true,
	}
	// These spellings only ever appear when something is about to open a raw
	// device, so a substring match is right for them.
	forbiddenAnywhere := []string{`\\.\`, "physicaldrive", "createpartition"}
	withMedia := []string{"", "{aaaaaaaa-0000-0000-0000-000000000000}"}

	for _, media := range withMedia {
		f := newFixture(t, sampleFiles())
		m := atVerifyBoundary(t, ModeDryRun, f.log)
		va, _, err := Verify(context.Background(), m, f.req())
		if err != nil {
			t.Fatal(err)
		}
		req := armReq(f.log)
		req.BootMediaGUID = media
		req.Restart = true
		res, err := Arm(context.Background(), m, va, req)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Steps) == 0 {
			t.Fatal("no plan was produced, so this test is checking nothing")
		}
		for _, s := range res.Steps {
			for _, argv := range [][]string{s.Argv, s.ReversalArgv} {
				if len(argv) > 0 && forbiddenCommands[strings.ToLower(argv[0])] {
					t.Errorf("step %q runs %q: D13 removed writing boot media from this tool",
						s.ID, s.Command)
				}
				for _, a := range argv {
					low := strings.ToLower(a)
					for _, bad := range forbiddenAnywhere {
						if strings.Contains(low, bad) {
							t.Errorf("step %q names %q, which is a raw-device handle: D13 removed "+
								"writing boot media from this tool", s.ID, a)
						}
					}
				}
			}
		}
		testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
	}
}

// TestArm_DoesNotRecheckThatTheSecondCopyIsStillThere records a real gap rather
// than pretending it is closed.
//
// Arm's refusals are all about the PROOF and the TARGET VOLUME: it never goes
// back to the disk to confirm the archive it is about to reboot away from is
// still readable. Between safety.Verify and safety.Arm in cmd/auros-migrate
// there is no Reassert, so a USB stick pulled in that window is not noticed.
// The system disk is still safe — this test proves that much — but the user
// reboots into a machine whose second copy is gone.
//
// This test is written to the behaviour as it IS. When someone adds the
// re-check, this test fails, and the person who reads it will find this comment
// saying that failing is the correct outcome.
func TestArm_DoesNotRecheckThatTheSecondCopyIsStillThere(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeDryRun, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	// The stick is pulled after the proof was minted.
	if rerr := os.RemoveAll(f.destDir); rerr != nil {
		t.Fatal(rerr)
	}
	res, aerr := Arm(context.Background(), m, va, armReq(f.log))
	if aerr != nil {
		t.Fatalf("this test documents that Arm does NOT re-check the destination; "+
			"if it now does, delete this test and keep the check: %v", aerr)
	}
	if res.Performed {
		t.Fatal("a dry run performed its steps")
	}
	// What IS guaranteed, and what this test is really holding down:
	if m.Crossed() {
		t.Fatal("a dry run crossed the wall")
	}
	if !m.SystemDiskUntouched() {
		t.Fatal("the system disk is not reported as untouched")
	}
	if va.VerifiedAt().IsZero() {
		t.Error("the archive carries no verification moment, which is the observable " +
			"instant SAFETY.md requires")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- phase ordering under concurrency ----------

// TestPhase_AbortAtEveryBoundaryStopsTheRun walks the abort to each of the five
// non-destructive phases in turn. SAFETY.md: "An abort anywhere in 1-5 is not a
// special case needing cleanup logic; it is a process exit."
func TestPhase_AbortAtEveryBoundaryStopsTheRun(t *testing.T) {
	boundaries := []Phase{PhaseNone, PhaseInventory, PhaseDisclose, PhaseDestination, PhaseCopy}

	for _, upTo := range boundaries {
		t.Run(upTo.String(), func(t *testing.T) {
			f := newFixture(t, sampleFiles())
			m := NewMachine(ModeCommit, f.log)
			for _, p := range []Phase{PhaseInventory, PhaseDisclose, PhaseDestination, PhaseCopy} {
				if p > upTo {
					break
				}
				if err := m.Advance(p); err != nil {
					t.Fatalf("advance to %s: %v", p, err)
				}
			}
			m.Abort("the user pulled the USB stick")

			if !m.Aborted() {
				t.Fatal("the machine does not report the abort")
			}
			if !m.SystemDiskUntouched() {
				t.Fatal("an abort before the wall must report the system disk untouched")
			}
			// Nothing may move afterwards, by any door.
			if _, _, err := Verify(context.Background(), m, f.req()); !errors.Is(err, ErrAborted) {
				t.Errorf("Verify after an abort = %v, want ErrAborted", err)
			}
			var zero VerifiedArchive
			if err := m.CrossWall(zero); !errors.Is(err, ErrAborted) {
				t.Errorf("CrossWall after an abort = %v, want ErrAborted", err)
			}
			if err := m.Advance(PhaseRestore); !errors.Is(err, ErrAborted) {
				t.Errorf("Advance after an abort = %v, want ErrAborted", err)
			}
			if m.Crossed() {
				t.Fatal("the wall was crossed after an abort")
			}
			testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
		})
	}
}

// TestPhase_ConcurrentCrossingAttemptsCrossAtMostOnce runs the wall under a
// race. The Machine is documented as safe for concurrent use because the copy
// engine reports progress from several goroutines; the property that actually
// matters is that concurrency cannot produce two crossings, and `go test -race`
// is where that gets proven.
func TestPhase_ConcurrentCrossingAttemptsCrossAtMostOnce(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}

	const goroutines = 32
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		succeeded int
	)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if cerr := m.CrossWall(va); cerr == nil {
				mu.Lock()
				succeeded++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("%d goroutines crossed the wall, want exactly 1", succeeded)
	}
	if !m.Crossed() {
		t.Fatal("the machine does not record the crossing")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// TestPhase_ConcurrentAbortAndCrossingNeverBothWin is the same race with an
// abort thrown in. Either the abort lands first and nobody crosses, or a
// crossing lands first and the abort records that the wall was already crossed.
// What must never happen is a crossing recorded AFTER the machine reports the
// system disk as untouched.
func TestPhase_ConcurrentAbortAndCrossingNeverBothWin(t *testing.T) {
	for attempt := 0; attempt < 50; attempt++ {
		f := newFixture(t, sampleFiles())
		m := atVerifyBoundary(t, ModeCommit, f.log)
		va, _, err := Verify(context.Background(), m, f.req())
		if err != nil {
			t.Fatal(err)
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		var crossErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			crossErr = m.CrossWall(va)
		}()
		go func() {
			defer wg.Done()
			<-start
			m.Abort("power button held down")
		}()
		close(start)
		wg.Wait()

		crossed := m.Crossed()
		if (crossErr == nil) != crossed {
			t.Fatalf("attempt %d: CrossWall returned %v but Crossed() = %v", attempt, crossErr, crossed)
		}
		if m.SystemDiskUntouched() == crossed {
			t.Fatalf("attempt %d: SystemDiskUntouched() and Crossed() agree; one of them is lying", attempt)
		}
		testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
	}
}

// TestPhase_CancelledContextAtEveryPhaseBoundaryLeavesTheDiskAlone cancels
// before phase 5 rather than during it, which is the case a mid-file
// cancellation test does not cover: the run reaches the boundary and then
// stops.
func TestPhase_CancelledContextAtEveryPhaseBoundaryLeavesTheDiskAlone(t *testing.T) {
	for _, mode := range []Mode{ModeDryRun, ModeCommit} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newFixture(t, sampleFiles())
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			m := atVerifyBoundary(t, mode, f.log)

			va, _, err := Verify(ctx, m, f.req())
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Verify = %v, want context.Canceled", err)
			}
			assertCannotArm(t, m, va, f)
			testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
		})
	}
}

// ---------- helpers ----------

func writeDest(t *testing.T, f *fixture, rel, content string) {
	t.Helper()
	p := filepath.Join(f.destDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasStep(res *ArmResult, id string) bool {
	for _, s := range res.Steps {
		if s.ID == id {
			return true
		}
	}
	return false
}

func stepByID(res *ArmResult, id string) Step {
	for _, s := range res.Steps {
		if s.ID == id {
			return s
		}
	}
	return Step{}
}
