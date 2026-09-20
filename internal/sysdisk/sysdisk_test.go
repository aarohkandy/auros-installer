package sysdisk

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func intent() Intent {
	i := Intent{}
	i.SystemVolumeGUID = `\\?\Volume{11111111-1111-1111-1111-111111111111}\`
	i.SystemMount = "C:"
	i.BitLocker = BitLockerOn
	i.BootMediaGUID = "{aaaa-bbbb}"
	i.Restart = true
	i.Commit = true
	return i
}

func TestExecute_IsCompiledOutByDefault(t *testing.T) {
	// The default build — every CI artifact, every `go build` — cannot touch a
	// system disk at all. Enabling it needs `-tags auros_arm_enabled`, which is
	// a decision recorded in a build command rather than a flag flipped at 2am.
	out, err := Execute(context.Background(), intent())
	if !errors.Is(err, ErrNotValidated) {
		t.Fatalf("err = %v, want ErrNotValidated", err)
	}
	if out != nil && len(out.Completed) != 0 {
		t.Errorf("steps were completed: %+v", out.Completed)
	}
}

func TestExecute_RefusesOutsideCommitMode(t *testing.T) {
	i := intent()
	i.Commit = false
	if _, err := Execute(context.Background(), i); !errors.Is(err, ErrNotCommitted) {
		t.Fatalf("err = %v, want ErrNotCommitted", err)
	}
}

func TestExecute_RefusesWithoutAVolumeGUID(t *testing.T) {
	// Acting on "the C: drive" rather than on a volume GUID is how a subst'd
	// letter gets written to.
	i := intent()
	i.SystemVolumeGUID = ""
	if _, err := Execute(context.Background(), i); !errors.Is(err, ErrNoSystemVolume) {
		t.Fatalf("err = %v, want ErrNoSystemVolume", err)
	}
}

func TestSteps_BitLockerIsAlwaysFirstAndAlwaysReversible(t *testing.T) {
	steps := intent().Steps()
	if len(steps) == 0 {
		t.Fatal("no steps")
	}
	if steps[0].ID != "bitlocker-suspend" {
		t.Fatalf("first step = %q, want bitlocker-suspend", steps[0].ID)
	}
	if !strings.Contains(steps[0].Command(), "RebootCount 1") {
		t.Errorf("BitLocker is not suspended for exactly one boot: %q", steps[0].Command())
	}
	for _, s := range steps {
		if len(s.ReversalArgv) == 0 {
			t.Errorf("step %q has no reversal; SAFETY.md requires every step to be individually reversible", s.ID)
		}
	}
}

func TestSteps_NoBitLockerStepWhenBitLockerIsOff(t *testing.T) {
	i := intent()
	i.BitLocker = BitLockerOff
	for _, s := range i.Steps() {
		if s.ID == "bitlocker-suspend" {
			t.Fatal("BitLocker was suspended on a machine that does not use it")
		}
	}
}

func TestSteps_NoBootMediaMeansTheFirmwareMenu(t *testing.T) {
	// BootNext is not honoured by every vendor's firmware, so the firmware-menu
	// route is a first-class path rather than an error case.
	i := intent()
	i.BootMediaGUID = ""
	found := false
	for _, s := range i.Steps() {
		if s.ID == "firmware-menu" {
			found = true
		}
		if s.ID == "boot-sequence" {
			t.Error("a boot sequence was set with no boot media")
		}
	}
	if !found {
		t.Fatal("no firmware-menu fallback was planned")
	}
}

func TestSteps_NothingWritesBootMedia(t *testing.T) {
	// DECISIONS.md D13: the Windows side does not write boot media. No raw
	// handle on \\.\PhysicalDriveN, no dismount, no hand-rolled GPT.
	for _, s := range intent().Steps() {
		lower := strings.ToLower(s.Command())
		for _, forbidden := range []string{"physicaldrive", "diskpart", "format", "dd ", "fsutil", "clean"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("step %q runs %q, which writes to a disk: %s", s.ID, forbidden, s.Command())
			}
		}
	}
}

func TestDescribe_ShowsEveryCommandAndItsUndo(t *testing.T) {
	out := intent().Describe()
	for _, s := range intent().Steps() {
		if !strings.Contains(out, s.Command()) {
			t.Errorf("the plan does not show %q", s.Command())
		}
		if !strings.Contains(out, s.Reversal()) {
			t.Errorf("the plan does not show the undo for %q", s.ID)
		}
	}
	if !strings.Contains(out, "does not write boot media") {
		t.Error("the plan does not state that this tool does not write boot media")
	}
}

func TestSteps_IsPure(t *testing.T) {
	// Steps() is what dry-run mode prints, so it must have no side effects and
	// must give the same answer every time.
	i := intent()
	a, b := i.Steps(), i.Steps()
	if len(a) != len(b) {
		t.Fatalf("Steps() is not deterministic: %d vs %d", len(a), len(b))
	}
	for n := range a {
		// DeepEqual rather than a field-by-field comparison: Step grew slice
		// fields (Argv, ReversalArgv) and so stopped being comparable with !=,
		// and the field list this test was narrowed to left Description, Note
		// and Destructive unchecked. Purity means the WHOLE value is the same.
		if !reflect.DeepEqual(a[n], b[n]) {
			t.Errorf("step %d differs between calls:\n  %+v\n  %+v", n, a[n], b[n])
		}
	}
}
