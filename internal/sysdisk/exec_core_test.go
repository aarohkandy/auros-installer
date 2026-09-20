package sysdisk

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The abort path, which had no test at all because the only implementation of it
// lived behind `windows && auros_arm_enabled` — a combination nothing in this
// repository can build. SAFETY.md rule 2: the abort path is tested more than the
// happy path. These are those tests.

// recorder is a stand-in for the process runner. It records every argv it is
// asked to run, fails the step the test names, and — like exec.CommandContext —
// refuses to start anything once its context is done.
type recorder struct {
	ran      [][]string
	failOn   string // first argv element + arg that should fail
	panicOn  string
	onStep   func(argv []string)
	ctxIsDry bool
}

func (r *recorder) run(ctx context.Context, argv []string) error {
	if err := ctx.Err(); err != nil {
		// This is exactly what exec.CommandContext does with a cancelled
		// context: it never starts the process.
		return err
	}
	line := strings.Join(argv, " ")
	if r.onStep != nil {
		r.onStep(argv)
	}
	if r.panicOn != "" && strings.Contains(line, r.panicOn) {
		panic("the machine went away mid-step")
	}
	r.ran = append(r.ran, argv)
	if r.failOn != "" && strings.Contains(line, r.failOn) {
		return errors.New("simulated failure")
	}
	return nil
}

func (r *recorder) didRun(sub string) bool {
	for _, argv := range r.ran {
		if strings.Contains(strings.Join(argv, " "), sub) {
			return true
		}
	}
	return false
}

func armIntent() Intent {
	i := intent()
	i.BootMediaGUID = "" // firmware-menu path: the one that changes the boot order
	return i
}

func TestExecute_CancellationBetweenStepsStillRunsTheReversals(t *testing.T) {
	// The attack: press Ctrl-C during phase 6. Step 1 (bitlocker-suspend)
	// completes, the cancellation arrives, step 2 fails because its context is
	// done — and the old unwind built every reversal from that SAME cancelled
	// context, so not one of them could start a process. BitLocker was left
	// suspended and the boot order left changed: the half-armed machine the
	// unwind exists to prevent, produced by the abort path itself.
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recorder{}
	rec.onStep = func(argv []string) {
		if strings.Contains(strings.Join(argv, " "), "manage-bde -protectors -disable") {
			cancel() // the user hits Ctrl-C the moment step 1 lands
		}
	}

	out, err := executeWith(ctx, armIntent(), rec.run)
	if err == nil {
		t.Fatal("the cancelled run reported success")
	}
	if !rec.didRun("manage-bde -protectors -enable") {
		t.Fatalf("BitLocker was left suspended on a cancelled run; commands run were %v", rec.ran)
	}
	if len(out.Reversed) == 0 {
		t.Error("nothing was recorded as reversed")
	}
	for _, r := range out.Reversed {
		if strings.Contains(r, "FAILED") {
			t.Errorf("a reversal failed on the abort path: %s", r)
		}
	}
}

func TestExecute_AlreadyCancelledContextStillReversesWhatRan(t *testing.T) {
	// The same shape with the cancellation arriving before the call: nothing
	// runs, so there is nothing to reverse, and the function must not claim
	// success.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := &recorder{}
	out, err := executeWith(ctx, armIntent(), rec.run)
	if err == nil {
		t.Fatal("a run on a dead context reported success")
	}
	if len(out.Completed) != 0 {
		t.Errorf("steps completed on a dead context: %v", out.Completed)
	}
}

func TestExecute_FailureUnwindsNewestFirst(t *testing.T) {
	i := armIntent()
	i.Restart = true
	rec := &recorder{failOn: "shutdown /r /t 0"}
	out, err := executeWith(context.Background(), i, rec.run)
	if err == nil {
		t.Fatal("the failing run reported success")
	}
	if out.Failed != "restart" {
		t.Errorf("Failed = %q, want restart", out.Failed)
	}
	want := []string{"firmware-menu", "bitlocker-suspend"}
	if len(out.Reversed) != len(want) {
		t.Fatalf("reversed %v, want %v", out.Reversed, want)
	}
	for n := range want {
		if out.Reversed[n] != want[n] {
			t.Errorf("reversal %d = %q, want %q (newest first)", n, out.Reversed[n], want[n])
		}
	}
}

func TestExecute_PanicUnwindsBeforeItPropagates(t *testing.T) {
	// Arm records the wall as crossed before calling Execute, so a panic that
	// skipped the unwind would leave a machine that boots to a recovery prompt
	// with nothing in the log saying why.
	rec := &recorder{panicOn: "shutdown /r /fw"}
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("the panic did not propagate; a swallowed panic is a silent half-armed machine")
		}
		if !rec.didRun("manage-bde -protectors -enable") {
			t.Fatalf("BitLocker was left suspended after a panic; commands run were %v", rec.ran)
		}
	}()
	_, _ = executeWith(context.Background(), armIntent(), rec.run)
	t.Fatal("unreachable: the panic should have propagated")
}

func TestExecute_HappyPathRunsEveryStepAndReversesNothing(t *testing.T) {
	rec := &recorder{}
	out, err := executeWith(context.Background(), armIntent(), rec.run)
	if err != nil {
		t.Fatalf("executeWith: %v", err)
	}
	if len(out.Reversed) != 0 {
		t.Errorf("a successful run reversed %v", out.Reversed)
	}
	if len(out.Completed) != len(armIntent().Steps()) {
		t.Errorf("completed %v, want every step", out.Completed)
	}
}

// ---------- BitLocker: unknown means protected ----------

func TestSteps_UnknownBitLockerIsTreatedAsProtected(t *testing.T) {
	// winEnv.Firmware() is a stub that returns Known:false on real Windows, so
	// this is the state a 2014 BitLocker laptop actually reaches.
	i := intent()
	i.BitLocker = BitLockerUnknown
	steps := i.Steps()
	if len(steps) == 0 || steps[0].ID != "bitlocker-suspend" {
		t.Fatalf("no suspend was planned for an unchecked machine: %+v", steps)
	}
}

func TestSteps_TheZeroValueIntentPlansTheSuspend(t *testing.T) {
	// A caller that forgets the field must get the safe behaviour. Suspending
	// BitLocker on a machine that is not using it is a no-op; failing to suspend
	// it on a machine that is leaves a school at a recovery prompt.
	var i Intent
	found := false
	for _, s := range i.Steps() {
		if s.ID == "bitlocker-suspend" {
			found = true
		}
	}
	if !found {
		t.Fatal("the zero-value Intent does not plan a BitLocker suspend")
	}
}

func TestBitLocker_OnlyAPositiveOffOmitsTheStep(t *testing.T) {
	if !BitLockerUnknown.SuspendNeeded() {
		t.Error("unknown does not need a suspend")
	}
	if !BitLockerOn.SuspendNeeded() {
		t.Error("on does not need a suspend")
	}
	if BitLockerOff.SuspendNeeded() {
		t.Error("off needs a suspend")
	}
}

// ---------- argv: a mount point with a space is one argument ----------

func TestSteps_AMountPointWithASpaceStaysOneArgument(t *testing.T) {
	// `strings.Fields` on the rendered command handed manage-bde
	// "-disable C:\Program" plus a stray "Files\Data", in the middle of the one
	// phase allowed to change the machine.
	i := intent()
	i.SystemMount = `C:\Program Files\Data`
	steps := i.Steps()
	if steps[0].ID != "bitlocker-suspend" {
		t.Fatalf("first step = %q", steps[0].ID)
	}
	found := false
	for _, a := range steps[0].Argv {
		if a == `C:\Program Files\Data` {
			found = true
		}
	}
	if !found {
		t.Fatalf("the mount point is not a single argument: %q", steps[0].Argv)
	}
	if len(steps[0].Argv) != 6 {
		t.Errorf("argv = %q, want exactly 6 arguments", steps[0].Argv)
	}
}

func TestValidate_RefusesAMountPointThatCannotBeOneArgument(t *testing.T) {
	i := intent()
	i.SystemMount = `C:\Program Files\Data`
	if _, err := Execute(context.Background(), i); !errors.Is(err, ErrBadMount) {
		t.Fatalf("err = %v, want ErrBadMount", err)
	}
}

func TestRunner_ReceivesArgvAndNeverASplitString(t *testing.T) {
	// The displayed command is rendered FROM the argv, so it cannot drift from
	// what runs. The quoted rendering is for humans only.
	i := intent()
	i.SystemMount = `C:\Program Files\Data`
	rec := &recorder{}
	if _, err := executeWith(context.Background(), i, rec.run); err != nil {
		t.Fatal(err)
	}
	for _, argv := range rec.ran {
		for _, a := range argv {
			if strings.HasPrefix(a, `"`) {
				t.Errorf("a quoted display string reached the runner: %q", argv)
			}
		}
	}
	if !rec.didRun(`manage-bde -protectors -disable C:\Program Files\Data -RebootCount 1`) {
		t.Errorf("the suspend did not run against the whole mount point: %v", rec.ran)
	}
	if !strings.Contains(i.Steps()[0].Command(), `"C:\Program Files\Data"`) {
		t.Errorf("the displayed command does not quote the mount point: %s", i.Steps()[0].Command())
	}
}

func TestParseBitLockerStatus_OnlyAPositiveOffIsOff(t *testing.T) {
	cases := map[string]BitLocker{
		"    Protection Status:    Protection On\r\n":  BitLockerOn,
		"    Protection Status:    Protection Off\r\n": BitLockerOff,
		"    Conversion Status:    Fully Decrypted\n":  BitLockerUnknown,
		"":                                    BitLockerUnknown,
		"ERROR: An error occurred (code 0x0)": BitLockerUnknown,
		// A locale or a format this parser does not recognise must NOT read as
		// off. Unknown is treated as protected, which is the safe direction.
		"    Statut de la protection : Protection désactivée\n": BitLockerUnknown,
	}
	for in, want := range cases {
		if got := ParseBitLockerStatus(in); got != want {
			t.Errorf("ParseBitLockerStatus(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestProbeBitLocker_RefusesAMountPointItCannotPassSafely(t *testing.T) {
	if _, err := ProbeBitLocker(context.Background(), `C:\Program Files\Data`); !errors.Is(err, ErrBadMount) {
		t.Fatalf("err = %v, want ErrBadMount", err)
	}
	if got, _ := ProbeBitLocker(context.Background(), ""); got != BitLockerUnknown {
		t.Errorf("an unanswerable probe returned %v, want unknown", got)
	}
}
