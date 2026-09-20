package sysdisk

import (
	"context"
	"fmt"
	"time"
)

// The step loop and the unwind loop live here, with no build tag and no
// dependency on os/exec, so the ABORT PATH IS TESTABLE ON EVERY PLATFORM.
//
// That is not a convenience. SAFETY.md rule 2 says the abort path is tested more
// than the happy path, and before this split the only implementation of the
// unwind lived behind `windows && auros_arm_enabled` — a combination no test in
// this repository can build, which meant the code that puts BitLocker back was
// the one piece of the program nothing had ever run.

// runner performs one step. The real one shells out; tests supply their own.
type runner func(ctx context.Context, argv []string) error

// unwindGrace is how long the reversals get. It is deliberately generous:
// manage-bde on a spinning disk is not fast, and a reversal that times out is a
// machine left half-armed.
const unwindGrace = 60 * time.Second

// executeWith performs the intent's steps in order and, on the first failure,
// reverses every step that already succeeded, newest first.
//
// Two properties the naive version did not have:
//
//   - The reversals DO NOT run on the caller's context. If the user pressed
//     Ctrl-C between step 1 and step 2, that context is already cancelled, and
//     every reversal built from it refuses to start a process — leaving BitLocker
//     suspended and the boot order changed, which is precisely the half-armed
//     machine the unwind exists to prevent. Reversals must survive the event
//     that triggered them, so they run on a context derived with
//     context.WithoutCancel and given its own deadline.
//   - A panic inside a step unwinds before it propagates. Arm has already
//     recorded the wall as crossed by this point; a panic that skipped the
//     unwind would leave a machine that boots to a recovery prompt with nothing
//     in the log saying why.
func executeWith(ctx context.Context, i Intent, run runner) (out *Outcome, err error) {
	out = &Outcome{}
	steps := i.Steps()

	defer func() {
		if r := recover(); r != nil {
			out.Failed = "panic"
			out.Err = fmt.Errorf("sysdisk: panic while arming: %v", r)
			unwind(ctx, steps, out, run)
			panic(r)
		}
	}()

	for _, s := range steps {
		if rerr := run(ctx, s.Argv); rerr != nil {
			out.Failed, out.Err = s.ID, fmt.Errorf("sysdisk: step %s failed: %w", s.ID, rerr)
			unwind(ctx, steps, out, run)
			return out, out.Err
		}
		out.Completed = append(out.Completed, s.ID)
	}
	return out, nil
}

// unwind reverses completed steps newest-first, on a context that cannot already
// be cancelled. A reversal that itself fails is recorded and does not stop the
// remaining reversals: getting BitLocker back on matters more than a tidy error.
func unwind(ctx context.Context, steps []Step, out *Outcome, run runner) {
	if ctx == nil {
		ctx = context.Background()
	}
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unwindGrace)
	defer cancel()

	byID := make(map[string]Step, len(steps))
	for _, s := range steps {
		byID[s.ID] = s
	}
	for n := len(out.Completed) - 1; n >= 0; n-- {
		id := out.Completed[n]
		s, ok := byID[id]
		if !ok || len(s.ReversalArgv) == 0 {
			continue
		}
		if err := run(uctx, s.ReversalArgv); err != nil {
			out.Reversed = append(out.Reversed, id+" (reversal FAILED: "+err.Error()+")")
			continue
		}
		out.Reversed = append(out.Reversed, id)
	}
}
