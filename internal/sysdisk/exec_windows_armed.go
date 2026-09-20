//go:build windows && auros_arm_enabled

package sysdisk

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// execute performs the privileged steps in order, and on the first failure runs
// the reversal of every step that already succeeded, in reverse order.
//
// The reversal loop is the reason this function is shaped the way it is.
// SAFETY.md: "Every step is individually reversible, and the reversal is tested
// more than the action." A half-armed machine — BitLocker suspended, boot order
// changed, no restart — is a machine that boots to a recovery prompt the next
// morning, and that is the outcome this unwinds.
//
// This code is UNVALIDATED. It is behind a build tag for that reason. It must
// not be enabled until SPEC §10 gate 3 has been met against a Windows VM.
func execute(ctx context.Context, i Intent) (*Outcome, error) {
	out := &Outcome{}
	steps := i.Steps()
	for _, s := range steps {
		if err := runCommandLine(ctx, s.Command); err != nil {
			out.Failed, out.Err = s.ID, fmt.Errorf("sysdisk: step %s failed: %w", s.ID, err)
			unwind(ctx, steps, out)
			return out, out.Err
		}
		out.Completed = append(out.Completed, s.ID)
	}
	return out, nil
}

// unwind reverses completed steps newest-first. A reversal that itself fails is
// recorded and does not stop the remaining reversals: getting BitLocker back on
// matters more than a tidy error.
func unwind(ctx context.Context, steps []Step, out *Outcome) {
	byID := make(map[string]Step, len(steps))
	for _, s := range steps {
		byID[s.ID] = s
	}
	for n := len(out.Completed) - 1; n >= 0; n-- {
		id := out.Completed[n]
		s, ok := byID[id]
		if !ok || s.Reversal == "" {
			continue
		}
		cmd := s.Reversal
		if idx := strings.Index(cmd, "   ("); idx >= 0 {
			cmd = strings.TrimSpace(cmd[:idx]) // strip the trailing human note
		}
		if err := runCommandLine(ctx, cmd); err != nil {
			out.Reversed = append(out.Reversed, id+" (reversal FAILED: "+err.Error()+")")
			continue
		}
		out.Reversed = append(out.Reversed, id)
	}
}

// runCommandLine splits on spaces deliberately: every command in Steps() is a
// literal built by this package from a volume GUID and a mount point, never from
// user input, and keeping them as readable strings means the string printed in
// dry-run mode is provably the string that runs.
func runCommandLine(ctx context.Context, line string) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return fmt.Errorf("sysdisk: empty command")
	}
	cmd := exec.CommandContext(ctx, fields[0], fields[1:]...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", fields[0], err, strings.TrimSpace(string(b)))
	}
	return nil
}
