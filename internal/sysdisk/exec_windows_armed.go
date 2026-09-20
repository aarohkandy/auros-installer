//go:build windows && auros_arm_enabled

package sysdisk

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// execute is the privileged implementation. All of its logic — the step order,
// the failure handling and the unwind — lives in exec_core.go, which has no
// build tag and is therefore covered by tests on every platform. What is behind
// the tag is only the part that actually starts a process.
//
// This code is UNVALIDATED. It is behind a build tag for that reason. It must
// not be enabled until SPEC §10 gate 3 has been met against a Windows VM.
func execute(ctx context.Context, i Intent) (*Outcome, error) {
	return executeWith(ctx, i, runArgv)
}

// runArgv runs one argument vector. There is no string splitting anywhere in
// this path: the argv the plan showed the user is the argv exec receives, so a
// mount point containing a space is one argument rather than two.
func runArgv(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("sysdisk: empty command")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", argv[0], err, strings.TrimSpace(string(b)))
	}
	return nil
}
