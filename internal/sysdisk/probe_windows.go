//go:build windows

package sysdisk

import (
	"context"
	"os/exec"
	"time"
)

// probeBitLocker runs `manage-bde -status <mount>` and parses the result.
//
// This is a READ. It has no build tag because it changes nothing: it does not
// suspend protectors, does not touch firmware variables and does not write to
// the disk. The steps that do change the machine stay behind
// `auros_arm_enabled`, where they belong.
func probeBitLocker(ctx context.Context, mount string) (BitLocker, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "manage-bde", "-status", mount).CombinedOutput()
	if err != nil {
		// manage-bde is absent on Home SKUs and returns non-zero for a volume it
		// does not manage. Either way the honest answer is Unknown, which the
		// planner treats as protected.
		return BitLockerUnknown, err
	}
	return ParseBitLockerStatus(string(out)), nil
}
