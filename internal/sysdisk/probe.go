package sysdisk

import (
	"context"
	"errors"
	"strings"
)

// BitLocker detection lives HERE and not in internal/winenv, for the reason the
// wall exists: asking Windows whether BitLocker protects a volume means running
// `manage-bde -status`, and running external commands is confined to this
// package. winenv is the read-only surface; this is the package that is allowed
// to shell out.
//
// The query itself changes nothing. It is a status read, and it is the only way
// a stdlib-only binary can answer a question SAFETY.md requires an answer to
// before phase 6 plans anything. `vssadmin`-style WMI is not available: `wmic`
// is gone from Windows 11 24H2 (DECISIONS.md D14) and there is no C-callable
// entry point for Win32_EncryptableVolume without COM vtable dispatch.

// ErrProbeUnavailable means this platform or this build cannot answer.
var ErrProbeUnavailable = errors.New("sysdisk: BitLocker status cannot be probed on this platform")

// ParseBitLockerStatus reads `manage-bde -status` output.
//
// It is deliberately conservative: anything it does not positively recognise as
// "off" comes back Unknown, which the planner treats as protected. A parser that
// guesses "off" from an unfamiliar locale or an unexpected line is a parser that
// skips the suspend step on a machine that needed it.
func ParseBitLockerStatus(out string) BitLocker {
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(key), "Protection Status") {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(value))
		switch {
		case strings.Contains(v, "protection off"):
			return BitLockerOff
		case strings.Contains(v, "protection on"):
			return BitLockerOn
		}
	}
	return BitLockerUnknown
}

// ProbeBitLocker asks Windows whether BitLocker protects the volume at mount.
// On every other platform, and on any error, it returns BitLockerUnknown — which
// the planner treats as protected.
func ProbeBitLocker(ctx context.Context, mount string) (BitLocker, error) {
	if mount == "" {
		return BitLockerUnknown, ErrProbeUnavailable
	}
	if strings.ContainsAny(mount, " \t\r\n\"'") {
		return BitLockerUnknown, ErrBadMount
	}
	return probeBitLocker(ctx, mount)
}
