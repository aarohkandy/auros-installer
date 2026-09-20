package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// "WINDOWS STILL BOOTS NORMALLY" — the exit condition most likely to be skipped
//
// Spec §6C: twenty induced-failure runs, twenty clean aborts, AND Windows still boots normally every
// time. The last clause is the expensive one. It costs a full Windows boot per run, it is the slowest
// thing in the suite, and it is the check whose absence nobody notices because every other number in
// the report still looks green.
//
// So it is not a flag. There is no --skip-boot-check and no --fast. Four things make skipping it hard:
//
//  1. RunResult.BootCheck is a REQUIRED field in result.schema.json. A result without it does not
//     validate, and the reporter counts anything that does not validate as a failure, never as unknown.
//  2. BootCheck.Performed defaults to false, and false is a fail. Absence is not neutral.
//  3. The verdict in the result file is recomputed by the reporter from the checks, so a harness that
//     wrote "pass" without doing the work would be caught by the thing reading it. (Same discipline as
//     auros-base's tools/gate.mjs, for the same reason.)
//  4. "Boots" is not "the process started": the evidence is a beacon the guest emits after reaching a
//     logged-on session, and its ABSENCE within the timeout is a failure rather than an inconclusive.
//
// The boot check boots the overlay with NOTHING of ours attached — no marker volume, no destination, no
// installer. That is deliberate: a machine that only boots when the harness's disks are present has not
// demonstrated the thing a school's IT person cares about.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// BootReport is the JSON line the bootbeacon service writes to COM1 on every boot. It is produced by
// runner/cmd/bootbeacon, which is installed into the BASE image once and is therefore present on every
// overlay without the harness having to attach anything.
type BootReport struct {
	Version string `json:"version"`
	// BootID increments on each boot, persisted in the guest. It proves this beacon is from THIS boot
	// and not a stale line left in the serial log by the run that came before.
	BootID           int     `json:"boot_id"`
	SecondsSinceBoot float64 `json:"seconds_since_boot"`

	Bugcheck       bool   `json:"bugcheck"`
	BugcheckDetail string `json:"bugcheck_detail,omitempty"`
	// DirtyShutdown is EventLog 6008 / Kernel-Power 41. After a power-cut scenario this is EXPECTED and
	// is not on its own a failure: the machine was switched off mid-write. What must not happen is a
	// bugcheck, a recovery environment, or a blocking chkdsk.
	DirtyShutdown bool `json:"dirty_shutdown"`
	// ChkdskBlockedBoot is the "Checking file system on C:" countdown, logged by Wininit. NTFS
	// self-healing is normal and silent; a scheduled chkdsk that holds the boot is not, and a school's
	// IT person would rightly call that "it did not boot normally".
	ChkdskBlockedBoot   bool `json:"chkdsk_blocked_boot"`
	RecoveryEnvironment bool `json:"recovery_environment"`

	// SystemStateSHA covers the first 1 MiB of PhysicalDrive0 (partition table + boot code), the EFI
	// System Partition's file tree, and the BCD store. It is the machine-checkable form of "the
	// installer did not cross the wall": SAFETY.md phase 6 is the only code permitted to change any of
	// these, and on an aborted run none of it ran.
	SystemStateSHA string `json:"system_state_sha256"`

	BootEntriesAdded []string `json:"boot_entries_added,omitempty"`
	BootNextSet      bool     `json:"boot_next_set"`
}

// BootCheck is what lands in the run result.
type BootCheck struct {
	// Performed false is a FAIL, not a skip. See the package comment above.
	Performed bool `json:"performed"`

	BeaconSeen      bool    `json:"beacon_seen"`
	SecondsToBeacon float64 `json:"seconds_to_beacon"`
	TimeoutSeconds  int     `json:"timeout_seconds"`

	Report *BootReport `json:"report,omitempty"`

	SystemStateBefore string `json:"system_state_sha256_before"`
	SystemStateAfter  string `json:"system_state_sha256_after"`
	SystemStateEqual  bool   `json:"system_state_equal"`

	ScreenshotPath string `json:"screenshot_path,omitempty"`
	SerialLogPath  string `json:"serial_log_path,omitempty"`

	Failures []string `json:"failures,omitempty"`
	// Verdict is recomputed by the reporter from Failures. It is written here for humans.
	Verdict string `json:"verdict"`
}

// Evaluate decides pass or fail. Every rule is binary; "mostly booted" is a fail.
func (b *BootCheck) Evaluate(normalBootSeconds float64) {
	b.Failures = nil
	if !b.Performed {
		b.Failures = append(b.Failures, "the boot check did not run — that is a failure, not a skip")
	}
	if !b.BeaconSeen {
		b.Failures = append(b.Failures,
			fmt.Sprintf("no boot beacon within %d seconds: Windows did not reach a usable session",
				b.TimeoutSeconds))
	}
	if b.Report != nil {
		r := b.Report
		if r.Bugcheck {
			b.Failures = append(b.Failures, "bugcheck on the boot after the run: "+r.BugcheckDetail)
		}
		if r.ChkdskBlockedBoot {
			b.Failures = append(b.Failures,
				"chkdsk held the boot. NTFS self-healing is silent and fine; a blocking file-system check "+
					"is not a normal boot")
		}
		if r.RecoveryEnvironment {
			b.Failures = append(b.Failures, "the machine booted into the Windows Recovery Environment")
		}
		if len(r.BootEntriesAdded) > 0 {
			b.Failures = append(b.Failures,
				"boot entries were added: "+strings.Join(r.BootEntriesAdded, ", ")+
					" — on an aborted run nothing may have crossed the wall (SAFETY.md phase 6)")
		}
		if r.BootNextSet {
			b.Failures = append(b.Failures, "BootNext was set on an aborted run")
		}
		if b.SecondsToBeacon > normalBootSeconds {
			b.Failures = append(b.Failures,
				fmt.Sprintf("boot took %.0fs, over the %.0fs 'normal' ceiling", b.SecondsToBeacon, normalBootSeconds))
		}
	}
	if b.SystemStateBefore != "" && b.SystemStateAfter != "" {
		b.SystemStateEqual = b.SystemStateBefore == b.SystemStateAfter
		if !b.SystemStateEqual {
			b.Failures = append(b.Failures,
				"the system disk's partition table / ESP / BCD changed during an aborted run: "+
					b.SystemStateBefore+" → "+b.SystemStateAfter)
		}
	} else {
		b.Failures = append(b.Failures, "no system-disk state hash to compare: this run proves nothing "+
			"about whether the wall was crossed")
	}
	if len(b.Failures) == 0 {
		b.Verdict = "pass"
	} else {
		b.Verdict = "fail"
	}
}

// awaitBeacon tails the serial log for the bootbeacon line. Returns the report and how long it took.
//
// The serial log is a FILE that QEMU appends to, so this is the same tailing problem the fault injector
// solves, and it is solved the same way: poll, tolerate half-written lines, and treat a timeout as a
// failure rather than as an absence of information.
func awaitBeacon(serialLog string, minBootID int, timeout time.Duration, pollMS int) (*BootReport, float64, error) {
	const marker = "auros-boot-beacon "
	start := time.Now()
	deadline := start.Add(timeout)
	pause := time.Duration(pollMS) * time.Millisecond
	if pause <= 0 {
		pause = 200 * time.Millisecond
	}
	// Re-scanning the whole file on each poll rather than tracking an offset. Serial logs are kilobytes,
	// and offset arithmetic over CRLF line endings is exactly the kind of small wrongness that turns
	// "the beacon never arrived" into a three-hour afternoon.
	for time.Now().Before(deadline) {
		f, err := os.Open(serialLog)
		if err != nil {
			time.Sleep(pause)
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			i := strings.Index(line, marker)
			if i < 0 {
				continue
			}
			var r BootReport
			if err := json.Unmarshal([]byte(strings.TrimSpace(line[i+len(marker):])), &r); err != nil {
				continue // a half-written line; it will be complete on the next pass
			}
			if r.BootID < minBootID {
				// A beacon from an earlier boot, still sitting in the log. Not evidence about this one.
				continue
			}
			f.Close()
			return &r, time.Since(start).Seconds(), nil
		}
		f.Close()
		time.Sleep(pause)
	}
	return nil, time.Since(start).Seconds(), errors.New("no boot beacon before the deadline")
}
