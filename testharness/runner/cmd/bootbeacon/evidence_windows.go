//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount64 = kernel32.NewProc("GetTickCount64")
)

func secondsSinceBoot() float64 {
	ms, _, _ := procGetTickCount64.Call()
	return float64(uint64(ms)) / 1000.0
}

type eventEvidence struct {
	bugcheck       bool
	bugcheckDetail string
	dirtyShutdown  bool
	chkdsk         bool
	recoveryEnv    bool
}

// collectEventEvidence asks the Windows event log the four questions that distinguish "booted" from
// "booted normally".
//
// DirtyShutdown is reported but is NOT on its own a failure: after an induced power cut the machine was
// switched off mid-write and Windows is right to say so. A bugcheck, a blocking chkdsk or the Recovery
// Environment are different — those are a machine that did not come back the way it went away.
func collectEventEvidence() eventEvidence {
	var e eventEvidence
	q := func(log, xpath string) string {
		out, err := exec.Command("wevtutil", "qe", log, "/q:"+xpath, "/c:5", "/rd:true", "/f:text").Output()
		if err != nil {
			return ""
		}
		return string(out)
	}
	// 1001 BugCheck (Microsoft-Windows-WER-SystemErrorReporting), 41 Kernel-Power unexpected loss.
	if s := q("System", "*[System[Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and (EventID=1001)]]"); strings.TrimSpace(s) != "" {
		e.bugcheck = true
		e.bugcheckDetail = firstLine(s)
	}
	if s := q("System", "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and (EventID=41)]]"); strings.TrimSpace(s) != "" {
		e.dirtyShutdown = true
	}
	if s := q("System", "*[System[Provider[@Name='EventLog'] and (EventID=6008)]]"); strings.TrimSpace(s) != "" {
		e.dirtyShutdown = true
	}
	// Wininit logs the autochk transcript when a file-system check actually held the boot. NTFS
	// self-healing does not log here, which is the distinction we want.
	if s := q("Application", "*[System[Provider[@Name='Microsoft-Windows-Wininit'] and (EventID=1001)]]"); strings.TrimSpace(s) != "" {
		e.chkdsk = true
	}
	// A boot into the Recovery Environment is WinPE, not Windows, and WinPE always has its scratch
	// volume mounted with winpeshl on it. If the beacon is running from there, the machine did not come
	// back to Windows — which is precisely the failure §6C's "still boots normally" is asking about.
	if _, err := os.Stat(`X:\Windows\System32\winpeshl.exe`); err == nil {
		e.recoveryEnv = true
	}
	return e
}

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			return l
		}
	}
	return ""
}

var bootEntryRe = regexp.MustCompile(`(?i)^identifier\s+(\{[0-9a-f-]+\}|\{[a-z]+\})`)

// systemState hashes the boot-critical region of the system disk:
//
//	the first 1 MiB of PhysicalDrive0  — protective MBR, GPT header and entries, boot code
//	the full BCD enumeration           — every boot entry and its device
//	the firmware boot manager entry    — boot order, and whether a one-time BootNext is set
//
// SAFETY.md phase 6 changes exactly these three and nothing else changes them. An aborted run that
// reproduces the base image's value has demonstrated it did not cross the wall — which is a much
// stronger statement than "the installer said it aborted".
func systemState() (string, []string, bool, error) {
	h := sha256.New()

	f, err := os.Open(`\\.\PhysicalDrive0`)
	if err != nil {
		return "", nil, false, err
	}
	if _, err := io.CopyN(h, f, 1<<20); err != nil && err != io.EOF {
		f.Close()
		return "", nil, false, err
	}
	f.Close()

	var entries []string
	if out, err := exec.Command("bcdedit", "/enum", "all").Output(); err == nil {
		h.Write(out)
		for _, line := range strings.Split(string(out), "\n") {
			if m := bootEntryRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
				entries = append(entries, m[1])
			}
		}
	}
	bootNext := false
	if out, err := exec.Command("bcdedit", "/enum", "{fwbootmgr}").Output(); err == nil {
		h.Write(out)
		// `bootsequence` is the firmware one-time boot list — BootNext by another name.
		if strings.Contains(strings.ToLower(string(out)), "bootsequence") {
			bootNext = true
		}
	}
	return hex.EncodeToString(h.Sum(nil)), entries, bootNext, nil
}
