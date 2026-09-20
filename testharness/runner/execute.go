package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

func sha256Bytes(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE HARNESS TOKEN — spec §4.7 made structural
//
// Minted fresh per run and written to the marker volume, which is attached READ-ONLY. It names the
// volume serials the harness is allowed to destroy, and every guest-side tool refuses to start without
// it. See fault/guard.go for the reasoning; the short version is that pointing this at a real laptop
// should require deliberate, written, awkward effort rather than a mistyped drive letter.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func mintToken(cfg *Config, suiteID, runID, corpusDigest string) fault.Token {
	return fault.Token{
		Harness:                runnerVersion,
		SuiteID:                suiteID,
		RunID:                  runID,
		BaseImageSHA:           cfg.Base.SystemSHA256,
		TargetVolSerial:        cfg.Base.SystemVolumeSerial,
		DestVolSerial:          cfg.Base.DestVolumeSerial,
		DestroysEverythingHere: true,
		CorpusDigest:           corpusDigest,
		Note: "Minted by runner for a throwaway qcow2 overlay. If you are reading this on a machine you " +
			"care about, something has gone wrong: spec §4.7 forbids testing the migration installer " +
			"against the operator's own machine, and this token is what enforces it.",
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MARKER VOLUME
//
// A small FAT image, labelled AUROS-HARNESS, carrying the token, the golden manifest, the guest
// binaries and the run script. Built with mtools so no root and no loop mount is needed — a harness
// that needs sudo to prepare a test is a harness that gets run less often.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func buildMarker(cfg *Config, imgPath, mode, scenarioID, corpusDigest string, tok fault.Token, allowMissing []string) error {
	sizeMB := cfg.Mtools.SizeMB
	if sizeMB <= 0 {
		sizeMB = 256
	}
	_ = os.Remove(imgPath)
	f, err := os.Create(imgPath)
	if err != nil {
		return err
	}
	if err := f.Truncate(int64(sizeMB) << 20); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if out, err := exec.Command(cfg.Mtools.MkfsVfat, "-F", "32", "-n", "AUROS-HARNESS", imgPath).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.vfat: %v: %s", err, strings.TrimSpace(string(out)))
	}

	stage, err := os.MkdirTemp("", "auros-marker")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)

	tb, _ := json.MarshalIndent(tok, "", "  ")
	if err := os.WriteFile(filepath.Join(stage, "token.json"), tb, 0o644); err != nil {
		return err
	}
	for _, c := range [][2]string{
		{cfg.Binaries.GoldenManifest, "golden-manifest.jsonl"},
		{cfg.Binaries.GoldenMeta, "golden-manifest.meta.json"},
		{cfg.Binaries.CorpusPlan, "corpus-plan.json"},
	} {
		if c[0] == "" {
			continue
		}
		if err := copyFile(c[0], filepath.Join(stage, c[1])); err != nil {
			return err
		}
	}
	binDir := filepath.Join(stage, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}
	for _, c := range [][2]string{
		{cfg.Binaries.Installer, "auros-migrate.exe"},
		{cfg.Binaries.FaultAgent, "faultagent.exe"},
		{cfg.Binaries.Gen, "gen.exe"},
	} {
		if err := copyFile(c[0], filepath.Join(binDir, c[1])); err != nil {
			return err
		}
	}
	script := runScript(cfg, mode, scenarioID, corpusDigest, allowMissing)
	if err := os.WriteFile(filepath.Join(stage, "run.cmd"), []byte(script), 0o644); err != nil {
		return err
	}

	entries, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	for _, e := range entries {
		args := []string{"-i", imgPath}
		if e.IsDir() {
			args = append(args, "-s")
		}
		args = append(args, filepath.Join(stage, e.Name()), "::")
		if out, err := exec.Command(cfg.Mtools.Mcopy, args...).CombinedOutput(); err != nil {
			return fmt.Errorf("mcopy %s: %v: %s", e.Name(), err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("marker input %s: %w", src, err)
	}
	return os.WriteFile(dst, b, 0o644)
}

// runScript generates X:\run.cmd. The base image's startup task runs it if it exists, which is the only
// hook the harness needs inside Windows — no agent to install per run, no network, no WinRM.
//
// CRLF line endings, because cmd.exe is old enough to care.
func runScript(cfg *Config, mode, scenarioID, corpusDigest string, allowMissing []string) string {
	g := cfg.Guest
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\r\n") }

	w("@echo off")
	w("setlocal")
	w("set X=%~d0")
	w("set CTL=" + `\\.\COM2`)
	w("echo beacon run-cmd-started " + mode + " > %CTL%")

	switch mode {
	case "run":
		w("if exist " + g.DestVolume + `auros-release-locks del /q ` + g.DestVolume + "auros-release-locks")
		// Locked files, held by a separate process: a process that has exited holds no handles.
		w(`start "" /B "%X%\bin\gen.exe" hold -plan "%X%\corpus-plan.json" -until ` +
			g.DestVolume + "auros-release-locks")
		if scenarioID != "" {
			w(`start "" /B "%X%\bin\faultagent.exe" ` +
				`-token "%X%\token.json" ` +
				`-corpus-root "` + g.CorpusRoot + `" ` +
				`-dest-volume "` + g.DestVolume + `" ` +
				`-dest-data-root "` + g.DestDataRoot + `" ` +
				`-golden-manifest "%X%\golden-manifest.jsonl" ` +
				`-expect-corpus-digest ` + corpusDigest + ` ` +
				`-progress "` + g.ProgressPath + `" ` +
				`-installer-manifest "` + g.InstallerManifest + `" ` +
				`-scenario ` + scenarioID + ` ` +
				`-control ` + `\\.\COM2`)
			// The agent needs to be tailing before the first byte is copied, or the early pins (F12 at
			// 1%) fire late or not at all.
			w("ping -n 4 127.0.0.1 >nul")
		}
		args := strings.Join(cfg.InstallerArgs, " ")
		args = strings.ReplaceAll(args, "%DEST%", g.DestVolume)
		args = strings.ReplaceAll(args, "%PROGRESS%", g.ProgressPath)
		args = strings.ReplaceAll(args, "%CORPUS%", g.CorpusRoot)
		w(`"%X%\bin\auros-migrate.exe" ` + args)
		w("echo exit %ERRORLEVEL% > %CTL%")
		w("echo done > " + g.DestVolume + "auros-release-locks")
		w("ping -n 3 127.0.0.1 >nul")
		w("shutdown /s /t 0 /f")

	case "verify":
		// Is there an archive on the destination that claims to be complete? On an aborted run there
		// must not be. This is postcondition P5 and it is the Wubi failure in one line.
		w("if exist " + g.DestVolume + `auros-archive\COMPLETE (echo archive-state complete > %CTL%) else (echo archive-state incomplete > %CTL%)`)
		allow := ""
		if len(allowMissing) > 0 {
			allow = ` -allow-missing "` + strings.Join(allowMissing, ",") + `"`
		}
		w(`"%X%\bin\gen.exe" verify -root "` + g.CorpusRoot + `" -manifest "%X%\golden-manifest.jsonl" -out ` +
			g.DestVolume + `auros-verify.json` + allow)
		w("echo verify-begin > %CTL%")
		w("type " + g.DestVolume + "auros-verify.json > %CTL%")
		w("echo verify-end > %CTL%")
		w("shutdown /s /t 0 /f")
	}
	return b.String()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ONE RUN
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func executeRun(cfg *Config, suiteID, outDir, kind string, ordinal int, scenarioID string,
	entries []fault.Entry, corpusDigest string) (*RunResult, error) {

	runID := runLabel(kind, ordinal, scenarioID)
	dir := filepath.Join(outDir, runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	started := time.Now().UTC()

	res := &RunResult{
		Harness:       runnerVersion, SuiteID: suiteID, RunID: runID, Kind: kind, Ordinal: ordinal,
		Scenario:      scenarioID,
		HostProfile:   fmt.Sprintf("parallel=%d reclaim_between_runs=%v", cfg.Host.Parallel, cfg.Host.ReclaimBetweenRuns),
		BaseSystemSHA: cfg.Base.SystemSHA256, BaseDestSHA: cfg.Base.DestSHA256,
		CorpusDigest:  corpusDigest, CorpusProfile: cfg.Base.CorpusProfile,
		CorpusSeed:    cfg.Base.CorpusSeed, CorpusFiles: len(entries),
		StartedAt:     started.Format(time.RFC3339),
	}

	// Before. If the base moved, nothing measured after this point means anything.
	if err := AssertBaseUnchanged(cfg.Base.SystemImage, cfg.Base.SystemSHA256); err != nil {
		return nil, err
	}
	if err := ReclaimDiskGuard(cfg.Host.WorkDir, cfg.Host.MinFreeGB); err != nil {
		return nil, err
	}

	work := filepath.Join(cfg.Host.WorkDir, suiteID, runID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	// Unix socket paths are capped at ~104 bytes, and an artefact directory named after a suite and a
	// run blows straight past that. The sockets live in a short temp directory; nothing durable does.
	sockDir, err := os.MkdirTemp("", "aur")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(sockDir)

	sysOverlay := filepath.Join(work, "system.qcow2")
	destOverlay := filepath.Join(work, "dest.qcow2")
	if err := CreateOverlay(cfg.Qemu.Img, cfg.Base.SystemImage, sysOverlay); err != nil {
		return nil, err
	}
	if err := CreateOverlay(cfg.Qemu.Img, cfg.Base.DestImage, destOverlay); err != nil {
		return nil, err
	}

	var sc fault.Scenario
	var allowMissing []string
	if kind == "fault" {
		sc, err = fault.Lookup(scenarioID)
		if err != nil {
			return nil, err
		}
		pin, perr := fault.ResolvePin(entries, sc.Trigger)
		if perr != nil {
			return nil, perr
		}
		res.Pin = &pin
	}

	tok := mintToken(cfg, suiteID, runID, corpusDigest)
	markerRun := filepath.Join(work, "marker-run.img")
	if err := buildMarker(cfg, markerRun, "run", scenarioID, corpusDigest, tok, nil); err != nil {
		return nil, err
	}

	// ── phase 1: the run itself ───────────────────────────────────────────────────────────────────
	spec := VMSpec{
		QemuBinary:    cfg.Qemu.Binary, Accel: cfg.Qemu.Accel,
		MemoryMB:      cfg.Machine.MemoryMB, CPUs: cfg.Machine.CPUs, Headless: cfg.Machine.Headless,
		SystemOverlay: sysOverlay, DestOverlay: destOverlay, MarkerImage: markerRun,
		QMPSock:       filepath.Join(sockDir, "qmp.sock"),
		ControlSock:   filepath.Join(sockDir, "ctl.sock"),
		SerialLog:     filepath.Join(dir, "serial.log"),
	}
	vm := &VM{}
	if err := vm.Start(spec); err != nil {
		return nil, err
	}
	ctl, err := newControl(filepath.Join(dir, "control.log"))
	if err != nil {
		vm.Close()
		return nil, err
	}
	conn, cerr := vm.Control(time.Duration(cfg.Timeouts.RunSec) * time.Second)
	if cerr == nil {
		go ctl.pump(conn)
	} else {
		res.Notes = append(res.Notes, "control channel never opened: "+cerr.Error())
	}

	// The host-fault dispatcher. It waits for the guest's "fire" line, screenshots the moment, and
	// executes. runDone releases it when the run ends without a fire, so the goroutine does not outlive
	// the run it belongs to — 120 of those would be 120 references to VMs that no longer exist.
	dispatchErr := make(chan error, 1)
	runDone := make(chan struct{})
	hostFired := make(chan fault.Action, 1)
	if kind == "fault" && sc.Site == fault.SiteHost {
		go func() {
			select {
			case f := <-ctl.fire:
				_ = vm.Screendump(filepath.Join(dir, "at-fire.ppm"))
				hostFired <- f.Action
				dispatchErr <- fault.HostDispatch(f, vm)
			case <-runDone:
			}
		}()
	}

	exited, _ := vm.Wait(time.Duration(cfg.Timeouts.RunSec) * time.Second)
	close(runDone)
	if !exited {
		_ = vm.Screendump(filepath.Join(dir, "timeout.ppm"))
		_ = vm.PowerCut()
		res.Installer.Killed = true
		res.Notes = append(res.Notes, fmt.Sprintf(
			"the guest did not power off within %d seconds and was killed", cfg.Timeouts.RunSec))
	}
	select {
	case de := <-dispatchErr:
		if de != nil {
			res.Notes = append(res.Notes, "host fault dispatch: "+de.Error())
		}
	default:
	}
	select {
	case act := <-hostFired:
		// A power cut kills the guest outright: there is no exit code and there never will be, so the
		// result must say the harness ended the run rather than leaving a zero exit code to be read as
		// success by anything downstream.
		if act == fault.ActionPowerCut {
			res.Installer.Killed = true
			res.Notes = append(res.Notes, "the run ended in an induced power cut; no installer exit code exists")
		}
	default:
	}
	fireRec, exitCode, exitSeen, _ := ctl.snapshot()
	ctl.Close()
	vm.Close()

	res.Fire = fireRec
	res.Installer.ExitCode = exitCode
	res.Installer.ExitReported = exitSeen

	if kind == "fault" && sc.DeviatesCorpus && fireRec != nil && fireRec.TargetPath != "" &&
		!strings.HasPrefix(fireRec.TargetPath, "«") {
		// The scenario damaged a source file on purpose. Verification is run against the golden manifest
		// MINUS that file — and the deviation is named in the result, so "zero data loss" never quietly
		// means "zero data loss apart from the ones we caused and did not mention".
		allowMissing = append(allowMissing, fireRec.TargetPath)
		res.Corpus.AllowedDev = allowMissing
	}

	// ── phase 2: THE BOOT CHECK ───────────────────────────────────────────────────────────────────
	// Nothing of ours attached. This is spec §6C's "Windows still boots normally", and it is not
	// optional, not flagged and not skippable. See bootcheck.go.
	res.BootCheck = runBootCheck(cfg, spec, sysOverlay, dir, sockDir)
	res.BootCheck.SystemStateBefore = cfg.Base.SystemStateSHA256
	if res.BootCheck.Report != nil {
		res.BootCheck.SystemStateAfter = res.BootCheck.Report.SystemStateSHA
	}
	res.BootCheck.Evaluate(cfg.Timeouts.NormalBootSeconds)

	// ── phase 3: the verify boot ──────────────────────────────────────────────────────────────────
	markerVerify := filepath.Join(work, "marker-verify.img")
	archiveState := "unknown"
	if err := buildMarker(cfg, markerVerify, "verify", "", corpusDigest, tok, allowMissing); err != nil {
		res.Notes = append(res.Notes, "could not build the verify marker: "+err.Error())
	} else {
		cv, state, verr := runVerifyBoot(cfg, spec, sysOverlay, destOverlay, markerVerify, dir, sockDir)
		if verr != nil {
			res.Notes = append(res.Notes, "verify boot: "+verr.Error())
		}
		if cv != nil {
			cv.AllowedDev = allowMissing
			res.Corpus = *cv
		}
		archiveState = state
	}

	// ── postconditions ────────────────────────────────────────────────────────────────────────────
	applyChecks(cfg, res, kind, sc, archiveState)

	finished := time.Now().UTC()
	res.FinishedAt = finished.Format(time.RFC3339)
	res.DurationMS = finished.Sub(started).Milliseconds()

	// After. A run that wrote through its overlay would be invisible without this.
	if err := AssertBaseUnchanged(cfg.Base.SystemImage, cfg.Base.SystemSHA256); err != nil {
		res.check("P6", "the immutable base image is unchanged after the run", false, err.Error())
	} else {
		res.check("P6", "the immutable base image is unchanged after the run", true, cfg.Base.SystemSHA256)
	}

	res.Artifacts = hashArtifacts(dir)
	res.Verdict = res.Recompute()

	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "result.json"), append(b, '\n'), 0o644); err != nil {
		return nil, err
	}

	// ── reclaim (BLOCKED.md B1) ───────────────────────────────────────────────────────────────────
	if cfg.Host.ReclaimBetweenRuns && !(cfg.Host.KeepOverlayOnFail && res.Verdict != "pass") {
		_ = os.RemoveAll(work)
	}
	return res, nil
}

func runBootCheck(cfg *Config, base VMSpec, sysOverlay, dir, sockDir string) *BootCheck {
	bc := &BootCheck{TimeoutSeconds: cfg.Timeouts.BootCheckSec}
	spec := base
	spec.MarkerImage = ""
	spec.DestOverlay = ""
	spec.SystemOverlay = sysOverlay
	spec.SerialLog = filepath.Join(dir, "bootcheck-serial.log")
	spec.QMPSock = filepath.Join(sockDir, "qmp-boot.sock")
	spec.ControlSock = filepath.Join(sockDir, "ctl-boot.sock")

	vm := &VM{}
	if err := vm.Start(spec); err != nil {
		bc.Performed = true
		bc.Failures = append(bc.Failures, "could not start the boot-check VM: "+err.Error())
		return bc
	}
	defer vm.Close()
	bc.Performed = true
	bc.SerialLogPath = spec.SerialLog

	// A fresh serial log means any beacon in it is from THIS boot, so no boot-id floor is needed.
	rep, secs, err := awaitBeacon(spec.SerialLog, 0, time.Duration(cfg.Timeouts.BootCheckSec)*time.Second, 500)
	bc.SecondsToBeacon = secs
	if err == nil && rep != nil {
		bc.BeaconSeen = true
		bc.Report = rep
	}
	shot := filepath.Join(dir, "bootcheck.ppm")
	if serr := vm.Screendump(shot); serr == nil {
		bc.ScreenshotPath = shot
	}
	return bc
}

func runVerifyBoot(cfg *Config, base VMSpec, sysOverlay, destOverlay, marker, dir, sockDir string) (*CorpusVerify, string, error) {
	spec := base
	spec.SystemOverlay = sysOverlay
	spec.DestOverlay = destOverlay
	spec.MarkerImage = marker
	spec.SerialLog = filepath.Join(dir, "verify-serial.log")
	spec.QMPSock = filepath.Join(sockDir, "qmp-verify.sock")
	spec.ControlSock = filepath.Join(sockDir, "ctl-verify.sock")

	vm := &VM{}
	if err := vm.Start(spec); err != nil {
		return nil, "unknown", err
	}
	defer vm.Close()
	ctlLog := filepath.Join(dir, "verify-control.log")
	ctl, err := newControl(ctlLog)
	if err != nil {
		return nil, "unknown", err
	}
	defer ctl.Close()
	conn, cerr := vm.Control(time.Duration(cfg.Timeouts.VerifySec) * time.Second)
	if cerr != nil {
		return nil, "unknown", cerr
	}
	go ctl.pump(conn)

	if exited, _ := vm.Wait(time.Duration(cfg.Timeouts.VerifySec) * time.Second); !exited {
		_ = vm.PowerCut()
	}
	return parseVerifyLog(ctlLog)
}

// parseVerifyLog pulls `gen verify`'s JSON out of the control log, between the markers the verify script
// writes around it. Indented JSON over a serial line, reassembled: unglamorous, and it means the guest
// needs no extra tool to report a structured result.
func parseVerifyLog(path string) (*CorpusVerify, string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "unknown", err
	}
	text := string(b)
	state := "unknown"
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "archive-state ") {
			state = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "archive-state "))
		}
	}
	i := strings.Index(text, "verify-begin")
	j := strings.Index(text, "verify-end")
	if i < 0 || j < 0 || j <= i {
		return nil, state, fmt.Errorf("no verify result between the markers in %s: the guest did not "+
			"finish re-hashing the corpus, so this run proves nothing about data loss", path)
	}
	body := text[i+len("verify-begin") : j]
	var cv CorpusVerify
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &cv); err != nil {
		return nil, state, fmt.Errorf("verify result did not parse: %w", err)
	}
	cv.Reported = true
	return &cv, state, nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// POSTCONDITIONS
//
// P0 is the one that stops the suite from going quietly green: it asserts the fault actually happened.
// Without it every other check can pass on a run where nothing was induced at all.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func applyChecks(cfg *Config, res *RunResult, kind string, sc fault.Scenario, archiveState string) {
	if kind == "fault" {
		if res.Fire == nil {
			res.check("P0", "the induced fault actually fired at its pin", false,
				"no fire record reached the runner: this run is not evidence of anything")
		} else if err := res.Fire.Valid(); err != nil {
			res.check("P0", "the induced fault actually fired at its pin", false, err.Error())
		} else {
			res.check("P0", "the induced fault actually fired at its pin", true,
				fmt.Sprintf("fired at %d bytes, %d past the pin, in phase %s",
					res.Fire.ObservedBytesDone, res.Fire.OvershootBytes, res.Fire.ObservedPhase))
		}

		if sc.ExpectAbort {
			aborted := res.Installer.Killed || (res.Installer.ExitReported && res.Installer.ExitCode != 0)
			res.check("P1", "the installer aborted", aborted,
				fmt.Sprintf("exit_reported=%v exit=%d killed=%v", res.Installer.ExitReported,
					res.Installer.ExitCode, res.Installer.Killed))
			res.check("P5", "no archive claims to be complete after an abort", archiveState != "complete",
				"archive-state="+archiveState)
		} else {
			// F10, F17, F18: the correct behaviour is to keep going. A tool that aborts on a clock jump
			// is a tool a school works around, and a tool that is worked around protects nobody.
			ok := res.Installer.ExitReported && res.Installer.ExitCode == 0
			res.check("P1", "the installer continued, as this scenario requires", ok,
				fmt.Sprintf("exit_reported=%v exit=%d", res.Installer.ExitReported, res.Installer.ExitCode))
		}
	} else {
		res.check("P1", "the installer completed successfully",
			res.Installer.ExitReported && res.Installer.ExitCode == 0,
			fmt.Sprintf("exit_reported=%v exit=%d", res.Installer.ExitReported, res.Installer.ExitCode))
		res.check("P5", "the archive is marked complete", archiveState == "complete",
			"archive-state="+archiveState)
	}

	bc := res.BootCheck
	res.check("P3", "Windows still boots normally", bc != nil && bc.Verdict == "pass",
		bootDetail(bc))
	res.check("P2", "the system disk's boot-critical region is byte-identical",
		bc != nil && bc.SystemStateEqual,
		fmt.Sprintf("before=%s after=%s", safeStr(bc, true), safeStr(bc, false)))

	cv := res.Corpus
	res.check("P4", "zero files lost, zero corrupted",
		cv.Reported && cv.Clean && cv.HashMatches+len(cv.AllowedDev) >= cv.Expected,
		fmt.Sprintf("reported=%v expected=%d hash_ok=%d missing=%d corrupt=%d allowed_deviations=%d",
			cv.Reported, cv.Expected, cv.HashMatches, len(cv.Missing), len(cv.Corrupt), len(cv.AllowedDev)))

	res.check("P7", "the corpus tested was the one this suite claims", res.CorpusDigest == cfg.Base.CorpusDigest,
		"corpus_digest="+res.CorpusDigest)
}

func bootDetail(bc *BootCheck) string {
	if bc == nil {
		return "the boot check did not run — a failure, not a skip"
	}
	if len(bc.Failures) > 0 {
		return strings.Join(bc.Failures, "; ")
	}
	return fmt.Sprintf("beacon after %.0fs", bc.SecondsToBeacon)
}

func safeStr(bc *BootCheck, before bool) string {
	if bc == nil {
		return "(none)"
	}
	if before {
		return bc.SystemStateBefore
	}
	return bc.SystemStateAfter
}

// hashArtifacts records every file the run produced with its size and SHA-256, so REPORT.md can cite a
// digest for each run rather than a sentence saying the run happened.
func hashArtifacts(dir string) []Artifact {
	var out []Artifact
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "result.json" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		sum, err := FileSHA256(p)
		if err != nil {
			continue
		}
		out = append(out, Artifact{Name: e.Name(), Path: p, SHA256: sum, Bytes: info.Size()})
	}
	return out
}
