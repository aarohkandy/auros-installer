package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

// ExitTokenRefused is the exit code the run script reports when the §4.7 token check refuses the
// volumes. It is outside anything the installer can return, so "the harness would not let the run
// start" can never be read as "the installer aborted", which is a pass for an abort scenario.
const ExitTokenRefused = 90

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
		// ── spec §4.7, on ALL 120 runs ────────────────────────────────────────────────────────────
		//
		// This check used to be reachable only on the twenty fault runs, because faultagent was the
		// only component that calls fault.AssertScratch and it was started only when a scenario was
		// named. The hundred clean runs launched `gen hold` and the installer with nothing consulting
		// the harness token at all — so the guard the README presents as the reason you cannot point
		// this at your own laptop was exercised on one run in six.
		//
		// It runs SYNCHRONOUSLY and the script halts on a refusal. Backgrounding it would put the
		// refusal in a window nobody reads, and a guard whose refusal does not stop the run is a log
		// line, not a guard.
		w(`"%X%\bin\faultagent.exe" -check-token-only ` +
			`-token "%X%\token.json" ` +
			`-corpus-root "` + g.CorpusRoot + `" ` +
			`-dest-volume "` + g.DestVolume + `"`)
		w("if errorlevel 1 goto :refused")

		w("if exist " + g.DestVolume + `auros-release-locks del /q ` + g.DestVolume + "auros-release-locks")
		// Locked files, held by a separate process: a process that has exited holds no handles. It is
		// given the token and the root for the same reason as everything else here — `gen hold` opens
		// exclusive handles on whatever its plan names.
		w(`start "" /B "%X%\bin\gen.exe" hold -plan "%X%\corpus-plan.json" ` +
			`-token "%X%\token.json" -root "` + g.CorpusRoot + `" -until ` +
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
				`-max-overshoot-bytes ` + strconv.FormatInt(cfg.maxOvershoot(), 10) + ` ` +
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
		w("goto :finish")

		w(":refused")
		w("echo beacon harness-token-refused > %CTL%")
		// A distinct, impossible-for-the-installer exit code, so a refused run can never be confused
		// with an installer that aborted for a reason of its own.
		w("echo exit " + strconv.Itoa(ExitTokenRefused) + " > %CTL%")

		w(":finish")
		w("ping -n 3 127.0.0.1 >nul")
		w("shutdown /s /t 0 /f")

	case "verify":
		// Is there an archive on the destination that claims to be complete? On an aborted run there
		// must not be. That is the COMPLETE marker, and it is the SUBJECT'S OPINION of itself: the
		// thing under test writes it. It is recorded as a cross-check (P5) and it is not evidence.
		w("if exist " + g.DestVolume + `auros-archive\COMPLETE (echo archive-state complete > %CTL%) else (echo archive-state incomplete > %CTL%)`)
		allow := ""
		if len(allowMissing) > 0 {
			allow = ` -allow-missing "` + strings.Join(allowMissing, ",") + `"`
		}
		// TWO verifications, and the second one is the one §4.1 actually asks for.
		//
		//   source  — the corpus on C: still hashes to the golden manifest. This is "the installer did
		//             not damage the original", and on a clean run phases 1-5 are read-only with
		//             respect to C:, so it passes trivially.
		//   archive — the tree the installer materialised on the destination hashes to the golden
		//             manifest, file for file. This is "the data exists in two places and the second
		//             copy has been verified by count and hash", computed by re-reading raw bytes.
		//
		// Without the second one, an installer that writes nothing to the destination, emits a
		// well-formed progress log, exits 0 and touches COMPLETE scores 100/100.
		//
		// -stdout-json straight down the serial line rather than via a file on the destination: a
		// scenario that has just filled or detached that volume would otherwise take the report about
		// itself down with it.
		w(`"%X%\bin\gen.exe" verify -label source -stdout-json -root "` + g.CorpusRoot +
			`" -manifest "%X%\golden-manifest.jsonl"` + allow + ` > %CTL%`)
		w(`"%X%\bin\gen.exe" verify -label archive -stdout-json -root "` + g.DestDataRoot +
			`" -manifest "%X%\golden-manifest.jsonl"` + allow + ` > %CTL%`)
		w("echo beacon verify-complete > %CTL%")
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
		Harness: runnerVersion, SuiteID: suiteID, RunID: runID, Kind: kind, Ordinal: ordinal,
		Scenario:    scenarioID,
		HostProfile: fmt.Sprintf("parallel=%d reclaim_between_runs=%v", cfg.Host.Parallel, cfg.Host.ReclaimBetweenRuns),
		// Provenance is recorded HERE, at run time, from the config this run actually used. The report
		// then reads it back out of the results and cross-checks them against each other, instead of
		// reprinting whatever the config file says at report time — which is a claim about a file, not
		// about the runs.
		BaseSystemSHA:  cfg.Base.SystemSHA256,
		BaseDestSHA:    cfg.Base.DestSHA256,
		CorpusDigest:   corpusDigest,
		CorpusProfile:  cfg.Base.CorpusProfile,
		CorpusSeed:     cfg.Base.CorpusSeed,
		CorpusFiles:    len(entries),
		CorpusFaithful: cfg.Base.CorpusFaithful,
		WindowsEdition: cfg.Base.WindowsEdition,
		ISOSource:      cfg.Base.ISOSource,
		InstallerScope: cfg.InstallerScope,
		StartedAt:      started.Format(time.RFC3339),
	}

	// abandon records the failure INTO the run's result file and returns it.
	//
	// Every error path below used to `return nil, err` and write nothing. A run that crashed was then
	// not a failure, it was invisible: `runner report` counts result.json files that happen to exist,
	// so forty runs that never started produced a report saying "60/60 clean". A run that could not
	// finish is a failed run, and it has to leave the same kind of artefact behind as any other.
	abandon := func(id, name string, cause error) (*RunResult, error) {
		res.check(id, name, false, cause.Error())
		res.Notes = append(res.Notes, "the run was abandoned: "+cause.Error())
		res.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		res.DurationMS = time.Since(started).Milliseconds()
		res.Artifacts = hashArtifacts(dir)
		res.Verdict = res.Recompute()
		b, _ := json.MarshalIndent(res, "", "  ")
		if werr := os.WriteFile(filepath.Join(dir, "result.json"), append(b, '\n'), 0o644); werr != nil {
			return res, fmt.Errorf("%w (and the result file could not be written: %v)", cause, werr)
		}
		return res, cause
	}

	// Before. If either base moved, nothing measured after this point means anything. BOTH images:
	// a destination base that is no longer empty makes a broken copy look complete.
	if err := AssertBasesUnchanged(cfg); err != nil {
		return abandon("E1", "both base images were unchanged when the run started", err)
	}
	if err := ReclaimDiskGuard(cfg.Host.WorkDir, cfg.Host.MinFreeGB); err != nil {
		return abandon("E2", "the host had room for this run", err)
	}

	work := filepath.Join(cfg.Host.WorkDir, suiteID, runID)
	if err := os.MkdirAll(work, 0o755); err != nil {
		return abandon("E3", "the run's working directory was created", err)
	}
	// Unix socket paths are capped at ~104 bytes, and an artefact directory named after a suite and a
	// run blows straight past that. The sockets live in a short temp directory; nothing durable does.
	sockDir, err := os.MkdirTemp("", "aur")
	if err != nil {
		return abandon("E4", "a socket directory was created for this run", err)
	}
	defer os.RemoveAll(sockDir)

	sysOverlay := filepath.Join(work, "system.qcow2")
	destOverlay := filepath.Join(work, "dest.qcow2")
	if err := CreateOverlay(cfg.Qemu.Img, cfg.Base.SystemImage, sysOverlay); err != nil {
		return abandon("E5", "a fresh system overlay was created over the immutable base", err)
	}
	if err := CreateOverlay(cfg.Qemu.Img, cfg.Base.DestImage, destOverlay); err != nil {
		return abandon("E5", "a fresh destination overlay was created over the immutable base", err)
	}

	var sc fault.Scenario
	var allowMissing []string
	if kind == "fault" {
		sc, err = fault.Lookup(scenarioID)
		if err != nil {
			return abandon("E6", "the scenario exists in the catalogue", err)
		}
		pin, perr := fault.ResolvePin(entries, sc.Trigger)
		if perr != nil {
			return abandon("E6", "the scenario's trigger resolved to a pin", perr)
		}
		res.Pin = &pin
	}

	tok := mintToken(cfg, suiteID, runID, corpusDigest)
	markerRun := filepath.Join(work, "marker-run.img")
	if err := buildMarker(cfg, markerRun, "run", scenarioID, corpusDigest, tok, nil); err != nil {
		return abandon("E7", "the marker volume was built", err)
	}

	// ── phase 1: the run itself ───────────────────────────────────────────────────────────────────
	spec := VMSpec{
		QemuBinary: cfg.Qemu.Binary, Accel: cfg.Qemu.Accel,
		MemoryMB: cfg.Machine.MemoryMB, CPUs: cfg.Machine.CPUs, Headless: cfg.Machine.Headless,
		SystemOverlay: sysOverlay, DestOverlay: destOverlay, MarkerImage: markerRun,
		QMPSock:     filepath.Join(sockDir, "qmp.sock"),
		ControlSock: filepath.Join(sockDir, "ctl.sock"),
		SerialLog:   filepath.Join(dir, "serial.log"),
	}
	vm := &VM{}
	if err := vm.Start(spec); err != nil {
		return abandon("E8", "the run's virtual machine started", err)
	}
	ctl, err := newControl(filepath.Join(dir, "control.log"))
	if err != nil {
		vm.Close()
		return abandon("E9", "the control log was opened", err)
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
		// NOT an abort. See InstallerOutcome and postcondition P9: the harness giving up on a guest
		// that never finished is the harness's act, not the installer's.
		res.Installer.KilledByTimeout = true
		res.Installer.TimeoutNote = fmt.Sprintf(
			"the guest did not power off within %d seconds and was killed by the harness", cfg.Timeouts.RunSec)
		res.Notes = append(res.Notes, res.Installer.TimeoutNote)
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
			res.Installer.KilledByPowerCut = true
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
		src, arc, state, verr := runVerifyBoot(cfg, spec, sysOverlay, destOverlay, markerVerify, dir, sockDir)
		if verr != nil {
			res.Notes = append(res.Notes, "verify boot: "+verr.Error())
		}
		if src != nil {
			src.AllowedDev = allowMissing
			res.Corpus = *src
		}
		if arc != nil {
			arc.AllowedDev = allowMissing
			res.Archive = *arc
		}
		archiveState = state
	}

	// ── postconditions ────────────────────────────────────────────────────────────────────────────
	applyChecks(cfg, res, kind, sc, archiveState)

	finished := time.Now().UTC()
	res.FinishedAt = finished.Format(time.RFC3339)
	res.DurationMS = finished.Sub(started).Milliseconds()

	// After. A run that wrote through its overlay would be invisible without this — and so would an
	// operator who edited a base image at run 40, or a stray `qemu-img commit`. BOTH images: the
	// destination base used to be hashed once per suite, before run 1, so "every run starts with a
	// genuinely empty destination" was verified for one run in a hundred and twenty.
	if err := AssertBasesUnchanged(cfg); err != nil {
		res.check("P6", "both immutable base images are unchanged after the run", false, err.Error())
	} else {
		res.check("P6", "both immutable base images are unchanged after the run", true,
			"system="+shortSHA(cfg.Base.SystemSHA256)+" dest="+shortSHA(cfg.Base.DestSHA256))
	}

	res.Artifacts = hashArtifacts(dir)
	res.Verdict = res.Recompute()

	b, _ := json.MarshalIndent(res, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "result.json"), append(b, '\n'), 0o644); err != nil {
		return res, err
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

// runVerifyBoot re-attaches everything and re-hashes BOTH trees: the source corpus on C: and the
// archive the installer materialised on the destination. It returns them separately because they answer
// different questions and conflating them is how a harness ends up measuring the source twice.
func runVerifyBoot(cfg *Config, base VMSpec, sysOverlay, destOverlay, marker, dir, sockDir string) (
	source, archive *CorpusVerify, archiveState string, err error) {
	spec := base
	spec.SystemOverlay = sysOverlay
	spec.DestOverlay = destOverlay
	spec.MarkerImage = marker
	spec.SerialLog = filepath.Join(dir, "verify-serial.log")
	spec.QMPSock = filepath.Join(sockDir, "qmp-verify.sock")
	spec.ControlSock = filepath.Join(sockDir, "ctl-verify.sock")

	vm := &VM{}
	if serr := vm.Start(spec); serr != nil {
		return nil, nil, "unknown", serr
	}
	defer vm.Close()
	ctlLog := filepath.Join(dir, "verify-control.log")
	ctl, cerr0 := newControl(ctlLog)
	if cerr0 != nil {
		return nil, nil, "unknown", cerr0
	}
	defer ctl.Close()
	conn, cerr := vm.Control(time.Duration(cfg.Timeouts.VerifySec) * time.Second)
	if cerr != nil {
		return nil, nil, "unknown", cerr
	}
	go ctl.pump(conn)

	if exited, _ := vm.Wait(time.Duration(cfg.Timeouts.VerifySec) * time.Second); !exited {
		_ = vm.PowerCut()
	}
	return parseVerifyLogs(ctlLog)
}

// parseVerifyLogs pulls `gen verify`'s JSON blocks out of the control log.
//
// There are TWO of them per verify boot, labelled `source` and `archive`, and they are matched by their
// label rather than by the order they arrive in. Two structurally identical JSON objects told apart by
// position is precisely how a harness ends up verifying the source twice and filing the second one as
// the destination — which is the shape of the bug this whole function exists to close.
//
// A block that is absent is a MEASUREMENT THAT DID NOT HAPPEN, and it is returned as nil so the
// postconditions fail rather than reading a zero-valued struct as "nothing wrong was found".
func parseVerifyLogs(path string) (source, archive *CorpusVerify, archiveState string, err error) {
	b, rerr := os.ReadFile(path)
	if rerr != nil {
		return nil, nil, "unknown", rerr
	}
	archiveState = "unknown"
	lines := strings.Split(string(b), "\n")

	var capturing string
	var buf []string
	take := func(label string, body string) error {
		var cv CorpusVerify
		if uerr := json.Unmarshal([]byte(strings.TrimSpace(body)), &cv); uerr != nil {
			return fmt.Errorf("the %s verify result did not parse: %w", label, uerr)
		}
		cv.Reported = true
		switch label {
		case "source":
			source = &cv
		case "archive":
			archive = &cv
		}
		return nil
	}

	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if strings.HasPrefix(line, "archive-state ") {
			archiveState = strings.TrimSpace(strings.TrimPrefix(line, "archive-state "))
			continue
		}
		if capturing == "" {
			if rest, ok := strings.CutPrefix(line, "verify-begin "); ok {
				capturing = strings.TrimSpace(rest)
				buf = buf[:0]
			}
			continue
		}
		if rest, ok := strings.CutPrefix(line, "verify-end "); ok {
			if strings.TrimSpace(rest) != capturing {
				return source, archive, archiveState, fmt.Errorf(
					"verify log: a %q block was closed by an %q marker", capturing, strings.TrimSpace(rest))
			}
			if terr := take(capturing, strings.Join(buf, "\n")); terr != nil {
				return source, archive, archiveState, terr
			}
			capturing = ""
			continue
		}
		buf = append(buf, line)
	}
	if capturing != "" {
		return source, archive, archiveState, fmt.Errorf(
			"verify log: the %q block never closed — the guest did not finish re-hashing it", capturing)
	}
	switch {
	case source == nil && archive == nil:
		return nil, nil, archiveState, fmt.Errorf("no verify result in %s: the guest did not re-hash "+
			"anything, so this run proves nothing about data loss", path)
	case source == nil:
		return nil, archive, archiveState, fmt.Errorf("the SOURCE verification is missing from %s: this "+
			"run proves nothing about whether the installer damaged the original", path)
	case archive == nil:
		return source, nil, archiveState, fmt.Errorf("the ARCHIVE verification is missing from %s: this "+
			"run proves nothing about whether the second copy exists, which is the half of spec §4.1 "+
			"that the COMPLETE marker cannot answer", path)
	}
	return source, archive, archiveState, nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// POSTCONDITIONS
//
// P0 is the one that stops the suite from going quietly green: it asserts the fault actually happened.
// Without it every other check can pass on a run where nothing was induced at all.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func applyChecks(cfg *Config, res *RunResult, kind string, sc fault.Scenario, archiveState string) {
	// ── P0 — the induced fault actually fired AT ITS PIN ──────────────────────────────────────────
	if kind == "fault" {
		if res.Fire == nil {
			res.check("P0", "the induced fault actually fired at its pin", false,
				"no fire record reached the runner: this run is not evidence of anything")
		} else if err := res.Fire.Valid(sc, cfg.maxOvershoot()); err != nil {
			res.check("P0", "the induced fault actually fired at its pin", false, err.Error())
		} else {
			res.check("P0", "the induced fault actually fired at its pin", true,
				fmt.Sprintf("fired at %d bytes, %d past the pin, in phase %s; destination held %d bytes "+
					"in %d files at that instant (%s)",
					res.Fire.ObservedBytesDone, res.Fire.OvershootBytes, res.Fire.ObservedPhase,
					res.Fire.DestBytesAtFire, res.Fire.DestFilesAtFire, res.Fire.DestScanNote))
		}
	}

	// ── P1 — the installer did what this scenario requires ────────────────────────────────────────
	expectContinue := kind == "clean" || (kind == "fault" && !sc.ExpectAbort)
	if expectContinue {
		name := "the installer completed successfully"
		if kind == "fault" {
			name = "the installer continued, as this scenario requires"
		}
		res.check("P1", name, res.Installer.ExitReported && res.Installer.ExitCode == 0,
			res.Installer.describe())
	} else {
		// An abort is the INSTALLER ending the run: either it reported a non-zero exit, or the fault we
		// induced was a power cut, which by construction leaves no exit code and never will.
		//
		// What is NOT an abort, and what this used to count as one: the harness killing a guest that
		// hung past the run timeout. An installer with no abort path at all — one that deadlocks on the
		// ENOSPC, blocks on the yanked USB, spins on the locked file — reaches this line having done
		// nothing, and scored a clean abort on all sixteen abort scenarios. There is no field here that
		// means both any more; see InstallerOutcome.
		aborted := res.Installer.KilledByPowerCut ||
			(res.Installer.ExitReported && res.Installer.ExitCode != 0)
		res.check("P1", "the installer aborted", aborted, res.Installer.describe())
	}

	// ── P2 / P3 — the wall, and the machine afterwards ────────────────────────────────────────────
	bc := res.BootCheck
	res.check("P3", "Windows still boots normally", bc != nil && bc.Verdict == "pass", bootDetail(bc))
	res.check("P2", "the system disk's boot-critical region is byte-identical",
		bc != nil && bc.SystemStateEqual,
		fmt.Sprintf("before=%s after=%s", safeStr(bc, true), safeStr(bc, false)))

	// ── P4 — the SOURCE is intact ─────────────────────────────────────────────────────────────────
	//
	// Every term below used to come out of the guest's own JSON, compared only against itself:
	// `hash_matches >= expected_files`, where `expected_files` was whatever the guest said it expected.
	// A guest verifying against a twelve-entry manifest reported 12/12 clean and scored a green tick
	// under a heading that says eighteen thousand. So the count is now pinned to the config, the
	// manifest the guest verified against is pinned to the one the pins were computed from, and the
	// comparison is equality rather than "at least".
	cv := res.Corpus
	p4 := cv.Reported && cv.Clean &&
		cv.Expected == cfg.Base.CorpusCount &&
		cv.Expected == res.CorpusFiles &&
		cv.ManifestSHA == res.CorpusDigest &&
		cv.HashMatches+len(cv.AllowedDev) == cv.Expected
	res.check("P4", "zero files lost, zero corrupted", p4,
		fmt.Sprintf("reported=%v clean=%v expected=%d (config says %d, manifest has %d) hash_ok=%d "+
			"missing=%d corrupt=%d allowed_deviations=%d manifest_sha256=%s (corpus digest %s)",
			cv.Reported, cv.Clean, cv.Expected, cfg.Base.CorpusCount, res.CorpusFiles, cv.HashMatches,
			len(cv.Missing), len(cv.Corrupt), len(cv.AllowedDev), shortSHA(cv.ManifestSHA),
			shortSHA(res.CorpusDigest)))

	// ── P8 — the SECOND COPY exists, measured from raw bytes ──────────────────────────────────────
	//
	// Spec §4.1: "there must be a moment where the data exists in two places and the second copy has
	// been verified by file count and hash". P4 measures place one. Until this check existed, place two
	// was taken entirely on the installer's word — the only destination-side evidence in the whole
	// harness was `if exist E:\auros-archive\COMPLETE`, a marker written by the thing under test.
	// "100/100 clean migrations" was fully compatible with 18,000 files of total destination data loss.
	av := res.Archive
	archiveMatches := av.Reported && av.Clean &&
		av.Expected == cfg.Base.CorpusCount &&
		av.Expected == res.CorpusFiles &&
		av.ManifestSHA == res.CorpusDigest &&
		av.HashMatches+len(av.AllowedDev) == av.Expected
	archiveDetail := fmt.Sprintf("reported=%v clean=%v expected=%d present=%d present_bytes=%d "+
		"hash_ok=%d missing=%d corrupt=%d allowed_deviations=%d manifest_sha256=%s",
		av.Reported, av.Clean, av.Expected, av.Present, av.PresentBytes, av.HashMatches,
		len(av.Missing), len(av.Corrupt), len(av.AllowedDev), shortSHA(av.ManifestSHA))
	if expectContinue {
		res.check("P8", "the archive on the destination matches the golden manifest by count and "+
			"per-file hash", archiveMatches, archiveDetail)
	} else {
		// An aborted run's archive is legitimately partial — that is what an abort means. What is NOT
		// legitimate is not having looked: an unmeasured destination is how a harness convinces itself
		// that an installer which never wrote anything was interrupted while writing.
		res.check("P8", "the archive on the destination was measured from raw bytes after the abort",
			av.Reported, archiveDetail)
	}

	// ── P5 — the COMPLETE marker tells the truth ──────────────────────────────────────────────────
	//
	// The marker is the subject's opinion of itself, so it is checked AGAINST the measurement rather
	// than instead of it. On an abort it must be absent. On a run that claims success it must be
	// present AND the archive must actually match.
	markerComplete := archiveState == "complete"
	if expectContinue {
		res.check("P5", "the COMPLETE marker is present and the archive it claims for really matches",
			markerComplete && archiveMatches, "archive-state="+archiveState+"; "+archiveDetail)
	} else {
		res.check("P5", "no archive claims to be complete after an abort", !markerComplete,
			"archive-state="+archiveState)
	}

	// ── P7 — the corpus is the one this suite names ───────────────────────────────────────────────
	res.check("P7", "the corpus tested was the one this suite claims",
		res.CorpusDigest == cfg.Base.CorpusDigest && res.CorpusDigest != "",
		"corpus_digest="+res.CorpusDigest)

	// ── P9 — the run ended on its own ─────────────────────────────────────────────────────────────
	//
	// The run timeout is the harness giving up, and until this check existed it was recorded only in
	// res.Notes, which nothing read. A hung guest, a bluescreened guest and a run script that died
	// before its `echo exit` line all arrive here indistinguishable from a tidy finish.
	res.check("P9", "the guest finished the run on its own; the harness did not have to kill it",
		!res.Installer.KilledByTimeout, res.Installer.TimeoutNote)
}

func shortSHA(s string) string {
	if len(s) <= 16 {
		if s == "" {
			return "(none)"
		}
		return s
	}
	return s[:16] + "…"
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
