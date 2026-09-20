package main

// Shared fixtures for the runner's regression tests.
//
// Every test in this package is an attack that once worked. The fixtures are deliberately VALID —
// a result that passes the schema, carries every postcondition, and agrees with its config — so that
// each test can break exactly one thing and the failure it produces is attributable to that one thing.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

const (
	testSuiteID   = "20260920T101500Z"
	testSysSHA    = "1111111111111111111111111111111111111111111111111111111111111111"
	testDestSHA   = "2222222222222222222222222222222222222222222222222222222222222222"
	testCorpusSHA = "3333333333333333333333333333333333333333333333333333333333333333"
	testArtSHA    = "4444444444444444444444444444444444444444444444444444444444444444"
	testCount     = 18000
	testScope     = "SAFETY.md phases 1-5 (INVENTORY, DISCLOSE, DESTINATION, COPY, VERIFY)."
)

func testConfig() *Config {
	return &Config{
		Base: BaseCfg{
			SystemImage: "/srv/auros/base/windows-base.qcow2", SystemSHA256: testSysSHA,
			SystemVolumeSerial: "AAAA-1111",
			DestImage:          "/srv/auros/base/dest-empty-ntfs.qcow2", DestSHA256: testDestSHA,
			DestVolumeSerial: "BBBB-2222",
			CorpusSeed:       20260920, CorpusProfile: "realistic", CorpusCount: testCount,
			CorpusDigest: testCorpusSHA, CorpusFaithful: true,
			SystemStateSHA256: "deadbeef", WindowsEdition: "Windows 11 Enterprise Evaluation",
			ISOSource: "Microsoft Evaluation Center, downloaded 2026-09-01",
		},
		Host: HostCfg{
			WorkDir: "/srv/auros/work", ArtifactDir: "/srv/auros/artifacts",
			Parallel: 1, MinFreeGB: 40, ReclaimBetweenRuns: true,
		},
		Guest: GuestCfg{
			CorpusRoot: `C:\Users\student`, DestVolume: `E:\`,
			DestDataRoot: `E:\auros-archive\data`, ProgressPath: `E:\auros-progress.ndjson`,
			InstallerManifest: `E:\auros-archive\manifest.jsonl`, MarkerDrive: `X:\`,
		},
		Binaries: BinariesCfg{
			Installer: "../../dist/auros-migrate.exe", FaultAgent: "../../dist/faultagent.exe",
			Gen: "../../dist/gen.exe",
		},
		Mtools:            MtoolsCfg{MkfsVfat: "/usr/sbin/mkfs.vfat", Mcopy: "/usr/bin/mcopy", SizeMB: 256},
		Timeouts:          TimeoutsCfg{RunSec: 5400, BootCheckSec: 600, VerifySec: 3600, NormalBootSeconds: 180},
		InstallerArgs:     []string{"--commit", "--dest", "%DEST%", "--progress", "%PROGRESS%", "--source", "%CORPUS%", "--no-arm"},
		InstallerScope:    testScope,
		MaxOvershootBytes: 4 << 20,
	}
}

func testHostProfile() string { return "parallel=1 reclaim_between_runs=true" }

// goodVerify is a verification that found everything, exactly.
func goodVerify(label string) CorpusVerify {
	return CorpusVerify{
		Label: label, ManifestSHA: testCorpusSHA,
		Expected: testCount, Present: testCount, PresentBytes: 8_400_000_000,
		HashMatches: testCount, Clean: true, Reported: true,
	}
}

func goodBootCheck() *BootCheck {
	return &BootCheck{
		Performed: true, BeaconSeen: true, SecondsToBeacon: 41, TimeoutSeconds: 600,
		SystemStateBefore: "deadbeef", SystemStateAfter: "deadbeef", SystemStateEqual: true,
		Verdict: "pass",
	}
}

// passingResult is a complete, schema-valid, fully-green run.
func passingResult(kind string, ordinal int, scenario string) *RunResult {
	r := &RunResult{
		Harness: runnerVersion, SuiteID: testSuiteID, RunID: runLabel(kind, ordinal, scenario),
		Kind: kind, Ordinal: ordinal, Scenario: scenario,
		HostProfile:   testHostProfile(),
		BaseSystemSHA: testSysSHA, BaseDestSHA: testDestSHA,
		CorpusDigest: testCorpusSHA, CorpusProfile: "realistic", CorpusSeed: 20260920,
		CorpusFiles: testCount, CorpusFaithful: true,
		WindowsEdition: "Windows 11 Enterprise Evaluation",
		ISOSource:      "Microsoft Evaluation Center, downloaded 2026-09-01",
		InstallerScope: testScope,
		StartedAt:      "2026-09-20T10:15:00Z", FinishedAt: "2026-09-20T10:47:00Z", DurationMS: 1_920_000,
		Installer: InstallerOutcome{ExitReported: true, ExitCode: 0},
		Corpus:    goodVerify("source"),
		Archive:   goodVerify("archive"),
		BootCheck: goodBootCheck(),
		Artifacts: []Artifact{{Name: "serial.log", Path: "/srv/auros/artifacts/serial.log", SHA256: testArtSHA, Bytes: 4096}},
	}
	if kind == "fault" {
		sc, err := fault.Lookup(scenario)
		if err != nil {
			panic(err)
		}
		pin := fault.Pin{Phase: sc.Trigger.Phase, BP: sc.Trigger.BP, FileIndex: 7742,
			Path: "Documents/x.docx", WinPath: `C:\Users\student\Documents\x.docx`,
			ByteOffsetInFile: 118243, CumulativeBytes: 3_612_004_182, TotalBytes: 8_400_009_726}
		r.Pin = &pin
		r.Fire = &fault.FireRecord{
			ScenarioID: sc.ID, Fired: true, Pin: pin,
			ObservedBytesDone: pin.CumulativeBytes + 1024, ObservedBytesTotal: pin.TotalBytes,
			ObservedIndex: 7742, ObservedPhase: string(sc.Trigger.Phase), OvershootBytes: 1024,
			DestBytesAtFire: pin.CumulativeBytes, DestFilesAtFire: 7000,
		}
		if sc.ExpectAbort {
			r.Installer = InstallerOutcome{ExitReported: true, ExitCode: 7}
			r.Archive = CorpusVerify{Label: "archive", ManifestSHA: testCorpusSHA,
				Expected: testCount, Present: 7000, PresentBytes: 3_612_004_182,
				HashMatches: 7000, Clean: false, Reported: true}
		}
	}
	for _, id := range requiredChecks(kind) {
		r.check(id, "postcondition "+id, true, "fixture")
	}
	r.Verdict = r.Recompute()
	return r
}

func writeResult(t *testing.T, dir string, r *RunResult) string {
	t.Helper()
	runDir := filepath.Join(dir, r.RunID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(runDir, "result.json")
	if err := os.WriteFile(p, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeSuite lays down nClean clean runs and the named scenarios.
func writeSuite(t *testing.T, dir string, nClean int, scenarios []fault.Scenario) {
	t.Helper()
	for i := 1; i <= nClean; i++ {
		writeResult(t, dir, passingResult("clean", i, ""))
	}
	for i, sc := range scenarios {
		writeResult(t, dir, passingResult("fault", i+1, sc.ID))
	}
}

func writeConfigFile(t *testing.T, cfg *Config) string {
	t.Helper()
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "runner.config.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// reportTemplate is a minimal stand-in for REPORT.md carrying every placeholder the reporter fills.
const reportTemplate = `# evidence
suite {{SUITE_ID}} harness {{HARNESS_VERSION}}
edition {{WINDOWS_EDITION}} iso {{ISO_SOURCE}}
system {{BASE_SYSTEM_SHA}} dest {{BASE_DEST_SHA}}
corpus {{CORPUS_COUNT}} profile {{CORPUS_PROFILE}} seed {{CORPUS_SEED}} digest {{CORPUS_DIGEST}}
host {{HOST_PROFILE}}
scope {{INSTALLER_SCOPE}}
power {{POWER_CUT_NOTE}}
clean {{CLEAN_PASS}}/{{CLEAN_TOTAL}}
fault {{FAULT_PASS}}/{{FAULT_TOTAL}}
{{CLEAN_RUN_ROWS}}
{{FAULT_RUN_ROWS}}
{{SCENARIO_TABLE}}
`

// runReport writes a template, runs cmdReport, and returns the filled output.
func runReport(t *testing.T, cfg *Config, resultsDir string, extra ...string) (string, error) {
	t.Helper()
	tmp := t.TempDir()
	tmplPath := filepath.Join(tmp, "REPORT.md")
	if err := os.WriteFile(tmplPath, []byte(reportTemplate), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(tmp, "REPORT.filled.md")
	args := append([]string{
		"-config", writeConfigFile(t, cfg),
		"-results", resultsDir,
		"-template", tmplPath,
		"-out", outPath,
	}, extra...)
	err := cmdReport(args)
	b, rerr := os.ReadFile(outPath)
	if rerr != nil {
		return "", err
	}
	return string(b), err
}

func countLinesContaining(s, needle string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

func checkStatus(r *RunResult, id string) string {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "(absent)"
}

func mustFail(t *testing.T, r *RunResult, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if got := checkStatus(r, id); got != "fail" {
			t.Errorf("%s: want fail, got %s\n%s", id, got, dumpChecks(r))
		}
	}
}

func mustPass(t *testing.T, r *RunResult, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if got := checkStatus(r, id); got != "pass" {
			t.Errorf("%s: want pass, got %s\n%s", id, got, dumpChecks(r))
		}
	}
}

func dumpChecks(r *RunResult) string {
	var b strings.Builder
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "    %-6s %-5s %s\n", c.ID, c.Status, c.Detail)
	}
	return b.String()
}
