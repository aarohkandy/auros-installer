package main

// The guest-side contract: what X:\run.cmd actually does, and what the runner will accept back from it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// MINOR, execute.go:158 — "ask which of the 120 runs actually exercise the §4.7 guard." Twenty.
// faultagent was the only component calling fault.AssertScratch and it was started only when a
// scenario was named, so the hundred clean runs consulted the harness token nowhere at all.
func TestCleanRunScriptRefusesWithoutTheHarnessToken(t *testing.T) {
	cfg := testConfig()
	script := runScript(cfg, "run", "", testCorpusSHA, nil)
	if !strings.Contains(script, "-check-token-only") {
		t.Fatal("a clean run never checks the §4.7 harness token: README §1 describes a guard that is " +
			"absent from five sixths of the suite")
	}
	if !strings.Contains(script, "if errorlevel 1 goto :refused") {
		t.Fatal("the token check must HALT the run; a guard whose refusal does not stop anything is a " +
			"log line, not a guard")
	}
	if !strings.Contains(script, ":refused") || !strings.Contains(script, "echo exit 90") {
		t.Fatal("a refused run must report a distinct exit code, or it is indistinguishable from an " +
			"installer that aborted for a reason of its own")
	}
	// Synchronous, not backgrounded: a `start /B`'d guard cannot fail a run.
	for _, line := range strings.Split(script, "\r\n") {
		if strings.Contains(line, "-check-token-only") && strings.Contains(line, "start ") {
			t.Fatalf("the token check is backgrounded, so its refusal is unreachable: %q", line)
		}
	}
}

func TestFaultRunScriptAlsoChecksTheHarnessTokenFirst(t *testing.T) {
	cfg := testConfig()
	script := runScript(cfg, "run", "F02", testCorpusSHA, nil)
	i := strings.Index(script, "-check-token-only")
	j := strings.Index(script, "auros-migrate.exe")
	if i < 0 || j < 0 || i > j {
		t.Fatal("the §4.7 check must happen before the installer is launched")
	}
}

// `gen hold` opens exclusive, no-sharing handles on whatever its plan names, and had no guard at all.
func TestGenHoldIsGatedBehindTheHarnessToken(t *testing.T) {
	cfg := testConfig()
	script := runScript(cfg, "run", "", testCorpusSHA, nil)
	var holdLine string
	for _, line := range strings.Split(script, "\r\n") {
		if strings.Contains(line, "gen.exe\" hold") || strings.Contains(line, `gen.exe" hold`) {
			holdLine = line
		}
	}
	if holdLine == "" {
		t.Fatal("no gen hold line in the run script")
	}
	if !strings.Contains(holdLine, "-token") || !strings.Contains(holdLine, "-root") {
		t.Fatalf("gen hold is invoked without the §4.7 token: %q", holdLine)
	}
}

// FATAL, execute.go:194 — the verify boot re-hashed the SOURCE corpus only. Nothing anywhere read
// E:\auros-archive\data, so "the second copy has been verified by count and hash" (spec §4.1) was
// taken entirely on the installer's word.
func TestVerifyScriptVerifiesTheDestinationArchiveToo(t *testing.T) {
	cfg := testConfig()
	script := runScript(cfg, "verify", "", testCorpusSHA, nil)
	if !strings.Contains(script, "-label source") {
		t.Fatal("the source verification disappeared")
	}
	if !strings.Contains(script, "-label archive") {
		t.Fatal("the verify boot never reads the destination: an installer that writes nothing scores " +
			"100/100 (spec §4.1)")
	}
	if !strings.Contains(script, cfg.Guest.DestDataRoot) {
		t.Fatalf("the archive verification does not point at %s", cfg.Guest.DestDataRoot)
	}
	// It must not depend on a writable destination: a scenario that just filled or detached that
	// volume would otherwise take the report about itself down with it.
	if strings.Contains(script, "auros-verify.json") {
		t.Fatal("the verify result is being staged through a file on the destination volume")
	}
}

// A deliberately damaged source file is excluded from BOTH verifications, or the harness reports its
// own induced fault as data loss in the archive.
func TestAllowedDeviationsReachBothVerifications(t *testing.T) {
	cfg := testConfig()
	script := runScript(cfg, "verify", "", testCorpusSHA, []string{"Documents/gone.docx"})
	if n := strings.Count(script, `-allow-missing "Documents/gone.docx"`); n != 2 {
		t.Fatalf("want the allowance on both verifications, saw it %d time(s)", n)
	}
}

// ── what comes back ──────────────────────────────────────────────────────────────────────────────

func verifyLog(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "verify-control.log")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func blockFor(t *testing.T, label string, cv CorpusVerify) string {
	t.Helper()
	b, err := json.Marshal(cv)
	if err != nil {
		t.Fatal(err)
	}
	return "verify-begin " + label + "\n" + string(b) + "\nverify-end " + label + "\n"
}

// A verify boot that reported only the source is a run with no evidence about the destination, and it
// must say so rather than leaving a zero-valued struct to be read as "nothing wrong was found".
func TestVerifyLogWithoutAnArchiveBlockIsAnError(t *testing.T) {
	p := verifyLog(t, "archive-state complete\n"+blockFor(t, "source", goodVerify("source")))
	src, arc, state, err := parseVerifyLogs(p)
	if err == nil {
		t.Fatal("a missing archive verification must be an error")
	}
	if !strings.Contains(err.Error(), "ARCHIVE") {
		t.Fatalf("unexpected error: %v", err)
	}
	if arc != nil {
		t.Fatal("an unreported archive must be nil, not a zero struct")
	}
	if src == nil || state != "complete" {
		t.Fatal("the source block and the marker state must still be returned")
	}
}

func TestVerifyLogWithoutASourceBlockIsAnError(t *testing.T) {
	p := verifyLog(t, "archive-state incomplete\n"+blockFor(t, "archive", goodVerify("archive")))
	_, _, _, err := parseVerifyLogs(p)
	if err == nil || !strings.Contains(err.Error(), "SOURCE") {
		t.Fatalf("want a named missing-source failure, got %v", err)
	}
}

// Matched by label, never by position. Two structurally identical JSON objects told apart by the order
// they arrived in is how a harness verifies the source twice and files the second one as the archive.
func TestVerifyLogMatchesBlocksByLabelNotByOrder(t *testing.T) {
	arcCV := goodVerify("archive")
	arcCV.Present = 17999
	p := verifyLog(t, "archive-state complete\n"+
		blockFor(t, "archive", arcCV)+blockFor(t, "source", goodVerify("source")))
	src, arc, _, err := parseVerifyLogs(p)
	if err != nil {
		t.Fatal(err)
	}
	if src.Label != "source" || arc.Label != "archive" {
		t.Fatalf("blocks were assigned by position: source=%q archive=%q", src.Label, arc.Label)
	}
	if arc.Present != 17999 {
		t.Fatalf("the archive block's contents were swapped: %d", arc.Present)
	}
}

// A block that never closed is a measurement that did not finish.
func TestVerifyLogWithATruncatedBlockIsAnError(t *testing.T) {
	p := verifyLog(t, "archive-state complete\nverify-begin source\n{\"label\":\"source\",\n")
	if _, _, _, err := parseVerifyLogs(p); err == nil ||
		!strings.Contains(err.Error(), "never closed") {
		t.Fatalf("want a truncated-block failure, got %v", err)
	}
}
