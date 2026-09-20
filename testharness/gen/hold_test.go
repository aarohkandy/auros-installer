package main

// `gen hold` opens exclusive, no-sharing handles on every file its plan names. It was the one guest
// tool in the harness with no §4.7 guard at all — and the one the 100 CLEAN runs start, so the guard
// README §1 describes was absent from five sixths of the suite.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePlan(t *testing.T, locked []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "corpus-plan.json")
	b, err := json.Marshal(Plan{Harness: "testharness/0.1.0", Seed: 1, LockedFiles: locked})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHoldRefusesWithoutAHarnessToken(t *testing.T) {
	plan := writePlan(t, []string{`C:\Users\student\Documents\a.docx`})
	err := cmdHold([]string{"-plan", plan, "-until", filepath.Join(t.TempDir(), "release")})
	if err == nil {
		t.Fatal("gen hold took exclusive handles with no token: spec §4.7 is not enforced on clean runs")
	}
	if !strings.Contains(err.Error(), "-token and -root are required") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

func TestHoldRefusesWithATokenItCannotRead(t *testing.T) {
	plan := writePlan(t, []string{`C:\Users\student\Documents\a.docx`})
	err := cmdHold([]string{
		"-plan", plan, "-until", filepath.Join(t.TempDir(), "release"),
		"-token", filepath.Join(t.TempDir(), "there-is-no-token.json"),
		"-root", `C:\Users\student`,
	})
	if err == nil {
		t.Fatal("an unreadable token must fail closed, never open")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// The token vouches for a VOLUME; the plan names PATHS. Without this, a plan naming
// C:\Windows\System32\config\SAM passes the volume check on a machine whose C: happens to be the
// vouched-for one — the same aliasing SAFETY.md phase 3 forbids in the installer itself.
func TestHoldRefusesAPlanThatEscapesTheCorpusRoot(t *testing.T) {
	for _, path := range []string{
		`C:\Windows\System32\config\SAM`,
		`C:\Users\student2\Documents\a.docx`, // prefix-similar, different directory
		`C:\Users\student`,                   // the root itself is not a file under the root
		`D:\elsewhere\a.docx`,
	} {
		if underRoot(`C:\Users\student`, path) {
			t.Errorf("%s was accepted as being under C:\\Users\\student", path)
		}
	}
	for _, path := range []string{
		`C:\Users\student\Documents\a.docx`,
		`c:\users\STUDENT\Pictures\b.jpg`, // Windows paths, compared case-insensitively
		`C:/Users/student/Downloads/c.zip`,
	} {
		if !underRoot(`C:\Users\student`, path) {
			t.Errorf("%s should be under C:\\Users\\student", path)
		}
	}
	if underRoot("", `C:\anything`) {
		t.Error("an empty root must vouch for nothing")
	}
}

// Off Windows, every destructive path refuses rather than pretending. The volume-serial read is the
// first thing AssertScratch does and it fails closed, so `gen hold` cannot run here at all.
func TestHoldRefusesOnANonWindowsHost(t *testing.T) {
	dir := t.TempDir()
	tok := filepath.Join(dir, "token.json")
	if err := os.WriteFile(tok, []byte(`{
      "harness":"testharness/0.1.0","suite_id":"s","run_id":"r",
      "target_volume_serial":"AAAA-1111","destroys_everything_on_target_volume":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan := writePlan(t, []string{filepath.Join(dir, "a.docx")})
	err := cmdHold([]string{"-plan", plan, "-until", filepath.Join(dir, "release"),
		"-token", tok, "-root", dir})
	if err == nil {
		t.Fatal("gen hold must not run outside the harness's Windows guest")
	}
}
