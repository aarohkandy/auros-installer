package main

// Reporter regressions. The attacks here are about the DENOMINATOR and the HEADER: what the published
// evidence counts, and where the sentences above the table come from.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

// The control: a complete, honest suite reports 100/100 and 20/20.
func TestCompleteSuiteReportsItsFullShape(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	filled, err := runReport(t, testConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filled, "clean 100/100") || !strings.Contains(filled, "fault 20/20") {
		t.Fatalf("headline wrong:\n%s", filled)
	}
}

// FATAL, runner.go:686 — "let any run fail before it writes result.json, then run `runner report`."
// The denominators were counted from the files that happened to exist, so forty runs that never
// started produced "60/60 clean" in the same sentence that quotes spec §6C.
func TestRunsThatNeverWroteAResultAreCountedAsFailures(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 60, fault.StandardSuite()) // forty clean runs never started
	filled, err := runReport(t, testConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(filled, "clean 60/60") {
		t.Fatalf("forty missing runs were reported as a complete suite:\n%s", filled)
	}
	if !strings.Contains(filled, "clean 60/100") {
		t.Fatalf("want clean 60/100, got:\n%s", filled)
	}
	if n := countLinesContaining(filled, "MISSING"); n != 40 {
		t.Fatalf("want 40 MISSING rows, got %d:\n%s", n, filled)
	}
}

// The same hole from the other side: a whole scenario absent from the abort suite.
func TestMissingScenariosAreCountedAsFailures(t *testing.T) {
	dir := t.TempDir()
	all := fault.StandardSuite()
	writeSuite(t, dir, 100, all[:18]) // F19 and F20 never ran
	filled, err := runReport(t, testConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filled, "fault 18/20") {
		t.Fatalf("want fault 18/20, got:\n%s", filled)
	}
}

// MAJOR, runner.go:669 — "drop a hand-written {\"kind\":\"clean\",\"checks\":[{\"id\":\"P1\",
// \"status\":\"pass\"}]} into the results tree." It was counted as a clean PASS: BootCheck was a nil
// pointer, no corpus verification existed, and result.schema.json was never loaded by any Go code.
func TestHandWrittenResultIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	forged := filepath.Join(dir, "forged")
	if err := os.MkdirAll(forged, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(forged, "result.json"),
		[]byte(`{"kind":"clean","checks":[{"id":"P1","status":"pass"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runReport(t, testConfig(), dir)
	if err == nil {
		t.Fatal("a hand-written result was accepted into the published evidence")
	}
	if !strings.Contains(err.Error(), "not one of the") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// A result that IS one of the expected runs but omits postconditions. `Recompute` looks only at the
// checks that are there, so a checks array missing P2/P3/P4 used to be indistinguishable from one
// where they passed.
func TestResultMissingPostconditionsFailsThatRun(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	r := passingResult("clean", 7, "")
	r.Checks = []Check{{ID: "P1", Name: "the installer completed successfully", Status: "pass"}}
	r.Verdict = "pass"
	writeResult(t, dir, r)

	filled, err := runReport(t, testConfig(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filled, "clean 99/100") {
		t.Fatalf("a result with seven postconditions missing was counted as a pass:\n%s", filled)
	}
}

// `kind` was read from the file and the `else` branch was "clean", so a result with a missing or empty
// kind counted as a clean pass.
func TestResultWithTheWrongKindIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	r := passingResult("clean", 7, "")
	r.Kind = ""
	writeResult(t, dir, r)
	if _, err := runReport(t, testConfig(), dir); err == nil ||
		!strings.Contains(err.Error(), "declares kind") {
		t.Fatalf("a result with no kind should be refused, got %v", err)
	}
}

// `filepath.Walk` accepted any nested result.json, so pointing -results at a parent artefact directory
// silently merged several suites into one headline.
func TestTwoSuitesUnderOneDirectoryAreRejected(t *testing.T) {
	parent := t.TempDir()
	a := filepath.Join(parent, "20260920T101500Z")
	b := filepath.Join(parent, "20260921T090000Z")
	writeSuite(t, a, 100, fault.StandardSuite())

	// A second suite, same run ids, different suite id.
	for i := 1; i <= 100; i++ {
		r := passingResult("clean", i, "")
		r.SuiteID = "20260921T090000Z"
		writeResult(t, b, r)
	}
	_, err := runReport(t, testConfig(), parent)
	if err == nil {
		t.Fatal("two suites merged into one headline")
	}
	if !strings.Contains(err.Error(), "a second result for run") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// MAJOR, runner.go:722 — "run the suite, then edit runner.config.json and run `runner report`."
// Every provenance field in the published evidence came from the config AS IT READ AT REPORT TIME.
func TestConfigEditedAfterTheRunsIsRejected(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())

	for _, tc := range []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"corpus profile", func(c *Config) { c.Base.CorpusProfile = "compact" }, "corpus_profile"},
		{"base image", func(c *Config) {
			c.Base.SystemSHA256 = "abababababababababababababababababababababababababababababababab"
		}, "base_system_sha256"},
		{"destination base", func(c *Config) {
			c.Base.DestSHA256 = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
		}, "base_dest_sha256"},
		{"corpus digest", func(c *Config) {
			c.Base.CorpusDigest = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
		}, "corpus_digest"},
		{"corpus count", func(c *Config) { c.Base.CorpusCount = 12 }, "corpus_files"},
		{"corpus seed", func(c *Config) { c.Base.CorpusSeed = 1 }, "corpus_seed"},
		{"windows edition", func(c *Config) { c.Base.WindowsEdition = "Windows 11 Pro" }, "windows_edition"},
		{"iso source", func(c *Config) { c.Base.ISOSource = "somewhere else" }, "iso_source"},
		{"installer scope", func(c *Config) { c.InstallerScope = "all seven phases" }, "installer_scope"},
		{"host profile", func(c *Config) { c.Host.Parallel = 8 }, "host_profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.mutate(cfg)
			_, err := runReport(t, cfg, dir)
			if err == nil {
				t.Fatalf("editing %s after the runs was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal should name %s, got: %v", tc.want, err)
			}
		})
	}
}

// Two runs that disagree with each other are not 120 runs of the same test, whatever the config says.
func TestRunsThatDisagreeWithEachOtherAreRejected(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	r := passingResult("clean", 40, "")
	r.CorpusProfile = "compact"
	writeResult(t, dir, r)
	_, err := runReport(t, testConfig(), dir)
	if err == nil || !strings.Contains(err.Error(), "differs between runs") {
		t.Fatalf("a suite that changed corpus profile mid-way was accepted: %v", err)
	}
}

// A suite run against a corpus generated off Windows is not the §6C exit condition, and the report is
// the last place that can still say so.
func TestUnfaithfulCorpusIsNeverPublished(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 100, fault.StandardSuite())
	r := passingResult("clean", 3, "")
	r.CorpusFaithful = false
	writeResult(t, dir, r)
	_, err := runReport(t, testConfig(), dir)
	if err == nil || !strings.Contains(err.Error(), "corpus_faithful=false") {
		t.Fatalf("an unfaithful corpus was published as the exit condition: %v", err)
	}
}

// MINOR, runner.go:764 — "take the Result digest column and re-hash the run's result.json, as the
// report invites an auditor to do." It never matched: the digest hashed a second serialisation of the
// struct while the file on disk was written indented with a trailing newline.
func TestResultDigestMatchesTheBytesOnDisk(t *testing.T) {
	dir := t.TempDir()
	writeSuite(t, dir, 1, nil)
	filled, err := runReport(t, testConfig(), dir, "-expect-clean", "1", "-expect-faults", "F01")
	if err != nil {
		// F01 is missing on purpose here; the report still writes.
		_ = err
	}
	path := filepath.Join(dir, "clean-0001", "result.json")
	want, herr := FileSHA256(path)
	if herr != nil {
		t.Fatal(herr)
	}
	if !strings.Contains(filled, want[:16]) {
		t.Fatalf("the published digest is not the SHA-256 of %s (want prefix %s):\n%s",
			path, want[:16], filled)
	}
}

// The published template and the reporter must agree. A placeholder REPORT.md carries that
// `runner report` does not fill is a hole in the evidence where a number should be, and the reporter
// refuses to write it — which means the whole suite's evidence is unpublishable, discovered at the end
// of 120 runs. This test discovers it on the commit that adds the placeholder.
func TestTheRealReportTemplateFillsCompletely(t *testing.T) {
	tmpl, err := os.ReadFile("../REPORT.md")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeSuite(t, dir, 3, fault.StandardSuite()[:2])

	work := t.TempDir()
	tmplPath := filepath.Join(work, "REPORT.md")
	if err := os.WriteFile(tmplPath, tmpl, 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(work, "REPORT.filled.md")
	err = cmdReport([]string{
		"-config", writeConfigFile(t, testConfig()),
		"-results", dir, "-template", tmplPath, "-out", outPath,
		"-expect-clean", "3", "-expect-faults", "F01,F02",
	})
	if err != nil {
		t.Fatalf("the shipped REPORT.md cannot be filled: %v", err)
	}
	filled, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(filled), "{{") {
		t.Fatal("the filled report still contains a placeholder")
	}
	// The report's headline must be the shape the suite owed, not a count of files found.
	if !strings.Contains(string(filled), "**Result: 3/3 clean · 2/2 induced-failure.**") {
		t.Fatalf("headline missing or wrong:\n%s", firstLines(string(filled), 40))
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
