package main

// Postcondition regressions. Each test is a specific attack from the audit, and each one PASSED the
// suite before the fix it guards.

import (
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

// evaluate reruns the postconditions over a result whose Checks have been cleared, so a test can set
// up the measured state and read back exactly what the harness concludes from it.
func evaluate(t *testing.T, cfg *Config, r *RunResult, archiveState string) *RunResult {
	t.Helper()
	r.Checks = nil
	var sc fault.Scenario
	if r.Kind == "fault" {
		var err error
		sc, err = fault.Lookup(r.Scenario)
		if err != nil {
			t.Fatal(err)
		}
	}
	applyChecks(cfg, r, r.Kind, sc, archiveState)
	return r
}

// FATAL, execute.go:194 — "ship an installer whose COPY phase writes nothing to E:\auros-archive\data
// but which emits a well-formed progress log, exits 0, and creates E:\auros-archive\COMPLETE."
//
// That scored 100/100. The only destination-side check in the harness was `if exist …\COMPLETE`, a
// marker written by the thing under test, and the single `gen verify` re-hashed the SOURCE.
func TestCleanRunWithAnEmptyArchiveFailsDespiteTheCompleteMarker(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	// The subject's own story is perfect: exit 0, source untouched, COMPLETE written.
	// The destination is empty.
	r.Archive = CorpusVerify{
		Label: "archive", ManifestSHA: testCorpusSHA,
		Expected: testCount, Present: 0, PresentBytes: 0, HashMatches: 0,
		Clean: false, Reported: true,
	}
	evaluate(t, cfg, r, "complete")

	mustPass(t, r, "P1", "P4") // the installer's account of itself, and the source, are both fine
	mustFail(t, r, "P8")       // …and the second copy does not exist
	mustFail(t, r, "P5")       // …so the COMPLETE marker is a lie, and P5 now says so
	if r.Recompute() != "fail" {
		t.Fatalf("18,000 files of total destination data loss was recorded as a pass:\n%s", dumpChecks(r))
	}
}

// The same attack, one step quieter: the harness never measures the destination at all. An unmeasured
// destination must never read as an undamaged one.
func TestCleanRunWithAnUnmeasuredArchiveFails(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Archive = CorpusVerify{} // Reported == false: the verify boot produced no archive block
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P8", "P5")
}

// An abort leaves a partial archive legitimately — but it must still have been LOOKED at, or "the
// installer was interrupted while copying" is indistinguishable from "the installer never copied".
func TestAbortRunWithAnUnmeasuredArchiveFails(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 2, "F02")
	r.Archive = CorpusVerify{}
	evaluate(t, cfg, r, "incomplete")
	mustFail(t, r, "P8")
}

func TestAbortRunWithAPartialMeasuredArchivePasses(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 2, "F02")
	evaluate(t, cfg, r, "incomplete")
	mustPass(t, r, "P8", "P5")
	if r.Recompute() != "pass" {
		t.Fatalf("a faithful abort should pass:\n%s", dumpChecks(r))
	}
}

// MAJOR, execute.go:322 — "ship an installer that, on any induced fault, hangs forever instead of
// aborting." The harness's run timeout killed the guest and `Killed` was read as "the installer
// aborted", so sixteen abort scenarios scored clean aborts for a tool with no abort path at all.
func TestHungInstallerKilledByTheRunTimeoutIsNotAnAbort(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 2, "F02")
	r.Installer = InstallerOutcome{
		ExitReported: false, ExitCode: 0,
		KilledByTimeout: true,
		TimeoutNote:     "the guest did not power off within 5400 seconds and was killed by the harness",
	}
	evaluate(t, cfg, r, "incomplete")
	mustFail(t, r, "P1") // "the harness killed the hung guest" is not "the installer aborted"
	mustFail(t, r, "P9") // and the timeout is a failure in its own right
	if r.Recompute() != "fail" {
		t.Fatalf("an installer that hung forever was scored as a clean abort:\n%s", dumpChecks(r))
	}
}

// A clean run that hung is equally invisible without P9.
func TestCleanRunKilledByTheRunTimeoutFails(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Installer.KilledByTimeout = true
	r.Installer.TimeoutNote = "killed by the harness"
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P9")
}

// The control: an INDUCED power cut is what an abort looks like for F01-F04, and it must still pass.
func TestInducedPowerCutStillCountsAsAnAbort(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 2, "F02")
	r.Installer = InstallerOutcome{ExitReported: false, ExitCode: 0, KilledByPowerCut: true}
	evaluate(t, cfg, r, "incomplete")
	mustPass(t, r, "P1", "P9")
}

// MAJOR, execute.go:565 — "make the guest verify against a smaller world: a golden manifest with 12
// entries. The guest reports expected_files: 12, hash_matches: 12, clean: true." P4's condition was
// `hash_matches >= expected`, with `expected` supplied by the guest, so twelve of twelve was a pass
// under a heading that says eighteen thousand.
func TestVerificationAgainstASmallerWorldFailsP4(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Corpus = CorpusVerify{
		Label: "source", ManifestSHA: testCorpusSHA,
		Expected: 12, Present: 12, HashMatches: 12, Clean: true, Reported: true,
	}
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P4")
	if d := detailOf(r, "P4"); !strings.Contains(d, "config says 18000") {
		t.Errorf("P4's detail should name the count it expected, got %q", d)
	}
}

// The same attack against the destination.
func TestArchiveVerificationAgainstASmallerWorldFailsP8(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Archive = CorpusVerify{
		Label: "archive", ManifestSHA: testCorpusSHA,
		Expected: 12, Present: 12, HashMatches: 12, Clean: true, Reported: true,
	}
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P8")
}

// `gen verify` has always emitted manifest_sha256 and the runner had nowhere to put it, so nothing
// checked that the manifest the guest verified against was the manifest the pins came from.
func TestVerificationAgainstTheWrongManifestFailsP4(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Corpus.ManifestSHA = "9999999999999999999999999999999999999999999999999999999999999999"
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P4")
}

// "hash_matches + allowed >= expected" let a run pass while reporting MORE matches than files. Equality
// is the only reading of "zero files lost" that is not also a reading of "some other number of files".
func TestP4RequiresEqualityNotAtLeast(t *testing.T) {
	cfg := testConfig()
	r := passingResult("clean", 1, "")
	r.Corpus.HashMatches = testCount + 5
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P4")
}

// MINOR, fault.go:453 — a fault pinned at 43% that actually fired at 99.9% was recorded as "the
// induced fault actually fired at its pin".
func TestP0RejectsAFireFarPastItsPin(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 2, "F02")
	r.Fire.ObservedBytesDone = r.Pin.TotalBytes - 1000
	r.Fire.OvershootBytes = r.Fire.ObservedBytesDone - r.Pin.CumulativeBytes
	evaluate(t, cfg, r, "incomplete")
	mustFail(t, r, "P0")
}

func TestP0RejectsAFireWhoseDestinationWasEmpty(t *testing.T) {
	cfg := testConfig()
	r := passingResult("fault", 7, "F07") // guest-site, COPY phase: the destination IS measured
	r.Fire.DestBytesAtFire = 0
	r.Fire.DestFilesAtFire = 0
	evaluate(t, cfg, r, "incomplete")
	mustFail(t, r, "P0")
}

func TestP7RejectsAnEmptyCorpusDigest(t *testing.T) {
	cfg := testConfig()
	cfg.Base.CorpusDigest = ""
	r := passingResult("clean", 1, "")
	r.CorpusDigest = ""
	evaluate(t, cfg, r, "complete")
	mustFail(t, r, "P7")
}

func detailOf(r *RunResult, id string) string {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Detail
		}
	}
	return ""
}
