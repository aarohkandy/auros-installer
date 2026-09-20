package fault

// FireRecord.Valid is postcondition P0's whole content: "the induced fault actually fired AT ITS PIN".
// It used to check two things — Fired, and OrderViolations — so a fault pinned at 43% that fired at
// 99.9%, or fired on the installer's first progress line before any byte reached the destination, or
// fired while the installer was in a different phase entirely, was recorded as having fired at its pin.

import (
	"strings"
	"testing"
)

func f02(t *testing.T) Scenario {
	t.Helper()
	sc, err := Lookup("F02") // power cut at 43% of COPY, host site
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func f07(t *testing.T) Scenario {
	t.Helper()
	sc, err := Lookup("F07") // destination fills at 61% of COPY, GUEST site: the destination is measured
	if err != nil {
		t.Fatal(err)
	}
	return sc
}

func faithfulFire(sc Scenario) FireRecord {
	pin := Pin{
		Phase: sc.Trigger.Phase, BP: sc.Trigger.BP, FileIndex: 7742,
		Path: "Documents/x.docx", ByteOffsetInFile: 118_243,
		CumulativeBytes: 3_612_004_182, TotalBytes: 8_400_009_726,
	}
	rec := FireRecord{
		ScenarioID: sc.ID, Fired: true, Pin: pin,
		ObservedBytesDone: pin.CumulativeBytes + 900_000, ObservedBytesTotal: pin.TotalBytes,
		ObservedIndex: 7742, ObservedPhase: string(sc.Trigger.Phase),
		OvershootBytes: 900_000,
	}
	if sc.Site == SiteHost {
		rec.DestBytesAtFire = -1
		rec.DestScanNote = "not measured: host-site scenario"
	} else {
		rec.DestBytesAtFire = pin.CumulativeBytes
		rec.DestFilesAtFire = 7000
	}
	return rec
}

// The control. A record that is what it says it is must pass, or P0 becomes a trap.
func TestFaithfulFireIsAccepted(t *testing.T) {
	for _, sc := range []Scenario{f02(t), f07(t)} {
		if err := faithfulFire(sc).Valid(sc, DefaultMaxOvershootBytes); err != nil {
			t.Errorf("%s: %v", sc.ID, err)
		}
	}
}

// MINOR, fault.go:453 — "a fault pinned at 43% that actually fired at 99.9% is recorded as 'the
// induced fault actually fired at its pin'."
func TestFireFarPastItsPinIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.ObservedBytesDone = rec.Pin.TotalBytes - 8_400_009 // 99.9% of the corpus
	rec.OvershootBytes = rec.ObservedBytesDone - rec.Pin.CumulativeBytes
	err := rec.Valid(sc, DefaultMaxOvershootBytes)
	if err == nil {
		t.Fatal("a fault that fired at 99.9% was accepted as a fault pinned at 43%")
	}
	if !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("unexpected: %v", err)
	}
}

// "…or that emits its first COPY line with bytes_done already at 100%" — and its mirror image, a fire
// on the first line, before any byte reached the destination.
func TestFireAtZeroBytesDoneIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.ObservedBytesDone = 0
	rec.OvershootBytes = -rec.Pin.CumulativeBytes
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("a fire before any byte was copied was accepted")
	}
}

// A fraction of COPY's bytes measured against VERIFY's total is a different trigger point wearing this
// one's name. Valid never looked at ObservedPhase at all.
func TestFireInTheWrongPhaseIsRejected(t *testing.T) {
	sc := f02(t) // pinned in COPY
	rec := faithfulFire(sc)
	rec.ObservedPhase = string(PhaseVerify)
	err := rec.Valid(sc, DefaultMaxOvershootBytes)
	if err == nil || !strings.Contains(err.Error(), "phase") {
		t.Fatalf("want a phase mismatch, got %v", err)
	}
}

// A record filed under the wrong scenario is not evidence about either of them.
func TestFireRecordForAnotherScenarioIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.ScenarioID = "F19"
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("a record for F19 was accepted as evidence about F02")
	}
}

// A pin that does not match what the scenario asks for means the arithmetic that makes `--scenario F02`
// a reproduction rather than an anecdote was not the arithmetic that ran.
func TestFireRecordPinnedAtTheWrongTriggerIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.Pin.BP = 9400
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("a record pinned at 94% was accepted for a scenario pinned at 43%")
	}
}

// "The harness's entire view of the copy is the log the subject writes about itself." This is the one
// cross-check that is not: a guest-site COPY fault whose destination tree was empty at fire time means
// the installer is reporting a copy it is not performing.
func TestFireWithAnEmptyDestinationIsRejected(t *testing.T) {
	sc := f07(t)
	rec := faithfulFire(sc)
	rec.DestBytesAtFire = 0
	rec.DestFilesAtFire = 0
	err := rec.Valid(sc, DefaultMaxOvershootBytes)
	if err == nil {
		t.Fatal("an installer whose progress log claims 3.6 GB copied while the destination holds " +
			"nothing was accepted")
	}
	if !strings.Contains(err.Error(), "not performing") {
		t.Fatalf("unexpected: %v", err)
	}
}

// Host-site scenarios deliberately do not measure, because the walk would move the power cut. -1 is
// "not measured" and must remain distinguishable from 0, which is a finding.
func TestUnmeasuredDestinationIsNotTreatedAsAnEmptyOne(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.DestBytesAtFire = -1
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err != nil {
		t.Fatalf("a host-site scenario must not be failed for not measuring: %v", err)
	}
}

// Self-consistency: a record whose overshoot does not equal observed-minus-pinned has been edited.
func TestInconsistentOvershootIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.OvershootBytes = 1 // but observed-minus-pinned is 900,000
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("a record whose overshoot contradicts its own numbers was accepted")
	}
}

// The two checks that were already there, kept.
func TestNeverFiredIsRejected(t *testing.T) {
	sc := f02(t)
	rec := FireRecord{ScenarioID: sc.ID, Fired: false, NotFired: "the run ended before the trigger"}
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("a scenario that never fired is not a scenario that passed")
	}
}

func TestOutOfOrderCopyIsRejected(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.OrderViolations = 3
	if err := rec.Valid(sc, DefaultMaxOvershootBytes); err == nil {
		t.Fatal("an installer not copying in manifest order makes every pin in the suite meaningless")
	}
}

// The ceiling is a number in the config; zero must fall back rather than disable the bound.
func TestZeroCeilingFallsBackRatherThanDisablingTheBound(t *testing.T) {
	sc := f02(t)
	rec := faithfulFire(sc)
	rec.ObservedBytesDone = rec.Pin.CumulativeBytes + (64 << 20)
	rec.OvershootBytes = 64 << 20
	if err := rec.Valid(sc, 0); err == nil {
		t.Fatal("max_overshoot_bytes = 0 must mean the default, never 'unbounded'")
	}
}

// The catalogue is Go rather than YAML so that it compiles or it does not — but nothing compiled it
// until now (the runner did not build, and this package had no tests), so `Validate` had never run.
func TestCatalogueValidates(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	if n := len(StandardSuite()); n != 20 {
		t.Fatalf("spec §6C requires 20 induced-failure runs, the catalogue has %d", n)
	}
}

// Pins are pure arithmetic over the manifest: same seed, same scenario, same number on every machine,
// forever. That property is what makes `--scenario F02` a reproduction rather than an anecdote.
func TestPinsAreDeterministicAndOrdered(t *testing.T) {
	entries := make([]Entry, 0, 100)
	for i := 0; i < 100; i++ {
		entries = append(entries, Entry{Index: i, Path: "f", Size: int64(1000 + i)})
	}
	for _, sc := range StandardSuite() {
		a, err := ResolvePin(entries, sc.Trigger)
		if err != nil {
			t.Fatalf("%s: %v", sc.ID, err)
		}
		b, err := ResolvePin(entries, sc.Trigger)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			t.Fatalf("%s resolved to two different pins: %v vs %v", sc.ID, a, b)
		}
		if a.CumulativeBytes < 0 || a.CumulativeBytes > a.TotalBytes {
			t.Fatalf("%s: pin outside the corpus: %v", sc.ID, a)
		}
	}
}
