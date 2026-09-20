package quarantine

import (
	"strings"
	"testing"
	"time"
)

func fixed() func() time.Time {
	t := time.Unix(1700000000, 0).UTC()
	return func() time.Time { return t }
}

func TestUnresolvedBlocksTheWallUntilWaived(t *testing.T) {
	s := NewSet(fixed())
	s.Add(Record{Path: "Documents/a.pst", Reason: ReasonLocked, Detail: "in use by Outlook"})
	s.Add(Record{Path: "Documents/b.doc", Reason: ReasonHashMismatch})

	if s.Unresolved() != 2 {
		t.Fatalf("Unresolved = %d, want 2", s.Unresolved())
	}
	if err := s.Waive("Documents/a.pst", ""); err == nil {
		t.Error("an unattributed waiver was accepted")
	}
	if err := s.Waive("Documents/a.pst", "operator: user accepts losing this file"); err != nil {
		t.Fatal(err)
	}
	if s.Unresolved() != 1 {
		t.Errorf("Unresolved = %d, want 1 after one waiver", s.Unresolved())
	}
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2: a waived record is still reported", s.Len())
	}
	if err := s.Waive("Documents/nope.txt", "someone"); err == nil {
		t.Error("waiving a record that does not exist was accepted")
	}
}

func TestWaiverDoesNotSurviveANewFailureMode(t *testing.T) {
	// Somebody waived a locked file. Later the same path fails verification for
	// a different reason. Nobody waived THAT.
	s := NewSet(fixed())
	s.Add(Record{Path: "a.txt", Reason: ReasonLocked})
	if err := s.Waive("a.txt", "operator"); err != nil {
		t.Fatal(err)
	}
	s.Add(Record{Path: "a.txt", Reason: ReasonHashMismatch})
	if s.Unresolved() != 1 {
		t.Fatalf("Unresolved = %d, want 1: the waiver carried over to a different failure", s.Unresolved())
	}
}

func TestAttemptsAccumulate(t *testing.T) {
	s := NewSet(fixed())
	s.Add(Record{Path: "a.txt", Reason: ReasonReadError, Attempts: 2})
	s.Add(Record{Path: "a.txt", Reason: ReasonReadError, Attempts: 2})
	recs := s.Records()
	if len(recs) != 1 {
		t.Fatalf("records = %d, want 1", len(recs))
	}
	if recs[0].Attempts != 4 {
		t.Errorf("Attempts = %d, want 4", recs[0].Attempts)
	}
}

func TestClearRemovesARecordWhenARetrySucceeds(t *testing.T) {
	s := NewSet(fixed())
	s.Add(Record{Path: "a.txt", Reason: ReasonReadError})
	s.Clear("a.txt")
	if s.Unresolved() != 0 || s.Len() != 0 {
		t.Fatalf("Len=%d Unresolved=%d, want 0 and 0", s.Len(), s.Unresolved())
	}
}

func TestRecordsAreSorted(t *testing.T) {
	s := NewSet(fixed())
	for _, p := range []string{"z.txt", "a.txt", "m.txt"} {
		s.Add(Record{Path: p, Reason: ReasonReadError})
	}
	recs := s.Records()
	for i := 1; i < len(recs); i++ {
		if recs[i-1].Path >= recs[i].Path {
			t.Fatalf("records not sorted: %q before %q", recs[i-1].Path, recs[i].Path)
		}
	}
}

func TestReportNamesEveryFile(t *testing.T) {
	// The user is asked to decide, so the report has to name files rather than
	// count them.
	s := NewSet(fixed())
	s.Add(Record{Path: "Documents/tax return.pdf", Reason: ReasonLocked, Detail: "in use"})
	s.Add(Record{Path: "Pictures/wedding.jpg", Reason: ReasonHashMismatch, Detail: "digest differs"})
	var b strings.Builder
	if err := s.WriteReport(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"Documents/tax return.pdf", "Pictures/wedding.jpg", "locked-or-in-use", "hash-mismatch", "NOT in the second copy"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not mention %q:\n%s", want, out)
		}
	}
}

func TestEmptyReportSaysSo(t *testing.T) {
	var b strings.Builder
	if err := NewSet(fixed()).WriteReport(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "No files were quarantined") {
		t.Errorf("an empty set produced: %q", b.String())
	}
}

func TestConcurrentAdds(t *testing.T) {
	// The copy engine reports from several goroutines. Run with -race.
	s := NewSet(fixed())
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(n int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				s.Add(Record{Path: string(rune('a'+n)) + string(rune('a'+j%26)), Reason: ReasonReadError})
				s.Unresolved()
				s.Records()
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	if s.Len() == 0 {
		t.Fatal("nothing was recorded")
	}
}
