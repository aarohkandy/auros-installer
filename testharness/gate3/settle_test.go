package gate3

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// settleWith replays one batch of changes per poll on a fake clock; after the
// script runs out, the journal is quiet.
func settleWith(script [][]string, pollErr error) *SettleReport {
	t0 := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	now := t0
	i := 0
	poll := func() ([]string, error) {
		if pollErr != nil {
			return nil, pollErr
		}
		if i < len(script) {
			i++
			return script[i-1], nil
		}
		return nil, nil
	}
	return Settle(poll, 60*time.Second, 10*time.Minute, 5*time.Second,
		func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) })
}

func TestSettleQuietMachineProceedsAfterTheQuietInterval(t *testing.T) {
	r := settleWith(nil, nil)
	if !r.Settled || r.Why() != "" || r.Seconds != 60 || r.Polls != 12 {
		t.Fatalf("quiet machine: %+v", r)
	}
}

func TestSettleBusyThenQuietWaitsThenProceeds(t *testing.T) {
	busy := make([][]string, 24) // two minutes of Store-update churn
	for i := range busy {
		busy[i] = []string{`C:\Program Files\WindowsApps\Microsoft.SecHealthUI\x.dll [file-create]`}
	}
	r := settleWith(busy, nil)
	if !r.Settled || r.Why() != "" || r.Seconds != 180 {
		t.Fatalf("busy then quiet: want settled after 120s busy + 60s quiet, got %+v", r)
	}
	if len(r.StillChanging) == 0 || !strings.Contains(r.StillChanging[0], "SecHealthUI") {
		t.Fatalf("the last change that reset the clock was not recorded: %+v", r)
	}
}

func TestSettleNeverQuietFailsAsNotQuiescent(t *testing.T) {
	busy := make([][]string, 1000)
	for i := range busy {
		busy[i] = []string{`C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Deployment.srd [data-extend]`}
	}
	r := settleWith(busy, nil)
	if r.Settled || r.Seconds != 600 {
		t.Fatalf("never quiet: must give up at the cap unsettled, got %+v", r)
	}
	if !strings.Contains(r.Why(), "machine not quiescent") || !strings.Contains(r.Why(), "StateRepository") {
		t.Fatalf("why: %q", r.Why())
	}
	res := &Result{Settle: r, SystemDisk: &SystemDiskReport{Records: 1, Excluded: 1}}
	res.Evaluate(nil, 0)
	found := false
	for _, c := range res.Checks {
		if c.ID == CheckSystemDisk {
			found = true
			if c.Status == Pass || !strings.Contains(c.Detail, "not quiescent") {
				t.Fatalf("C1 must fail on an unsettled machine: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("C1 was not evaluated")
	}
}

func TestSettleJournalErrorFails(t *testing.T) {
	r := settleWith(nil, errors.New("journal recreated"))
	if r.Settled || !strings.Contains(r.Why(), "journal recreated") {
		t.Fatalf("journal error: %+v", r)
	}
}
