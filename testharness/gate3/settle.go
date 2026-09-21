package gate3

import (
	"fmt"
	"sort"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// SETTLE
//
// A fresh runner is busy for minutes after boot: a Store update queued before
// the job started, the Entra broker, the state repository. Chasing each writer
// with a rule or a service stop never ended. Instead no run is measured until
// the machine has been quiet: the C: change journal is polled after quiescing,
// and the run proceeds only once nothing outside the noise list has changed for
// Quiet. If that never happens within Max, the run fails as "machine not
// quiescent": a busy machine is never measured, and never passed.
// ─────────────────────────────────────────────────────────────────────────────

// Settle defaults: how long C: must stay quiet, the most time given to get
// there, and how often the journal is read meanwhile.
const (
	DefaultSettleQuiet = 60 * time.Second
	DefaultSettleMax   = 10 * time.Minute
	SettleEvery        = 5 * time.Second
)

// SettleReport is what the settle phase measured, recorded in every result.
type SettleReport struct {
	Settled       bool     `json:"settled"`
	Seconds       float64  `json:"seconds"`        // how long settling took
	QuietSeconds  float64  `json:"quiet_required"` // the quiet interval asked for
	Polls         int      `json:"polls"`
	StillChanging []string `json:"still_changing,omitempty"` // the last changes that reset the clock
	Error         string   `json:"error,omitempty"`
}

// Settle polls until quiet has passed with no change outside the noise list,
// or max has passed. poll returns the changes since its previous call.
func Settle(poll func() ([]string, error), quiet, max, every time.Duration,
	now func() time.Time, sleep func(time.Duration)) *SettleReport {
	rep := &SettleReport{QuietSeconds: quiet.Seconds()}
	start := now()
	quietSince := start
	for {
		sleep(every)
		changes, err := poll()
		rep.Polls++
		t := now()
		rep.Seconds = t.Sub(start).Seconds()
		if err != nil {
			rep.Error = err.Error()
			return rep
		}
		if len(changes) > 0 {
			quietSince = t
			rep.StillChanging = capList(append([]string{}, changes...), 20)
		}
		if t.Sub(quietSince) >= quiet {
			rep.Settled = true
			return rep
		}
		if t.Sub(start) >= max {
			return rep
		}
	}
}

// Why says, for C1, why a run could not be measured.
func (s *SettleReport) Why() string {
	switch {
	case s == nil:
		return "the machine was never settled before measuring"
	case s.Error != "":
		return "settling failed: " + s.Error
	case !s.Settled:
		first := "nothing recorded"
		if len(s.StillChanging) > 0 {
			first = s.StillChanging[0]
		}
		return fmt.Sprintf("machine not quiescent: C: never went %.0fs without a change outside the noise "+
			"list in %.0fs of polling; still changing: %s", s.QuietSeconds, s.Seconds, first)
	}
	return ""
}

func capList(l []string, n int) []string {
	sort.Strings(l)
	if len(l) > n {
		l = append(l[:n:n], fmt.Sprintf("… and %d more", len(l)-n))
	}
	return l
}
