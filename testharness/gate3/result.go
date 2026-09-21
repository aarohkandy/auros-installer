package gate3

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE RESULT, AND WHY THE VERDICT IS RECOMPUTED
//
// A result file records what was measured. The verdict is derived from those
// measurements every time it is needed — here, and again by the aggregator —
// and a stored "verdict: pass" is never read back. A field that says pass is
// exactly what a broken harness would write.
//
// There is no `skip`. A check that did not run is a check that failed, and a
// result missing a check its run OWED is a failed run rather than a run with a
// shorter list. Both of those are enforced in Recompute.
// ─────────────────────────────────────────────────────────────────────────────

// Status is a check's outcome. Two values on purpose.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
)

// Check is one measured property of one run.
type Check struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// Check IDs. Every one of them is a measurement the harness makes itself,
// except C4, which compares the installer's own claims against the outcome the
// scenario requires.
const (
	CheckSystemDisk    = "C1-system-disk-untouched"
	CheckSourceIntact  = "C2-source-intact"
	CheckArchiveSound  = "C3-archive-not-corrupted"
	CheckOutcome       = "C4-outcome-as-required"
	CheckFaultFired    = "C5-fault-fired-at-its-pin"
	CheckWallNotCrossed = "C6-wall-not-crossed"
	CheckArchiveFull   = "C7-archive-complete"
	CheckManifestSound = "C8-manifest-on-destination-agrees"
	CheckKnownFolders  = "C9-known-folders-resolved-to-the-corpus"
	CheckEndedItself   = "C10-installer-ended-on-its-own"
)

// Kind distinguishes the two halves of §6C.
type Kind string

const (
	KindClean Kind = "clean"
	KindFault Kind = "fault"
)

// Result is one run's evidence.
type Result struct {
	Harness    string `json:"harness"`
	RunID      string `json:"run_id"`
	Kind       Kind   `json:"kind"`
	ScenarioID string `json:"scenario_id,omitempty"`
	Scenario   string `json:"scenario_name,omitempty"`
	Expect     Expect `json:"expect,omitempty"`

	Machine  string `json:"machine"`
	Image    string `json:"runner_image"`
	Hosted   bool   `json:"github_hosted"`
	Elevated bool   `json:"installer_ran_elevated"`

	CorpusRoot   string `json:"corpus_root"`
	CorpusFiles  int    `json:"corpus_files"`
	CorpusBytes  int64  `json:"corpus_bytes"`
	CorpusDigest string `json:"corpus_digest"`
	CorpusSeed   uint64 `json:"corpus_seed"`
	Profile      string `json:"corpus_profile"`
	Faithful     bool   `json:"corpus_faithful"`

	ToolPath   string   `json:"installer_path"`
	ToolSHA256 string   `json:"installer_sha256"`
	ToolArgs   []string `json:"installer_args"`
	DestDir    string   `json:"destination"`
	DestVolume string   `json:"destination_volume"`

	ExitCode    int     `json:"installer_exit_code"`
	KilledByUs  bool    `json:"killed_by_harness"`
	TimedOut    bool    `json:"timed_out"`
	DurationSec float64 `json:"duration_sec"`

	Pin       *Pin        `json:"pin,omitempty"`
	Fire      *FireRecord `json:"fire,omitempty"`
	Deviations []Deviation `json:"deviations,omitempty"`

	SystemDisk *SystemDiskReport `json:"system_disk,omitempty"`
	Source     *TreeReport       `json:"source,omitempty"`
	Archive    *TreeReport       `json:"archive,omitempty"`
	Claims     *Claims           `json:"installer_claims,omitempty"`
	Manifest   *ManifestFile     `json:"installer_manifest,omitempty"`
	Quarantine *QuarantineReport `json:"installer_quarantine,omitempty"`
	Inventory  map[string]string `json:"installer_inventory,omitempty"`

	// Findings are things the harness measured that are not part of the §6C
	// exit condition but that a reader must be told: alternate data streams
	// dropped, placeholders hydrated, and so on. They never change a verdict.
	Findings []string `json:"findings,omitempty"`

	Checks []Check `json:"checks"`

	LogTail string `json:"installer_output_tail,omitempty"`

	// manifestGolden is the corpus the installer's own manifest is compared
	// against. It is not serialised: a result file records measurements, and the
	// corpus it was measured against is named by its digest above.
	manifestGolden *Golden
}

// FireRecord is the anti-vacuous-pass evidence: a scenario that never fired
// produces a run that looks exactly like a pass.
type FireRecord struct {
	ScenarioID string `json:"scenario_id"`
	Fired      bool   `json:"fired"`
	NotFired   string `json:"not_fired_reason,omitempty"`

	TargetPath    string `json:"target_path,omitempty"`
	TargetArchive string `json:"target_archive,omitempty"`

	// ObservedBytes is what the OPERATING SYSTEM had seen the installer move in
	// the trigger's phase at the instant the action was dispatched — not a
	// number the installer reported about itself.
	ObservedBytes  int64  `json:"observed_phase_bytes"`
	OvershootBytes int64  `json:"overshoot_bytes"`
	ObservedNote   string `json:"observed_note,omitempty"`

	// DestFilesAtFire is a count of what was really on the destination at fire
	// time. An installer that writes a convincing log and copies nothing is the
	// failure this catches.
	DestFilesAtFire int   `json:"dest_files_at_fire"`
	DestBytesAtFire int64 `json:"dest_bytes_at_fire"`

	ActionError string `json:"action_error,omitempty"`
}

// SystemDiskReport is the D27 invariant, measured.
type SystemDiskReport struct {
	Method string `json:"method"`
	// JournalID and the USN range make the window auditable: everything that
	// happened to C: between these two numbers was examined.
	JournalID  uint64 `json:"usn_journal_id"`
	StartUSN   int64  `json:"usn_start"`
	EndUSN     int64  `json:"usn_end"`
	Records    int    `json:"records_examined"`
	Excluded   int    `json:"records_excluded_as_noise"`
	Unexplained []string `json:"unexplained_changes,omitempty"`
	// Wrapped is the fail-closed case: the journal overwrote records before we
	// read them, so the window cannot be accounted for and the run cannot claim
	// the invariant held.
	Wrapped     bool     `json:"journal_wrapped"`
	Error       string   `json:"error,omitempty"`
	Exclusions   []string `json:"exclusion_rules"`
	ExclusionSHA string   `json:"exclusion_rules_sha256"`

	// topDirs is a diagnostic — the directories with the most journal records,
	// excused or not — so that a noise list can be built from measurement rather
	// than from guesses. Not serialised; printed in the job log.
	topDirs []string
}

// TopDirs is the churn summary for the job log.
func (s *SystemDiskReport) TopDirs() []string {
	if s == nil {
		return nil
	}
	return s.topDirs
}

// OK reports whether the invariant held. It fails closed: an error, a wrapped
// journal or any unexplained change is a failure.
func (s *SystemDiskReport) OK() bool {
	return s != nil && s.Error == "" && !s.Wrapped && len(s.Unexplained) == 0 && s.Records >= 0
}

// RequiredChecks is the list of check IDs a run of this shape owes. A result
// that does not contain every one of them is a failed run: a checks array that
// simply omits C1 is otherwise indistinguishable from one where C1 passed.
func RequiredChecks(kind Kind, sc *Scenario) []string {
	req := []string{CheckSystemDisk, CheckSourceIntact, CheckArchiveSound, CheckOutcome,
		CheckWallNotCrossed, CheckKnownFolders, CheckEndedItself}
	switch {
	case kind == KindClean:
		req = append(req, CheckArchiveFull, CheckManifestSound)
	case sc != nil:
		if sc.Trigger != TriggerNone {
			req = append(req, CheckFaultFired)
		}
		if sc.Expect == ExpectSurvive {
			req = append(req, CheckArchiveFull, CheckManifestSound)
		}
	}
	sort.Strings(req)
	return req
}

// Recompute derives the verdict from the checks. It fails closed on a missing
// check, an unknown status and an empty list.
func (r *Result) Recompute(required []string) (Status, []string) {
	var reasons []string
	have := map[string]Check{}
	for _, c := range r.Checks {
		if _, dup := have[c.ID]; dup {
			reasons = append(reasons, "duplicate check "+c.ID)
		}
		have[c.ID] = c
	}
	if len(r.Checks) == 0 {
		return Fail, []string{"the result carries no checks at all"}
	}
	for _, id := range required {
		c, ok := have[id]
		if !ok {
			reasons = append(reasons, "missing check "+id+" (a check that did not run is a check that failed)")
			continue
		}
		switch c.Status {
		case Pass:
		case Fail:
			reasons = append(reasons, id+": "+c.Detail)
		default:
			reasons = append(reasons, id+": unknown status "+string(c.Status))
		}
	}
	for _, c := range r.Checks {
		if c.Status != Pass && c.Status != Fail {
			reasons = append(reasons, c.ID+": unknown status "+string(c.Status))
		}
	}
	if len(reasons) > 0 {
		return Fail, reasons
	}
	return Pass, nil
}

// Add appends a check.
func (r *Result) Add(id string, ok bool, format string, args ...any) {
	st := Fail
	if ok {
		st = Pass
	}
	r.Checks = append(r.Checks, Check{ID: id, Status: st, Detail: fmt.Sprintf(format, args...)})
}

// Write saves the result as JSON.
func (r *Result) Write(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

// Summary is the one-screen rendering for a job log.
func (r *Result) Summary(required []string) string {
	verdict, reasons := r.Recompute(required)
	var b strings.Builder
	fmt.Fprintf(&b, "\n── run %s (%s%s) — %s ──\n", r.RunID, r.Kind, scenarioSuffix(r), strings.ToUpper(string(verdict)))
	fmt.Fprintf(&b, "   installer exit %d in %.1fs%s\n", r.ExitCode, r.DurationSec, killNote(r))
	if r.Source != nil {
		fmt.Fprintf(&b, "   source   : %d/%d hashed OK, %d lost, %d corrupted, %d unexpected\n",
			r.Source.HashMatches, r.Source.Expected, len(r.Source.Missing), len(r.Source.Corrupt), len(r.Source.Extra))
	}
	if r.Archive != nil {
		fmt.Fprintf(&b, "   archive  : %d present, %d hashed OK, %d corrupted, %d extra, %d partial\n",
			r.Archive.Present, r.Archive.HashMatches, len(r.Archive.Corrupt), len(r.Archive.Extra), len(r.Archive.Partials))
	}
	if r.SystemDisk != nil {
		for _, d := range r.SystemDisk.TopDirs() {
			fmt.Fprintf(&b, "   churn    : %s\n", d)
		}
		fmt.Fprintf(&b, "   C:       : %d change-journal records examined, %d matched the noise list, %d unexplained\n",
			r.SystemDisk.Records, r.SystemDisk.Excluded, len(r.SystemDisk.Unexplained))
		for i, u := range r.SystemDisk.Unexplained {
			if i >= 20 {
				fmt.Fprintf(&b, "              … and %d more\n", len(r.SystemDisk.Unexplained)-20)
				break
			}
			fmt.Fprintf(&b, "              ! %s\n", u)
		}
	}
	if r.Fire != nil {
		if r.Fire.Fired {
			fmt.Fprintf(&b, "   fault    : fired at %d bytes (%+d from the pin) on %s\n",
				r.Fire.ObservedBytes, r.Fire.OvershootBytes, r.Fire.TargetPath)
		} else {
			fmt.Fprintf(&b, "   fault    : DID NOT FIRE — %s\n", r.Fire.NotFired)
		}
	}
	if r.Claims != nil {
		fmt.Fprintf(&b, "   claims   : verified=%v (%d files) wall-reached=%v crossed=%v\n",
			r.Claims.ClaimedVerified, r.Claims.VerifiedCount, r.Claims.ReachedWall, r.Claims.CrossedWall)
	}
	for _, c := range r.Checks {
		mark := "ok  "
		if c.Status != Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "   [%s] %-40s %s\n", mark, c.ID, c.Detail)
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "   note: %s\n", f)
	}
	for _, why := range reasons {
		fmt.Fprintf(&b, "   >>> %s\n", why)
	}
	return b.String()
}

func scenarioSuffix(r *Result) string {
	if r.ScenarioID == "" {
		return ""
	}
	return " " + r.ScenarioID + " " + r.Scenario
}

func killNote(r *Result) string {
	switch {
	case r.TimedOut:
		return " (the harness had to kill it on its timeout — that is not an abort)"
	case r.KilledByUs:
		return " (killed by the scenario)"
	}
	return ""
}

// ReadResult loads a result file for the aggregator.
func ReadResult(path string) (*Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}
