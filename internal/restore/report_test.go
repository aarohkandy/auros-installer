package restore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/verify"
)

// cleanSummary is a summary that passes every arm of Clean. Every test below
// breaks exactly one thing about it and asserts the gate goes red, which is the
// D37 lesson applied to this program's own aggregate: the gate had never been
// watched failing for each reason separately.
func cleanSummary() *Summary {
	return &Summary{
		Archive:       &Archive{Root: "/run/media/u/BACKUP", Digest: "abcd"},
		Home:          "/home/u",
		ManifestCount: 2,
		Results: []Result{
			{Path: "Documents/a.txt", Bucket: "Documents", Outcome: OutWritten, Final: "/home/u/Documents/a.txt"},
			{Path: "Documents/b.txt", Bucket: "Documents", Outcome: OutWritten, Final: "/home/u/Documents/b.txt"},
		},
		Counts:     map[Outcome]int{OutWritten: 2},
		PreVerify:  &verify.Report{ManifestCount: 2, DestinationCount: 2, Checked: 2},
		ReVerify:   &ReVerifyReport{Expected: 2, Checked: 2, Matched: 2, Accounted: 2, Manifest: 2, Reconciled: true},
		StartedAt:  time.Unix(1700000000, 0).UTC(),
		FinishedAt: time.Unix(1700000010, 0).UTC(),
	}
}

func TestClean_TheGateGoesRedForEveryReasonSeparately(t *testing.T) {
	if !cleanSummary().Clean() {
		t.Fatal("the baseline is not clean, so every case below would pass vacuously")
	}
	cases := map[string]func(*Summary){
		"the archive check failed": func(s *Summary) {
			s.PreVerify.Disagreements = []verify.Disagreement{{Path: "x", Kind: verify.KindHash}}
		},
		"the archive check ran over nothing": func(s *Summary) { s.PreVerify.ManifestCount = 0 },
		"the archive count disagreed":        func(s *Summary) { s.PreVerify.DestinationCount = 3 },
		"the archive check did not finish":   func(s *Summary) { s.PreVerify.Checked = 1 },
		"there is no archive check at all":   func(s *Summary) { s.PreVerify = nil },
		"the re-check failed": func(s *Summary) {
			s.ReVerify.Disagreements = []string{"a.txt does not match"}
		},
		"the re-check did not read everything": func(s *Summary) { s.ReVerify.Checked = 1 },
		"the re-check matched fewer":           func(s *Summary) { s.ReVerify.Matched = 1 },
		"the count did not reconcile":          func(s *Summary) { s.ReVerify.Reconciled = false },
		"there is no re-check at all":          func(s *Summary) { s.ReVerify = nil },
		"a file failed":                        func(s *Summary) { s.Counts[OutFailed] = 1 },
		"the run stopped early":                func(s *Summary) { s.StoppedEarly = "power cut" },
		"an entry fell out of the results":     func(s *Summary) { s.Results = s.Results[:1] },
		"the manifest was empty":               func(s *Summary) { s.ManifestCount = 0 },
		"it was only a dry run":                func(s *Summary) { s.ReVerify.DryRun = true },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			s := cleanSummary()
			breakIt(s)
			if s.Clean() {
				t.Fatalf("Clean() is still true after: %s", name)
			}
			// And the report must SAY why. A red gate with a silent report is
			// how a discrepancy gets swallowed.
			body := RenderReport(s, mustLayout(t))
			if !strings.Contains(body, "PLEASE READ") {
				t.Errorf("the report does not lead with the problem:\n%s", body)
			}
			if strings.Contains(body, "What is wrong:\n\n") {
				t.Errorf("the report says something is wrong and then lists nothing:\n%s", body)
			}
		})
	}
}

func mustLayout(t *testing.T) *Layout {
	t.Helper()
	home := t.TempDir()
	l, err := NewLayout(home, filepath.Join(home, ".config"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestReport_TheFileNameCarriesTheVerdict(t *testing.T) {
	// The filename is the only part a person is guaranteed to read.
	if ReportName(cleanSummary()) != ReportNameOK {
		t.Errorf("a clean run is named %q", ReportName(cleanSummary()))
	}
	bad := cleanSummary()
	bad.Counts[OutFailed] = 1
	if ReportName(bad) != ReportNameProblem {
		t.Errorf("a failed run is named %q", ReportName(bad))
	}
	if !strings.Contains(ReportNameProblem, "PLEASE READ") {
		t.Errorf("the problem filename does not ask to be read: %q", ReportNameProblem)
	}
}

func TestWriteReport_AStaleGoodNewsFileIsRemoved(t *testing.T) {
	// Two reports on one desktop, one saying it went fine and one saying it did
	// not, is worse than either alone.
	home, l := newHome(t)
	desktop := filepath.Join(home, "Desktop")
	if err := os.MkdirAll(desktop, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteReport(cleanSummary(), l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(desktop, ReportNameOK)); err != nil {
		t.Fatalf("the good report is not on the desktop: %v", err)
	}
	bad := cleanSummary()
	bad.Counts[OutFailed] = 1
	bad.Results = append(bad.Results, Result{
		Path: "Documents/c.txt", Outcome: OutFailed, Final: "/home/u/Documents/c.txt",
		Detail: "the disk is full",
	})
	bad.ManifestCount = 3
	if _, err := WriteReport(bad, l); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(desktop, ReportNameOK)); err == nil {
		t.Error("the stale 'it went fine' report is still on the desktop next to the problem one")
	}
	body, err := os.ReadFile(filepath.Join(desktop, ReportNameProblem))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Documents/c.txt") {
		t.Errorf("the problem report does not name the file that failed:\n%s", body)
	}
}

func TestWriteReport_NoDesktopFallsBackToTheHomeDirectory(t *testing.T) {
	// A report the user cannot find is the same as no report. A report in the
	// wrong place still beats a line in a log nobody opens.
	home := t.TempDir()
	l, err := NewLayout(home, filepath.Join(home, ".config"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	// Make the desktop directory impossible to create: put a FILE where it goes.
	if err := os.WriteFile(filepath.Join(home, "Desktop"), []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := WriteReport(cleanSummary(), l)
	if err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	if filepath.Dir(p) != home {
		t.Errorf("the report went to %s, want the home directory %s", p, home)
	}
}

func TestNotifyBody_LeadsWithTheCountAndNeverOverstates(t *testing.T) {
	sum, body, urgent := NotifyBody(cleanSummary())
	if urgent {
		t.Error("a clean restore raised a critical notification")
	}
	if !strings.Contains(body, "2 files") {
		t.Errorf("the pop-up does not carry the count, which is the thing SPEC §6C asks for: %q", body)
	}
	if !strings.Contains(body, "desktop") {
		t.Errorf("the pop-up does not point at the note on the desktop: %q", body)
	}
	_ = sum

	bad := cleanSummary()
	bad.Counts[OutFailed] = 1
	sum, body, urgent = NotifyBody(bad)
	if !urgent {
		t.Error("a failed restore did not raise a critical notification")
	}
	if strings.Contains(strings.ToLower(sum+body), "success") {
		t.Errorf("a failed restore's pop-up mentions success: %q / %q", sum, body)
	}
	if !strings.Contains(body, "not been changed") {
		t.Errorf("the pop-up does not reassure the user about the backup drive: %q", body)
	}
}

func TestReport_ANotificationThatDidNotHappenIsNotClaimed(t *testing.T) {
	s := cleanSummary()
	s.NotifyAttempt = "not shown as a pop-up: no session bus address"
	body := RenderReport(s, mustLayout(t))
	if !strings.Contains(body, "not shown as a pop-up") {
		t.Errorf("the report hides the fact that the pop-up never appeared:\n%s", body)
	}
}

func TestReport_TheWithheldSectionNamesTheRealReason(t *testing.T) {
	s := cleanSummary()
	s.ManifestCount = 3
	s.Results = append(s.Results, Result{
		Path: "Chrome/Default/Login Data", Bucket: "Chrome", Outcome: OutWithheld,
		Detail: "D15: Chrome passwords...",
	})
	s.Counts[OutWithheld] = 1
	s.ReVerify.Accounted = 3
	s.ReVerify.Manifest = 3
	body := RenderReport(s, mustLayout(t))
	for _, want := range []string{
		"ON PURPOSE", "BOOKMARKS", "BROWSING HISTORY", "sign in to Chrome",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the report does not say %q, so the user is left guessing:\n%s", want, body)
		}
	}
}

func TestReport_ASummaryThatIsNotCleanAlwaysListsAtLeastOneProblem(t *testing.T) {
	// The worst possible bug in report.go: a red run that renders a page with
	// no reason on it. The last branch of problems() exists for that and it
	// must be reachable.
	s := &Summary{ManifestCount: 5, Counts: map[Outcome]int{}}
	lines := problems(s)
	if len(lines) == 0 {
		t.Fatal("a run that is not clean produced no problem lines")
	}
	s2 := &Summary{
		ManifestCount: 5,
		Counts:        map[Outcome]int{},
		PreVerify:     &verify.Report{ManifestCount: 5, DestinationCount: 5, Checked: 5},
		ReVerify:      &ReVerifyReport{Expected: 5, Checked: 5, Matched: 5, Accounted: 5, Manifest: 5, Reconciled: true},
		Results:       make([]Result, 4), // one short: nothing else is wrong
	}
	if s2.Clean() {
		t.Fatal("a summary with a missing result is clean")
	}
	got := strings.Join(problems(s2), " ")
	if !strings.Contains(got, "cannot say why") {
		t.Errorf("the catch-all branch was not reached; problems() said: %q", got)
	}
}

func TestReport_WhereThingsWentCountsOnlyFilesThatAreReallyThere(t *testing.T) {
	// The first version of this section counted every result in a bucket, so a
	// Chrome profile whose passwords were withheld reported four files under
	// ~/.config/google-chrome/Default when two of them had deliberately not
	// been written. Found by running the real binary and reading the note.
	s := cleanSummary()
	s.ManifestCount = 6
	s.Results = []Result{
		{Path: "Chrome/Default/Bookmarks", Bucket: "Chrome", Outcome: OutWritten,
			Final: "/home/u/.config/google-chrome/Default/Bookmarks"},
		{Path: "Chrome/Default/History", Bucket: "Chrome", Outcome: OutWritten,
			Final: "/home/u/.config/google-chrome/Default/History"},
		{Path: "Chrome/Default/Login Data", Bucket: "Chrome", Outcome: OutWithheld},
		{Path: "Chrome/Default/Cookies", Bucket: "Chrome", Outcome: OutWithheld},
		{Path: "Documents/a.txt", Bucket: "Documents", Outcome: OutWritten, Final: "/home/u/Documents/a.txt"},
		{Path: "Documents/reports/b.txt", Bucket: "Documents", Outcome: OutWritten,
			Final: "/home/u/Documents/reports/b.txt"},
	}
	s.Counts = map[Outcome]int{OutWritten: 4, OutWithheld: 2}
	s.PreVerify.ManifestCount, s.PreVerify.DestinationCount, s.PreVerify.Checked = 6, 6, 6
	s.ReVerify = &ReVerifyReport{Expected: 4, Checked: 4, Matched: 4, Accounted: 6, Manifest: 6, Reconciled: true}

	lines := whereItWent(s)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Chrome         2 files") {
		t.Errorf("Chrome is not counted as 2 files:\n%s", joined)
	}
	if strings.Contains(joined, "Chrome         4 files") {
		t.Errorf("withheld files are being counted as delivered:\n%s", joined)
	}
	// And the directory must be one that really holds both Documents files.
	if !strings.Contains(joined, "Documents      2 files, under /home/u/Documents") {
		t.Errorf("Documents names a directory that does not hold all of them:\n%s", joined)
	}
	if strings.Contains(joined, "/home/u/Documents/reports") {
		t.Errorf("the directory named is too deep to be true of every file:\n%s", joined)
	}
}

func TestReport_WhereThingsWentSaysSoWhenNothingWasWritten(t *testing.T) {
	s := &Summary{Counts: map[Outcome]int{}, Results: []Result{
		{Path: "Chrome/Default/Cookies", Bucket: "Chrome", Outcome: OutWithheld},
	}}
	lines := whereItWent(s)
	if len(lines) != 1 || !strings.Contains(lines[0], "no files") {
		t.Fatalf("an empty section reads like a rendering bug: %v", lines)
	}
}
