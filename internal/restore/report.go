package restore

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The report is the product.
//
// SPEC §6C says "report the count to the user on the desktop" — on the desktop,
// not in a log. A school's IT person is not going to run journalctl, and the
// person whose files these are is definitely not. So there are two artefacts:
//
//   - a file on the desktop, with a name that says whether it went well, that
//     opens in a text editor on a double click; and
//   - a desktop notification, so they know the file is there.
//
// Everything that did not go perfectly is in the file, at the TOP, named. The
// rule from SAFETY.md is "a discrepancy is shown, never swallowed", and the
// easiest way to swallow one is to put it after four screens of good news.

// ReportNameOK and ReportNameProblem are the two filenames. The name itself
// carries the verdict, because a filename is the only part of a report a person
// is guaranteed to read.
const (
	ReportNameOK      = "Your files are here.txt"
	ReportNameProblem = "PLEASE READ — a problem with your files.txt"
)

// ReportName is the filename this summary should be written under.
func ReportName(s *Summary) string {
	if s.Clean() {
		return ReportNameOK
	}
	return ReportNameProblem
}

// WriteReport writes the report onto the desktop and returns its path.
//
// If the desktop directory cannot be written, the report goes to the home
// directory instead — a report the user cannot find is the same as no report,
// but a report in the wrong place still beats an error message in a log.
func WriteReport(s *Summary, l *Layout) (string, error) {
	body := RenderReport(s, l)
	desktop, _ := l.Dir("XDG_DESKTOP_DIR")
	candidates := []string{desktop, l.Home}
	var lastErr error
	for _, dir := range candidates {
		if dir == "" {
			continue
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			lastErr = err
			continue
		}
		p := filepath.Join(dir, ReportName(s))
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			lastErr = err
			continue
		}
		// A stale "it went fine" report next to a "there was a problem" one is
		// worse than either alone. The other name is removed, and only the
		// other one: nothing else in the directory is touched.
		other := ReportNameOK
		if other == ReportName(s) {
			other = ReportNameProblem
		}
		_ = os.Remove(filepath.Join(dir, other))
		return p, nil
	}
	return "", fmt.Errorf("restore: could not write the report: %w", lastErr)
}

// RenderReport builds the text. It is a pure function of the summary so a test
// can assert what a user would actually read, rather than asserting that a
// function was called.
func RenderReport(s *Summary, l *Layout) string {
	var b strings.Builder

	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	rule := func() { w("%s", strings.Repeat("-", 62)) }

	if s.Clean() {
		w("YOUR FILES ARE ON THIS COMPUTER")
		w("")
		w("%s came across from your old Windows computer.", plural(s.FilesRestored(), "file", "files"))
		w("Every one of them was checked twice: once on the backup drive")
		w("before anything was copied, and once here after it was written.")
		w("They match, file for file, byte for byte.")
	} else {
		w("PLEASE READ — SOMETHING DID NOT GO AS PLANNED")
		w("")
		w("Your backup drive has NOT been changed. Nothing on it was deleted")
		w("and nothing on it was moved. Whatever went wrong below, the")
		w("original copy of your files is still on that drive.")
		w("")
		if s.StoppedEarly != "" {
			w("What stopped: %s", s.StoppedEarly)
			w("")
		}
		w("What is wrong:")
		for _, line := range problems(s) {
			w("  * %s", line)
		}
	}
	w("")
	rule()

	w("THE NUMBERS")
	w("")
	w("  in the backup's list      %s", plural(s.ManifestCount, "file", "files"))
	for _, o := range []Outcome{OutWritten, OutAlreadyPresent, OutPlacedAside, OutWithheld, OutHandled, OutFailed} {
		if n := s.Counts[o]; n > 0 {
			w("  %-24s %d", o, n)
		}
	}
	if s.PreVerify != nil {
		w("")
		w("  check 1, on the backup drive, before anything was written:")
		w("    %d checked, %d disagreed", s.PreVerify.Checked, len(s.PreVerify.Disagreements))
	}
	if s.ReVerify != nil {
		w("  check 2, on this computer, after everything was written:")
		w("    %d read back, %d matched, %d disagreed",
			s.ReVerify.Checked, s.ReVerify.Matched, len(s.ReVerify.Disagreements))
		w("    %d of %d entries accounted for", s.ReVerify.Accounted, s.ReVerify.Manifest)
	}
	w("")
	rule()

	w("WHERE THINGS WENT")
	w("")
	for _, line := range whereItWent(s) {
		w("  %s", line)
	}
	w("")
	rule()

	if aside := renamedFiles(s); len(aside) > 0 {
		// A file that quietly acquired a different name is a discrepancy, and
		// the rule is that a discrepancy is SHOWN. A user who cannot find
		// "notes.txt" and was never told it is now "notes (from Windows).txt"
		// has been failed by this program even though every byte is correct.
		w("RENAMED, BECAUSE SOMETHING WAS ALREADY HERE")
		w("")
		w("  %s came from your old computer, but this computer already had a", plural(len(aside), "file", "files"))
		w("  file with the same name. Nothing was overwritten. Your old file is")
		w("  saved beside the new one, under the name shown on the right.")
		w("")
		for _, line := range aside {
			w("  %s", line)
		}
		w("")
		rule()
	}

	if n := s.Counts[OutWithheld]; n > 0 {
		w("WHAT DID NOT COME ACROSS, ON PURPOSE")
		w("")
		w("  %d file(s). Chrome and Microsoft Edge lock your saved passwords,", n)
		w("  cookies and card details to the computer they were saved on. They")
		w("  cannot be moved to another machine by anyone, including us, and we")
		w("  do not try. Your BOOKMARKS and your BROWSING HISTORY did come across.")
		w("")
		w("  To bring your passwords over, sign in to Chrome or Edge on this")
		w("  computer with the same account, or export them from your old")
		w("  computer's browser before it is wiped.")
		w("")
		rule()
	}

	for _, h := range []*HandlerReport{s.WiFi, s.Printers} {
		if h == nil {
			continue
		}
		w("%s", strings.ToUpper(h.Title))
		w("")
		for _, line := range h.Lines {
			w("  %s", line)
		}
		for _, p := range h.Problems {
			w("  ! %s", p)
		}
		w("")
		rule()
	}

	if s.PreVerify != nil && len(s.PreVerify.Disagreements) > 0 {
		w("%s", preVerifyHeading)
		w("")
		w("  These are files on the BACKUP DRIVE, not on this computer. Nothing")
		w("  was written here. Do not wipe or reformat that drive: whoever set")
		w("  this computer up may still be able to get these back.")
		w("")
		for _, d := range s.PreVerify.Disagreements {
			w("  %s", d.Path)
			w("      %s", d.Kind)
			w("      the list says: %s", orNone(d.Want))
			w("      the drive has: %s", orNone(d.Got))
		}
		w("")
		rule()
	}

	if bad := badFiles(s); len(bad) > 0 {
		w("FILES WITH A PROBLEM — every one of them, named")
		w("")
		for _, line := range bad {
			w("  %s", line)
		}
		w("")
		rule()
	}

	w("DETAIL, FOR SOMEBODY WHO NEEDS IT")
	w("")
	if s.Archive != nil {
		w("  backup found at    %s", s.Archive.Root)
		if s.Archive.FSType != "" {
			w("  on a              %s filesystem", s.Archive.FSType)
		}
		w("  backup's list id   %s", s.Archive.Digest)
	}
	w("  restored into      %s", s.Home)
	w("  started            %s", s.StartedAt.Format(time.RFC3339))
	w("  finished           %s", s.FinishedAt.Format(time.RFC3339))
	if s.NotifyAttempt != "" {
		w("  desktop popup      %s", s.NotifyAttempt)
	}
	w("")
	w("  You can run the restore again safely. It checks every file that is")
	w("  already here and only writes the ones that are missing.")

	return b.String()
}

// problems collects every reason this run is not clean. A summary that is not
// clean and produces no problem lines would be the worst possible bug in this
// file, so the last branch says so out loud rather than printing nothing.
func problems(s *Summary) []string {
	var out []string
	if s.ManifestCount == 0 {
		out = append(out, "the backup's file list was empty, so there was nothing to restore")
	}
	if s.PreVerify != nil && !s.PreVerify.Clean() {
		out = append(out, fmt.Sprintf(
			"the backup drive itself did not check out: %d of %d files disagreed with the list. "+
				"NOTHING WAS WRITTEN to this computer.",
			len(s.PreVerify.Disagreements), s.PreVerify.ManifestCount))
		if s.PreVerify.ManifestCount != s.PreVerify.DestinationCount {
			out = append(out, fmt.Sprintf(
				"the backup's list describes %d file(s) and the drive holds %d. Those are different "+
					"numbers, so the drive is not the backup the list describes.",
				s.PreVerify.ManifestCount, s.PreVerify.DestinationCount))
		}
		// NAMED, not counted. "1 of 1 files disagreed" is a swallowed
		// discrepancy wearing a number: the user cannot act on it, cannot
		// tell whether it is the file that matters, and cannot tell anyone
		// else what happened. Everything beyond the first few is in the
		// section below, and nothing is dropped.
		for i, d := range s.PreVerify.Disagreements {
			if i >= preVerifyInline {
				out = append(out, fmt.Sprintf(
					"...and %d more, every one of them named under %q below.",
					len(s.PreVerify.Disagreements)-preVerifyInline, preVerifyHeading))
				break
			}
			out = append(out, fmt.Sprintf("%s — %s (the list says %s, the drive has %s)",
				d.Path, d.Kind, orNone(d.Want), orNone(d.Got)))
		}
	}
	if s.ReVerify != nil && !s.ReVerify.Clean() {
		if s.ReVerify.DryRun {
			out = append(out, "this was a practice run, so no file was actually written")
		} else if !s.ReVerify.Reconciled {
			out = append(out, fmt.Sprintf(
				"%d of the %d files in the backup's list were accounted for. The rest are unexplained, "+
					"which is a bug in this program and not something you did.",
				s.ReVerify.Accounted, s.ReVerify.Manifest))
		}
		for _, d := range s.ReVerify.Disagreements {
			out = append(out, d)
		}
	}
	if n := s.Counts[OutFailed]; n > 0 {
		out = append(out, fmt.Sprintf("%d file(s) could not be written — each one is named below", n))
	}
	for _, h := range []*HandlerReport{s.WiFi, s.Printers} {
		if h == nil {
			continue
		}
		out = append(out, h.Problems...)
	}
	if len(out) == 0 {
		out = append(out, "the run did not finish cleanly and this program cannot say why, "+
			"which is itself a fault. Do not wipe the backup drive. Show this file to whoever set the computer up.")
	}
	return out
}

// preVerifyInline is how many damaged files are named in the summary at the
// top before the rest are deferred to their own section. Nothing is ever
// dropped; this only decides where it is printed.
const preVerifyInline = 12

// preVerifyHeading is the section title, referenced from the summary so the
// pointer and the section cannot drift apart.
const preVerifyHeading = "EVERY FILE ON THE BACKUP THAT DID NOT CHECK OUT"

func orNone(s string) string {
	if s == "" {
		return "(nothing recorded)"
	}
	return s
}

// plural spells a count the way a person writes it. "1 files" in the first
// sentence of the only document a school's IT person reads is the kind of
// detail that makes them trust the rest of it less, and they would be right.
func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// renamedFiles lists every file that went in beside something else.
func renamedFiles(s *Summary) []string {
	var out []string
	for _, r := range s.Results {
		if r.Outcome != OutPlacedAside {
			continue
		}
		out = append(out, fmt.Sprintf("%s\n      is now: %s", r.Path, r.Final))
	}
	sort.Strings(out)
	return out
}

func badFiles(s *Summary) []string {
	var out []string
	for _, r := range s.Results {
		if r.Outcome == OutFailed {
			out = append(out, fmt.Sprintf("%s\n      wanted at: %s\n      what happened: %s", r.Path, r.Final, r.Detail))
		}
	}
	sort.Strings(out)
	return out
}

// whereItWent is the orientation paragraph: which Windows folder became which
// Linux folder. It is the part a user actually reads.
//
// It counts ONLY files that are really on the disk. The first version counted
// every result in a bucket, so a Chrome profile whose passwords were withheld
// reported "4 file(s), under ~/.config/google-chrome/Default" when two of them
// had deliberately not been written. A count that is off by the number of
// things we chose not to do is worse than no count: it is the report telling
// the user something happened that did not, in the section they read first.
// Withheld files and the Wi-Fi and printer items have sections of their own.
func whereItWent(s *Summary) []string {
	type bucket struct {
		n   int
		dir string
	}
	seen := map[string]*bucket{}
	for _, r := range s.Results {
		switch r.Outcome {
		case OutWritten, OutAlreadyPresent, OutPlacedAside:
		default:
			continue
		}
		b, ok := seen[r.Bucket]
		if !ok {
			b = &bucket{}
			seen[r.Bucket] = b
		}
		b.n++
		d := filepath.Dir(r.Final)
		switch {
		case b.dir == "":
			b.dir = d
		case underPath(b.dir, d):
			// A shallower directory holds the ones already counted, so name
			// the shallower one: "under ~/Documents" is true of a file in
			// ~/Documents/reports, and "under ~/Documents/reports" is not
			// true of a file in ~/Documents.
			b.dir = d
		case underPath(d, b.dir):
			// already the shallower one
		default:
			b.dir = commonDir(b.dir, d)
		}
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		b := seen[n]
		if b.dir == "" || b.dir == "." {
			out = append(out, fmt.Sprintf("%-14s %s", n, plural(b.n, "file", "files")))
			continue
		}
		out = append(out, fmt.Sprintf("%-14s %s, under %s", n, plural(b.n, "file", "files"), b.dir))
	}
	if len(out) == 0 {
		// Said out loud rather than printed as an empty section. A restore
		// that placed nothing is a fact the user needs, and a blank heading
		// reads like a rendering bug.
		out = append(out, "no files were written to this computer.")
	}
	return out
}

// commonDir is the deepest directory that holds both a and b.
func commonDir(a, b string) string {
	as := strings.Split(filepath.Clean(a), string(filepath.Separator))
	bs := strings.Split(filepath.Clean(b), string(filepath.Separator))
	n := 0
	for n < len(as) && n < len(bs) && as[n] == bs[n] {
		n++
	}
	if n == 0 {
		return string(filepath.Separator)
	}
	return strings.Join(as[:n], string(filepath.Separator))
}

// NotifyBody is the one-line message for the desktop popup. It leads with the
// count, because the count is what SPEC §6C asks to be reported and it is the
// only thing a popup has room to say.
func NotifyBody(s *Summary) (summary, body string, urgent bool) {
	if s.Clean() {
		return "Your files are here",
			fmt.Sprintf("%d files came across from your old computer, and every one was checked twice. "+
				"There is a note on your desktop.", s.FilesRestored()),
			false
	}
	return "Please read the note on your desktop",
		"Some of your files need your attention. Your backup drive has not been changed.",
		true
}
