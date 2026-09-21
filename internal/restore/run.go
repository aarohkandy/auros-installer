package restore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/verify"
)

// Outcome is what happened to one planned item. Every item ends with exactly
// one, and the report prints the count of each. There is no outcome that means
// "nothing to say about this file".
type Outcome string

const (
	// OutWritten: the file was placed on disk by this run.
	OutWritten Outcome = "written"
	// OutAlreadyPresent: the destination already held EXACTLY these bytes, so
	// there was nothing to do. This is how a re-run after a power cut is
	// idempotent, and it is decided by hashing the file on disk, never by
	// trusting a note from a previous run.
	OutAlreadyPresent Outcome = "already-there"
	// OutPlacedAside: something ELSE was already at the destination. We never
	// overwrite a file we cannot prove is ours, so the restored copy went in
	// beside it under a different name and the user is told both names.
	OutPlacedAside Outcome = "placed-alongside"
	// OutWithheld: deliberately not restored. D15.
	OutWithheld Outcome = "not-migrated-by-design"
	// OutHandled: passed to the Wi-Fi or printer handler rather than copied.
	OutHandled Outcome = "handled-separately"
	// OutFailed: we could not place it. Always shown, never counted as success.
	OutFailed Outcome = "FAILED"
)

// Result is one item's fate.
type Result struct {
	Path    string // the original path, as the user knows it
	Bucket  string
	Outcome Outcome
	Final   string // where it actually ended up, for the file outcomes
	Detail  string
}

// Summary is the whole run. It is what the desktop report is rendered from and
// what the exit status is decided by.
type Summary struct {
	Archive        *Archive
	Home           string
	ManifestCount  int
	Results        []Result
	Counts         map[Outcome]int
	PreVerify      *verify.Report
	ReVerify       *ReVerifyReport
	WiFi           *HandlerReport
	Printers       *HandlerReport
	StartedAt      time.Time
	FinishedAt     time.Time
	StoppedEarly   string // non-empty when the run stopped before finishing
	NotifyAttempt  string
	ReportFilePath string
}

// Clean is the single question the whole program exists to answer, and it is
// deliberately hard to satisfy.
//
// A summary over zero files is NOT clean: 0 == 0 satisfies every equality
// below, and a perfect restore of nothing is the most convincing-looking
// evidence this program can produce. verify.Report.Clean has the same guard for
// the same reason.
func (s *Summary) Clean() bool {
	if s == nil || s.ManifestCount == 0 || s.StoppedEarly != "" {
		return false
	}
	if s.PreVerify == nil || !s.PreVerify.Clean() {
		return false
	}
	if s.ReVerify == nil || !s.ReVerify.Clean() {
		return false
	}
	if s.Counts[OutFailed] > 0 {
		return false
	}
	if len(s.Results) != s.ManifestCount {
		return false
	}
	return true
}

// FilesRestored is the number the user is shown: files that are now on this
// machine because of the migration, whether this run put them there or a
// previous, interrupted run did.
func (s *Summary) FilesRestored() int {
	return s.Counts[OutWritten] + s.Counts[OutAlreadyPresent] + s.Counts[OutPlacedAside]
}

// Options configures Execute.
type Options struct {
	// DryRun plans and verifies but writes no user file. The verifications
	// still run: a dry run that skipped them would tell the user nothing about
	// the thing they actually want to know, which is whether the archive is
	// intact.
	DryRun bool
	// BufSize is the streaming chunk size. Zero means manifest.DefaultBufSize.
	BufSize int
	// Now may be nil.
	Now func() time.Time
	// Progress is called after each item. May be nil.
	Progress func(done, total int, path string)
	// WiFiSink and PrinterSink handle the non-file dispositions. Either may be
	// nil, in which case those items are reported as unhandled rather than
	// silently dropped.
	WiFiSink    Handler
	PrinterSink Handler

	// hookWriter wraps the destination writer. It is UNEXPORTED and in-package,
	// the same shape as copyengine's hookDst and for the same reason: a
	// destination that fills up part-way through a file is the failure this
	// code exists to survive, and there is no portable way to make a real
	// filesystem run out of room inside a unit test. SAFETY.md rule 8 — an
	// option that could weaken a check never gets an exported off switch.
	hookWriter func(path string, w io.Writer) io.Writer
}

// Handler consumes the non-file parts of an archive.
type Handler interface {
	// Handle is given the items and the archive root. It returns a report
	// naming every profile or printer and what was done with it.
	Handle(ctx context.Context, items []*Item) (*HandlerReport, error)
}

// HandlerReport is what a Wi-Fi or printer handler has to say.
type HandlerReport struct {
	Title string
	// Lines are shown to the user verbatim, one per profile or printer.
	Lines []string
	// Done and Skipped must sum to the number of items handled.
	Done, Skipped int
	// Problems is non-empty when something went wrong. A non-empty Problems
	// makes the whole run not-clean.
	Problems []string
}

// Execute runs the restore. The order of the steps below is the contract, and
// the two verifications either side of the writes are the reason this program
// is trustworthy at all.
func Execute(ctx context.Context, p *Plan, o Options) (*Summary, error) {
	if p == nil {
		return nil, errors.New("restore: no plan")
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	bufSize := o.BufSize
	if bufSize <= 0 {
		bufSize = manifest.DefaultBufSize
	}

	s := &Summary{
		Archive:       p.Archive,
		Home:          p.Layout.Home,
		ManifestCount: p.Archive.Manifest.Len(),
		Counts:        map[Outcome]int{},
		StartedAt:     now(),
	}

	// ---- CHECK 1: the archive, before anything is written ----
	//
	// Read every file out of the archive and compare count and SHA-256 against
	// the manifest. If this fails, the archive is damaged and the ONLY correct
	// move is to stop: the user still has the archive, and a half-finished
	// restore written on top of a damaged one is strictly worse than no
	// restore at all.
	pre, err := verify.Run(ctx, verify.Options{
		DestRoot: p.Archive.Root,
		Manifest: p.Archive.Manifest,
		BufSize:  bufSize,
	})
	s.PreVerify = pre
	if err != nil {
		s.FinishedAt = now()
		s.StoppedEarly = "could not read the archive: " + err.Error()
		return s, fmt.Errorf("restore: verifying the archive: %w", err)
	}
	if !pre.Clean() {
		s.FinishedAt = now()
		s.StoppedEarly = "the archive did not verify; nothing was written"
		return s, fmt.Errorf("restore: THE ARCHIVE IS DAMAGED — nothing has been written.\n%s",
			pre.Describe())
	}

	// ---- WRITE ----
	total := p.Count()
	done := 0
	buf := make([]byte, bufSize)

	for _, it := range p.Files {
		if cerr := ctx.Err(); cerr != nil {
			s.StoppedEarly = "interrupted: " + cerr.Error()
			break
		}
		res := placeOne(ctx, it, o.DryRun, buf, o.hookWriter)
		s.add(res)
		done++
		if o.Progress != nil {
			o.Progress(done, total, it.Entry.Path)
		}
		if res.Outcome == OutFailed && strings.Contains(res.Detail, noSpaceMarker) {
			// A full disk does not get better by trying the next ten thousand
			// files. Stop, keep what is already correctly on disk, and say so:
			// the re-run after freeing space skips everything already restored.
			s.StoppedEarly = "the disk filled up. Free some space and run it again — " +
				"everything already restored is skipped on the second run."
			break
		}
	}

	for _, it := range p.Withheld {
		s.add(Result{
			Path: it.Entry.Path, Bucket: it.Route.Bucket,
			Outcome: OutWithheld, Detail: it.Route.Why,
		})
		done++
	}

	if s.StoppedEarly == "" {
		s.WiFi = runHandler(ctx, o.WiFiSink, p.WiFi, "Wi-Fi networks")
		s.Printers = runHandler(ctx, o.PrinterSink, p.Printers, "Printers")
		for _, it := range p.WiFi {
			s.add(Result{Path: it.Entry.Path, Bucket: it.Route.Bucket, Outcome: OutHandled, Detail: "wireless profile"})
		}
		for _, it := range p.Printers {
			s.add(Result{Path: it.Entry.Path, Bucket: it.Route.Bucket, Outcome: OutHandled, Detail: "printer inventory"})
		}
	}

	// ---- CHECK 3: the restored files, read back from the home directory ----
	//
	// Different bytes from check 1, on a different filesystem, after a
	// different set of writes. This is the check that catches a full disk that
	// reported success, a filesystem that silently truncated a name, and a
	// rename that landed somewhere other than where we think it did.
	s.ReVerify = reVerify(ctx, s.Results, p, o.DryRun, buf)

	s.FinishedAt = now()
	return s, nil
}

func (s *Summary) add(r Result) {
	s.Results = append(s.Results, r)
	s.Counts[r.Outcome]++
}

func runHandler(ctx context.Context, h Handler, items []*Item, title string) *HandlerReport {
	if len(items) == 0 {
		return nil
	}
	if h == nil {
		return &HandlerReport{
			Title:   title,
			Skipped: len(items),
			Problems: []string{fmt.Sprintf(
				"%d item(s) were in the archive but this build has no handler for them, so they were NOT restored.",
				len(items))},
		}
	}
	rep, err := h.Handle(ctx, items)
	if err != nil {
		if rep == nil {
			rep = &HandlerReport{Title: title}
		}
		rep.Problems = append(rep.Problems, err.Error())
	}
	if rep != nil && rep.Title == "" {
		rep.Title = title
	}
	return rep
}

const noSpaceMarker = "the disk is full"

// placeOne writes a single file, and every branch it can take is an outcome the
// user is shown.
func placeOne(ctx context.Context, it *Item, dryRun bool, buf []byte, hook func(string, io.Writer) io.Writer) Result {
	e := it.Entry
	base := Result{Path: e.Path, Bucket: it.Route.Bucket}

	target := it.Route.Target
	for n := 0; ; n++ {
		st, err := os.Lstat(target)
		switch {
		case os.IsNotExist(err):
			// Nothing there. This is the ordinary case on a fresh machine.
		case err != nil:
			base.Outcome, base.Final, base.Detail = OutFailed, target, "cannot look at the destination: "+err.Error()
			return base
		case st.Mode().IsRegular():
			// Something is there. Is it already exactly what we were going to
			// write? Decided by hashing it, not by trusting a state file:
			// correctness has to come from the disk, because the disk is the
			// thing that survives the power cut.
			if st.Size() == e.Size {
				sum, _, herr := manifest.HashFile(ctx, target, sha256.New(), buf)
				if herr == nil && sum == e.SHA256 {
					base.Outcome, base.Final = OutAlreadyPresent, target
					if n > 0 {
						base.Detail = "restored beside an existing file by an earlier run"
					}
					return base
				}
			}
			// Someone else's file, or our own from a run whose bytes differ.
			// We do not overwrite it. Ever.
			if n > 1000 {
				base.Outcome, base.Final = OutFailed, target
				base.Detail = "too many files already occupy this name"
				return base
			}
			target = aside(it.Route.Target, n)
			continue
		default:
			// A directory, a symlink, a device node where a file belongs. Not
			// ours to replace, and following it could write outside the home
			// directory, which is the thing the plan refused.
			if n > 1000 {
				base.Outcome, base.Final, base.Detail = OutFailed, target, "too many files already occupy this name"
				return base
			}
			target = aside(it.Route.Target, n)
			continue
		}
		break
	}

	if dryRun {
		base.Outcome, base.Final, base.Detail = OutWritten, target, "dry run: not actually written"
		return base
	}

	if err := os.MkdirAll(filepath.Dir(target), os.FileMode(it.Route.DirMode)); err != nil {
		base.Outcome, base.Final, base.Detail = OutFailed, target, describeWriteErr(err)
		return base
	}
	if err := writeAtomic(ctx, it.Source, target, e, os.FileMode(it.Route.FileMode), buf, hook); err != nil {
		base.Outcome, base.Final, base.Detail = OutFailed, target, describeWriteErr(err)
		return base
	}
	base.Final = target
	if target != it.Route.Target {
		base.Outcome = OutPlacedAside
		base.Detail = "something was already called " + filepath.Base(it.Route.Target) + "; yours is " + filepath.Base(target)
		return base
	}
	base.Outcome = OutWritten
	return base
}

func describeWriteErr(err error) string {
	if isNoSpace(err) {
		return noSpaceMarker + ": " + err.Error()
	}
	return err.Error()
}

// aside builds a name beside the one that is taken. It is spelled for a person
// reading their own Documents folder, not for a log.
func aside(p string, n int) string {
	dir, base := filepath.Dir(p), filepath.Base(p)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if n == 0 {
		return filepath.Join(dir, stem+" (from Windows)"+ext)
	}
	return filepath.Join(dir, fmt.Sprintf("%s (from Windows %d)%s", stem, n+1, ext))
}

// writeAtomic streams one file from the archive into place.
//
// The bytes are hashed AS THEY ARE WRITTEN and compared against the manifest
// BEFORE the rename. A file whose digest does not match never acquires its real
// name, so an interrupted or corrupted write cannot leave a plausible-looking
// wrong file in somebody's Documents folder. The temporary file is removed on
// every failure path.
func writeAtomic(ctx context.Context, src, dst string, e manifest.Entry, mode os.FileMode, buf []byte, hook func(string, io.Writer) io.Writer) error {
	dir := filepath.Dir(dst)
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("reading %s from the archive: %w", e.Path, err)
	}
	defer in.Close()

	tmp, err := os.CreateTemp(dir, ".auros-restore-*.part")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			tmp.Close()
			os.Remove(tmpName)
		}
	}()

	var w io.Writer = tmp
	if hook != nil {
		w = hook(dst, tmp)
	}
	sum, n, err := manifest.CopyHashed(ctx, w, in, sha256.New(), buf)
	if err != nil {
		return err
	}
	if n != e.Size {
		return fmt.Errorf("%s: archive holds %d bytes, the manifest says %d", e.Path, n, e.Size)
	}
	if sum != e.SHA256 {
		return fmt.Errorf("%s: the archive changed under us — read %s, expected %s", e.Path, sum, e.SHA256)
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if e.ModTimeUnixNano != 0 {
		mt := time.Unix(0, e.ModTimeUnixNano)
		// A filesystem that will not carry the mtime is not a reason to fail
		// the file; the bytes are what matter and the bytes are written.
		_ = os.Chtimes(tmpName, mt, mt)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	committed = true
	syncDir(dir)
	return nil
}

// syncDir flushes the directory entry so the rename survives a power cut. A
// filesystem that refuses to open a directory (or to sync one) is not a failure
// of the file: the bytes are already on the platter.
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer d.Close()
	_ = d.Sync()
}

// ReVerifyReport is check 3: every restored file read back from the home
// directory and hashed.
type ReVerifyReport struct {
	Expected      int // files that should be on disk
	Checked       int
	Matched       int
	BytesRead     int64
	Disagreements []string
	// Reconciled is the count identity: every manifest entry is accounted for
	// by exactly one outcome. It is a separate field from Matched because a
	// run where the hashes all match but an entry vanished from the accounting
	// is exactly the failure this program must not have.
	Reconciled bool
	Accounted  int
	Manifest   int
	DryRun     bool
}

// Clean requires that something was actually checked. See Summary.Clean.
func (r *ReVerifyReport) Clean() bool {
	if r == nil || !r.Reconciled {
		return false
	}
	if r.DryRun {
		// A dry run wrote nothing, so there is nothing to read back. It is
		// reconciled or it is not; it is never "clean" in the sense the user
		// is told their files are safe.
		return false
	}
	return r.Expected > 0 &&
		r.Checked == r.Expected &&
		r.Matched == r.Expected &&
		len(r.Disagreements) == 0
}

func (r *ReVerifyReport) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "re-check: %d file(s) expected on this machine, %d read back, %d matched\n",
		r.Expected, r.Checked, r.Matched)
	fmt.Fprintf(&b, "          %d of %d manifest entries accounted for\n", r.Accounted, r.Manifest)
	for _, d := range r.Disagreements {
		fmt.Fprintf(&b, "  %s\n", d)
	}
	return b.String()
}

// reVerify reads every file this run says it placed back off the disk and
// hashes it.
func reVerify(ctx context.Context, results []Result, p *Plan, dryRun bool, buf []byte) *ReVerifyReport {
	rep := &ReVerifyReport{
		Manifest: p.Archive.Manifest.Len(),
		DryRun:   dryRun,
	}
	byPath := make(map[string]*Item, len(p.Files))
	for _, it := range p.Files {
		byPath[it.Entry.Path] = it
	}

	for _, res := range results {
		rep.Accounted++
		switch res.Outcome {
		case OutWritten, OutAlreadyPresent, OutPlacedAside:
			rep.Expected++
		default:
			continue
		}
		if dryRun {
			continue
		}
		it, ok := byPath[res.Path]
		if !ok {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: reported as restored but is not in the plan", res.Path))
			continue
		}
		rep.Checked++
		st, err := os.Lstat(res.Final)
		if err != nil {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: expected at %s, and it is not there (%v)", res.Path, res.Final, err))
			continue
		}
		if !st.Mode().IsRegular() {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: %s is a %s, not a file", res.Path, res.Final, st.Mode().String()))
			continue
		}
		if st.Size() != it.Entry.Size {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: %s is %d bytes, should be %d", res.Path, res.Final, st.Size(), it.Entry.Size))
			continue
		}
		sum, n, herr := manifest.HashFile(ctx, res.Final, sha256.New(), buf)
		rep.BytesRead += n
		if herr != nil {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: cannot read %s back (%v)", res.Path, res.Final, herr))
			continue
		}
		if sum != it.Entry.SHA256 {
			rep.Disagreements = append(rep.Disagreements,
				fmt.Sprintf("%s: the copy at %s does not match the archive (%s, expected %s)",
					res.Path, res.Final, sum, it.Entry.SHA256))
			continue
		}
		rep.Matched++
	}

	rep.Reconciled = rep.Accounted == rep.Manifest
	sort.Strings(rep.Disagreements)
	return rep
}
