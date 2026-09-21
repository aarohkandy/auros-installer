// Package verify is SAFETY.md phase 5.
//
// It re-reads every file FROM THE DESTINATION and re-hashes it. It never reads
// the source. That is the whole point: the manifest digest was computed from the
// bytes that were written (phase 4), and this compares it against the bytes that
// can now be read back. A verification that re-read the source would prove only
// that the source is still the source.
//
// This package cannot mint a token of success. It returns a Report saying
// exactly what disagreed. safety.Verify calls it and is the only place a
// safety.VerifiedArchive comes into existence, because Go gives a struct with
// unexported fields exactly one legitimate constructor site: its own package.
// Keeping the report here and the token there is deliberate — this package can
// be changed, extended and argued about without anyone acquiring the ability to
// declare a run verified.
package verify

import (
	"context"
	"crypto/sha256"
	"fmt"
	"hash"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
)

// Kind classifies a disagreement. Each one is a different story to tell the user.
type Kind string

const (
	KindMissing    Kind = "missing-from-destination"
	KindExtra      Kind = "unexpected-at-destination"
	KindSize       Kind = "size-differs"
	KindHash       Kind = "contents-differ"
	KindUnreadable Kind = "unreadable-at-destination"
	KindNotRegular Kind = "not-a-regular-file-at-destination"
)

// Disagreement is one file that did not match.
type Disagreement struct {
	Path    string // original source path, as the user knows it
	Stored  string // path under the destination root
	Kind    Kind
	Want    string
	Got     string
	Retried bool
}

func (d Disagreement) String() string {
	s := fmt.Sprintf("%-32s %s", d.Kind, d.Path)
	if d.Want != "" || d.Got != "" {
		s += fmt.Sprintf("\n    expected: %s\n    found:    %s", d.Want, d.Got)
	}
	if d.Retried {
		s += "\n    (retried once)"
	}
	return s
}

// disagree builds a Disagreement. Every failure site in this file goes through
// it, so the shape of a disagreement is defined once and a new failure mode
// cannot quietly omit the field that tells the user what was expected.
func disagree(e manifest.Entry, kind Kind, want, got string) *Disagreement {
	return &Disagreement{
		Path:   e.Path,
		Stored: e.Stored,
		Kind:   kind,
		Want:   want,
		Got:    got,
	}
}

// Report is the full result. A Report is produced whether verification passed or
// failed; Clean is what distinguishes them.
type Report struct {
	ManifestCount    int
	DestinationCount int
	Checked          int
	Retried          int
	BytesRead        int64
	Disagreements    []Disagreement
	// Litter is every file at the destination that is NOT in the manifest and
	// is something an operating system leaves in any folder a person opens:
	// Thumbs.db, desktop.ini, a Mac's ._ files, a Linux desktop's .Trash-1000.
	// Each is NAMED here and in Describe, and is not a disagreement. See
	// isLitter for the list and for why it cannot hide a real file.
	Litter     []string
	StartedAt  time.Time
	FinishedAt time.Time
}

// Counted is the number of files at the destination that count against the
// manifest: everything that was found, less the named litter. The equality
// Clean asks for is ManifestCount == Counted, and it is still exact.
func (r *Report) Counted() int {
	if r == nil {
		return 0
	}
	return r.DestinationCount - len(r.Litter)
}

// Clean reports whether every file in the manifest was found at the destination
// with the right size and the right digest, with nothing extra alongside it.
//
// A report over zero files is NOT clean. 0 == 0 == 0 satisfies every equality
// below, so without this an empty verification reads as a perfect one, and a
// perfect verification of nothing is the strongest-looking evidence in the
// program. "Nothing disagreed" is only reassuring if something was checked.
func (r *Report) Clean() bool {
	return r != nil &&
		r.ManifestCount > 0 &&
		len(r.Disagreements) == 0 &&
		r.ManifestCount == r.Counted() &&
		r.Checked == r.ManifestCount
}

// Describe renders the report for a human. When it fails it names files, because
// "verification failed" is not something a user can act on.
func (r *Report) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "verify: %d file(s) in the manifest, %d found at the destination, %d checked\n",
		r.ManifestCount, r.DestinationCount, r.Checked)
	if r.Retried > 0 {
		fmt.Fprintf(&b, "        %d file(s) needed a second read\n", r.Retried)
	}
	if len(r.Litter) > 0 {
		fmt.Fprintf(&b, "        %d file(s) beside the archive are not part of it and were not counted:\n", len(r.Litter))
		for _, l := range r.Litter {
			fmt.Fprintf(&b, "          %s\n", l)
		}
	}
	if r.Clean() {
		b.WriteString("        every file matched by count, size and SHA-256.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "        %d disagreement(s):\n", len(r.Disagreements))
	for _, d := range r.Disagreements {
		fmt.Fprintf(&b, "  %s\n", d)
	}
	if r.ManifestCount != r.Counted() {
		fmt.Fprintf(&b, "  COUNT MISMATCH: manifest %d, destination %d\n", r.ManifestCount, r.Counted())
	}
	return b.String()
}

// Options configures Run.
type Options struct {
	// DestRoot is the destination volume root. Nothing outside it is read.
	DestRoot string
	// Manifest is what the copy claims it wrote.
	Manifest *manifest.Manifest
	// Quarantine receives a record for every unresolved disagreement, so the
	// user sees one list rather than two.
	Quarantine *quarantine.Set
	// Retries is how many extra reads a mismatching file gets. SAFETY.md phase
	// 5 specifies one. Zero here means one; use -1 for none.
	Retries int
	// BufSize is the streaming chunk size.
	BufSize int
	// MetaDir is excluded from the destination file count. Empty means "_auros".
	MetaDir string
	// Progress is called after each file. May be nil.
	Progress func(done, total int)
	// Clock may be nil.
	Clock func() time.Time
}

func (o Options) retries() int {
	switch {
	case o.Retries < 0:
		return 0
	case o.Retries == 0:
		return 1
	default:
		return o.Retries
	}
}

// Run performs phase 5. It returns an error only for conditions that made
// verification impossible (no manifest, unreadable destination, cancellation);
// a file that simply did not match is a Disagreement in the Report, not an error.
func Run(ctx context.Context, o Options) (*Report, error) {
	if o.Manifest == nil {
		return nil, fmt.Errorf("verify: no manifest")
	}
	if o.DestRoot == "" {
		return nil, fmt.Errorf("verify: no destination root")
	}
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	meta := o.MetaDir
	if meta == "" {
		meta = manifest.MetaDir
	}
	bufSize := o.BufSize
	if bufSize <= 0 {
		bufSize = manifest.DefaultBufSize
	}

	rep := &Report{StartedAt: clock()}
	entries := o.Manifest.Entries()
	rep.ManifestCount = len(entries)

	found, err := scanDestination(ctx, o.DestRoot, meta)
	if err != nil {
		return rep, err
	}
	rep.DestinationCount = len(found)

	buf := make([]byte, bufSize)
	h := sha256.New()

	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			rep.FinishedAt = clock()
			return rep, err
		}
		full := filepath.Join(o.DestRoot, filepath.FromSlash(e.Stored))
		d, retried, n := checkOne(ctx, full, e, h, buf, o.retries())
		rep.BytesRead += n
		if retried {
			rep.Retried++
		}
		rep.Checked++
		delete(found, e.Stored)
		if d != nil {
			d.Retried = retried
			rep.Disagreements = append(rep.Disagreements, *d)
			recordQuarantine(o.Quarantine, *d)
		}
		if o.Progress != nil {
			o.Progress(rep.Checked, rep.ManifestCount)
		}
	}

	// Anything left in found is at the destination but not in the manifest. That
	// is not harmless: it means the destination is not the archive we think it
	// is, and a restore would either copy a stranger's file onto the new machine
	// or silently ignore it. Either way the count no longer means anything.
	//
	// EXCEPT litter. A Thumbs.db that Windows Explorer dropped when somebody
	// opened the folder is not evidence that the archive is somebody else's,
	// and the first version treated it exactly as if it were: one thumbnail
	// cache beside a perfect archive made the Linux restore refuse the whole
	// run with "THE ARCHIVE IS DAMAGED", and told a school that its only copy
	// was not the backup the list describes. Litter is named, not counted,
	// and never quarantined. Everything else still is.
	extras := make([]string, 0, len(found))
	for stored := range found {
		if isLitter(stored) {
			rep.Litter = append(rep.Litter, stored)
			continue
		}
		extras = append(extras, stored)
	}
	sort.Strings(rep.Litter)
	sort.Strings(extras)
	for _, stored := range extras {
		extra := manifest.Entry{Path: stored, Stored: stored}
		d := *disagree(extra, KindExtra, "not present", "present at destination")
		rep.Disagreements = append(rep.Disagreements, d)
		recordQuarantine(o.Quarantine, d)
	}

	rep.FinishedAt = clock()
	return rep, nil
}

// litterNames are files an operating system writes into a folder because a
// person LOOKED at it. Compared case-insensitively on the last path segment.
var litterNames = map[string]bool{
	"thumbs.db":         true, // Windows Explorer thumbnail cache
	"ehthumbs.db":       true, // Windows Media Center thumbnail cache
	"ehthumbs_vista.db": true,
	"desktop.ini":       true, // Windows folder view settings
	".ds_store":         true, // macOS Finder view settings
	".localized":        true, // macOS
	".directory":        true, // KDE Dolphin folder view settings
}

// litterDirs are directories an operating system creates at the top of a
// removable volume or in a folder it has been asked to delete from. Anything
// inside one is litter. Compared case-insensitively on any path segment.
var litterDirs = map[string]bool{
	"$recycle.bin":              true, // Windows recycle bin on a removable drive
	"system volume information": true, // Windows indexer / restore point metadata
	".spotlight-v100":           true, // macOS Spotlight index
	".fseventsd":                true, // macOS filesystem event log
	".trashes":                  true, // macOS trash on a removable drive
	".temporaryitems":           true, // macOS
}

// isLitter reports whether a file at the destination, WHICH THE MANIFEST DOES
// NOT LIST, is operating-system noise rather than an unexplained file.
//
// It is only ever asked about files left over after every manifest entry has
// been checked and removed from the scan, and that ordering is the whole
// safety argument: a real Thumbs.db that was in the user's Pictures folder is
// IN the manifest, is verified by size and hash like any other file, and never
// reaches this function. Litter is not restored — the restore only ever writes
// manifest entries — so calling a file litter can only change the COUNT, never
// what lands on the user's machine.
func isLitter(stored string) bool {
	segs := strings.Split(stored, "/")
	for _, seg := range segs[:len(segs)-1] {
		low := strings.ToLower(seg)
		if litterDirs[low] || strings.HasPrefix(low, ".trash-") {
			// .Trash-<uid>: a Linux desktop's trash on a removable volume.
			return true
		}
	}
	last := segs[len(segs)-1]
	if litterNames[strings.ToLower(last)] {
		return true
	}
	// AppleDouble: "._report.txt" carries a Mac's resource fork for
	// "report.txt". Always at least one character after the prefix.
	return strings.HasPrefix(last, "._") && len(last) > 2
}

func recordQuarantine(q *quarantine.Set, d Disagreement) {
	if q == nil {
		return
	}
	reason := quarantine.ReasonHashMismatch
	switch d.Kind {
	case KindMissing:
		reason = quarantine.ReasonMissingAtDest
	case KindExtra:
		reason = quarantine.ReasonExtraAtDest
	case KindSize:
		reason = quarantine.ReasonSizeMismatch
	case KindUnreadable:
		reason = quarantine.ReasonReadError
	case KindNotRegular:
		reason = quarantine.ReasonUnsupportedType
	}
	q.Add(quarantine.Record{
		Path:     d.Path,
		Stored:   d.Stored,
		Reason:   reason,
		Detail:   fmt.Sprintf("verify: expected %q, found %q", d.Want, d.Got),
		Attempts: 1,
	})
}

// checkOne verifies a single file, retrying a mismatch before condemning it.
//
// SAFETY.md phase 5 is explicit about why the retry exists: on a real machine
// OneDrive hydrates, antivirus touches files, a browser rewrites its profile. A
// tool that aborts the whole run on the first transient read gets worked around,
// and a worked-around safety tool is more dangerous than one that reports
// precisely. The invariant is untouched — it is about what is true before the
// wall, not about how many reads it took to establish it.
func checkOne(ctx context.Context, full string, e manifest.Entry, h hash.Hash, buf []byte, retries int) (*Disagreement, bool, int64) {
	var last *Disagreement
	var bytesRead int64
	attempts := retries + 1
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return disagree(e, KindUnreadable, e.SHA256, "cancelled"), attempt > 0, bytesRead
		}
		d, n := checkOnce(ctx, full, e, h, buf)
		bytesRead += n
		if d == nil {
			return nil, attempt > 0, bytesRead
		}
		last = d
	}
	return last, attempts > 1, bytesRead
}

func checkOnce(ctx context.Context, full string, e manifest.Entry, h hash.Hash, buf []byte) (*Disagreement, int64) {
	st, err := os.Lstat(full)
	if err != nil {
		if os.IsNotExist(err) {
			return disagree(e, KindMissing, fmt.Sprintf("%d bytes, %s", e.Size, e.SHA256), "no such file"), 0
		}
		return disagree(e, KindUnreadable, e.SHA256, err.Error()), 0
	}
	if !st.Mode().IsRegular() {
		return disagree(e, KindNotRegular, "regular file", st.Mode().String()), 0
	}
	if st.Size() != e.Size {
		return disagree(e, KindSize, fmt.Sprintf("%d bytes", e.Size), fmt.Sprintf("%d bytes", st.Size())), 0
	}
	h.Reset()
	sum, n, err := manifest.HashFile(ctx, full, h, buf)
	if err != nil {
		return disagree(e, KindUnreadable, e.SHA256, err.Error()), n
	}
	if sum != e.SHA256 {
		return disagree(e, KindHash, e.SHA256, sum), n
	}
	return nil, n
}

// scanDestination lists every regular file under root as a slash-separated
// relative path, excluding the metadata directory. The count it produces is the
// count compared against the manifest, which is how "all the hashes are fine but
// there are 99 files where there should be 100" is caught.
func scanDestination(ctx context.Context, root, meta string) (map[string]bool, error) {
	out := make(map[string]bool)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == meta || strings.HasPrefix(rel, meta+"/") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		out[rel] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("verify: scanning destination: %w", err)
	}
	return out, nil
}
