// Package copyengine is SAFETY.md phase 4: the copy to the destination volume.
//
// It writes ONLY to the destination. There is no code path in this package that
// opens a file on the system disk for writing, and it does not import
// internal/sysdisk — internal/safety/wall_test.go enforces that.
//
// Four properties it must have, all of which come from SAFETY.md:
//
//   - The SHA-256 is computed during the copy, from the same read that produced
//     the bytes written. Hashing the source again afterwards hashes a file that
//     may have changed in between; on a live Windows machine it often has.
//   - A file that fails is retried once and then QUARANTINED, not skipped and
//     not fatal. One bad file must not abort a 40-minute run — but the run must
//     not reach the wall while any quarantined file is unresolved, and that
//     second half is enforced in internal/safety, not here.
//   - It is resumable, because a school's laptop gets unplugged.
//   - Cancellation at any point leaves the destination in a knowable state: no
//     stray partial files, and a manifest on disk describing exactly what is
//     complete.
package copyengine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
)

// partialSuffix marks a file that is mid-copy. A file carrying it is never
// complete and is never in the manifest; the engine sweeps them at the start of
// a run and removes the one it is writing if it is interrupted.
const partialSuffix = ".auros-partial"

// Progress is reported after every file.
type Progress struct {
	Files       int
	FilesTotal  int
	Bytes       int64
	BytesTotal  int64
	Quarantined int
	Current     string
}

// Options configures Run.
type Options struct {
	Sources    []Source
	DestRoot   string
	Quarantine *quarantine.Set
	Log        *runlog.Logger

	// BufSize is the streaming chunk size. Every file, of any size, is copied
	// through one buffer of this size, so a file larger than available RAM is an
	// ordinary file.
	BufSize int

	// Retries is the number of EXTRA attempts a failing file gets. SAFETY.md
	// phase 5 specifies one. Zero here means one; use -1 for none.
	Retries int

	// MaxFileBytes, if positive, quarantines anything larger.
	MaxFileBytes int64

	// Resume reuses a manifest left by an earlier interrupted run.
	Resume bool

	// Progress may be nil.
	Progress func(Progress)

	// Clock may be nil.
	Clock func() time.Time

	// MetaDir defaults to manifest.MetaDir.
	MetaDir string

	// Test hooks. Unexported, so they exist only for tests inside this package
	// and cannot be reached from any shipped code path: no other package can
	// name these fields, let alone set them.
	hookAfterOpen  func(src string)
	hookBeforeCopy func(src string)
	// hookDst substitutes the destination writer, which is how a destination
	// volume filling up MID-COPY is tested without needing a real full volume.
	hookDst func(path string, w io.Writer) io.Writer
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

func (o Options) bufSize() int {
	if o.BufSize <= 0 {
		return manifest.DefaultBufSize
	}
	return o.BufSize
}

func (o Options) metaDir() string {
	if o.MetaDir == "" {
		return manifest.MetaDir
	}
	return o.MetaDir
}

// Result is what the copy achieved.
type Result struct {
	Manifest        *manifest.Manifest
	Planned         int
	Copied          int
	Resumed         int
	Quarantined     int
	BytesCopied     int64
	BytesPlanned    int64
	DestinationFull bool
	Cancelled       bool
	PartialsSwept   []string
	ManifestPath    string
}

// Describe renders the result for a human, always saying what did NOT happen.
func (r *Result) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "copy: %d planned, %d copied, %d resumed, %d quarantined\n",
		r.Planned, r.Copied, r.Resumed, r.Quarantined)
	fmt.Fprintf(&b, "      %d of %d bytes written to the destination\n", r.BytesCopied, r.BytesPlanned)
	if r.DestinationFull {
		b.WriteString("      THE DESTINATION FILLED UP. The remaining files were not copied.\n")
	}
	if r.Cancelled {
		b.WriteString("      CANCELLED. Partial files were removed; the manifest lists what is complete.\n")
	}
	b.WriteString("      nothing was written to the system disk.\n")
	return b.String()
}

// sentinel errors used to classify a failed attempt
var (
	errSourceGone    = errors.New("source file disappeared during the copy")
	errSourceChanged = errors.New("source file changed during the copy")
)

// Run performs phase 4.
//
// It returns an error only for conditions that make the copy impossible or that
// stopped it (bad configuration, a full destination, cancellation). A file that
// could not be copied is a quarantine record, not an error — that distinction is
// the whole of SAFETY.md phase 5's argument about tools that abort constantly.
func Run(ctx context.Context, o Options) (*Result, error) {
	clock := o.Clock
	if clock == nil {
		clock = time.Now
	}
	q := o.Quarantine
	if q == nil {
		q = quarantine.NewSet(clock)
	}
	res := &Result{Manifest: manifest.New()}

	if o.DestRoot == "" {
		return res, ErrNoDestination
	}
	metaPath := filepath.Join(o.DestRoot, o.metaDir())
	if err := os.MkdirAll(metaPath, 0o755); err != nil {
		return res, fmt.Errorf("copyengine: preparing destination: %w", err)
	}
	res.ManifestPath = filepath.Join(metaPath, manifest.FileName)

	// Sweep partials left by a previous interrupted run before doing anything
	// else. A stale ".auros-partial" is not data, it is debris, and leaving it
	// means the destination file count no longer means what verify thinks it
	// means.
	swept, serr := sweepPartials(ctx, o.DestRoot)
	res.PartialsSwept = swept
	if serr != nil {
		logEvent(o.Log, "warn", runlog.Fields{"stage": "sweep-partials", "error": serr.Error()})
	}

	prior := map[string]manifest.Entry{}
	if o.Resume {
		prior = loadPrior(res.ManifestPath)
		logEvent(o.Log, "resume", runlog.Fields{"prior_entries": len(prior)})
	}

	files, err := plan(ctx, o, q)
	if err != nil {
		res.Quarantined = q.Len()
		_ = writeManifest(res.Manifest, res.ManifestPath)
		return res, err
	}
	res.Planned = len(files)
	for _, f := range files {
		res.BytesPlanned += f.Size
	}
	logEvent(o.Log, "plan", runlog.Fields{
		"files": res.Planned, "bytes": res.BytesPlanned, "quarantined_during_plan": q.Len(),
	})

	buf := make([]byte, o.bufSize())
	h := sha256.New()

	for i, f := range files {
		if err := ctx.Err(); err != nil {
			res.Cancelled = true
			quarantineRemaining(q, files[i:], quarantine.ReasonCancelled, "the run was cancelled before this file was copied")
			break
		}
		if res.DestinationFull {
			quarantineRemaining(q, files[i:], quarantine.ReasonDestinationFull, "the destination volume filled up before this file was copied")
			break
		}

		// Resume: an entry from a previous run whose destination file is still
		// there at the right size is carried forward. It is not trusted — phase
		// 5 re-reads and re-hashes every single file from the destination
		// regardless of how it got there. This only avoids re-writing bytes.
		if e, ok := prior[f.Rel]; ok && e.Stored == f.Stored && e.Size == f.Size && e.ModTimeUnixNano == f.ModTime {
			if st, serr := os.Lstat(filepath.Join(o.DestRoot, filepath.FromSlash(e.Stored))); serr == nil &&
				st.Mode().IsRegular() && st.Size() == e.Size {
				if aerr := res.Manifest.Add(e); aerr == nil {
					res.Resumed++
					q.Clear(f.Rel)
					report(o, res, q, f.Rel)
					continue
				}
			}
		}

		entry, cerr := copyWithRetry(ctx, o, f, h, buf, q)
		if cerr != nil {
			if isNoSpace(cerr) {
				res.DestinationFull = true
			}
			if errors.Is(cerr, context.Canceled) || errors.Is(cerr, context.DeadlineExceeded) {
				res.Cancelled = true
				// files[i:], not files[i+1:]: the file that was in flight when
				// the cancellation arrived was not copied either, and a file
				// that is neither copied nor quarantined is a file that went
				// missing silently.
				quarantineRemaining(q, files[i:], quarantine.ReasonCancelled, "the run was cancelled while this file was being copied")
				break
			}
			report(o, res, q, f.Rel)
			continue
		}
		if aerr := res.Manifest.Add(entry); aerr != nil {
			// Two planned files claiming one destination name. plan() should
			// have made this impossible; if it happens anyway, quarantine rather
			// than overwrite.
			q.Add(quarantine.Record{
				Path:   f.Rel, Stored: f.Stored, Reason: quarantine.ReasonNameCollision,
				Detail: aerr.Error(), Attempts: 1,
			})
			report(o, res, q, f.Rel)
			continue
		}
		q.Clear(f.Rel)
		res.Copied++
		res.BytesCopied += entry.Size
		report(o, res, q, f.Rel)
	}

	res.Quarantined = q.Len()

	// The manifest is written whatever happened, including on cancellation and
	// on a full disk. That is what makes the destination knowable: it always
	// describes exactly the set of files that are complete.
	if werr := writeManifest(res.Manifest, res.ManifestPath); werr != nil {
		return res, fmt.Errorf("copyengine: writing manifest: %w", werr)
	}
	if werr := writeQuarantineReport(q, filepath.Join(metaPath, "quarantine.txt")); werr != nil {
		logEvent(o.Log, "warn", runlog.Fields{"stage": "quarantine-report", "error": werr.Error()})
	}
	logEvent(o.Log, "complete", runlog.Fields{
		"copied": res.Copied, "resumed": res.Resumed, "quarantined": res.Quarantined,
		"bytes": res.BytesCopied, "destination_full": res.DestinationFull, "cancelled": res.Cancelled,
		"manifest_digest": res.Manifest.Digest(), "system_disk_untouched": true,
	})

	switch {
	case res.Cancelled:
		if cerr := ctx.Err(); cerr != nil {
			return res, cerr
		}
		return res, context.Canceled
	case res.DestinationFull:
		return res, fmt.Errorf("copyengine: destination volume is full after %d of %d files", res.Copied, res.Planned)
	}
	return res, nil
}

func report(o Options, res *Result, q *quarantine.Set, current string) {
	if o.Progress == nil {
		return
	}
	o.Progress(Progress{
		Files:       res.Copied + res.Resumed, FilesTotal: res.Planned,
		Bytes:       res.BytesCopied, BytesTotal: res.BytesPlanned,
		Quarantined: q.Len(), Current: current,
	})
}

func quarantineRemaining(q *quarantine.Set, rest []planned, reason quarantine.Reason, detail string) {
	for _, f := range rest {
		q.Add(quarantine.Record{Path: f.Rel, Stored: f.Stored, Reason: reason, Detail: detail, Attempts: 1})
	}
}

// copyWithRetry is SAFETY.md phase 5's retry rule applied at copy time: one
// retry, then quarantine. It never returns a partially written destination file;
// every failed attempt removes its own partial before the next one starts.
func copyWithRetry(ctx context.Context, o Options, f planned, h hash.Hash, buf []byte, q *quarantine.Set) (manifest.Entry, error) {
	attempts := o.retries() + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return manifest.Entry{}, err
		}
		e, err := copyOne(ctx, o, f, h, buf)
		if err == nil {
			return e, nil
		}
		lastErr = err
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return manifest.Entry{}, err
		}
		if isNoSpace(err) {
			// Retrying onto a full volume cannot succeed and wastes the user's
			// remaining battery. Stop immediately.
			break
		}
		if attempt < attempts {
			logEvent(o.Log, "retry", runlog.Fields{"path": f.Rel, "attempt": attempt, "error": err.Error()})
		}
	}
	q.Add(quarantine.Record{
		Path:   f.Rel, Stored: f.Stored, Reason: reasonFor(lastErr),
		Detail: lastErr.Error(), Attempts: attempts,
	})
	return manifest.Entry{}, lastErr
}

func reasonFor(err error) quarantine.Reason {
	switch {
	case err == nil:
		return quarantine.ReasonReadError
	case isNoSpace(err):
		return quarantine.ReasonDestinationFull
	case errors.Is(err, errSourceGone), errors.Is(err, fs.ErrNotExist):
		return quarantine.ReasonSourceDisappeared
	case errors.Is(err, errSourceChanged):
		return quarantine.ReasonSourceChanged
	case errors.Is(err, fs.ErrPermission):
		return quarantine.ReasonLocked
	default:
		return quarantine.ReasonReadError
	}
}

// copyOne copies a single file and returns its manifest entry.
//
// The order is the point:
//
//	stat  →  open  →  stream-and-hash into a PARTIAL file  →  fsync  →
//	re-stat the source  →  compare  →  rename the partial into place
//
// A file only acquires its real name after the source has been re-checked. An
// interruption at any earlier point leaves a ".auros-partial" that the next run
// sweeps, never a file that looks complete and is not.
func copyOne(ctx context.Context, o Options, f planned, h hash.Hash, buf []byte) (manifest.Entry, error) {
	if o.hookBeforeCopy != nil {
		o.hookBeforeCopy(f.Src)
	}

	before, err := os.Lstat(f.Src)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest.Entry{}, fmt.Errorf("%w: %s", errSourceGone, f.Rel)
		}
		return manifest.Entry{}, err
	}
	if !before.Mode().IsRegular() {
		return manifest.Entry{}, fmt.Errorf("copyengine: %s is not a regular file", f.Rel)
	}

	src, err := os.Open(f.Src)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest.Entry{}, fmt.Errorf("%w: %s", errSourceGone, f.Rel)
		}
		return manifest.Entry{}, err
	}
	defer src.Close()

	if o.hookAfterOpen != nil {
		o.hookAfterOpen(f.Src)
	}

	finalPath := filepath.Join(o.DestRoot, filepath.FromSlash(f.Stored))
	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		return manifest.Entry{}, err
	}
	partPath := finalPath + partialSuffix
	dst, err := os.OpenFile(partPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return manifest.Entry{}, err
	}

	var w io.Writer = dst
	if o.hookDst != nil {
		w = o.hookDst(finalPath, dst)
	}

	h.Reset()
	sum, n, cerr := manifest.CopyHashed(ctx, w, src, h, buf)
	if cerr == nil {
		// fsync before the rename. Without it a power cut can leave a file with
		// the right name, the right size and no contents, which is precisely the
		// shape of file that a count check passes and a hash check catches —
		// but only if the hash check is still to come.
		if serr := dst.Sync(); serr != nil {
			cerr = serr
		}
	}
	if clerr := dst.Close(); clerr != nil && cerr == nil {
		cerr = clerr
	}
	if cerr != nil {
		os.Remove(partPath)
		return manifest.Entry{}, cerr
	}

	// Re-stat the source. If it changed under us, the bytes we just wrote are a
	// mixture of two versions of the file and the digest describes nothing.
	after, serr := os.Lstat(f.Src)
	if serr != nil {
		os.Remove(partPath)
		if os.IsNotExist(serr) {
			return manifest.Entry{}, fmt.Errorf("%w: %s", errSourceGone, f.Rel)
		}
		return manifest.Entry{}, serr
	}
	if after.Size() != before.Size() || after.ModTime().UnixNano() != before.ModTime().UnixNano() || n != before.Size() {
		os.Remove(partPath)
		return manifest.Entry{}, fmt.Errorf("%w: %s (was %d bytes at %d, now %d bytes at %d, read %d)",
			errSourceChanged, f.Rel, before.Size(), before.ModTime().UnixNano(),
			after.Size(), after.ModTime().UnixNano(), n)
	}

	if err := os.Rename(partPath, finalPath); err != nil {
		os.Remove(partPath)
		return manifest.Entry{}, err
	}

	return manifest.Entry{
		Path:            f.Rel,
		Stored:          f.Stored,
		Size:            n,
		ModTimeUnixNano: before.ModTime().UnixNano(),
		SHA256:          sum,
	}, nil
}

// sweepPartials removes debris from an earlier interrupted run.
func sweepPartials(ctx context.Context, destRoot string) ([]string, error) {
	var removed []string
	err := filepath.WalkDir(destRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if d.IsDir() || !strings.HasSuffix(p, partialSuffix) {
			return nil
		}
		if rerr := os.Remove(p); rerr == nil {
			removed = append(removed, p)
		}
		return nil
	})
	return removed, err
}

// loadPrior reads a manifest left by an earlier run. A corrupt or truncated one
// is simply not used: resuming from a manifest we cannot parse would mean
// trusting entries we cannot read.
func loadPrior(path string) map[string]manifest.Entry {
	out := map[string]manifest.Entry{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	m, err := manifest.Read(f)
	if err != nil {
		return out
	}
	for _, e := range m.Entries() {
		out[e.Path] = e
	}
	return out
}

// writeManifest writes the manifest atomically: a torn manifest is worse than no
// manifest, because a torn one might still parse.
func writeManifest(m *manifest.Manifest, path string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(m.Bytes()); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

func writeQuarantineReport(q *quarantine.Set, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return q.WriteReport(f)
}

func logEvent(l *runlog.Logger, kind string, f runlog.Fields) {
	if l == nil {
		return
	}
	l.Event("4-copy", kind, f)
}
