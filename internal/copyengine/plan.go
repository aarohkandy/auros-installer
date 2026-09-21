package copyengine

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// Source is one tree to copy. Label becomes the first path segment at the
// destination, so "Documents" and "Desktop" stay distinguishable in the archive
// even when both resolved to redirected locations on a file server.
type Source struct {
	Root  string
	Label string
}

var (
	// ErrNoSources means there is nothing to copy.
	ErrNoSources = errors.New("copyengine: no sources")
	// ErrNoDestination means no destination root was given.
	ErrNoDestination = errors.New("copyengine: no destination root")
	// ErrDestinationInsideSource means the destination is inside a tree we are
	// about to walk, which would copy the archive into itself forever.
	ErrDestinationInsideSource = errors.New("copyengine: destination is inside a source tree")
	// ErrBadLabel means a source label is not a usable path segment.
	ErrBadLabel = errors.New("copyengine: source label is not a valid relative path")
)

// planned is one file the engine intends to copy.
type planned struct {
	Src     string // absolute source path
	Rel     string // "<label>/<path>", slash-separated: this becomes Entry.Path
	Stored  string // path under the destination root: this becomes Entry.Stored
	Size    int64  // size at plan time; re-checked at copy time
	ModTime int64
}

// plan walks every source and decides what to copy.
//
// A walk error is quarantined and the walk continues. An unreadable subdirectory
// on a ten-year-old disk is normal; aborting the entire inventory because of one
// of them produces a tool that never gets past the first bad sector, and a tool
// that cannot finish is a tool people route around.
func plan(ctx context.Context, o Options, q *quarantine.Set, links *[]Link) ([]planned, error) {
	if len(o.Sources) == 0 {
		return nil, ErrNoSources
	}
	if o.DestRoot == "" {
		return nil, ErrNoDestination
	}
	destAbs, err := filepath.Abs(o.DestRoot)
	if err != nil {
		return nil, fmt.Errorf("copyengine: resolving destination: %w", err)
	}

	var out []planned
	taken := make(map[string]bool)

	for _, s := range o.Sources {
		label, lerr := manifest.CleanRel(s.Label)
		if lerr != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrBadLabel, s.Label, lerr)
		}
		rootAbs, aerr := filepath.Abs(s.Root)
		if aerr != nil {
			return nil, fmt.Errorf("copyengine: resolving source %q: %w", s.Root, aerr)
		}
		if under(destAbs, rootAbs) {
			return nil, fmt.Errorf("%w: %s is inside %s", ErrDestinationInsideSource, destAbs, rootAbs)
		}

		werr := filepath.WalkDir(rootAbs, func(p string, d fs.DirEntry, err error) error {
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err != nil {
				q.Add(quarantine.Record{
					Path:     displayPath(rootAbs, label, p),
					Reason:   quarantine.ReasonReadError,
					Detail:   err.Error(),
					Attempts: 1,
				})
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			rel, rerr := filepath.Rel(rootAbs, p)
			if rerr != nil {
				q.Add(quarantine.Record{Path: p, Reason: quarantine.ReasonReadError, Detail: rerr.Error(), Attempts: 1})
				return nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			logical := label + "/" + rel

			// A link is a pointer, not data, and it is never followed: following
			// LocalAppData\Application Data walks LocalAppData again, and a link
			// out of the tree copies C:\Windows or a network share. It is not
			// quarantined either — there is nothing here to recover, and an
			// unresolved record per legacy junction is a run that can never
			// reach the wall (SYSTEM-REVIEW §2.20). It is REPORTED, with its
			// target, as "not copied: link, not data".
			if isLink(p, d) {
				*links = append(*links, Link{Path: logical, Target: linkTarget(p)})
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !d.Type().IsRegular() {
				q.Add(quarantine.Record{
					Path:     logical,
					Reason:   quarantine.ReasonUnsupportedType,
					Detail:   "mode " + d.Type().String(),
					Attempts: 1,
				})
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				reason := quarantine.ReasonReadError
				if os.IsNotExist(ierr) {
					reason = quarantine.ReasonSourceDisappeared
				}
				q.Add(quarantine.Record{Path: logical, Reason: reason, Detail: ierr.Error(), Attempts: 1})
				return nil
			}
			if o.MaxFileBytes > 0 && info.Size() > o.MaxFileBytes {
				q.Add(quarantine.Record{
					Path:     logical,
					Reason:   quarantine.ReasonTooLarge,
					Detail:   fmt.Sprintf("%d bytes exceeds the %d byte limit", info.Size(), o.MaxFileBytes),
					Attempts: 1,
				})
				return nil
			}

			cleanRel, cerr := manifest.CleanRel(logical)
			if cerr != nil {
				q.Add(quarantine.Record{
					Path:     logical,
					Reason:   quarantine.ReasonPathEscape,
					Detail:   cerr.Error(),
					Attempts: 1,
				})
				return nil
			}
			stored, _ := manifest.Sanitize(cleanRel)
			stored = manifest.DeCollide(stored, taken)
			if taken[manifest.FoldKey(stored)] {
				// DeCollide exhausted its suffixes. Never silently overwrite.
				q.Add(quarantine.Record{
					Path:     cleanRel,
					Reason:   quarantine.ReasonNameCollision,
					Detail:   "could not find an unused destination name",
					Attempts: 1,
				})
				return nil
			}
			taken[manifest.FoldKey(stored)] = true

			out = append(out, planned{
				Src:     p,
				Rel:     cleanRel,
				Stored:  stored,
				Size:    info.Size(),
				ModTime: info.ModTime().UnixNano(),
			})
			return nil
		})
		if werr != nil {
			return out, werr // context cancellation is the only way out of here
		}
	}

	// Deterministic order: the same tree produces the same run, and a resumed
	// run picks up where the previous one stopped rather than somewhere else.
	sort.Slice(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out, nil
}

// Link is a name that points somewhere else. It is reported and not copied.
type Link struct {
	Path   string // "<label>/<path>", as it would have appeared in the archive
	Target string // where it points, or why that could not be read
}

// isLink reports whether the entry is a junction, a symbolic link or an app
// execution alias.
//
// Go (1.23+) reports a symbolic link as ModeSymlink and every other reparse
// point — junctions included — as ModeIrregular, never as a directory, so
// WalkDir does not descend into either. ModeIrregular also covers OneDrive's
// cloud files, which ARE data, so for those the reparse tag decides. If the tag
// cannot be read the entry is not called a link and falls through to the
// quarantine below: when in doubt, stop, never skip.
func isLink(p string, d fs.DirEntry) bool {
	t := d.Type()
	if t&fs.ModeSymlink != 0 {
		return true
	}
	if t&fs.ModeIrregular == 0 {
		return false
	}
	tag, err := winenv.ReparseTag(p)
	return err == nil && winenv.IsLinkTag(tag)
}

func linkTarget(p string) string {
	t, err := os.Readlink(p)
	if err != nil {
		return "(target unreadable: " + err.Error() + ")"
	}
	return t
}

// under reports whether p is root or is contained in root. It compares cleaned
// absolute paths segment-wise, so "/a/bc" is not treated as being under "/a/b".
func under(p, root string) bool {
	p = filepath.Clean(p)
	root = filepath.Clean(root)
	if p == root {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(p, strings.TrimSuffix(root, sep)+sep)
}

func displayPath(rootAbs, label, p string) string {
	rel, err := filepath.Rel(rootAbs, p)
	if err != nil {
		return p
	}
	return label + "/" + filepath.ToSlash(rel)
}
