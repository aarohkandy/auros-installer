// Package restore is SAFETY.md phase 7, the Linux half of the migration.
//
// It runs on the user's ONLY copy of their data, at the moment it is most
// vulnerable: the archive exists, the Windows disk it came from has been
// overwritten. There is no second chance and no undo. Every design choice in
// this package is downstream of that sentence.
//
// The shape of a run:
//
//	FIND     locate the archive by its MANIFEST, on any attached volume,
//	         never by a drive letter or a remembered path. Several found
//	         means ASK, never guess.
//	VERIFY   re-read every file FROM THE ARCHIVE and compare count and
//	         SHA-256 against the manifest. BEFORE ANYTHING IS WRITTEN. A
//	         mismatch here means the archive is damaged, and the correct
//	         response is to stop and say so: the user still has the archive,
//	         and a half-written restore on top of a damaged one makes a bad
//	         day worse.
//	PLAN     map every entry to its destination and validate ALL of them.
//	         One path that escapes the home directory refuses the whole run,
//	         before the first byte is written.
//	WRITE    atomically, per file, never over a file we cannot prove is ours.
//	REVERIFY read every restored file back FROM THE HOME DIRECTORY and hash
//	         it. Third check. Different bytes from the second one.
//	REPORT   on the desktop, where the user can see it. Any discrepancy is
//	         SHOWN, never swallowed.
//
// # Nothing in this package writes to the archive
//
// Not a lock file, not a stamp, not a log. The archive is the only copy. State
// that must survive a reboot goes under the user's home directory. This is also
// why the restore is idempotent without a state file: correctness comes from
// re-hashing what is on disk, never from trusting a note we left ourselves.
package restore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/manifest"
)

var (
	// ErrNoArchive means no attached volume carried a readable manifest.
	ErrNoArchive = errors.New("restore: no archive found on any attached volume")
	// ErrAmbiguous means several DIFFERENT archives are attached. We refuse to
	// pick one. Restoring the wrong archive onto a fresh machine is not
	// recoverable by the user, and "it chose the newest" is exactly the kind of
	// helpfulness that loses somebody's work.
	ErrAmbiguous = errors.New("restore: more than one archive is attached")
)

// Archive is one located, parsed archive. Finding it does NOT mean it is
// intact: that is VerifyArchive's job, and it runs before anything is written.
type Archive struct {
	Root         string // directory containing the _auros metadata directory
	ManifestPath string
	Manifest     *manifest.Manifest
	Digest       string // manifest digest: identifies this exact archive
	FileCount    int
	TotalBytes   int64
	MountPoint   string // the mount the archive was found on, for the report
	FSType       string // as reported by the kernel, "" when unknown
}

func (a *Archive) String() string {
	return fmt.Sprintf("%s (%d files, %d bytes, manifest %s)", a.Root, a.FileCount, a.TotalBytes, short(a.Digest))
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// MountPoint is one filesystem the kernel says is mounted.
type MountPoint struct {
	Path   string
	FSType string
	Source string
}

// Finder locates archives. Every input it depends on is injectable, because a
// test that cannot drive the search cannot demonstrate its refusals, and a
// refusal nobody has watched happen is not a refusal.
type Finder struct {
	// Mounts enumerates mounted filesystems. nil means the real kernel list.
	Mounts func() ([]MountPoint, error)
	// ExtraRoots are directories searched in addition to the mount list:
	// the conventional removable-media parents, whose CHILDREN are searched.
	ExtraRoots []string
	// Explicit, when non-empty, is the only root considered. This is the
	// --archive flag: the user has told us, so we do not search.
	Explicit string
	// MetaDir overrides the metadata directory name. Empty means manifest.MetaDir.
	MetaDir string
	// Searched records every directory actually examined, so a "not found"
	// message can print where it looked instead of asserting an absence.
	Searched []string
}

// DefaultExtraRoots are the directories whose immediate children are
// conventional mount points for removable media on a Fedora/KDE machine.
//
// They are a SUPPLEMENT to the kernel's mount list, never a substitute: the
// mount list is the probe, this is belt and braces for a volume mounted
// somewhere the parse missed. Searching a directory that does not exist costs
// one failed syscall.
func DefaultExtraRoots() []string {
	var out []string
	for _, p := range []string{"/run/media", "/media", "/mnt"} {
		out = append(out, p)
	}
	if u := os.Getenv("USER"); u != "" {
		out = append(out, filepath.Join("/run/media", u), filepath.Join("/media", u))
	}
	return out
}

// pseudoFS are kernel filesystems that cannot hold an archive. Everything not
// in this list IS searched, which is the correct bias: a wasted stat costs
// nothing, and a volume we declined to look at costs somebody their files.
var pseudoFS = map[string]bool{
	"autofs": true, "bpf": true, "binfmt_misc": true, "cgroup": true,
	"cgroup2": true, "configfs": true, "debugfs": true, "devpts": true,
	"devtmpfs": true, "efivarfs": true, "fusectl": true, "hugetlbfs": true,
	"mqueue": true, "nsfs": true, "proc": true, "pstore": true,
	"ramfs": true, "rpc_pipefs": true, "securityfs": true, "selinuxfs": true,
	"sysfs": true, "tracefs": true,
}

// Find returns every DISTINCT archive it can see.
//
// Two mount points showing the same archive — a USB stick bind-mounted twice,
// which is ordinary on a systemd machine — are one archive, not an ambiguity.
// Sameness is decided by os.SameFile on the manifest (device and inode), not by
// comparing paths, because comparing paths is what makes a bind mount look like
// two sticks.
func (f *Finder) Find() ([]*Archive, error) {
	f.Searched = nil
	meta := f.MetaDir
	if meta == "" {
		meta = manifest.MetaDir
	}

	type cand struct {
		root   string
		mount  string
		fstype string
	}
	var cands []cand
	seenRoot := make(map[string]bool)

	add := func(root, mount, fstype string) {
		abs, err := filepath.Abs(root)
		if err != nil {
			return
		}
		if seenRoot[abs] {
			return
		}
		seenRoot[abs] = true
		cands = append(cands, cand{root: abs, mount: mount, fstype: fstype})
	}

	if f.Explicit != "" {
		add(f.Explicit, f.Explicit, "")
	} else {
		mountsFn := f.Mounts
		if mountsFn == nil {
			mountsFn = KernelMounts
		}
		mounts, err := mountsFn()
		// A machine with no /proc/self/mountinfo is not a reason to give up: the
		// extra roots below are still searched, and the error is carried into the
		// "not found" message rather than swallowed.
		var mountErr error
		if err != nil {
			mountErr = err
		}
		for _, m := range mounts {
			if pseudoFS[m.FSType] {
				continue
			}
			add(m.Path, m.Path, m.FSType)
		}
		extra := f.ExtraRoots
		if extra == nil {
			extra = DefaultExtraRoots()
		}
		for _, parent := range extra {
			ents, derr := os.ReadDir(parent)
			if derr != nil {
				continue
			}
			for _, e := range ents {
				if e.IsDir() {
					add(filepath.Join(parent, e.Name()), parent, "")
				}
			}
		}
		if mountErr != nil && len(cands) == 0 {
			return nil, fmt.Errorf("%w: could not enumerate mounts: %v", ErrNoArchive, mountErr)
		}
	}

	var found []*Archive
	var manifestInfos []os.FileInfo
	for _, c := range cands {
		mp := filepath.Join(c.root, meta, manifest.FileName)
		f.Searched = append(f.Searched, c.root)
		st, err := os.Stat(mp)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		dup := false
		for _, prev := range manifestInfos {
			if os.SameFile(prev, st) {
				dup = true
				break
			}
		}
		if dup {
			continue
		}
		a, aerr := loadArchive(c.root, mp)
		if aerr != nil {
			// A manifest that is present but unreadable is a FINDING, not a
			// non-result. It is returned as an error so the user is told their
			// archive is damaged rather than told no archive exists.
			return nil, fmt.Errorf("restore: %s: %w", mp, aerr)
		}
		a.MountPoint, a.FSType = c.mount, c.fstype
		manifestInfos = append(manifestInfos, st)
		found = append(found, a)
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Root < found[j].Root })

	if len(found) == 0 {
		return nil, fmt.Errorf("%w (looked in: %s)", ErrNoArchive, strings.Join(f.Searched, ", "))
	}
	// Distinct archives with the same digest describe identical data. That is a
	// copy of the same archive, not two answers, so it is not an ambiguity.
	allSame := true
	for _, a := range found[1:] {
		if a.Digest != found[0].Digest {
			allSame = false
			break
		}
	}
	if len(found) > 1 && !allSame {
		var b strings.Builder
		for _, a := range found {
			fmt.Fprintf(&b, "\n  %s  %d files, %s, manifest %s",
				a.Root, a.FileCount, humanBytes(a.TotalBytes), short(a.Digest))
		}
		return found, fmt.Errorf("%w — tell it which one with --archive:%s", ErrAmbiguous, b.String())
	}
	return found[:1], nil
}

func loadArchive(root, mp string) (*Archive, error) {
	fh, err := os.Open(mp)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	m, err := manifest.Read(fh)
	if err != nil {
		return nil, err
	}
	return &Archive{
		Root:         root,
		ManifestPath: mp,
		Manifest:     m,
		Digest:       m.Digest(),
		FileCount:    m.Len(),
		TotalBytes:   m.TotalBytes(),
	}, nil
}

// KernelMounts parses /proc/self/mountinfo.
//
// mountinfo, not /proc/mounts: mountinfo is the one that distinguishes bind
// mounts and carries the mount id, and its field layout is stable. The mount
// point is field 5 (1-based) and it is OCTAL-ESCAPED — a USB stick labelled
// "Mr Smith's backup" appears as /run/media/u/Mr\040Smith's\040backup, and a
// parser that does not unescape looks for a directory that does not exist.
func KernelMounts() ([]MountPoint, error) {
	fh, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(fh)
	if err != nil {
		return nil, err
	}
	return parseMountinfo(string(b)), nil
}

func parseMountinfo(s string) []MountPoint {
	var out []MountPoint
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		// Optional fields sit between index 6 and a literal "-" separator.
		sep := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sep = i
				break
			}
		}
		if sep < 0 || sep+2 >= len(fields) {
			continue
		}
		out = append(out, MountPoint{
			Path:   unoctal(fields[4]),
			FSType: unoctal(fields[sep+1]),
			Source: unoctal(fields[sep+2]),
		})
	}
	return out
}

// unoctal reverses the \nnn escaping the kernel applies to space, tab, newline
// and backslash in mountinfo paths.
func unoctal(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+3 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n, err := strconv.ParseUint(s[i+1:i+4], 8, 8)
		if err != nil {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(byte(n))
		i += 3
	}
	return b.String()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
