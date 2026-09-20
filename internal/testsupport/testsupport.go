// Package testsupport holds the assertions the whole test suite is built around.
//
// AssertUnchanged is the important one. SPEC §6C and SAFETY.md both require that
// every abort path leaves the system disk untouched, and the brief for this code
// was explicit: "Every one must leave the system disk untouched. Assert that,
// don't assume it."
//
// So every abort-path test creates a directory standing in for the system disk,
// fingerprints it by path and SHA-256 before the run, and fingerprints it again
// afterwards. A test that merely checks an error was returned proves nothing
// about what happened to the disk on the way to returning it.
package testsupport

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Fingerprint is a snapshot of a directory tree: relative path -> digest or
// marker. Directories and symlinks are recorded too, so a run that created an
// empty directory or a dangling link on the system disk is caught.
type Fingerprint map[string]string

// Snapshot fingerprints a tree.
func Snapshot(t *testing.T, root string) Fingerprint {
	t.Helper()
	fp := Fingerprint{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			fp[rel+"/"] = "dir"
		case d.Type()&fs.ModeSymlink != 0:
			target, lerr := os.Readlink(p)
			if lerr != nil {
				return lerr
			}
			fp[rel] = "symlink:" + target
		default:
			f, oerr := os.Open(p)
			if oerr != nil {
				return oerr
			}
			h := sha256.New()
			_, cerr := io.Copy(h, f)
			f.Close()
			if cerr != nil {
				return cerr
			}
			st, serr := os.Stat(p)
			if serr != nil {
				return serr
			}
			fp[rel] = hex.EncodeToString(h.Sum(nil)) + ":" + itoa(st.Size())
		}
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return fp
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [24]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// AssertUnchanged fails the test if anything under root differs from before.
// The failure message names every added, removed and modified path, because
// "the system disk changed" without saying how is not a usable bug report.
func AssertUnchanged(t *testing.T, root string, before Fingerprint) {
	t.Helper()
	after := Snapshot(t, root)
	var added, removed, changed []string
	for p, v := range after {
		old, ok := before[p]
		switch {
		case !ok:
			added = append(added, p)
		case old != v:
			changed = append(changed, p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	if len(added)+len(removed)+len(changed) == 0 {
		return
	}
	var b strings.Builder
	b.WriteString("SYSTEM DISK WAS MODIFIED — the invariant in SAFETY.md was broken\n")
	b.WriteString("  root: " + root + "\n")
	if len(added) > 0 {
		b.WriteString("  added:   " + strings.Join(added, ", ") + "\n")
	}
	if len(removed) > 0 {
		b.WriteString("  removed: " + strings.Join(removed, ", ") + "\n")
	}
	if len(changed) > 0 {
		b.WriteString("  changed: " + strings.Join(changed, ", ") + "\n")
	}
	t.Fatal(b.String())
}

// Tree writes a set of files under root, creating parent directories. The key is
// a slash-separated relative path.
func Tree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", p, err)
		}
		if err := os.WriteFile(full, []byte(files[p]), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
}

// SHA256 is the digest of a string, for building expected manifest entries.
func SHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// MustRead reads a file or fails the test.
func MustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// CountFiles counts regular files under root, skipping any path segment equal to
// skip. It is how tests check a destination file count independently of the
// manifest's own idea of it.
func CountFiles(t *testing.T, root, skip string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if skip != "" && (rel == skip || strings.HasPrefix(rel, skip+"/")) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && d.Type().IsRegular() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("count %s: %v", root, err)
	}
	return n
}
