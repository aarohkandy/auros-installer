package manifest

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Path handling.
//
// Two distinct strings exist for every file and conflating them loses data:
//
//	Entry.Path   the ORIGINAL relative path as it existed on the source machine,
//	             slash-separated. This is what RESTORE must put back. It may contain
//	             characters that cannot be written to the destination filesystem.
//	Entry.Stored the path actually written under the destination root. Derived from
//	             Path by Sanitize, then de-collided if a case-fold clash occurs.
//
// Sanitize is reversible: Unsanitize(Sanitize(p)) == p for every p it accepts. The
// de-collision suffix is NOT reversible, which is exactly why Path is recorded
// separately rather than recomputed.

var (
	// ErrPathEscape is returned for a path that leaves its root.
	ErrPathEscape = errors.New("manifest: path escapes root")
	// ErrPathEmpty is returned for an empty path or an empty path segment.
	ErrPathEmpty = errors.New("manifest: empty path or path segment")
	// ErrPathAbsolute is returned for a path that is not relative.
	ErrPathAbsolute = errors.New("manifest: path is absolute")
)

const hexDigits = "0123456789ABCDEF"

// CleanRel normalises a slash-separated relative path and refuses anything that
// escapes its root. It is deliberately strict: no absolute paths, no "..", no
// empty segments, no "." segments, no leading or trailing slash, no drive letters
// and no UNC prefixes. A path this function rejects never reaches the copy engine.
func CleanRel(p string) (string, error) {
	if p == "" {
		return "", ErrPathEmpty
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: NUL byte in path", ErrPathEmpty)
	}
	if strings.HasPrefix(p, "/") {
		return "", ErrPathAbsolute
	}
	// Reject "C:/..." and "//server/share/..." before any cleaning can hide them.
	if len(p) >= 2 && p[1] == ':' {
		return "", ErrPathAbsolute
	}
	segs := strings.Split(p, "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		switch s {
		case "":
			return "", ErrPathEmpty
		case ".":
			return "", fmt.Errorf(`%w: "." segment`, ErrPathEmpty)
		case "..":
			return "", ErrPathEscape
		}
		out = append(out, s)
	}
	cleaned := path.Join(out...)
	// path.Join cannot reintroduce ".." here, but assert rather than assume.
	if cleaned == "" || cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", ErrPathEscape
	}
	return cleaned, nil
}

// needsEscape reports whether a byte must be percent-encoded in a stored path.
//
// The set is the union of:
//   - bytes illegal on ext4/POSIX: NUL and '/' (handled by segmenting, not here)
//   - bytes illegal on NTFS/FAT/exFAT: < > : " | ? * \ and control characters
//   - '%' itself, so the encoding is reversible
//
// The destination is frequently exFAT (a USB stick formatted by Windows), so a
// name that is legal on the SOURCE NTFS volume via the \\?\ prefix — a colon, a
// trailing space — is not necessarily writable on the destination. Encoding is
// the only option that neither renames silently nor drops the file.
func needsEscape(b byte) bool {
	if b < 0x20 || b == 0x7F {
		return true
	}
	switch b {
	case '<', '>', ':', '"', '|', '?', '*', '\\', '%':
		return true
	}
	return false
}

// reservedStems are Windows device names. A file called "CON" or "aux.txt" cannot
// be created on a Windows-formatted destination volume even though it is a
// perfectly ordinary name on the ext4 side.
var reservedStems = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM0": true, "COM1": true, "COM2": true, "COM3": true, "COM4": true,
	"COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT0": true, "LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true,
	"LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// Sanitize converts a cleaned relative source path into a path that can be
// written on any of ext4, NTFS, exFAT and FAT32. It reports whether it changed
// anything. It never returns an empty segment and never returns a path that
// differs from its input only in case.
func Sanitize(rel string) (string, bool) {
	segs := strings.Split(rel, "/")
	changed := false
	for i, s := range segs {
		ns := sanitizeSegment(s)
		if ns != s {
			changed = true
		}
		segs[i] = ns
	}
	return strings.Join(segs, "/"), changed
}

func sanitizeSegment(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if needsEscape(c) {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	out := b.String()

	// Trailing dots and spaces are silently stripped by Windows when a file is
	// created, which would make the stored name differ from the recorded name.
	// Encode the offender instead.
	// One pass is enough: the replacement ends in a hex digit, never in "." or " ".
	if n := len(out); n > 0 {
		if last := out[n-1]; last == '.' || last == ' ' {
			out = out[:n-1] + "%" + string(hexDigits[last>>4]) + string(hexDigits[last&0x0F])
		}
	}

	// Reserved device name: encode the first byte of the stem.
	stem := out
	if i := strings.IndexByte(out, '.'); i >= 0 {
		stem = out[:i]
	}
	if reservedStems[strings.ToUpper(stem)] && len(out) > 0 {
		c := out[0]
		out = "%" + string(hexDigits[c>>4]) + string(hexDigits[c&0x0F]) + out[1:]
	}
	return out
}

// Unsanitize reverses Sanitize. It is used by the Linux-side restore to put the
// original name back. It returns an error on a malformed escape rather than
// guessing, because guessing here silently renames somebody's file.
func Unsanitize(stored string) (string, error) {
	var b strings.Builder
	b.Grow(len(stored))
	for i := 0; i < len(stored); i++ {
		c := stored[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(stored) {
			return "", fmt.Errorf("manifest: truncated escape in %q", stored)
		}
		hi, ok1 := unhex(stored[i+1])
		lo, ok2 := unhex(stored[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("manifest: bad escape in %q at %d", stored, i)
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	}
	return 0, false
}

// FoldKey is the case-insensitive key used to detect two stored paths that would
// collide on a case-insensitive destination volume. Two source files whose names
// differ only in case are legal on ext4 and on NTFS opened in its POSIX
// namespace, and they are the classic way to lose exactly one of a pair of files
// on a copy to a FAT-family USB stick.
func FoldKey(stored string) string { return strings.ToLower(stored) }

// DeCollide returns a stored path that is not already present in taken, by
// inserting a "~N" before the extension. It records nothing; the caller is
// responsible for recording the original path in Entry.Path so restore can undo
// this.
func DeCollide(stored string, taken map[string]bool) string {
	if !taken[FoldKey(stored)] {
		return stored
	}
	dir, base := "", stored
	if i := strings.LastIndexByte(stored, '/'); i >= 0 {
		dir, base = stored[:i+1], stored[i+1:]
	}
	stem, ext := base, ""
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		stem, ext = base[:i], base[i:]
	}
	for n := 1; ; n++ {
		cand := fmt.Sprintf("%s%s~%d%s", dir, stem, n, ext)
		if !taken[FoldKey(cand)] {
			return cand
		}
		if n > 1_000_000 {
			// Unreachable in practice; refuse rather than spin.
			return fmt.Sprintf("%s%s~overflow%s", dir, stem, ext)
		}
	}
}
