// Package manifest defines the record of what was copied: a per-file SHA-256,
// size, modification time and count, in a serialization that is stable enough to
// diff two runs against each other.
//
// Stability rules, all of which are load-bearing:
//
//   - Entries are sorted by source path using raw byte order. No locale, no
//     Unicode collation, no map iteration order.
//   - Lines end with LF. A CR anywhere is a corrupt manifest, not something to
//     tolerate, because a manifest that survived a text-mode round trip has had
//     its bytes changed and its digest is meaningless.
//   - No timestamps, hostnames, usernames, versions or other ambient state are
//     written. Two runs of the same tool over the same unchanged tree produce
//     byte-identical manifests.
//   - The trailer carries the count, total size and a digest of everything above
//     it. A manifest whose tail was lost to a pulled USB stick is DETECTABLY
//     truncated rather than quietly short — a short manifest that parses is how a
//     verifier is fooled into passing on a partial copy.
package manifest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const (
	// Header is the exact first line of every serialized manifest.
	Header = "auros-manifest/1"

	// MetaDir is the directory on the DESTINATION volume holding the manifest,
	// the run log and the quarantine report. It is excluded from the copy and
	// from the destination file count.
	MetaDir = "_auros"

	// FileName is the manifest's name inside MetaDir.
	FileName = "manifest.tsv"

	// EmptySHA256 is the digest of zero bytes. A 0-byte file is ordinary, not an
	// error, and this is what its entry must carry.
	EmptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	trailerPrefix = "end\t"
)

var (
	ErrBadHeader       = errors.New("manifest: bad or missing header")
	ErrTruncated       = errors.New("manifest: truncated: trailer line missing")
	ErrCorrupt         = errors.New("manifest: corrupt")
	ErrDuplicatePath   = errors.New("manifest: duplicate source path")
	ErrDuplicateStored = errors.New("manifest: duplicate stored path")
)

// Entry is one file. See path.go for why Path and Stored are both recorded.
type Entry struct {
	Path            string // original relative source path, slash-separated
	Stored          string // relative path under the destination root
	Size            int64  // bytes actually read and written
	ModTimeUnixNano int64  // source mtime at the moment of the copy
	SHA256          string // lowercase hex, computed from the bytes that were written
}

// Validate rejects an entry that could not have come from a real copy.
func (e Entry) Validate() error {
	if e.Path == "" {
		return fmt.Errorf("%w: empty source path", ErrCorrupt)
	}
	if e.Stored == "" {
		return fmt.Errorf("%w: empty stored path", ErrCorrupt)
	}
	if e.Size < 0 {
		return fmt.Errorf("%w: negative size for %q", ErrCorrupt, e.Path)
	}
	if !isLowerHex64(e.SHA256) {
		return fmt.Errorf("%w: bad digest %q for %q", ErrCorrupt, e.SHA256, e.Path)
	}
	if e.Size == 0 && e.SHA256 != EmptySHA256 {
		return fmt.Errorf("%w: zero-length %q has non-empty digest", ErrCorrupt, e.Path)
	}
	if e.Size != 0 && e.SHA256 == EmptySHA256 {
		return fmt.Errorf("%w: %q has %d bytes but the empty digest", ErrCorrupt, e.Path, e.Size)
	}
	return nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Manifest is an unordered set of entries with a deterministic serialization.
// It is not safe for concurrent use; the copy engine owns one and serialises
// access to it.
type Manifest struct {
	byPath   map[string]Entry
	byStored map[string]string // stored -> source path, for collision detection
}

// New returns an empty manifest.
func New() *Manifest {
	return &Manifest{byPath: make(map[string]Entry), byStored: make(map[string]string)}
}

func (m *Manifest) init() {
	if m.byPath == nil {
		m.byPath = make(map[string]Entry)
	}
	if m.byStored == nil {
		m.byStored = make(map[string]string)
	}
}

// Add records an entry. It refuses a duplicate source path and refuses two
// entries that claim the same stored path — the second would have overwritten
// the first on the destination, which is silent data loss.
func (m *Manifest) Add(e Entry) error {
	m.init()
	if err := e.Validate(); err != nil {
		return err
	}
	if _, ok := m.byPath[e.Path]; ok {
		return fmt.Errorf("%w: %q", ErrDuplicatePath, e.Path)
	}
	if prev, ok := m.byStored[e.Stored]; ok {
		return fmt.Errorf("%w: %q wanted by both %q and %q", ErrDuplicateStored, e.Stored, prev, e.Path)
	}
	m.byPath[e.Path] = e
	m.byStored[e.Stored] = e.Path
	return nil
}

// Len is the file count.
func (m *Manifest) Len() int { return len(m.byPath) }

// Lookup finds an entry by source path.
func (m *Manifest) Lookup(p string) (Entry, bool) {
	e, ok := m.byPath[p]
	return e, ok
}

// StoredTaken reports whether a stored path (case-folded) is already claimed.
func (m *Manifest) StoredTaken() map[string]bool {
	out := make(map[string]bool, len(m.byStored))
	for s := range m.byStored {
		out[FoldKey(s)] = true
	}
	return out
}

// Entries returns every entry sorted by source path in raw byte order.
func (m *Manifest) Entries() []Entry {
	out := make([]Entry, 0, len(m.byPath))
	for _, e := range m.byPath {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// TotalBytes is the sum of every entry's size.
func (m *Manifest) TotalBytes() int64 {
	var n int64
	for _, e := range m.byPath {
		n += e.Size
	}
	return n
}

// Bytes returns the stable serialization.
func (m *Manifest) Bytes() []byte {
	var body bytes.Buffer
	body.WriteString(Header)
	body.WriteByte('\n')
	entries := m.Entries()
	var total int64
	for _, e := range entries {
		total += e.Size
		body.WriteString(e.SHA256)
		body.WriteByte('\t')
		body.WriteString(strconv.FormatInt(e.Size, 10))
		body.WriteByte('\t')
		body.WriteString(strconv.FormatInt(e.ModTimeUnixNano, 10))
		body.WriteByte('\t')
		body.WriteString(wireEscape(e.Path))
		body.WriteByte('\t')
		body.WriteString(wireEscape(e.Stored))
		body.WriteByte('\n')
	}
	sum := sha256.Sum256(body.Bytes())
	fmt.Fprintf(&body, "%s%d\t%d\t%s\n", trailerPrefix, len(entries), total, hex.EncodeToString(sum[:]))
	return body.Bytes()
}

// Digest is the SHA-256 of the serialization. It identifies one exact archive.
func (m *Manifest) Digest() string {
	sum := sha256.Sum256(m.Bytes())
	return hex.EncodeToString(sum[:])
}

// WriteTo implements io.WriterTo.
func (m *Manifest) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(m.Bytes())
	return int64(n), err
}

// Read parses a manifest, rejecting anything it cannot vouch for. Every failure
// mode here is a reason NOT to cross the wall, so each is a distinct error.
func Read(r io.Reader) (*Manifest, error) {
	br := bufio.NewReader(r)
	var body bytes.Buffer

	first, err := readLine(br)
	if err != nil {
		// A CRLF or truncation found on the header line is not a "bad header" — it says the file was
		// REWRITTEN or CUT, which is a different thing for the caller to act on. A manifest that has
		// been through a Windows editor or git autocrlf no longer describes the bytes that were
		// hashed, so callers distinguish it from a file that was simply never a manifest.
		if errors.Is(err, ErrCorrupt) || errors.Is(err, ErrTruncated) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrBadHeader, err)
	}
	if first != Header {
		return nil, fmt.Errorf("%w: got %q", ErrBadHeader, first)
	}
	body.WriteString(first)
	body.WriteByte('\n')

	m := New()
	sawTrailer := false
	var trailer string
	var lastPath string
	for {
		line, err := readLine(br)
		if errors.Is(err, io.EOF) {
			if !sawTrailer {
				return nil, ErrTruncated
			}
			break
		}
		if errors.Is(err, ErrTruncated) {
			return nil, ErrTruncated
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
		}
		if sawTrailer {
			return nil, fmt.Errorf("%w: content after trailer", ErrCorrupt)
		}
		if strings.HasPrefix(line, trailerPrefix) {
			sawTrailer = true
			trailer = line
			continue
		}
		e, err := parseEntryLine(line)
		if err != nil {
			return nil, err
		}
		if e.Path <= lastPath && lastPath != "" {
			return nil, fmt.Errorf("%w: entries out of order at %q (after %q)", ErrCorrupt, e.Path, lastPath)
		}
		lastPath = e.Path
		if err := m.Add(e); err != nil {
			return nil, err
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if !sawTrailer {
		return nil, ErrTruncated
	}

	fields := strings.Split(strings.TrimPrefix(trailer, trailerPrefix), "\t")
	if len(fields) != 3 {
		return nil, fmt.Errorf("%w: trailer has %d fields, want 3", ErrCorrupt, len(fields))
	}
	count, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("%w: trailer count: %v", ErrCorrupt, err)
	}
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("%w: trailer total: %v", ErrCorrupt, err)
	}
	if count != m.Len() {
		return nil, fmt.Errorf("%w: trailer claims %d entries, found %d", ErrCorrupt, count, m.Len())
	}
	if total != m.TotalBytes() {
		return nil, fmt.Errorf("%w: trailer claims %d bytes, entries sum to %d", ErrCorrupt, total, m.TotalBytes())
	}
	sum := sha256.Sum256(body.Bytes())
	if got := hex.EncodeToString(sum[:]); got != fields[2] {
		return nil, fmt.Errorf("%w: body digest %s does not match trailer %s", ErrCorrupt, got, fields[2])
	}
	return m, nil
}

// readLine returns one LF-terminated line without the LF. A CR is rejected
// outright: CRLF means the bytes were rewritten in transit and the digest below
// can no longer be trusted to mean what it says.
func readLine(br *bufio.Reader) (string, error) {
	s, err := br.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			if s == "" {
				return "", io.EOF
			}
			// Bytes with no terminating LF: the file was cut short.
			return "", ErrTruncated
		}
		return "", err
	}
	s = strings.TrimSuffix(s, "\n")
	if strings.ContainsRune(s, '\r') {
		return "", fmt.Errorf("%w: CR in manifest (CRLF line endings)", ErrCorrupt)
	}
	return s, nil
}

func parseEntryLine(line string) (Entry, error) {
	f := strings.Split(line, "\t")
	if len(f) != 5 {
		return Entry{}, fmt.Errorf("%w: entry has %d fields, want 5", ErrCorrupt, len(f))
	}
	size, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: size: %v", ErrCorrupt, err)
	}
	mt, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: mtime: %v", ErrCorrupt, err)
	}
	p, err := wireUnescape(f[3])
	if err != nil {
		return Entry{}, fmt.Errorf("%w: path: %v", ErrCorrupt, err)
	}
	st, err := wireUnescape(f[4])
	if err != nil {
		return Entry{}, fmt.Errorf("%w: stored: %v", ErrCorrupt, err)
	}
	e := Entry{Path: p, Stored: st, Size: size, ModTimeUnixNano: mt, SHA256: f[0]}
	if err := e.Validate(); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// wireEscape percent-encodes the bytes that would otherwise break the line-and-tab
// framing, plus '%' so the encoding is reversible. It is independent of Sanitize:
// Sanitize protects the FILESYSTEM, wireEscape protects the FILE FORMAT, and a
// path can need both.
func wireEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F || c == '%' {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func wireUnescape(s string) (string, error) { return Unsanitize(s) }
