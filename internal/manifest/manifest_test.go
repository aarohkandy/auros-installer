package manifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func entry(path, content string) Entry {
	sum := sha256.Sum256([]byte(content))
	digest := fmt.Sprintf("%x", sum)
	return Entry{
		Path: path, Stored: path, Size: int64(len(content)),
		ModTimeUnixNano: 1700000000000000000, SHA256: digest,
	}
}

func build(t *testing.T, entries ...Entry) *Manifest {
	t.Helper()
	m := New()
	for _, e := range entries {
		if err := m.Add(e); err != nil {
			t.Fatalf("Add(%q): %v", e.Path, err)
		}
	}
	return m
}

// ---------- stability ----------

func TestSerialization_IsStableRegardlessOfInsertionOrder(t *testing.T) {
	a := build(t, entry("z.txt", "zed"), entry("a.txt", "ay"), entry("m/n.txt", "en"))
	b := build(t, entry("m/n.txt", "en"), entry("z.txt", "zed"), entry("a.txt", "ay"))
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatalf("insertion order changed the serialization:\n--- a ---\n%s\n--- b ---\n%s", a.Bytes(), b.Bytes())
	}
	if a.Digest() != b.Digest() {
		t.Fatalf("digests differ: %s vs %s", a.Digest(), b.Digest())
	}
}

func TestSerialization_IsSortedAndLFOnly(t *testing.T) {
	m := build(t, entry("b.txt", "1"), entry("a.txt", "2"), entry("c.txt", "3"))
	s := string(m.Bytes())
	if strings.Contains(s, "\r") {
		t.Error("serialization contains CR; the format is LF-only")
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if lines[0] != Header {
		t.Fatalf("first line = %q, want %q", lines[0], Header)
	}
	var paths []string
	for _, l := range lines[1 : len(lines)-1] {
		paths = append(paths, strings.Split(l, "\t")[3])
	}
	for i := 1; i < len(paths); i++ {
		if paths[i-1] >= paths[i] {
			t.Errorf("entries not sorted: %q before %q", paths[i-1], paths[i])
		}
	}
	if !strings.HasPrefix(lines[len(lines)-1], "end\t") {
		t.Errorf("last line = %q, want a trailer", lines[len(lines)-1])
	}
}

func TestRoundTrip(t *testing.T) {
	m := build(t, entry("Documents/a.txt", "alpha"), entry("Desktop/b.txt", "bravo"))
	got, err := Read(bytes.NewReader(m.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Len() != 2 {
		t.Fatalf("Len = %d, want 2", got.Len())
	}
	if !bytes.Equal(got.Bytes(), m.Bytes()) {
		t.Error("round trip changed the bytes")
	}
}

func TestRoundTrip_PathsWithTabsAndNewlines(t *testing.T) {
	// A filename containing a tab or a newline must not be able to forge an
	// extra manifest line. This is the injection case.
	nasty := "Documents/evil\tname\nfake\tline.txt"
	e := entry(nasty, "x")
	m := build(t, e)
	got, err := Read(bytes.NewReader(m.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Len() != 1 {
		t.Fatalf("Len = %d, want 1: a filename forged a manifest line", got.Len())
	}
	back, ok := got.Lookup(nasty)
	if !ok {
		t.Fatalf("path did not survive the round trip; entries: %+v", got.Entries())
	}
	if back.Path != nasty {
		t.Errorf("Path = %q, want %q", back.Path, nasty)
	}
}

// ---------- the abort paths: a manifest we cannot trust ----------

func TestRead_RefusesTruncatedManifest(t *testing.T) {
	m := build(t, entry("a.txt", "1"), entry("b.txt", "2"), entry("c.txt", "3"))
	full := m.Bytes()
	// Cut the trailer off, as a pulled USB stick would.
	cut := bytes.LastIndexByte(full[:len(full)-1], '\n') + 1
	_, err := Read(bytes.NewReader(full[:cut]))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

func TestRead_RefusesManifestCutMidLine(t *testing.T) {
	m := build(t, entry("a.txt", "1"), entry("b.txt", "2"))
	full := m.Bytes()
	_, err := Read(bytes.NewReader(full[:len(full)-20]))
	if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrTruncated or ErrCorrupt", err)
	}
}

func TestRead_RefusesCorruptDigest(t *testing.T) {
	m := build(t, entry("a.txt", "one"))
	s := string(m.Bytes())
	// Change a content byte without changing the trailer.
	s = strings.Replace(s, "\t3\t", "\t4\t", 1)
	_, err := Read(strings.NewReader(s))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestRead_RefusesTrailerCountMismatch(t *testing.T) {
	m := build(t, entry("a.txt", "one"), entry("b.txt", "two"))
	s := string(m.Bytes())
	s = strings.Replace(s, "end\t2\t", "end\t3\t", 1)
	_, err := Read(strings.NewReader(s))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestRead_RefusesCRLF(t *testing.T) {
	m := build(t, entry("a.txt", "one"))
	s := strings.ReplaceAll(string(m.Bytes()), "\n", "\r\n")
	_, err := Read(strings.NewReader(s))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt (CRLF means the bytes were rewritten)", err)
	}
}

func TestRead_RefusesBadHeader(t *testing.T) {
	for _, in := range []string{"", "auros-manifest/2\nend\t0\t0\tx\n", "garbage\n"} {
		if _, err := Read(strings.NewReader(in)); !errors.Is(err, ErrBadHeader) {
			t.Errorf("Read(%q): err = %v, want ErrBadHeader", in, err)
		}
	}
}

func TestRead_RefusesOutOfOrderEntries(t *testing.T) {
	m := build(t, entry("a.txt", "1"), entry("b.txt", "2"))
	lines := strings.Split(strings.TrimSuffix(string(m.Bytes()), "\n"), "\n")
	lines[1], lines[2] = lines[2], lines[1]
	_, err := Read(strings.NewReader(strings.Join(lines, "\n") + "\n"))
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestRead_RefusesContentAfterTrailer(t *testing.T) {
	m := build(t, entry("a.txt", "1"))
	s := string(m.Bytes()) + string(m.Bytes())
	if _, err := Read(strings.NewReader(s)); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt", err)
	}
}

func TestAdd_RefusesDuplicates(t *testing.T) {
	m := New()
	if err := m.Add(entry("a.txt", "1")); err != nil {
		t.Fatal(err)
	}
	if err := m.Add(entry("a.txt", "2")); !errors.Is(err, ErrDuplicatePath) {
		t.Errorf("duplicate path: err = %v, want ErrDuplicatePath", err)
	}
	e := entry("b.txt", "2")
	e.Stored = "a.txt" // two sources, one destination name: silent overwrite
	if err := m.Add(e); !errors.Is(err, ErrDuplicateStored) {
		t.Errorf("duplicate stored: err = %v, want ErrDuplicateStored", err)
	}
}

func TestEntry_ValidateRejectsImpossibleEntries(t *testing.T) {
	good := strings.Repeat("a", 64)
	type tc struct {
		name string
		e    Entry
	}
	cases := []tc{
		{"empty path", Entry{Path: "", Stored: "a", Size: 1, SHA256: good}},
		{"empty stored", Entry{Path: "a", Stored: "", Size: 1, SHA256: good}},
		{"negative size", Entry{Path: "a", Stored: "a", Size: -1, SHA256: good}},
		{"short digest", Entry{Path: "a", Stored: "a", Size: 1, SHA256: "abc"}},
		{"uppercase digest", Entry{Path: "a", Stored: "a", Size: 1, SHA256: strings.Repeat("A", 64)}},
		{"zero size, real hash", Entry{Path: "a", Stored: "a", Size: 0, SHA256: good}},
		{"nonzero size, empty hash", Entry{Path: "a", Stored: "a", Size: 5, SHA256: EmptySHA256}},
	}
	for _, c := range cases {
		if err := c.e.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", c.name, c.e)
		}
	}
}

func TestZeroByteFile(t *testing.T) {
	e := entry("empty.txt", "")
	if e.SHA256 != EmptySHA256 {
		t.Fatalf("empty digest constant is wrong: %s", e.SHA256)
	}
	m := build(t, e)
	got, err := Read(bytes.NewReader(m.Bytes()))
	if err != nil {
		t.Fatalf("a 0-byte file broke the manifest: %v", err)
	}
	if got.TotalBytes() != 0 || got.Len() != 1 {
		t.Errorf("Len=%d TotalBytes=%d, want 1 and 0", got.Len(), got.TotalBytes())
	}
}

// ---------- streaming ----------

func TestCopyHashed_StreamsThroughASmallBuffer(t *testing.T) {
	// Proof that a file larger than the buffer — and therefore a file larger
	// than RAM — is an ordinary file. 512 KiB through a 7-byte buffer.
	data := bytes.Repeat([]byte("auros!"), 87381)
	var out bytes.Buffer
	h := sha256.New()
	sum, n, err := CopyHashed(context.Background(), &out, bytes.NewReader(data), h, make([]byte, 7))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(data)) {
		t.Fatalf("wrote %d bytes, want %d", n, len(data))
	}
	want := fmt.Sprintf("%x", sha256.Sum256(data))
	if sum != want {
		t.Fatalf("digest = %s, want %s", sum, want)
	}
	if !bytes.Equal(out.Bytes(), data) {
		t.Fatal("the bytes written are not the bytes read")
	}
}

func TestCopyHashed_HashesExactlyTheBytesItWrites(t *testing.T) {
	data := []byte("the read that produced the bytes we wrote is the read we hashed")
	var out bytes.Buffer
	h := sha256.New()
	sum, _, err := CopyHashed(context.Background(), &out, bytes.NewReader(data), h, make([]byte, 4))
	if err != nil {
		t.Fatal(err)
	}
	if sum != fmt.Sprintf("%x", sha256.Sum256(out.Bytes())) {
		t.Fatal("the digest does not describe the bytes that were written")
	}
}

func TestCopyHashed_StopsOnCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	_, _, err := CopyHashed(ctx, &out, bytes.NewReader(bytes.Repeat([]byte("x"), 1<<20)), sha256.New(), make([]byte, 8))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if out.Len() != 0 {
		t.Errorf("wrote %d bytes after cancellation", out.Len())
	}
}

func TestCopyHashed_ReportsShortWrite(t *testing.T) {
	_, _, err := CopyHashed(context.Background(), shortWriter{}, bytes.NewReader([]byte("hello")), sha256.New(), make([]byte, 8))
	if err == nil {
		t.Fatal("a short write was not reported")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
