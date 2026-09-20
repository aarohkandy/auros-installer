package manifest

import (
	"bytes"
	"strings"
	"testing"
)

// Fuzz targets.
//
// Two functions in this package parse bytes nobody in this company chose: the
// manifest parser, which reads a file off a USB stick that has been in a
// stranger's pocket, and the path sanitiser, which reads filenames off a disk
// that has had ten years of software on it. Those are exactly the two places a
// fuzzer earns its keep, and they are the two places where a crash or a wrong
// answer decides whether somebody's disk gets wiped.
//
// Run them properly with, for example:
//
//	go test ./internal/manifest -run=Fuzz -fuzz=FuzzManifestBody -fuzztime=5m
//
// A plain `go test` runs the seed corpus only, which is why the seeds below are
// chosen rather than arbitrary: each one is a shape that has broken a parser
// somewhere.

// ---------- the manifest parser ----------

// FuzzManifestRead throws arbitrary bytes at Read.
//
// The contract is asymmetric on purpose. REFUSING is always a correct answer —
// there is no input the parser owes acceptance to. What it may never do is
// panic, hang, or accept something that then fails to round-trip, because a
// manifest that parses and re-serialises differently is a manifest whose digest
// identifies two different archives.
func FuzzManifestRead(f *testing.F) {
	seed := New()
	for _, e := range []Entry{entry("Documents/a.txt", "alpha"), entry("Documents/b.txt", "bravo")} {
		if err := seed.Add(e); err != nil {
			f.Fatalf("building the seed manifest: %v", err)
		}
	}
	good := seed.Bytes()
	half := append([]byte(nil), good[:len(good)/2]...)
	twice := append(append([]byte(nil), good...), good...)
	crlf := []byte(strings.ReplaceAll(string(good), "\n", "\r\n"))

	// Each seed is a shape that has broken a parser somewhere: a valid file, an
	// empty one, a header with nothing after it, a file cut in half, a file
	// written twice, a file that went through a Windows editor, a trailer with
	// no body, an unknown version, and bytes that are not text at all.
	for _, seed := range [][]byte{
		good,
		nil,
		[]byte(Header),
		[]byte(Header + "\n"),
		half,
		twice,
		crlf,
		[]byte(Header + "\nend\t0\t0\t" + digestOf(Header+"\n") + "\n"),
		[]byte(Header + "\nend\t0\t0\t\n"),
		[]byte("auros-manifest/2\nend\t0\t0\t\n"),
		[]byte("\x00\x00\x00\x00"),
		[]byte(strings.Repeat("\t", 64)),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Read(bytes.NewReader(data))
		if err != nil {
			if m != nil {
				t.Fatalf("Read returned both a manifest and an error (%v): a caller that "+
					"checks only one of them gets the wrong answer", err)
			}
			return
		}
		if m == nil {
			t.Fatal("Read returned no error and no manifest")
		}
		assertAcceptedManifestIsSound(t, m)
	})
}

// FuzzManifestBody fuzzes the BODY and lets the test compute a correct trailer.
//
// FuzzManifestRead above will almost never get past the trailer, because
// guessing a SHA-256 is the one thing a fuzzer cannot brute-force. That is good
// for the format and useless for coverage: it means the entry-line rules —
// field counts, digest shapes, sizes, escapes, ordering, duplicate detection —
// are never reached. This target hands the fuzzer the body and does the
// arithmetic for it, so the rules that decide whether a line is trustworthy are
// the rules under test.
func FuzzManifestBody(f *testing.F) {
	alpha := digestOf("alpha")

	f.Add("")
	f.Add(entryLine(alpha, 5, 1, "a.txt", "a.txt"))
	f.Add(entryLine(alpha, 5, 1, "a.txt", "a.txt") + "\n" + entryLine(alpha, 5, 1, "b.txt", "b.txt"))
	f.Add(entryLine(alpha, 5, 1, "b.txt", "b.txt") + "\n" + entryLine(alpha, 5, 1, "a.txt", "a.txt"))
	f.Add(entryLine(alpha, 0, 1, "a.txt", "a.txt"))
	f.Add(entryLine(EmptySHA256, 0, 1, "a.txt", "a.txt"))
	f.Add(entryLine(alpha, -1, 1, "a.txt", "a.txt"))
	f.Add(alpha + "\t5\t1\ta.txt")
	f.Add(alpha + "\t5\t1\ta.txt\ta.txt\tsix")
	f.Add("\t\t\t\t")
	f.Add("a%2\ta%zz")
	f.Add(strings.Repeat("a", 4096))

	f.Fuzz(func(t *testing.T, body string) {
		lines := []string{}
		if body != "" {
			lines = strings.Split(body, "\n")
		}
		// The trailer's count and total are computed from what the body CLAIMS,
		// so an inconsistent body still reaches the entry-line rules rather
		// than being turned away by arithmetic.
		count, total := claimedBy(lines)
		raw := assemble(lines, count, total)

		m, err := Read(bytes.NewReader(raw))
		if err != nil {
			return
		}
		assertAcceptedManifestIsSound(t, m)

		// CANONICALITY. An accepted body must re-serialise to exactly the bytes
		// it came from, because Manifest.Digest() is used as the identity of one
		// exact archive. If two different byte sequences are both accepted and
		// describe the same files, that identity is not an identity.
		//
		// A failure here is a finding about the FORMAT, not a bug in the test.
		// The places to look are the ones where parse-then-render is not the
		// identity function: a size or modification time written with a leading
		// zero or a leading "+", and a path whose percent-escapes are not the
		// minimal set wireEscape would have produced.
		if again := m.Bytes(); !bytes.Equal(again, raw) {
			t.Fatalf("an accepted manifest does not re-serialise to itself, so two byte "+
				"sequences describe one archive under two digests\n  in:  %q\n  out: %q",
				raw, again)
		}
	})
}

// claimedBy reads the count and total a body asserts about itself, so assemble
// can build a trailer that agrees with it whatever it says.
func claimedBy(lines []string) (int, int64) {
	count := 0
	var total int64
	for _, l := range lines {
		f := strings.Split(l, "\t")
		if len(f) != 5 {
			count++
			continue
		}
		count++
		var n int64
		neg := false
		s := f[1]
		if strings.HasPrefix(s, "-") {
			neg, s = true, s[1:]
		}
		ok := s != ""
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				ok = false
				break
			}
			if n > (1<<62)/10 {
				ok = false
				break
			}
			n = n*10 + int64(s[i]-'0')
		}
		if !ok {
			continue
		}
		if neg {
			n = -n
		}
		total += n
	}
	return count, total
}

// assertAcceptedManifestIsSound states what "accepted" has to mean. Refusing is
// always allowed; accepting carries obligations.
func assertAcceptedManifestIsSound(t *testing.T, m *Manifest) {
	t.Helper()
	entries := m.Entries()
	if len(entries) != m.Len() {
		t.Fatalf("Entries() has %d, Len() says %d", len(entries), m.Len())
	}

	seenPath := map[string]bool{}
	seenStored := map[string]bool{}
	var sum int64
	prev := ""
	for i, e := range entries {
		if err := e.Validate(); err != nil {
			t.Fatalf("entry %d was accepted but does not validate: %v (%+v)", i, err, e)
		}
		if i > 0 && !(prev < e.Path) {
			t.Fatalf("entries are not in strictly ascending order: %q then %q", prev, e.Path)
		}
		prev = e.Path
		if seenPath[e.Path] {
			t.Fatalf("duplicate source path %q survived parsing", e.Path)
		}
		seenPath[e.Path] = true
		if seenStored[e.Stored] {
			t.Fatalf("duplicate stored path %q survived parsing: one file would overwrite "+
				"the other at the destination", e.Stored)
		}
		seenStored[e.Stored] = true
		sum += e.Size
	}
	if sum != m.TotalBytes() {
		t.Fatalf("TotalBytes() = %d, entries sum to %d", m.TotalBytes(), sum)
	}

	// Parsing what it just produced must give the same thing back.
	round, err := Read(bytes.NewReader(m.Bytes()))
	if err != nil {
		t.Fatalf("a manifest this package serialised does not parse: %v", err)
	}
	if round.Digest() != m.Digest() {
		t.Fatal("a manifest does not survive its own round trip")
	}
}

// ---------- the path sanitiser ----------

// FuzzPathSanitiser is the other untrusted-bytes surface: filenames.
//
// The properties are the three claims path.go makes, and each one is a way
// somebody loses a file if it is false:
//
//	CleanRel never returns a path that escapes its root  — or a restore writes
//	                                                        outside the folder
//	                                                        it was told to;
//	Unsanitize(Sanitize(p)) == p                          — or the restored name
//	                                                        is not the name that
//	                                                        was there before;
//	Sanitize's output is writable on exFAT                — or the file is not
//	                                                        copied at all.
func FuzzPathSanitiser(f *testing.F) {
	seeds := []string{
		"", ".", "..", "../x", "a/../b", "/abs", `C:\x`, `\\server\share\x`,
		"a//b", "a/./b", "x\x00y", "a/", "ordinary.txt", "Documents/a.txt",
		`Documents\a.txt`, "CON", "con.txt", "aux.log/inner.txt", "NUL",
		"trailing dot.", "trailing space ", "report:2024.txt", "what?.txt",
		`quote".txt`, "%already%.txt", "\x01control.txt", "\x7f.txt",
		"caf\u00e9.txt", "cafe\u0301.txt", "\U0001F5C2/\U0001F4C4.txt",
		strings.Repeat("x", 300), strings.Repeat("a/", 100) + "b.txt",
		"...", "..a", "a..", "%", "%%", "%2", "%2E", "%zz", "~", "~1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, p string) {
		clean, err := CleanRel(p)
		if err != nil {
			// Refusing is always allowed. What is not allowed is refusing and
			// also handing back a path somebody might use.
			if clean != "" {
				t.Fatalf("CleanRel(%q) returned both %q and the error %v", p, clean, err)
			}
			return
		}

		// 1. The result cannot escape its root, by any spelling.
		if clean == "" {
			t.Fatalf("CleanRel(%q) accepted and returned an empty path", p)
		}
		if strings.HasPrefix(clean, "/") {
			t.Fatalf("CleanRel(%q) = %q, which is absolute", p, clean)
		}
		if strings.Contains(clean, `\`) {
			t.Fatalf("CleanRel(%q) = %q, which still contains a backslash separator", p, clean)
		}
		if strings.Contains(clean, "\x00") {
			t.Fatalf("CleanRel(%q) = %q, which contains a NUL", p, clean)
		}
		for _, seg := range strings.Split(clean, "/") {
			switch seg {
			case "", ".", "..":
				t.Fatalf("CleanRel(%q) = %q, which has a %q segment", p, clean, seg)
			}
		}
		// Idempotent: cleaning a cleaned path is a no-op. A cleaner that is not
		// idempotent has a second, different answer hiding in it.
		if again, aerr := CleanRel(clean); aerr != nil || again != clean {
			t.Fatalf("CleanRel is not idempotent: %q -> %q -> (%q, %v)", p, clean, again, aerr)
		}

		// 2. Sanitize is reversible.
		stored, changed := Sanitize(clean)
		back, uerr := Unsanitize(stored)
		if uerr != nil {
			t.Fatalf("Unsanitize(Sanitize(%q)) = %v", clean, uerr)
		}
		if back != clean {
			t.Fatalf("the round trip lost the name: %q -> %q -> %q", clean, stored, back)
		}
		if !changed && stored != clean {
			t.Fatalf("Sanitize reported no change but returned %q for %q", stored, clean)
		}
		if changed && stored == clean {
			t.Fatalf("Sanitize reported a change but returned the input unaltered: %q", clean)
		}

		// 3. The stored path is writable where it has to go.
		assertStorable(t, stored)

		// 4. De-collision only ever moves a name out of the way, never onto
		//    something else.
		empty := map[string]bool{}
		if got := DeCollide(stored, empty); got != stored {
			t.Fatalf("DeCollide renamed %q to %q with nothing taken", stored, got)
		}
		taken := map[string]bool{FoldKey(stored): true}
		alt := DeCollide(stored, taken)
		if FoldKey(alt) == FoldKey(stored) {
			t.Fatalf("DeCollide(%q) returned a name that still collides: %q", stored, alt)
		}
		assertStorable(t, alt)
	})
}

// FuzzUnsanitize points the fuzzer at the decoder on its own, because the
// restore side runs it on whatever is in the manifest on the stick — which is
// to say, on bytes the tool did not write.
func FuzzUnsanitize(f *testing.F) {
	for _, s := range []string{
		"", "a", "%", "%2", "%2E", "%2e", "%ZZ", "%%%%", "%25", "%00",
		"a%2Eb", "%41%42%43", strings.Repeat("%25", 200), "\x00", "\xff",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, err := Unsanitize(s)
		if err != nil {
			if out != "" {
				t.Fatalf("Unsanitize(%q) returned both %q and the error %v", s, out, err)
			}
			return
		}
		// A successful decode never invents length: every output byte came from
		// either one input byte or a three-byte escape.
		if len(out) > len(s) {
			t.Fatalf("Unsanitize(%q) produced %d bytes from %d", s, len(out), len(s))
		}
	})
}
