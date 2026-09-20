package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Manifest properties.
//
// The manifest is the only description of what was copied. Phase 5 verifies
// against it, phase 7 restores from it, and the decision to wipe a stranger's
// disk is taken on the strength of it. So the properties here are not "the
// parser handles bad input gracefully"; they are "a manifest that has been
// changed in ANY way is refused", and the way to be sure of that is to change
// it in every way and check.
//
// Ratio note (SAFETY.md rule 2): this file is almost entirely refusals.

// ---------- building known-good and known-bad manifests ----------

// assemble builds a manifest with a CORRECT trailer over whatever body lines it
// is given.
//
// That is the point of it. A hand-corrupted manifest with a stale trailer fails
// on the digest, which means the test proves the digest works and proves
// nothing about the rule it was written for. assemble recomputes the trailer,
// so the only thing left to reject the body is the rule under test.
func assemble(lines []string, count int, total int64) []byte {
	var body bytes.Buffer
	body.WriteString(Header)
	body.WriteByte('\n')
	for _, l := range lines {
		body.WriteString(l)
		body.WriteByte('\n')
	}
	sum := sha256.Sum256(body.Bytes())
	out := body.Bytes()
	out = append(out, []byte(fmt.Sprintf("end\t%d\t%d\t%s\n",
		count, total, hex.EncodeToString(sum[:])))...)
	return out
}

// entryLine renders one body line without going through Manifest.Add, so a test
// can write a line Add would have refused.
func entryLine(digest string, size, mtime int64, path, stored string) string {
	return strings.Join([]string{
		digest,
		strconv.FormatInt(size, 10),
		strconv.FormatInt(mtime, 10),
		wireEscape(path),
		wireEscape(stored),
	}, "\t")
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// goodManifest is a small, ordinary, valid manifest, used as the thing every
// mutation below starts from.
func goodManifest(t *testing.T) *Manifest {
	t.Helper()
	return build(t,
		entry("Desktop/empty.txt", ""),
		entry("Documents/a.txt", "alpha"),
		entry("Documents/sub/b.txt", "bravo"),
		entry("Pictures/gran.jpg", strings.Repeat("jpeg", 64)),
	)
}

// ---------- byte stability ----------

// TestProperty_SerialiseParseSerialiseIsByteStable is the round trip that has
// to be exact. Two runs of the tool over the same unchanged tree must produce
// identical bytes, and a manifest read back off a USB stick must re-serialise
// to exactly what was written, or the digest that identifies an archive is not
// identifying anything.
func TestProperty_SerialiseParseSerialiseIsByteStable(t *testing.T) {
	m := goodManifest(t)
	first := m.Bytes()

	for round := 0; round < 4; round++ {
		parsed, err := Read(bytes.NewReader(first))
		if err != nil {
			t.Fatalf("round %d: Read: %v", round, err)
		}
		again := parsed.Bytes()
		if !bytes.Equal(first, again) {
			t.Fatalf("round %d: re-serialising changed the bytes\n first: %q\nsecond: %q",
				round, first, again)
		}
		if parsed.Digest() != m.Digest() {
			t.Fatalf("round %d: digest changed across a round trip", round)
		}
		if parsed.Len() != m.Len() || parsed.TotalBytes() != m.TotalBytes() {
			t.Fatalf("round %d: count or size changed across a round trip", round)
		}
	}
}

// TestProperty_InsertionOrderNeverReachesTheBytes checks the sort, hard. Map
// iteration order in Go is deliberately randomised, so a manifest that leaked
// it would be unstable between two runs of the SAME binary on the SAME tree —
// and would fail intermittently, which is the worst way for this to be found.
func TestProperty_InsertionOrderNeverReachesTheBytes(t *testing.T) {
	entries := []Entry{
		entry("Z.txt", "zed"),
		entry("a.txt", "ay"),
		entry("_underscore.txt", "us"),
		entry("Documents/b.txt", "bee"),
		entry("documents/b.txt", "bee too"),
		entry("0-digit.txt", "zero"),
		entry("~tilde.txt", "tilde"),
	}
	// Make the stored paths distinct, since two of these differ only in case.
	for i := range entries {
		entries[i].Stored = fmt.Sprintf("s%02d/%s", i, entries[i].Path)
	}

	want := build(t, entries...).Bytes()
	for shift := 1; shift < len(entries); shift++ {
		rotated := append(append([]Entry(nil), entries[shift:]...), entries[:shift]...)
		got := build(t, rotated...).Bytes()
		if !bytes.Equal(want, got) {
			t.Fatalf("insertion order changed the serialisation (rotation %d)\n want: %q\n got:  %q",
				shift, want, got)
		}
	}

	// And the order is RAW BYTE order, not a locale collation: "Z" sorts before
	// "_" which sorts before "a", because that is what their bytes do.
	var paths []string
	for _, e := range build(t, entries...).Entries() {
		paths = append(paths, e.Path)
	}
	if !sort.SliceIsSorted(paths, func(i, j int) bool { return paths[i] < paths[j] }) {
		t.Fatalf("entries are not in raw byte order: %v", paths)
	}
	if idx(paths, "Z.txt") > idx(paths, "a.txt") {
		t.Errorf("uppercase sorted after lowercase, so this is a locale collation and not "+
			"byte order: %v", paths)
	}
}

func idx(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}

// TestProperty_NoAmbientStateReachesTheBytes is the "no timestamps, hostnames,
// usernames or versions" rule. Two independently-built manifests describing the
// same files must be byte-identical, and nothing about WHEN or WHERE they were
// built may appear.
func TestProperty_NoAmbientStateReachesTheBytes(t *testing.T) {
	a := goodManifest(t).Bytes()
	b := goodManifest(t).Bytes()
	if !bytes.Equal(a, b) {
		t.Fatalf("two manifests over the same tree differ:\n%q\n%q", a, b)
	}
	text := string(a)
	// None of these appears in any path this fixture uses, so any of them
	// turning up means the serialisation started carrying something about the
	// machine or the moment rather than about the files.
	for _, leak := range []string{"hostname", "auros-migrate", "localhost", "/home/", "/Users/", "C:\\"} {
		if strings.Contains(text, leak) {
			t.Errorf("the serialisation contains %q, which is ambient state", leak)
		}
	}
	if !strings.HasPrefix(text, Header+"\n") {
		t.Errorf("the manifest does not start with the header line")
	}
	if strings.Contains(text, "\r") {
		t.Error("the serialisation contains a CR")
	}
	if !strings.HasSuffix(text, "\n") {
		t.Error("the serialisation does not end with a newline")
	}
}

// TestProperty_DigestMovesWhenAnyFieldMoves makes sure the digest is actually
// covering every field. A digest that ignored, say, the stored path would let
// two different archives claim the same identity.
func TestProperty_DigestMovesWhenAnyFieldMoves(t *testing.T) {
	base := goodManifest(t)
	baseDigest := base.Digest()

	mutations := []struct {
		name  string
		apply func(e Entry) Entry
	}{
		{"the source path", func(e Entry) Entry { e.Path = e.Path + "x"; return e }},
		{"the stored path", func(e Entry) Entry { e.Stored = e.Stored + "x"; return e }},
		{"the size", func(e Entry) Entry { e.Size++; return e }},
		{"the modification time", func(e Entry) Entry { e.ModTimeUnixNano++; return e }},
		{"the digest", func(e Entry) Entry { e.SHA256 = digestOf("something else"); return e }},
	}

	for _, mu := range mutations {
		t.Run(mu.name, func(t *testing.T) {
			m := New()
			for i, e := range base.Entries() {
				if i == 1 {
					e = mu.apply(e)
				}
				if err := m.Add(e); err != nil {
					t.Fatalf("Add: %v", err)
				}
			}
			if m.Digest() == baseDigest {
				t.Fatalf("changing %s did not change the manifest digest: the digest is not "+
					"covering that field, so two different archives would claim one identity",
					mu.name)
			}
		})
	}
}

// ---------- every mutation is refused ----------

// TestProperty_EverySingleBitFlipIsRefused is the exhaustive one.
//
// For a valid manifest, flip one bit — every bit, one at a time — and the
// parser must refuse all of them. There is no "harmless" bit: a flip in a path
// renames somebody's file, a flip in a size hides a truncation, a flip in a
// digest breaks the only check that would have caught either.
func TestProperty_EverySingleBitFlipIsRefused(t *testing.T) {
	good := goodManifest(t).Bytes()
	if len(good) < 100 {
		t.Fatalf("the fixture manifest is only %d bytes; this test is barely testing anything", len(good))
	}

	accepted := 0
	var examples []string
	for i := 0; i < len(good); i++ {
		for bit := 0; bit < 8; bit++ {
			mutated := append([]byte(nil), good...)
			mutated[i] ^= 1 << bit
			if bytes.Equal(mutated, good) {
				continue
			}
			if _, err := Read(bytes.NewReader(mutated)); err == nil {
				accepted++
				if len(examples) < 5 {
					examples = append(examples, fmt.Sprintf("byte %d bit %d (%q -> %q)",
						i, bit, good[i], mutated[i]))
				}
			}
		}
	}
	if accepted != 0 {
		t.Fatalf("%d single-bit flips were accepted as a valid manifest: %s",
			accepted, strings.Join(examples, "; "))
	}
}

// TestProperty_EveryTruncationIsRefused is the USB stick pulled while the
// manifest was being written. A short manifest that PARSES is how a verifier is
// fooled into passing on a partial copy, so every prefix short of the whole
// thing has to be rejected.
func TestProperty_EveryTruncationIsRefused(t *testing.T) {
	good := goodManifest(t).Bytes()
	for n := 0; n < len(good); n++ {
		if _, err := Read(bytes.NewReader(good[:n])); err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte manifest parsed successfully:\n%q",
				n, len(good), good[:n])
		}
	}
	// The control: the whole thing does parse. Without this, a Read that
	// always errored would make the loop above pass for the wrong reason.
	if _, err := Read(bytes.NewReader(good)); err != nil {
		t.Fatalf("the complete manifest does not parse: %v", err)
	}
}

// TestProperty_EveryTrailingByteIsRefused covers the other end: something
// appended after the trailer. A manifest with extra content is not a manifest
// with a bonus; it is a manifest somebody edited.
func TestProperty_EveryTrailingByteIsRefused(t *testing.T) {
	good := goodManifest(t).Bytes()
	suffixes := [][]byte{
		[]byte("\n"),
		[]byte(" "),
		[]byte("\t"),
		[]byte("\x00"),
		[]byte("end\t0\t0\t" + digestOf("") + "\n"),
		[]byte("Documents/extra.txt\n"),
		append([]byte(nil), good...), // the whole manifest, twice
	}
	for _, suffix := range suffixes {
		mutated := append(append([]byte(nil), good...), suffix...)
		if _, err := Read(bytes.NewReader(mutated)); err == nil {
			t.Errorf("a manifest with %q appended parsed successfully", trunc(suffix))
		}
	}
}

func trunc(b []byte) string {
	if len(b) > 32 {
		return string(b[:32]) + "..."
	}
	return string(b)
}

// TestProperty_CRLFIsRefusedAtEveryLine is the git-autocrlf and
// opened-in-Notepad case. A manifest that has been through a text-mode round
// trip no longer describes the bytes that were hashed.
func TestProperty_CRLFIsRefusedAtEveryLine(t *testing.T) {
	good := string(goodManifest(t).Bytes())
	lines := strings.Split(strings.TrimSuffix(good, "\n"), "\n")

	// Every line converted.
	all := strings.Join(lines, "\r\n") + "\r\n"
	if _, err := Read(strings.NewReader(all)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a fully CRLF manifest: err = %v, want ErrCorrupt", err)
	}

	// And one line at a time, including the header and the trailer.
	for i := range lines {
		mutated := append([]string(nil), lines...)
		mutated[i] += "\r"
		text := strings.Join(mutated, "\n") + "\n"
		if _, err := Read(strings.NewReader(text)); err == nil {
			t.Errorf("a CR on line %d parsed successfully", i)
		}
	}
}

// TestProperty_BodyRulesAreEnforcedEvenWithACorrectTrailer is the table that
// assemble exists for. Each body below has a perfectly valid trailer, so the
// digest cannot be what rejects it — the named rule has to.
func TestProperty_BodyRulesAreEnforcedEvenWithACorrectTrailer(t *testing.T) {
	alpha, bravo := digestOf("alpha"), digestOf("bravo")

	cases := []struct {
		name    string
		lines   []string
		count   int
		total   int64
		wantErr error
	}{
		{
			name: "control: an ordinary two-entry body",
			lines: []string{
				entryLine(alpha, 5, 1, "a.txt", "a.txt"),
				entryLine(bravo, 5, 1, "b.txt", "b.txt"),
			},
			count:   2,
			total:   10,
			wantErr: nil,
		},
		{
			name: "the same source path twice",
			lines: []string{
				entryLine(alpha, 5, 1, "a.txt", "a.txt"),
				entryLine(alpha, 5, 1, "a.txt", "a-2.txt"),
			},
			count:   2,
			total:   10,
			wantErr: ErrCorrupt, // caught as out-of-order before Add sees it
		},
		{
			name: "two source paths claiming one stored path",
			lines: []string{
				entryLine(alpha, 5, 1, "a.txt", "same.txt"),
				entryLine(bravo, 5, 1, "b.txt", "same.txt"),
			},
			count:   2,
			total:   10,
			wantErr: ErrDuplicateStored,
		},
		{
			name: "entries out of order",
			lines: []string{
				entryLine(bravo, 5, 1, "b.txt", "b.txt"),
				entryLine(alpha, 5, 1, "a.txt", "a.txt"),
			},
			count:   2,
			total:   10,
			wantErr: ErrCorrupt,
		},
		{
			name:    "an entry with four fields",
			lines:   []string{alpha + "\t5\t1\ta.txt"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "an entry with six fields",
			lines:   []string{alpha + "\t5\t1\ta.txt\ta.txt\textra"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a negative size",
			lines:   []string{entryLine(alpha, -5, 1, "a.txt", "a.txt")},
			count:   1,
			total:   -5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a size that is not a number",
			lines:   []string{alpha + "\tfive\t1\ta.txt\ta.txt"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a modification time that is not a number",
			lines:   []string{alpha + "\t5\tyesterday\ta.txt\ta.txt"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "an uppercase digest",
			lines:   []string{entryLine(strings.ToUpper(alpha), 5, 1, "a.txt", "a.txt")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a digest one character short",
			lines:   []string{entryLine(alpha[:63], 5, 1, "a.txt", "a.txt")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a digest with a non-hex character",
			lines:   []string{entryLine("g"+alpha[1:], 5, 1, "a.txt", "a.txt")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a zero-length file with a non-empty digest",
			lines:   []string{entryLine(alpha, 0, 1, "a.txt", "a.txt")},
			count:   1,
			total:   0,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a non-empty file with the empty digest",
			lines:   []string{entryLine(EmptySHA256, 5, 1, "a.txt", "a.txt")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "an empty source path",
			lines:   []string{entryLine(alpha, 5, 1, "", "a.txt")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "an empty stored path",
			lines:   []string{entryLine(alpha, 5, 1, "a.txt", "")},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a truncated percent escape in a path",
			lines:   []string{alpha + "\t5\t1\ta%2\ta.txt"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name:    "a malformed percent escape in a path",
			lines:   []string{alpha + "\t5\t1\ta%zz.txt\ta.txt"},
			count:   1,
			total:   5,
			wantErr: ErrCorrupt,
		},
		{
			name: "control: a zero-entry manifest is legal and means nothing was copied",
			// safety.Verify is what refuses to arm on this, not the parser.
			lines:   nil,
			count:   0,
			total:   0,
			wantErr: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := assemble(tc.lines, tc.count, tc.total)
			m, err := Read(bytes.NewReader(raw))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Read = %v, want nil\n%s", err, raw)
				}
				if m.Len() != tc.count {
					t.Errorf("parsed %d entries, want %d", m.Len(), tc.count)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Read = %v, want %v\n%s", err, tc.wantErr, raw)
			}
		})
	}
}

// TestProperty_TheTrailerMustAgreeWithTheBody covers the trailer's own fields.
// The trailer is what makes a truncated manifest DETECTABLE rather than quietly
// short, so each of its three numbers has to be checked against the body.
func TestProperty_TheTrailerMustAgreeWithTheBody(t *testing.T) {
	good := goodManifest(t).Bytes()
	text := string(good)
	cut := strings.LastIndex(text, "end\t")
	if cut < 0 {
		t.Fatal("the fixture manifest has no trailer")
	}
	body, trailer := text[:cut], strings.TrimSuffix(text[cut:], "\n")
	fields := strings.Split(strings.TrimPrefix(trailer, "end\t"), "\t")
	if len(fields) != 3 {
		t.Fatalf("the trailer has %d fields: %q", len(fields), trailer)
	}

	cases := []struct {
		name    string
		trailer string
	}{
		{"the count is one too high", fmt.Sprintf("end\t%s\t%s\t%s", bump(fields[0], 1), fields[1], fields[2])},
		{"the count is one too low", fmt.Sprintf("end\t%s\t%s\t%s", bump(fields[0], -1), fields[1], fields[2])},
		{"the count is zero", fmt.Sprintf("end\t0\t%s\t%s", fields[1], fields[2])},
		{"the total is one byte out", fmt.Sprintf("end\t%s\t%s\t%s", fields[0], bump(fields[1], 1), fields[2])},
		{"the total is zero", fmt.Sprintf("end\t%s\t0\t%s", fields[0], fields[2])},
		{"the digest is another digest", fmt.Sprintf("end\t%s\t%s\t%s", fields[0], fields[1], digestOf("not this"))},
		{"the digest is empty", fmt.Sprintf("end\t%s\t%s\t", fields[0], fields[1])},
		{"the trailer has two fields", fmt.Sprintf("end\t%s\t%s", fields[0], fields[1])},
		{"the trailer has four fields", fmt.Sprintf("end\t%s\t%s\t%s\textra", fields[0], fields[1], fields[2])},
		{"the count is not a number", fmt.Sprintf("end\tmany\t%s\t%s", fields[1], fields[2])},
		{"the total is not a number", fmt.Sprintf("end\t%s\tlots\t%s", fields[0], fields[2])},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(body + tc.trailer + "\n")); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Read = %v, want ErrCorrupt", err)
			}
		})
	}

	// Control: the untouched trailer parses.
	if _, err := Read(strings.NewReader(body + trailer + "\n")); err != nil {
		t.Fatalf("the untouched manifest does not parse: %v", err)
	}
}

func bump(s string, by int64) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return s + "x"
	}
	return strconv.FormatInt(n+by, 10)
}

// TestProperty_HeaderIsExact refuses anything that is not this format at this
// version. A parser that shrugs at an unknown version is a parser that will one
// day read a future format with today's rules.
func TestProperty_HeaderIsExact(t *testing.T) {
	good := string(goodManifest(t).Bytes())
	rest := good[len(Header):]

	for _, header := range []string{
		"",
		" " + Header,
		Header + " ",
		strings.ToUpper(Header),
		"auros-manifest/2",
		"auros-manifest/10",
		"auros-manifest",
		"auros-manifest/1.0",
		"# auros-manifest/1",
	} {
		if _, err := Read(strings.NewReader(header + rest)); err == nil {
			t.Errorf("header %q was accepted", header)
		}
	}
}

// ---------- paths ----------

// TestProperty_SanitizeRoundTripsForEveryAwkwardName is the reversibility claim
// in path.go, checked against the names that actually turn up.
func TestProperty_SanitizeRoundTripsForEveryAwkwardName(t *testing.T) {
	names := []string{
		"ordinary.txt",
		"Documents/notes.txt",
		"a/b/c/d/e/f/g.txt",
		"report:2024.txt",
		"notes.txt:Zone.Identifier",
		"what?.txt",
		"star*.txt",
		"pipe|name.txt",
		"less<than.txt",
		"more>than.txt",
		`quote".txt`,
		`back\slash.txt`,
		"trailing dot.",
		"trailing space ",
		"CON",
		"con.txt",
		"AUX",
		"aux.log/inner.txt",
		"COM1",
		"LPT9.dat",
		"NUL",
		"nulled.txt",
		"%already%encoded%.txt",
		"%2E%2E.txt",
		"\x01control.txt",
		"\x7fdelete.txt",
		"caf\u00e9.txt",
		"cafe\u0301.txt",
		"\U0001F5C2 folder/\U0001F4C4 file.txt",
		strings.Repeat("x", 200) + ".txt",
		"dots...many...txt",
		"dir with spaces/file with spaces.txt",
	}

	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			clean, err := CleanRel(n)
			if err != nil {
				t.Fatalf("CleanRel(%q) = %v", n, err)
			}
			stored, _ := Sanitize(clean)
			back, uerr := Unsanitize(stored)
			if uerr != nil {
				t.Fatalf("Unsanitize(%q) = %v", stored, uerr)
			}
			if back != clean {
				t.Fatalf("round trip lost the name: %q -> %q -> %q", clean, stored, back)
			}
			assertStorable(t, stored)
		})
	}
}

// assertStorable is what "portable" means, written out. Every one of these is a
// way a name that was fine on the source NTFS volume silently becomes a
// different file, or no file, on an exFAT stick.
func assertStorable(t *testing.T, stored string) {
	t.Helper()
	if stored == "" {
		t.Fatal("the stored path is empty")
	}
	for _, seg := range strings.Split(stored, "/") {
		if seg == "" {
			t.Fatalf("stored path %q has an empty segment", stored)
		}
		if strings.ContainsAny(seg, "<>:\"|?*\\") {
			t.Errorf("segment %q contains a character exFAT refuses", seg)
		}
		for i := 0; i < len(seg); i++ {
			if seg[i] < 0x20 || seg[i] == 0x7F {
				t.Errorf("segment %q contains a control character", seg)
				break
			}
		}
		if strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") {
			t.Errorf("segment %q ends in a dot or a space, which Windows strips on create", seg)
		}
		stem := seg
		if i := strings.IndexByte(seg, '.'); i >= 0 {
			stem = seg[:i]
		}
		if reservedStems[strings.ToUpper(stem)] {
			t.Errorf("segment %q is a reserved device name", seg)
		}
	}
}

// TestProperty_CleanRelRefusesEveryEscape is the path-escape table. A path that
// leaves its root is how a copy of Documents turns into a copy of C:\Windows,
// and how a restore writes outside the folder it was told to write in.
func TestProperty_CleanRelRefusesEveryEscape(t *testing.T) {
	escapes := []string{
		"..",
		"../",
		"../x",
		"a/..",
		"a/../b",
		"a/../../b",
		`..\x`,
		`a\..\b`,
		"./x",
		"a/./b",
		".",
		"a//b",
		"/abs",
		`\abs`,
		`C:/x`,
		`C:\x`,
		`c:x`,
		"//server/share/x",
		`\\server\share\x`,
		"",
		"a/",
		"/",
		"x\x00y",
		"a/\x00/b",
	}

	for _, p := range escapes {
		t.Run(fmt.Sprintf("%q", p), func(t *testing.T) {
			got, err := CleanRel(p)
			if err == nil {
				t.Fatalf("CleanRel(%q) = %q, want a refusal", p, got)
			}
		})
	}

	// Control: the ordinary forms are accepted, and a backslash separator is
	// translated rather than refused, because that is how Windows spells a path.
	for in, want := range map[string]string{
		"a.txt":               "a.txt",
		"Documents/a.txt":     "Documents/a.txt",
		"Documents\\a.txt":    "Documents/a.txt",
		"a/b/c.txt":           "a/b/c.txt",
		"..twodots.txt":       "..twodots.txt",
		"dir..name/file.txt":  "dir..name/file.txt",
		"a/..b/c.txt":         "a/..b/c.txt",
		"trailing.dots...txt": "trailing.dots...txt",
	} {
		got, err := CleanRel(in)
		if err != nil {
			t.Errorf("CleanRel(%q) = %v, want %q", in, err, want)
			continue
		}
		if got != want {
			t.Errorf("CleanRel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestProperty_DeCollideNeverReturnsATakenName is the last line of defence
// against one file overwriting another at the destination.
func TestProperty_DeCollideNeverReturnsATakenName(t *testing.T) {
	taken := map[string]bool{}
	inputs := []string{
		"a.txt", "A.txt", "a.TXT", "A.TXT",
		"dir/a.txt", "DIR/a.txt", "dir/A.TXT",
		"noext", "NOEXT", "noext.", "NoExt",
		".hidden", ".HIDDEN",
		"a.tar.gz", "A.TAR.GZ",
	}
	for _, in := range inputs {
		got := DeCollide(in, taken)
		if taken[FoldKey(got)] {
			t.Fatalf("DeCollide(%q) returned %q, which is already taken", in, got)
		}
		if strings.Contains(got, "~overflow") {
			t.Fatalf("DeCollide(%q) gave up after one attempt", in)
		}
		taken[FoldKey(got)] = true
	}
	if len(taken) != len(inputs) {
		t.Fatalf("%d inputs produced %d distinct names", len(inputs), len(taken))
	}
}
