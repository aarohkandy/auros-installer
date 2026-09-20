package manifest

import (
	"errors"
	"strings"
	"testing"
)

func TestCleanRel_RefusesEscapes(t *testing.T) {
	// Every one of these has to be refused before the copy engine ever opens a
	// file, because each one is a way to read or write outside the tree the user
	// agreed to.
	bad := []string{
		"..",
		"../etc/passwd",
		"Documents/../../Windows/System32/config/SAM",
		"a/../../b",
		"/etc/passwd",
		`\Windows\System32`,
		`C:\Windows`,
		`C:/Windows`,
		`\\server\share\file`,
		"",
		"a//b",
		"a/./b",
		"a/",
		"./a",
		"a/\x00b",
	}
	for _, p := range bad {
		if got, err := CleanRel(p); err == nil {
			t.Errorf("CleanRel(%q) = %q, want an error", p, got)
		}
	}
}

func TestCleanRel_AcceptsOrdinaryPaths(t *testing.T) {
	cases := [][2]string{
		{"a.txt", "a.txt"},
		{"Documents/a.txt", "Documents/a.txt"},
		{`Documents\sub\a.txt`, "Documents/sub/a.txt"},
		{"Documents/..a.txt", "Documents/..a.txt"},
		{"Documents/a..txt", "Documents/a..txt"},
	}
	for _, c := range cases {
		got, err := CleanRel(c[0])
		if err != nil {
			t.Errorf("CleanRel(%q): %v", c[0], err)
			continue
		}
		if got != c[1] {
			t.Errorf("CleanRel(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestCleanRel_ErrorKinds(t *testing.T) {
	if _, err := CleanRel("../x"); !errors.Is(err, ErrPathEscape) {
		t.Errorf("err = %v, want ErrPathEscape", err)
	}
	if _, err := CleanRel("/x"); !errors.Is(err, ErrPathAbsolute) {
		t.Errorf("err = %v, want ErrPathAbsolute", err)
	}
	if _, err := CleanRel(""); !errors.Is(err, ErrPathEmpty) {
		t.Errorf("err = %v, want ErrPathEmpty", err)
	}
}

func TestSanitize_HandlesNamesLegalOnNTFSButNotElsewhere(t *testing.T) {
	// These are real names that a Windows volume will hold — via the \\?\ prefix,
	// via a POSIX-namespace create, or because the name was written by a
	// non-Windows tool — and that an exFAT or FAT32 USB stick will refuse or
	// silently rewrite. Silently rewriting is the failure: the file lands under a
	// name the manifest does not describe, and verification then reports a file
	// missing that is actually right there.
	cases := []string{
		`report:2024.txt`,
		`what?.txt`,
		`a*b.txt`,
		`a|b.txt`,
		`a<b>c.txt`,
		`quote".txt`,
		`back\slash.txt`,
		"trailing space ",
		"trailing dot.",
		"CON",
		"con.txt",
		"AUX.log",
		"LPT1",
		"nul.dat",
		"has%percent.txt",
		"control\x01char.txt",
	}
	for _, name := range cases {
		stored, changed := Sanitize(name)
		if !changed {
			t.Errorf("Sanitize(%q) reported no change; it must be made portable", name)
		}
		if strings.ContainsAny(stored, `<>:"|?*\`) {
			t.Errorf("Sanitize(%q) = %q still contains a hostile character", name, stored)
		}
		if n := len(stored); n > 0 && (stored[n-1] == '.' || stored[n-1] == ' ') {
			t.Errorf("Sanitize(%q) = %q still ends in a dot or space", name, stored)
		}
		back, err := Unsanitize(stored)
		if err != nil {
			t.Errorf("Unsanitize(%q): %v", stored, err)
			continue
		}
		if back != name {
			t.Errorf("round trip: %q -> %q -> %q", name, stored, back)
		}
	}
}

func TestSanitize_LeavesOrdinaryNamesAlone(t *testing.T) {
	for _, name := range []string{"a.txt", "Documents/report 2024.pdf", "résumé.odt", "日本語.txt"} {
		stored, changed := Sanitize(name)
		if changed || stored != name {
			t.Errorf("Sanitize(%q) = %q, changed=%v; ordinary names must be left alone", name, stored, changed)
		}
	}
}

func TestSanitize_ReservedNamesAreOnlyTheStem(t *testing.T) {
	if s, changed := Sanitize("console.txt"); changed || s != "console.txt" {
		t.Errorf("Sanitize(console.txt) = %q changed=%v; only the exact device names are reserved", s, changed)
	}
	if s, _ := Sanitize("CON"); s == "CON" {
		t.Error("Sanitize(CON) left a reserved device name unchanged")
	}
}

func TestUnsanitize_RefusesMalformedEscapes(t *testing.T) {
	for _, s := range []string{"a%", "a%Z1", "a%1", "a%GG"} {
		if got, err := Unsanitize(s); err == nil {
			t.Errorf("Unsanitize(%q) = %q, want an error rather than a guess", s, got)
		}
	}
}

func TestDeCollide_SeparatesNamesDifferingOnlyInCase(t *testing.T) {
	// Legal on ext4 and in NTFS's POSIX namespace, impossible on the exFAT stick
	// the archive is going to. Without this, one of the two files is lost.
	taken := map[string]bool{}
	first := DeCollide("Documents/Report.txt", taken)
	taken[FoldKey(first)] = true
	second := DeCollide("Documents/report.txt", taken)
	taken[FoldKey(second)] = true
	third := DeCollide("Documents/REPORT.txt", taken)

	if first != "Documents/Report.txt" {
		t.Errorf("first = %q, want the name unchanged", first)
	}
	if FoldKey(second) == FoldKey(first) {
		t.Errorf("second = %q collides with %q", second, first)
	}
	if FoldKey(third) == FoldKey(first) || FoldKey(third) == FoldKey(second) {
		t.Errorf("third = %q collides with %q or %q", third, first, second)
	}
	if !strings.HasSuffix(second, ".txt") {
		t.Errorf("second = %q lost its extension", second)
	}
}

func TestFoldKey(t *testing.T) {
	if FoldKey("A/B.TXT") != FoldKey("a/b.txt") {
		t.Fatal("FoldKey is not case-insensitive")
	}
}
