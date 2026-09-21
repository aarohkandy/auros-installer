package restore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
)

func TestPlan_LabelsLandInTheUsersOwnFolders(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Documents/report.txt":  "r",
		"Desktop/note.txt":      "n",
		"Pictures/trip/sea.jpg": "s",
		"Downloads/setup.zip":   "z",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Documents/report.txt":  filepath.Join(home, "Documents", "report.txt"),
		"Desktop/note.txt":      filepath.Join(home, "Desktop", "note.txt"),
		"Pictures/trip/sea.jpg": filepath.Join(home, "Pictures", "trip", "sea.jpg"),
		"Downloads/setup.zip":   filepath.Join(home, "Downloads", "setup.zip"),
	}
	got := map[string]string{}
	for _, it := range p.Files {
		got[it.Entry.Path] = it.Route.Target
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s -> %s, want %s", k, got[k], v)
		}
	}
}

func TestPlan_LocalisedUserDirsAreHonoured(t *testing.T) {
	// A Marathi-locale school laptop, which SPEC §6B is explicitly about. A
	// restore that wrote to ~/Documents would put every file somewhere the
	// user's own file manager does not show.
	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "XDG_DOCUMENTS_DIR=\"$HOME/दस्तऐवज\"\nXDG_DESKTOP_DIR=\"$HOME/डेस्कटॉप\"\n"
	if err := os.WriteFile(filepath.Join(cfg, "user-dirs.dirs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := NewLayout(home, cfg, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/report.txt": "r"})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "दस्तऐवज", "report.txt")
	if p.Files[0].Route.Target != want {
		t.Errorf("target = %s, want %s", p.Files[0].Route.Target, want)
	}
}

func TestPlan_APathEscapingHomeRefusesTheWholeRun(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/ok.txt": "fine"})

	// CleanRel refuses ".." at copy time, so the only way this reaches a plan
	// is a manifest written by something other than our own copy engine — a
	// hand-edited file, a future version with a bug, or somebody being
	// deliberate. The plan is the last place to catch it and it must catch it.
	hostile := manifest.Entry{
		Path: "Documents/../../../../etc/cron.d/pwn", Stored: "Documents/ok.txt",
		Size: 4, ModTimeUnixNano: 1, SHA256: a.Manifest.Entries()[0].SHA256,
	}
	m2 := manifest.New()
	if err := m2.Add(hostile); err != nil {
		t.Fatalf("the manifest itself refused the entry, so this test cannot reach the plan: %v", err)
	}
	a.Manifest = m2

	_, err := BuildPlan(a, l)
	if !errors.Is(err, ErrPathEscape) {
		t.Fatalf("err = %v, want ErrPathEscape", err)
	}
	if !strings.Contains(err.Error(), l.Home) {
		t.Errorf("the refusal does not say what home IS:\n%v", err)
	}
}

func TestPlan_AnAbsolutePathIsRefused(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/ok.txt": "fine"})
	e := a.Manifest.Entries()[0]
	m2 := manifest.New()
	if err := m2.Add(manifest.Entry{
		Path: "/etc/shadow", Stored: e.Stored, Size: e.Size,
		ModTimeUnixNano: e.ModTimeUnixNano, SHA256: e.SHA256,
	}); err != nil {
		t.Fatalf("manifest refused the entry: %v", err)
	}
	a.Manifest = m2
	if _, err := BuildPlan(a, l); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("err = %v, want ErrPathEscape", err)
	}
}

func TestPlan_AnEmptyManifestIsRefused(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	buildArchive(t, root, map[string]string{})
	a := loadForTest(t, root)
	if _, err := BuildPlan(a, l); !errors.Is(err, ErrPlanEmpty) {
		t.Fatalf("err = %v, want ErrPlanEmpty: a restore of nothing is not a successful restore", err)
	}
}

func TestPlan_ChromeSecretsAreWithheldAndNamed(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Chrome/Default/Bookmarks":            "{}",
		"Chrome/Default/History":              "sqlite",
		"Chrome/Default/Login Data":           "SECRET",
		"Chrome/Default/Cookies":              "SECRET",
		"Chrome/Default/Web Data":             "SECRET",
		"Chrome/Local State":                  "SECRET",
		"Chrome/Default/Network/Cookies":      "SECRET",
		"Edge/Default/Login Data For Account": "SECRET",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	restored := map[string]bool{}
	for _, it := range p.Files {
		restored[it.Entry.Path] = true
	}
	for _, secret := range []string{
		"Chrome/Default/Login Data", "Chrome/Default/Cookies", "Chrome/Default/Web Data",
		"Chrome/Local State", "Chrome/Default/Network/Cookies",
		"Edge/Default/Login Data For Account",
	} {
		if restored[secret] {
			t.Errorf("D15 BREACH: %q is planned for restore", secret)
		}
	}
	if !restored["Chrome/Default/Bookmarks"] || !restored["Chrome/Default/History"] {
		t.Error("bookmarks and history must migrate — D15 says they do")
	}
	if len(p.Withheld) != 6 {
		t.Errorf("withheld %d item(s), want 6", len(p.Withheld))
	}
	for _, it := range p.Withheld {
		if !strings.Contains(it.Route.Why, "D15") {
			t.Errorf("%s is withheld without naming the rule: %q", it.Entry.Path, it.Route.Why)
		}
	}
}

func TestPlan_AnUnknownChromeFileIsWithheldByDefault(t *testing.T) {
	// The allow-list's whole purpose: a file Google adds next year does not
	// migrate until somebody decides it should.
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Chrome/Default/Something Invented In 2027": "who knows",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 0 || len(p.Withheld) != 1 {
		t.Fatalf("files=%d withheld=%d, want 0 and 1", len(p.Files), len(p.Withheld))
	}
}

func TestPlan_FirefoxGoesToDotMozilla(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Firefox/profiles.ini":                          "[Profile0]",
		"Firefox/Profiles/abcd.default-release/key4.db": "k",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"Firefox/profiles.ini": filepath.Join(home, ".mozilla", "firefox", "profiles.ini"),
		"Firefox/Profiles/abcd.default-release/key4.db": filepath.Join(
			home, ".mozilla", "firefox", "Profiles", "abcd.default-release", "key4.db"),
	}
	for _, it := range p.Files {
		if want[it.Entry.Path] != it.Route.Target {
			t.Errorf("%s -> %s, want %s", it.Entry.Path, it.Route.Target, want[it.Entry.Path])
		}
		if it.Route.FileMode != 0o600 {
			t.Errorf("%s mode %04o, want 0600: a Firefox profile is not world-readable material",
				it.Entry.Path, it.Route.FileMode)
		}
	}
}

func TestPlan_AnUnknownLabelIsKeptNeverDropped(t *testing.T) {
	home, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"SageAccounts2016/company.dta": "data",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Files) != 1 {
		t.Fatalf("an unrecognised label produced %d planned files, want 1 — nothing is dropped", len(p.Files))
	}
	want := filepath.Join(home, FallbackDirName, "SageAccounts2016", "company.dta")
	if p.Files[0].Route.Target != want {
		t.Errorf("target = %s, want %s", p.Files[0].Route.Target, want)
	}
}

func TestPlan_EveryEntryIsAccountedFor(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Documents/a.txt":        "a",
		"Chrome/Default/Cookies": "secret",
		"WiFi/SchoolWiFi.xml":    "<WLANProfile/>",
		"Printers/printers.tsv":  "x",
		"Something/else.bin":     "b",
	})
	p, err := BuildPlan(a, l)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != a.Manifest.Len() {
		t.Fatalf("plan accounts for %d of %d entries", p.Count(), a.Manifest.Len())
	}
	if len(p.WiFi) != 1 || len(p.Printers) != 1 || len(p.Withheld) != 1 || len(p.Files) != 2 {
		t.Errorf("files=%d wifi=%d printers=%d withheld=%d", len(p.Files), len(p.WiFi), len(p.Printers), len(p.Withheld))
	}
}

func TestLayout_ADirectoryOutsideHomeIsRefused(t *testing.T) {
	home := t.TempDir()
	elsewhere := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "XDG_DOCUMENTS_DIR=\"" + elsewhere + "\"\n"
	if err := os.WriteFile(filepath.Join(cfg, "user-dirs.dirs"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := NewLayout(home, cfg, noEnv)
	if !errors.Is(err, ErrDirOutsideHome) {
		t.Fatalf("err = %v, want ErrDirOutsideHome", err)
	}
	for _, want := range []string{home, elsewhere, "XDG_DOCUMENTS_DIR"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not print %q, so nobody can act on it:\n%v", want, err)
		}
	}
}

func TestLayout_MissingUserDirsFallsBackAndSaysSo(t *testing.T) {
	home := t.TempDir()
	l, err := NewLayout(home, filepath.Join(home, ".config"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	dir, src := l.Dir("XDG_DOWNLOAD_DIR")
	if dir != filepath.Join(home, "Downloads") {
		t.Errorf("dir = %s, want %s", dir, filepath.Join(home, "Downloads"))
	}
	if !strings.Contains(src, "default") {
		t.Errorf("source = %q, want it to admit it is a default", src)
	}
}

func TestLayout_UnknownKeyIsNotAnsweredWithAPlausiblePath(t *testing.T) {
	home := t.TempDir()
	l, err := NewLayout(home, filepath.Join(home, ".config"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	dir, src := l.Dir("XDG_INVENTED_DIR")
	if dir != "" {
		t.Errorf("dir = %q, want empty: guessing here is how files go somewhere nobody looks", dir)
	}
	if !strings.Contains(src, "unknown") {
		t.Errorf("source = %q, want it to say the key is unknown", src)
	}
}

func TestPlan_ARoutingRuleThatLandsOutsideHomeIsRefused(t *testing.T) {
	// The second of the plan's two independent path checks, exercised on its
	// own. The first — re-validating what the manifest says — catches an
	// escaping SOURCE path. This one catches an escaping DESTINATION, which is
	// what a future routing rule pointing at /etc or /usr would produce, and
	// it is the check the prove-red harness caught as unreachable.
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/ok.txt": "fine"})

	rogue := &Router{L: l, override: func(logical string) (Route, bool) {
		return Route{
			Disposition: DispFile,
			Target:      "/etc/cron.d/auros-pwn",
			DirMode:     0o755, FileMode: 0o644,
			Why: "a rule somebody adds in two years", Bucket: "Documents",
		}, true
	}}
	_, err := buildPlanWith(a, l, rogue)
	if !errors.Is(err, ErrPathEscape) {
		t.Fatalf("err = %v, want ErrPathEscape", err)
	}
	for _, want := range []string{"/etc/cron.d/auros-pwn", l.Home} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not print %q:\n%v", want, err)
		}
	}
}

// The lexical check's own case. Once the plan also resolved links, a target in
// /etc was refused by BOTH checks, so disabling the lexical one left the test
// above green (prove-red M04). The case only it catches: a target spelled
// outside the home whose directory is a link back INTO the home. The resolved
// check calls that fine; a routing rule that names a path outside the home is
// wrong however the disk happens to be linked today.
func TestPlan_ARoutedTargetSpelledOutsideHomeIsRefusedEvenIfItLinksBackIn(t *testing.T) {
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{"Documents/ok.txt": "fine"})
	back := filepath.Join(t.TempDir(), "back-into-home")
	if err := os.Symlink(l.Home, back); err != nil {
		t.Skipf("cannot create a link here: %v", err)
	}
	rogue := &Router{L: l, override: func(string) (Route, bool) {
		return Route{Disposition: DispFile, Target: filepath.Join(back, "ok.txt"),
			DirMode: 0o755, FileMode: 0o644, Bucket: "Documents"}, true
	}}
	if _, err := buildPlanWith(a, l, rogue); !errors.Is(err, ErrPathEscape) {
		t.Fatalf("err = %v, want ErrPathEscape: a target spelled outside the home was planned", err)
	}
}

func TestPlan_TwoEntriesWantingOneDestinationIsRefused(t *testing.T) {
	// Silent data loss wearing a plausible face: the second file overwrites
	// the first and the count still comes out right.
	_, l := newHome(t)
	root := t.TempDir()
	a := buildArchive(t, root, map[string]string{
		"Documents/a.txt": "one", "Documents/b.txt": "two",
	})
	collide := &Router{L: l, override: func(string) (Route, bool) {
		return Route{
			Disposition: DispFile,
			Target:      filepath.Join(l.Home, "Documents", "same.txt"),
			DirMode:     0o755, FileMode: 0o644, Bucket: "Documents",
		}, true
	}}
	_, err := buildPlanWith(a, l, collide)
	if !errors.Is(err, ErrTargetCollision) {
		t.Fatalf("err = %v, want ErrTargetCollision", err)
	}
}

func TestPlan_APathThatIsNotWhatItClaimsIsRefused(t *testing.T) {
	// The OTHER arm of the plan's path validation, and the one the
	// home-directory assertion cannot stand in for.
	//
	// "Documents/./notes.txt" and `Documents/a\b.txt` both resolve to somewhere
	// perfectly ordinary INSIDE the home directory, so underPath has nothing to
	// say about either. What is wrong with them is that the manifest's Path is
	// not the path it claims to be — and Entry.Path is what the restore puts
	// back, so a Path that needs cleaning means the file lands somewhere other
	// than where the manifest says it came from, with the count still adding up.
	for _, bad := range []string{
		"Documents/./notes.txt",
		`Documents/a\b.txt`,
		"Documents//notes.txt",
	} {
		t.Run(bad, func(t *testing.T) {
			_, l := newHome(t)
			root := t.TempDir()
			a := buildArchive(t, root, map[string]string{"Documents/ok.txt": "fine"})
			e := a.Manifest.Entries()[0]
			m2 := manifest.New()
			if err := m2.Add(manifest.Entry{
				Path: bad, Stored: e.Stored, Size: e.Size,
				ModTimeUnixNano: e.ModTimeUnixNano, SHA256: e.SHA256,
			}); err != nil {
				t.Fatalf("the manifest refused the entry, so this cannot reach the plan: %v", err)
			}
			a.Manifest = m2
			_, err := BuildPlan(a, l)
			if !errors.Is(err, ErrPathEscape) {
				t.Fatalf("err = %v, want ErrPathEscape for %q", err, bad)
			}
		})
	}
}
