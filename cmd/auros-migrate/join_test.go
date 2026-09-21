package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/labels"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/restore"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// The join nobody tested (SYSTEM-REVIEW §2.7). Each half passed its own
// tests; the Linux router's tests fed it "Chrome/Default/Login Data", a shape
// the Windows half never produces. This test produces the archive the way the
// Windows half does — its known-folder labels (pinned to labels.Folders by
// winenv's own test), this command's buildSources, the real copy engine, the
// manifest as written to the stick — and routes every entry of it through the
// real Linux router.
//
// winPath is where each known folder sits under a user profile on a stock
// Windows install; the browser paths below are the browsers' own, and the ones
// the Gate 3 corpus uses (testharness/gen/generate.go).
var winPath = map[string]string{
	labels.Desktop: "Desktop", labels.Documents: "Documents", labels.Downloads: "Downloads",
	labels.Pictures: "Pictures", labels.Music: "Music", labels.Videos: "Videos",
	labels.RoamingAppData: "AppData/Roaming", labels.LocalAppData: "AppData/Local",
}

func TestJoin_TheWindowsArchiveRoutesWhereTheLinuxHalfMeansItTo(t *testing.T) {
	profile := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(profile, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	chrome := "AppData/Local/Google/Chrome/User Data/"
	edge := "AppData/Local/Microsoft/Edge/User Data/"
	firefox := "AppData/Roaming/Mozilla/Firefox/"
	for _, f := range []string{
		"Documents/Year 7/report.docx", "Desktop/notes.txt",
		chrome + "Default/Bookmarks", chrome + "Default/History", chrome + "Default/Login Data",
		chrome + "Default/Cookies", chrome + "Default/Network/Cookies", chrome + "Default/Web Data",
		chrome + "Local State",
		edge + "Default/Bookmarks", edge + "Default/Login Data",
		firefox + "profiles.ini", firefox + "Profiles/8f3k2p1q.default-release/places.sqlite",
	} {
		put(f, f)
	}

	var folders []winenv.Folder
	for _, l := range labels.Folders {
		rel, ok := winPath[l]
		if !ok {
			t.Fatalf("labels.Folders has %q and this test does not know where Windows keeps it: add it to winPath", l)
		}
		p := filepath.Join(profile, filepath.FromSlash(rel))
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		folders = append(folders, winenv.Folder{ID: l, Path: p, Present: true})
	}
	sources, err := buildSources(folders, nil)
	if err != nil {
		t.Fatal(err)
	}
	stick := filepath.Join(t.TempDir(), manifest.ArchiveSubdir)
	res, err := copyengine.Run(context.Background(), copyengine.Options{Sources: sources, DestRoot: stick})
	if err != nil || res.Quarantined != 0 {
		t.Fatalf("copy: err=%v quarantined=%d", err, res.Quarantined)
	}
	f, err := os.Open(filepath.Join(stick, manifest.MetaDir, manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m, err := manifest.Read(f)
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	cfg := filepath.Join(home, ".config")
	if err := os.MkdirAll(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "user-dirs.dirs"),
		[]byte("XDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOCUMENTS_DIR=\"$HOME/Documents\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lay, err := restore.NewLayout(home, cfg, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	router := &restore.Router{L: lay}

	withheld := map[string]bool{
		chrome + "Default/Login Data": true, chrome + "Default/Cookies": true,
		chrome + "Default/Network/Cookies": true, chrome + "Default/Web Data": true,
		chrome + "Local State": true, edge + "Default/Login Data": true,
	}
	wantAt := map[string]string{
		"Documents/Year 7/report.docx":                              "Documents/Year 7/report.docx",
		"Desktop/notes.txt":                                         "Desktop/notes.txt",
		chrome + "Default/Bookmarks":                                ".config/google-chrome/Default/Bookmarks",
		chrome + "Default/History":                                  ".config/google-chrome/Default/History",
		edge + "Default/Bookmarks":                                  ".config/microsoft-edge/Default/Bookmarks",
		firefox + "profiles.ini":                                    ".mozilla/firefox/profiles.ini",
		firefox + "Profiles/8f3k2p1q.default-release/places.sqlite": ".mozilla/firefox/Profiles/8f3k2p1q.default-release/places.sqlite",
	}
	// The manifest speaks labels, not Windows paths: map back for the lookup.
	toWin := strings.NewReplacer(labels.LocalAppData+"/", "AppData/Local/", labels.RoamingAppData+"/", "AppData/Roaming/")

	if m.Len() != len(withheld)+len(wantAt) {
		t.Fatalf("the archive holds %d entries, want %d", m.Len(), len(withheld)+len(wantAt))
	}
	for _, e := range m.Entries() {
		win := toWin.Replace(e.Path)
		rt, err := router.Route(e.Path)
		if err != nil {
			t.Errorf("%s: %v", e.Path, err)
			continue
		}
		if withheld[win] {
			if rt.Disposition != restore.DispWithheld {
				t.Errorf("D15 BREACH: %s is %s to %s; it must be withheld", e.Path, rt.Disposition, rt.Target)
			}
			continue
		}
		want := filepath.Join(home, filepath.FromSlash(wantAt[win]))
		if rt.Disposition != restore.DispFile || rt.Target != want {
			t.Errorf("%s: routed %s to %s, want %s", e.Path, rt.Disposition, rt.Target, want)
		}
	}
}
