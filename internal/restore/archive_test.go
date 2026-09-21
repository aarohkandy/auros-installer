package restore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/manifest"
)

func TestFind_ByManifestNotByPath(t *testing.T) {
	// The archive is at a directory nothing could have remembered. It is found
	// because the manifest is in it, which is the whole point.
	media := t.TempDir()
	root := filepath.Join(media, "KINGSTON 32GB")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	buildArchive(t, root, map[string]string{"Documents/report.txt": "hello"})

	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: root, FSType: "exfat"}}, nil },
		ExtraRoots: []string{},
	}
	got, err := f.Find()
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 || got[0].Root != root {
		t.Fatalf("found %v, want exactly %s", got, root)
	}
	if got[0].FSType != "exfat" {
		t.Errorf("FSType = %q, want exfat (the kernel's answer, carried into the report)", got[0].FSType)
	}
}

func TestFind_MissingArchiveIsRefusedAndSaysWhereItLooked(t *testing.T) {
	empty := t.TempDir()
	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return []MountPoint{{Path: empty, FSType: "ext4"}}, nil },
		ExtraRoots: []string{},
	}
	_, err := f.Find()
	if !errors.Is(err, ErrNoArchive) {
		t.Fatalf("err = %v, want ErrNoArchive", err)
	}
	// "Never guess a path... when an assertion fails it must print what IS
	// there." A bare "not found" is exactly the message that wastes a build
	// cycle.
	if !strings.Contains(err.Error(), empty) {
		t.Errorf("the refusal does not name where it looked:\n%v", err)
	}
	if len(f.Searched) == 0 {
		t.Error("Searched is empty, so the program cannot say where it looked")
	}
}

func TestFind_TwoDifferentArchivesRefuseToBeGuessedBetween(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	buildArchive(t, a, map[string]string{"Documents/a.txt": "one"})
	buildArchive(t, b, map[string]string{"Documents/b.txt": "two"})

	f := &Finder{
		Mounts: func() ([]MountPoint, error) {
			return []MountPoint{{Path: a, FSType: "ext4"}, {Path: b, FSType: "vfat"}}, nil
		},
		ExtraRoots: []string{},
	}
	found, err := f.Find()
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous — guessing here restores the wrong person's files", err)
	}
	if len(found) != 2 {
		t.Fatalf("returned %d archives, want both so the user can choose", len(found))
	}
	for _, want := range []string{a, b, "--archive"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

func TestFind_TheSameArchiveSeenTwiceIsNotAmbiguous(t *testing.T) {
	// A USB stick that systemd mounted twice, or a bind mount. Two paths, one
	// inode. Refusing here would strand a user whose machine did something
	// completely ordinary.
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "one"})
	f := &Finder{
		Mounts: func() ([]MountPoint, error) {
			return []MountPoint{{Path: root, FSType: "ext4"}, {Path: root + string(filepath.Separator), FSType: "ext4"}}, nil
		},
		ExtraRoots: []string{},
	}
	got, err := f.Find()
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d archives, want 1", len(got))
	}
}

func TestFind_CorruptManifestIsAFindingNotAnAbsence(t *testing.T) {
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "one"})
	// Flip one byte of the body. The trailer digest no longer matches.
	p := filepath.Join(root, manifest.MetaDir, manifest.FileName)
	body := []byte(mustRead(t, p))
	body[len(manifest.Header)+3] ^= 0x20
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}

	f := &Finder{Explicit: root}
	_, err := f.Find()
	if err == nil {
		t.Fatal("a damaged manifest was accepted")
	}
	if errors.Is(err, ErrNoArchive) {
		t.Fatalf("a damaged manifest was reported as 'no archive', which tells the user to look "+
			"for a stick that is already plugged in: %v", err)
	}
	if !errors.Is(err, manifest.ErrCorrupt) && !errors.Is(err, manifest.ErrBadHeader) {
		t.Errorf("err = %v, want a manifest error", err)
	}
}

func TestFind_TruncatedManifestIsRefused(t *testing.T) {
	root := t.TempDir()
	buildArchive(t, root, map[string]string{
		"Documents/a.txt": "one", "Documents/b.txt": "two", "Documents/c.txt": "three",
	})
	p := filepath.Join(root, manifest.MetaDir, manifest.FileName)
	body := mustRead(t, p)
	// Cut the trailer off: the classic pulled-USB-stick failure. Without the
	// trailer the count and the digest are gone, and a verifier that accepted
	// this would pass a partial archive.
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	if err := os.WriteFile(p, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &Finder{Explicit: root}
	if _, err := f.Find(); !errors.Is(err, manifest.ErrTruncated) {
		t.Fatalf("err = %v, want ErrTruncated", err)
	}
}

func TestFind_CRLFManifestIsRefused(t *testing.T) {
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "one"})
	p := filepath.Join(root, manifest.MetaDir, manifest.FileName)
	body := strings.ReplaceAll(mustRead(t, p), "\n", "\r\n")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &Finder{Explicit: root}
	if _, err := f.Find(); !errors.Is(err, manifest.ErrCorrupt) {
		t.Fatalf("err = %v, want ErrCorrupt: a manifest that went through a text-mode round trip "+
			"no longer describes the bytes it hashed", err)
	}
}

func TestFind_MalformedMountinfoDoesNotStopTheSearch(t *testing.T) {
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "one"})
	f := &Finder{
		Mounts:     func() ([]MountPoint, error) { return nil, errors.New("no /proc on this machine") },
		ExtraRoots: []string{filepath.Dir(root)},
	}
	got, err := f.Find()
	if err != nil {
		t.Fatalf("a machine with no mount list should still search the conventional places: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d archives, want 1", len(got))
	}
}

func TestFind_PseudoFilesystemsAreNeverSearched(t *testing.T) {
	root := t.TempDir()
	buildArchive(t, root, map[string]string{"Documents/a.txt": "one"})
	f := &Finder{
		Mounts: func() ([]MountPoint, error) {
			return []MountPoint{{Path: root, FSType: "proc"}}, nil
		},
		ExtraRoots: []string{},
	}
	if _, err := f.Find(); !errors.Is(err, ErrNoArchive) {
		t.Fatalf("a proc mount was searched: %v", err)
	}
	if len(f.Searched) != 0 {
		t.Errorf("searched %v, want nothing", f.Searched)
	}
}

func TestParseMountinfo_UnescapesOctalAndIgnoresMalformedLines(t *testing.T) {
	in := strings.Join([]string{
		"25 30 0:22 / /proc rw,nosuid - proc proc rw",
		`36 25 8:17 / /run/media/pupil/Mr\040Smith\047s\040backup rw,nosuid,nodev - exfat /dev/sdb1 rw`,
		"this line is nonsense",
		"41 25 0:40 / /mnt/usb rw shared:1 master:2 - vfat /dev/sdc1 rw",
		"42 25 0:41 / /broken rw",
	}, "\n")
	got := parseMountinfo(in)
	want := []MountPoint{
		{Path: "/proc", FSType: "proc", Source: "proc"},
		{Path: "/run/media/pupil/Mr Smith's backup", FSType: "exfat", Source: "/dev/sdb1"},
		{Path: "/mnt/usb", FSType: "vfat", Source: "/dev/sdc1"},
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d mounts, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mount %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestFind_AnEmptyDirectoryIsNotAnArchive(t *testing.T) {
	root := t.TempDir()
	// A _auros directory with no manifest in it. The shape of a run that was
	// killed on the Windows side before it wrote anything.
	if err := os.MkdirAll(filepath.Join(root, manifest.MetaDir), 0o755); err != nil {
		t.Fatal(err)
	}
	// Asked for by path, so the refusal is the explicit one: the user named a
	// folder and it is not a backup. It must not read as "nothing attached".
	f := &Finder{Explicit: root}
	_, err := f.Find()
	if !errors.Is(err, ErrExplicitArchiveMissing) {
		t.Fatalf("err = %v, want ErrExplicitArchiveMissing", err)
	}
	if errors.Is(err, ErrNoArchive) {
		t.Fatalf("an explicit path with no manifest also matches ErrNoArchive, so a caller would exit 0: %v", err)
	}
}
