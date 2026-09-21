// Package gate3 is the runner-side half of the Gate 3 harness: the one that
// drives the REAL `auros-migrate` CLI against a real Windows machine that is
// destroyed afterwards (DECISIONS.md D27), and measures what happened without
// taking anything from the thing under test.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHAT MAKES A MEASUREMENT HERE ADMISSIBLE
// ─────────────────────────────────────────────────────────────────────────────
//
//  1. The golden manifest is produced by `gen`, which shares no code with the
//     installer: different module, different hash loop, different path handling.
//     Spec §6C's "zero corrupted" is a comparison between two independent
//     accounts of the same bytes. If one program produced both sides it would
//     only prove the program is self-consistent.
//
//  2. Nothing in a verdict comes from the installer's own log. The installer's
//     claims ARE read — a run that says "verified" while the archive is short is
//     a much worse finding than a run that aborts — but they are read as a
//     CLAIM to be checked against the harness's own measurement, never as the
//     measurement.
//
//  3. Progress is measured from outside the process, through the Windows job
//     object's I/O accounting, so "kill at 43% of the copy" does not depend on
//     the installer reporting anything at all. The installer has no progress
//     protocol and this harness does not ask it to grow one.
//
// This file holds the part that needs no Windows: the golden manifest, the
// installer's copy ORDER, and the arithmetic that turns "43% of the copy" into
// an exact file and byte offset. It is tested on Linux in ci.yml.
package gate3

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// HarnessVersion is stamped into every result. Bumping it invalidates older
// evidence, the same discipline gen and fault already use.
const HarnessVersion = "gate3/0.1.0"

// Stream is an NTFS alternate data stream as gen recorded it.
type Stream struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Rec is one golden-manifest record, plus the two things this harness derives:
// where the installer must put the file, and where that lands in copy order.
type Rec struct {
	Index   int      `json:"index"` // gen's index: byte order of the corpus-relative path
	Path    string   `json:"path"`  // corpus-relative, forward slashes
	WinPath string   `json:"win_path"`
	Size    int64    `json:"size"`
	SHA256  string   `json:"sha256"`
	Cohort  string   `json:"cohort"`
	Attrs   []string `json:"attrs,omitempty"`
	Streams []Stream `json:"streams,omitempty"`

	Placeholder         bool   `json:"placeholder,omitempty"`
	PlaceholderFidelity string `json:"placeholder_fidelity,omitempty"`
	LockedAtRuntime     bool   `json:"locked_at_runtime,omitempty"`
	WinPathLen          int    `json:"win_path_len"`
	RequiresLongPath    bool   `json:"requires_long_path,omitempty"`

	// Archive is where this file must appear under the destination root, as a
	// forward-slash relative path. Derived here, from the known-folder layout,
	// not read from anything the installer wrote.
	Archive string `json:"-"`
	// CopyIndex is this file's position in the installer's copy order.
	CopyIndex int `json:"-"`
	// CumEnd is the cumulative byte total after this file has been copied.
	CumEnd int64 `json:"-"`
}

// Golden is the whole corpus, in both orders.
type Golden struct {
	// ByGolden is gen's order (corpus-relative path).
	ByGolden []Rec
	// ByCopy is the installer's order, and the one every pin is computed in.
	ByCopy []Rec
	// Digest is the SHA-256 of golden-manifest.jsonl exactly as written, which
	// is the string `gen` prints as corpus_digest.
	Digest     string
	TotalBytes int64
}

// knownFolderRoots maps a corpus subtree onto the label the installer stores it
// under.
//
// This is the harness's INDEPENDENT model of what `auros-migrate` must do, and
// it is the reason the corpus is laid out as a user profile: the installer
// inventories the known folders (SHGetKnownFolderPath) and stores each one under
// its folder ID, so `AppData/Local/Google/...` in the corpus must appear as
// `LocalAppData/Google/...` in the archive. The labels are the FOLDERID names in
// internal/winenv, which is a contract between the two programs; if the
// installer renames one, every file in that subtree comes up missing here and
// the run goes red. That is the correct outcome: the archive is what the Linux
// restore reads, and a silent rename of a top-level folder is a migration that
// puts the user's Documents somewhere else.
//
// Longest prefix wins, so AppData/Local is matched before AppData.
var knownFolderRoots = []struct{ Corpus, Label string }{
	{"AppData/Local", "LocalAppData"},
	{"AppData/Roaming", "RoamingAppData"},
	{"Desktop", "Desktop"},
	{"Documents", "Documents"},
	{"Downloads", "Downloads"},
	{"Music", "Music"},
	{"Pictures", "Pictures"},
	{"Videos", "Videos"},
}

// KnownFolderLabels lists the labels a corpus can map onto, for the redirection
// step and for error messages.
func KnownFolderLabels() [][2]string {
	out := make([][2]string, 0, len(knownFolderRoots))
	for _, r := range knownFolderRoots {
		out = append(out, [2]string{r.Corpus, r.Label})
	}
	return out
}

// ErrOutsideKnownFolders means a corpus file is somewhere the installer will
// never look. It is fatal at load time rather than a missing file at verdict
// time: a corpus the harness cannot fully account for cannot support a statement
// about zero files lost.
var ErrOutsideKnownFolders = errors.New("gate3: corpus file is outside every known folder")

// ArchivePathFor maps a corpus-relative path to the archive-relative path the
// installer must store it at.
func ArchivePathFor(corpusRel string) (string, error) {
	p := strings.ReplaceAll(corpusRel, `\`, "/")
	best := -1
	for i, r := range knownFolderRoots {
		if p == r.Corpus || strings.HasPrefix(p, r.Corpus+"/") {
			if best < 0 || len(knownFolderRoots[best].Corpus) < len(r.Corpus) {
				best = i
			}
		}
	}
	if best < 0 {
		return "", fmt.Errorf("%w: %s", ErrOutsideKnownFolders, corpusRel)
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(p, knownFolderRoots[best].Corpus), "/")
	if rest == "" {
		return "", fmt.Errorf("%w: %s names a known folder root, not a file", ErrOutsideKnownFolders, corpusRel)
	}
	return knownFolderRoots[best].Label + "/" + rest, nil
}

// ErrNeedsEscaping means a corpus name is one the installer is required to
// percent-encode on the destination (internal/manifest.Sanitize).
//
// This harness deliberately does NOT reimplement that encoding. Re-deriving the
// stored name with a second copy of the same rules would make the comparison a
// comparison of two guesses, and getting it subtly wrong would report data loss
// that had not happened. The corpus `gen` produces contains no name that needs
// it — every vocabulary entry is legal on NTFS, on exFAT and on ext4 — so the
// expected archive path is the relative path verbatim, and a corpus that ever
// stops satisfying that assumption stops this harness at load time instead of
// quietly measuring the wrong paths.
var ErrNeedsEscaping = errors.New("gate3: corpus name would have to be escaped on the destination")

var escapeBytes = `<>:"|?*\%`

// checkNoEscaping is the assumption above, asserted.
func checkNoEscaping(rel string) error {
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" {
			return fmt.Errorf("%w: empty segment in %q", ErrNeedsEscaping, rel)
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if c < 0x20 || c == 0x7F || strings.IndexByte(escapeBytes, c) >= 0 {
				return fmt.Errorf("%w: %q contains %q", ErrNeedsEscaping, rel, string(c))
			}
		}
		if last := seg[len(seg)-1]; last == '.' || last == ' ' {
			return fmt.Errorf("%w: %q has a trailing %q", ErrNeedsEscaping, rel, string(last))
		}
		stem := strings.ToUpper(seg)
		if i := strings.IndexByte(stem, '.'); i >= 0 {
			stem = stem[:i]
		}
		if reservedStems[stem] {
			return fmt.Errorf("%w: %q is a reserved device name", ErrNeedsEscaping, rel)
		}
	}
	return nil
}

var reservedStems = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range strings.Fields("CON PRN AUX NUL COM0 COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 " +
		"LPT0 LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9") {
		m[n] = true
	}
	return m
}()

// LoadGolden reads golden-manifest.jsonl, derives the archive path of every
// file, and sorts a second view into the installer's copy order.
//
// The copy order is defined by internal/copyengine: every planned file is sorted
// by its logical path, which is "<label>/<relative path>" in raw byte order —
// the same comparison gen uses within the corpus, applied to the mapped path. A
// pin is only reproducible because both programs sort the same way, so this is
// asserted rather than assumed: see TestCopyOrderIsByteOrderOfArchivePath.
func LoadGolden(path string) (*Golden, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22) // near-MAX_PATH records are long
	g := &Golden{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Rec
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("golden manifest line %d: %w", len(g.ByGolden)+1, err)
		}
		if err := checkNoEscaping(r.Path); err != nil {
			return nil, err
		}
		arch, aerr := ArchivePathFor(r.Path)
		if aerr != nil {
			return nil, aerr
		}
		r.Archive = arch
		g.ByGolden = append(g.ByGolden, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(g.ByGolden) == 0 {
		return nil, errors.New("gate3: the golden manifest is empty; there is nothing this run could prove")
	}
	for i := range g.ByGolden {
		if g.ByGolden[i].Index != i {
			return nil, fmt.Errorf("gate3: golden manifest index %d at line %d: gen's order is not "+
				"contiguous from zero, so the corpus is not the one this harness can pin against",
				g.ByGolden[i].Index, i+1)
		}
		g.TotalBytes += g.ByGolden[i].Size
	}
	g.Digest = hex.EncodeToString(h.Sum(nil))

	g.ByCopy = append([]Rec(nil), g.ByGolden...)
	sort.Slice(g.ByCopy, func(i, j int) bool { return g.ByCopy[i].Archive < g.ByCopy[j].Archive })
	seen := make(map[string]bool, len(g.ByCopy))
	var cum int64
	for i := range g.ByCopy {
		a := g.ByCopy[i].Archive
		if seen[strings.ToLower(a)] {
			// Two source files claiming one destination name. The installer
			// de-collides with a "~N" suffix, which this harness does not model,
			// so a corpus that collides is one it cannot measure.
			return nil, fmt.Errorf("gate3: two corpus files both map to %q; this harness cannot "+
				"predict the installer's de-collision suffix", a)
		}
		seen[strings.ToLower(a)] = true
		g.ByCopy[i].CopyIndex = i
		cum += g.ByCopy[i].Size
		g.ByCopy[i].CumEnd = cum
	}
	return g, nil
}

// ByArchive indexes the corpus by expected archive path.
func (g *Golden) ByArchive() map[string]Rec {
	out := make(map[string]Rec, len(g.ByCopy))
	for _, r := range g.ByCopy {
		out[r.Archive] = r
	}
	return out
}

// AddBaselineExtras folds files that are in the corpus tree but not in the
// golden manifest into the model, hashing them here, before the run.
//
// Nothing should ever be there — `gen` writes the corpus and nothing else
// touches it. But the corpus IS a Windows user profile's known folders, and
// Windows writes into those on its own account (a desktop.ini when a folder is
// first opened, for instance). A file the installer will faithfully copy and
// that the harness does not know about would otherwise be reported as an
// unexplained extra in the archive on every single run, and the honest fix is
// not to ignore extras — it is to measure the starting state and require the
// archive to match THAT, exactly, with hashes the harness computed itself.
//
// Every file folded in this way is returned, so the run result says so out loud.
func (g *Golden) AddBaselineExtras(root string) ([]string, error) {
	known := make(map[string]bool, len(g.ByGolden))
	for i := range g.ByGolden {
		known[strings.ToLower(g.ByGolden[i].Path)] = true
	}
	var added []string
	buf := make([]byte, 1<<20)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil || d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if known[strings.ToLower(rel)] {
			return nil
		}
		if err := checkNoEscaping(rel); err != nil {
			return err
		}
		arch, aerr := ArchivePathFor(rel)
		if aerr != nil {
			// Outside every known folder: the installer will never see it, so it
			// is not part of what the archive must contain.
			return nil
		}
		sum, n, herr := hashFile(p, buf)
		if herr != nil {
			return fmt.Errorf("gate3: baseline hash of %s: %w", rel, herr)
		}
		g.ByGolden = append(g.ByGolden, Rec{
			Index: len(g.ByGolden), Path: rel, Size: n, SHA256: sum,
			Cohort: "baseline-extra", Archive: arch,
		})
		added = append(added, rel)
		return nil
	})
	if err != nil {
		return added, err
	}
	if len(added) == 0 {
		return nil, nil
	}
	g.TotalBytes = 0
	for i := range g.ByGolden {
		g.ByGolden[i].Index = i
		g.TotalBytes += g.ByGolden[i].Size
	}
	g.ByCopy = append([]Rec(nil), g.ByGolden...)
	sort.Slice(g.ByCopy, func(i, j int) bool { return g.ByCopy[i].Archive < g.ByCopy[j].Archive })
	var cum int64
	for i := range g.ByCopy {
		g.ByCopy[i].CopyIndex = i
		cum += g.ByCopy[i].Size
		g.ByCopy[i].CumEnd = cum
	}
	return added, nil
}

// Placeholders counts the files carrying FILE_ATTRIBUTE_OFFLINE. The installer
// refuses to start while they exist and no --cloud-files choice was made, so the
// harness has to know there are some.
func (g *Golden) Placeholders() int {
	n := 0
	for i := range g.ByGolden {
		if g.ByGolden[i].Placeholder {
			n++
		}
	}
	return n
}

// StreamFiles counts files carrying at least one alternate data stream.
func (g *Golden) StreamFiles() (files int, streams int) {
	for i := range g.ByGolden {
		if len(g.ByGolden[i].Streams) > 0 {
			files++
			streams += len(g.ByGolden[i].Streams)
		}
	}
	return files, streams
}

// GeneratorJunctions reads the junctions gen made in the corpus from the
// corpus-plan.json it wrote next to the golden manifest, as corpus-relative
// slash paths. They are not files, so they are not in the manifest; without
// this list the source check reads them as links that appeared during the run.
// A plan without junctions (an older gen) is not an error: there are none.
func GeneratorJunctions(planPath, corpusRoot string) ([]string, error) {
	b, err := os.ReadFile(planPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var p struct {
		Junctions []string `json:"junctions"`
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("gate3: %s: %w", planPath, err)
	}
	prefix := strings.ToLower(strings.TrimRight(corpusRoot, `\/`) + `\`)
	var out []string
	for _, j := range p.Junctions {
		if !strings.HasPrefix(strings.ToLower(j), prefix) {
			return nil, fmt.Errorf("gate3: the plan names a junction outside the corpus: %s", j)
		}
		out = append(out, strings.ReplaceAll(j[len(prefix):], `\`, "/"))
	}
	return out, nil
}
