package gate3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE TWO MEASUREMENTS
//
// Spec §4.1 asks for the data to exist in two places with the second copy
// verified by count and hash. CheckSource measures place one after the run —
// "zero data loss" is a statement about the ORIGINAL, and it is the one that
// matters most, because the original is the only copy a school has. CheckArchive
// measures place two.
//
// Both re-read raw bytes and re-hash them. Neither reads anything the installer
// wrote about itself.
// ─────────────────────────────────────────────────────────────────────────────

// MetaDirName is the installer's metadata directory on the destination. Its
// contents are the installer's own bookkeeping — manifest, run log, quarantine
// report — and are checked separately (see claims.go) rather than compared
// against the corpus.
const MetaDirName = "_auros"

// PartialSuffix marks a file the installer had not finished writing. Debris
// after a power cut is legitimate; a file under its FINAL name that does not
// match the manifest is not.
const PartialSuffix = ".auros-partial"

// Variant is one state a file was genuinely in at some point during the run.
type Variant struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Note   string `json:"note,omitempty"`
}

// Deviation records damage THE HARNESS did on purpose, with the bytes it
// actually left behind, measured at the moment it did it.
//
// It is recorded by the injector rather than derived from the scenario table for
// the reason the whole harness exists: a scenario table says what was meant to
// happen. If the harness's own fault did not land the way it intended, the
// difference has to show up as a failure, not be absorbed by an expectation
// written in advance.
type Deviation struct {
	Tree string `json:"tree"` // "source" or "archive"
	Path string `json:"path"` // corpus-relative, or archive-relative
	Kind string `json:"kind"`
	// Absent means the file must not exist after the run.
	Absent bool `json:"absent,omitempty"`
	// Allowed lists every state the file may legitimately be in. More than one
	// entry is not sloppiness: when a source file is rewritten during its copy,
	// the archive may hold either the version before or the version after, and
	// anything else is a torn file — a mixture that never existed, which is the
	// corruption this scenario is hunting.
	Allowed []Variant `json:"allowed,omitempty"`
	// MayBeAbsent covers the archive side of an aborted run: the installer may
	// legitimately never have got to this file.
	MayBeAbsent bool   `json:"may_be_absent,omitempty"`
	Note        string `json:"note,omitempty"`
}

func deviationFor(devs []Deviation, tree, path string) *Deviation {
	for i := range devs {
		if devs[i].Tree == tree && strings.EqualFold(devs[i].Path, path) {
			return &devs[i]
		}
	}
	return nil
}

// Problem is one file that disagreed.
type Problem struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Want   string `json:"want,omitempty"`
	Got    string `json:"got,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// TreeReport is the result of re-hashing a tree against the golden manifest.
type TreeReport struct {
	Tree           string    `json:"tree"`
	Root           string    `json:"root"`
	Expected       int       `json:"expected_files"`
	Present        int       `json:"present_files"`
	HashMatches    int       `json:"hash_matches"`
	BytesHashed    int64     `json:"bytes_hashed"`
	Missing        []string  `json:"missing,omitempty"`
	Corrupt        []Problem `json:"corrupt,omitempty"`
	Unreadable     []Problem `json:"unreadable,omitempty"`
	Extra          []string  `json:"extra,omitempty"`
	NonRegular     []string  `json:"non_regular,omitempty"`
	Partials       []string  `json:"partials,omitempty"`
	DeviationsSeen []string  `json:"deviations_seen,omitempty"`
	DeviationsLost []Problem `json:"deviations_not_as_injected,omitempty"`
	// StreamsFound counts alternate data streams the harness found on the copies
	// it checked. It is a MEASUREMENT, not a check: see ArchiveStreamNote.
	StreamsChecked int `json:"streams_checked,omitempty"`
	StreamsFound   int `json:"streams_found,omitempty"`
}

const maxListed = 40

func (r *TreeReport) trim() {
	if len(r.Missing) > maxListed {
		r.Missing = append(r.Missing[:maxListed:maxListed], fmt.Sprintf("… and %d more", len(r.Missing)-maxListed))
	}
	if len(r.Extra) > maxListed {
		r.Extra = append(r.Extra[:maxListed:maxListed], fmt.Sprintf("… and %d more", len(r.Extra)-maxListed))
	}
	if len(r.Corrupt) > maxListed {
		r.Corrupt = r.Corrupt[:maxListed]
	}
}

// LostFiles is the number of golden files that are simply not there, ignoring
// the ones a scenario removed on purpose.
func (r *TreeReport) LostFiles() int { return len(r.Missing) }

// CorruptFiles is the number that are there and wrong.
func (r *TreeReport) CorruptFiles() int { return len(r.Corrupt) + len(r.Unreadable) }

// CheckSource re-hashes the corpus after a run.
//
// "Zero data loss" is a claim about the user's original files, so this is the
// check that would have caught Wubi. A file that a scenario deleted on purpose
// is expected to be gone; everything else must be byte-identical to what `gen`
// wrote, which is a manifest produced by a program that shares no code with the
// installer.
func CheckSource(g *Golden, root string, devs []Deviation) (*TreeReport, error) {
	rep := &TreeReport{Tree: "source", Root: root, Expected: len(g.ByGolden)}
	buf := make([]byte, 1<<20)
	for i := range g.ByGolden {
		rec := g.ByGolden[i]
		full := filepath.Join(root, filepath.FromSlash(rec.Path))
		dev := deviationFor(devs, "source", rec.Path)
		st, err := os.Lstat(full)
		if err != nil {
			if os.IsNotExist(err) {
				if dev != nil && dev.Absent {
					rep.DeviationsSeen = append(rep.DeviationsSeen, rec.Path+" (absent, as injected)")
					continue
				}
				rep.Missing = append(rep.Missing, rec.Path)
				continue
			}
			rep.Unreadable = append(rep.Unreadable, Problem{Path: rec.Path, Kind: "lstat", Detail: err.Error()})
			continue
		}
		rep.Present++
		if dev != nil && dev.Absent {
			rep.DeviationsLost = append(rep.DeviationsLost, Problem{
				Path: rec.Path, Kind: "deviation-not-applied",
				Detail: "the scenario deleted this file, and it is back",
			})
			continue
		}
		sum, n, herr := hashFile(full, buf)
		rep.BytesHashed += n
		if herr != nil {
			rep.Unreadable = append(rep.Unreadable, Problem{Path: rec.Path, Kind: "read", Detail: herr.Error()})
			continue
		}
		if dev != nil {
			if matchVariant(dev.Allowed, sum, n) {
				rep.DeviationsSeen = append(rep.DeviationsSeen, rec.Path+" ("+dev.Kind+", as injected)")
				continue
			}
			rep.DeviationsLost = append(rep.DeviationsLost, Problem{
				Path: rec.Path, Kind: "deviation-not-as-injected",
				Want: describeVariants(dev.Allowed), Got: fmt.Sprintf("%s (%d bytes)", sum, n),
				Detail: "the harness damaged this file on purpose and it is not in the state the harness left it in",
			})
			continue
		}
		if st.Size() != rec.Size {
			rep.Corrupt = append(rep.Corrupt, Problem{
				Path: rec.Path, Kind: "size", Want: fmt.Sprintf("%d", rec.Size), Got: fmt.Sprintf("%d", st.Size()),
			})
			continue
		}
		if sum != rec.SHA256 {
			rep.Corrupt = append(rep.Corrupt, Problem{Path: rec.Path, Kind: "hash", Want: rec.SHA256, Got: sum})
			continue
		}
		rep.HashMatches++
	}

	// Anything in the corpus that is not in the golden manifest. The corpus is
	// generated, so a new file appearing in it during a run is either the
	// harness's own planted link or something writing into the user's folders
	// while the tool reads them — and both of those change what "18,000 files"
	// means.
	known := make(map[string]bool, len(g.ByGolden))
	for i := range g.ByGolden {
		known[strings.ToLower(g.ByGolden[i].Path)] = true
	}
	werr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if dev := deviationFor(devs, "source", rel); dev != nil {
			rep.DeviationsSeen = append(rep.DeviationsSeen, rel+" ("+dev.Kind+")")
			return nil
		}
		if !d.Type().IsRegular() {
			// A link, a device, a junction. It is not in the golden manifest
			// because gen does not create them, so its presence is a change to
			// the source tree and is reported rather than hashed.
			rep.NonRegular = append(rep.NonRegular, rel)
			rep.Extra = append(rep.Extra, rel)
			return nil
		}
		if known[strings.ToLower(rel)] {
			return nil
		}
		rep.Extra = append(rep.Extra, rel)
		return nil
	})
	if werr != nil {
		return rep, werr
	}
	sort.Strings(rep.Extra)
	sort.Strings(rep.Missing)
	rep.trim()
	return rep, nil
}

// CheckArchive re-hashes the archive the installer materialised.
//
// It takes nothing from the installer: it walks the destination, maps every file
// back to the corpus by the known-folder layout, and compares raw bytes against
// the golden manifest. `complete` says whether every file is required to be
// there — true for a clean run, false for one that aborted, where a partial
// archive is the correct outcome and the question is only whether what IS there
// is right.
func CheckArchive(g *Golden, root string, devs []Deviation, complete bool) (*TreeReport, error) {
	rep := &TreeReport{Tree: "archive", Root: root, Expected: len(g.ByCopy)}
	if _, err := os.Stat(root); os.IsNotExist(err) {
		// No archive directory at all. That is the CORRECT state after a phase-3
		// refusal — the installer must refuse before it creates anything — so it
		// is an empty measurement rather than an unreadable one. Whether it is
		// allowed to be empty is the outcome check's business, not this one's.
		if complete {
			for rel := range g.ByArchive() {
				rep.Missing = append(rep.Missing, rel)
			}
			sort.Strings(rep.Missing)
			rep.trim()
		}
		return rep, nil
	}
	byArchive := g.ByArchive()
	buf := make([]byte, 1<<20)
	seen := make(map[string]bool, len(byArchive))

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			// An unreadable directory inside the archive is itself a finding: it
			// means the destination is not something a restore could read.
			rel, _ := filepath.Rel(root, p)
			rep.Unreadable = append(rep.Unreadable, Problem{
				Path: filepath.ToSlash(rel), Kind: "walk", Detail: err.Error()})
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if rel == MetaDirName || strings.HasPrefix(rel, MetaDirName+"/") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(rel, PartialSuffix) {
			rep.Partials = append(rep.Partials, rel)
			return nil
		}
		rec, ok := byArchive[rel]
		if !ok {
			if dev := deviationFor(devs, "archive", rel); dev != nil {
				rep.DeviationsSeen = append(rep.DeviationsSeen, rel+" ("+dev.Kind+")")
				return nil
			}
			rep.Extra = append(rep.Extra, rel)
			return nil
		}
		seen[rel] = true
		rep.Present++
		sum, n, herr := hashFile(p, buf)
		rep.BytesHashed += n
		if herr != nil {
			rep.Unreadable = append(rep.Unreadable, Problem{Path: rel, Kind: "read", Detail: herr.Error()})
			return nil
		}
		if dev := deviationFor(devs, "archive", rel); dev != nil {
			if matchVariant(dev.Allowed, sum, n) {
				rep.DeviationsSeen = append(rep.DeviationsSeen, rel+" ("+dev.Kind+", as injected)")
				return nil
			}
			rep.DeviationsLost = append(rep.DeviationsLost, Problem{
				Path: rel, Kind: "deviation-not-as-injected",
				Want: describeVariants(dev.Allowed), Got: fmt.Sprintf("%s (%d bytes)", sum, n),
			})
			return nil
		}
		if n != rec.Size {
			rep.Corrupt = append(rep.Corrupt, Problem{
				Path: rel, Kind: "size", Want: fmt.Sprintf("%d", rec.Size), Got: fmt.Sprintf("%d", n)})
			return nil
		}
		if sum != rec.SHA256 {
			rep.Corrupt = append(rep.Corrupt, Problem{Path: rel, Kind: "hash", Want: rec.SHA256, Got: sum})
			return nil
		}
		rep.HashMatches++
		return nil
	})
	if err != nil {
		return rep, err
	}

	for rel, rec := range byArchive {
		if seen[rel] {
			continue
		}
		if dev := deviationFor(devs, "archive", rel); dev != nil && (dev.Absent || dev.MayBeAbsent) {
			continue
		}
		if dev := deviationFor(devs, "source", rec.Path); dev != nil && (dev.Absent || dev.MayBeAbsent) {
			// A file the scenario removed from the SOURCE cannot be in the
			// archive, and its absence there is not data loss.
			continue
		}
		if complete {
			rep.Missing = append(rep.Missing, rel)
		}
	}
	sort.Strings(rep.Missing)
	sort.Strings(rep.Extra)
	sort.Strings(rep.Partials)
	rep.trim()
	return rep, nil
}

func matchVariant(allowed []Variant, sum string, size int64) bool {
	for _, v := range allowed {
		if v.SHA256 == sum && (v.Size == 0 || v.Size == size) {
			return true
		}
	}
	return false
}

func describeVariants(vs []Variant) string {
	parts := make([]string, 0, len(vs))
	for _, v := range vs {
		parts = append(parts, fmt.Sprintf("%s (%d bytes, %s)", v.SHA256, v.Size, v.Note))
	}
	return strings.Join(parts, " or ")
}

func hashFile(path string, buf []byte) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	var n int64
	for {
		k, rerr := f.Read(buf)
		if k > 0 {
			h.Write(buf[:k])
			n += int64(k)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return "", n, rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// HashOf is hashFile with its own buffer, for one-off measurements.
func HashOf(path string) (Variant, error) {
	sum, n, err := hashFile(path, make([]byte, 1<<20))
	if err != nil {
		return Variant{}, err
	}
	return Variant{SHA256: sum, Size: n}, nil
}
