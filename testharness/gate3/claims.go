package gate3

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// WHAT THE INSTALLER SAYS ABOUT ITSELF
//
// Everything in this file is a CLAIM. None of it is evidence on its own, and
// nothing here is allowed to turn a failing measurement into a pass. It is read
// for two reasons:
//
//  1. A run that aborted must not have claimed a verified archive. "The archive
//     is short AND the installer says it verified it" is a far worse finding
//     than "the archive is short", and the difference is only visible if the
//     claim is read.
//
//  2. The manifest on the destination is what the Linux side restores against.
//     Parsing it here — with a second implementation of the format, not the
//     installer's — is how the harness can say whether what the installer
//     verified is what it left behind.
// ─────────────────────────────────────────────────────────────────────────────

// LogEvent is one line of the installer's run log.
type LogEvent struct {
	Seq   int    `json:"seq"`
	TS    string `json:"ts"`
	Phase string `json:"phase"`
	Kind  string `json:"kind"`

	FileCount      int    `json:"file_count"`
	TotalBytes     int64  `json:"total_bytes"`
	ManifestDigest string `json:"manifest_digest"`
	DestRoot       string `json:"dest_root"`
	DestVolume     string `json:"dest_volume"`
	SystemVolume   string `json:"system_volume"`
	Reason         string `json:"reason"`
	Note           string `json:"note"`
	Unresolved     int    `json:"unresolved"`
	Quarantined    int    `json:"quarantined"`
	Copied         int    `json:"copied"`
	Error          string `json:"error"`
}

// Claims is everything the installer said, reduced to the handful of statements
// a verdict is allowed to care about.
type Claims struct {
	LogPath string `json:"log_path"`
	Events  int    `json:"events"`

	// ClaimedVerified is the "5-verify / verified" event: the installer's
	// assertion that the data now exists in two places. On an aborted run it
	// must not be there.
	ClaimedVerified bool   `json:"claimed_verified"`
	VerifiedCount   int    `json:"verified_file_count"`
	VerifiedBytes   int64  `json:"verified_total_bytes"`
	ManifestDigest  string `json:"manifest_digest"`
	DestRoot        string `json:"dest_root"`
	DestVolume      string `json:"dest_volume"`
	SystemVolume    string `json:"system_volume"`

	// ReachedWall is the dry run's "I would have crossed here" record.
	ReachedWall bool `json:"reached_wall_dry_run"`
	// CrossedWall must never be true in this harness: every run is a dry run,
	// and the privileged steps are compiled out of the binary under test.
	CrossedWall bool `json:"crossed_wall"`

	Aborted     bool     `json:"aborted"`
	AbortReason string   `json:"abort_reason,omitempty"`
	Refusals    []string `json:"refusals,omitempty"`
	Quarantined int      `json:"quarantined_reported,omitempty"`
}

// ReadClaims parses every run log the installer left in the destination's
// metadata directory.
func ReadClaims(destRoot string) (*Claims, error) {
	c := &Claims{}
	metaDir := filepath.Join(destRoot, MetaDirName)
	entries, err := os.ReadDir(metaDir)
	if err != nil {
		// No metadata directory at all is a legitimate state after an early
		// abort, and an unreadable destination is the point of some scenarios.
		return c, nil
	}
	var logs []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "run-") && strings.HasSuffix(e.Name(), ".jsonl") {
			logs = append(logs, filepath.Join(metaDir, e.Name()))
		}
	}
	sort.Strings(logs)
	for _, p := range logs {
		c.LogPath = p
		f, oerr := os.Open(p)
		if oerr != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var ev LogEvent
			if json.Unmarshal([]byte(line), &ev) != nil {
				continue
			}
			c.Events++
			switch {
			case ev.Phase == "5-verify" && ev.Kind == "verified":
				c.ClaimedVerified = true
				c.VerifiedCount = ev.FileCount
				c.VerifiedBytes = ev.TotalBytes
				c.ManifestDigest = ev.ManifestDigest
			case ev.Phase == "5-verify" && ev.Kind == "wall-reached-dry-run":
				c.ReachedWall = true
			case ev.Kind == "wall-crossed":
				c.CrossedWall = true
			case ev.Kind == "abort":
				c.Aborted = true
				c.AbortReason = ev.Reason
			case ev.Kind == "refused":
				c.Refusals = append(c.Refusals, ev.Reason+" "+ev.Error)
			}
			if ev.Kind == "chosen" && ev.DestRoot == "" {
				// phase 3's "chosen" event carries dir/volume under different
				// names; the fields we can read are filled opportunistically.
				c.DestVolume = ev.DestVolume
			}
			if ev.DestRoot != "" {
				c.DestRoot = ev.DestRoot
			}
			if ev.DestVolume != "" {
				c.DestVolume = ev.DestVolume
			}
			if ev.SystemVolume != "" {
				c.SystemVolume = ev.SystemVolume
			}
			if ev.Quarantined > 0 {
				c.Quarantined = ev.Quarantined
			}
		}
		f.Close()
	}
	return c, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// THE MANIFEST ON THE DESTINATION
//
// internal/manifest's format, parsed by a second implementation on purpose. The
// installer verifies against the manifest it holds in memory; this is the file
// it leaves behind, and the file the Linux-side restore will re-check every hash
// against. If those two ever differ, the run verified something other than what
// it is going to rely on, and that difference is only visible from out here.
// ─────────────────────────────────────────────────────────────────────────────

// ManifestEntry is one line of the installer's manifest.tsv.
type ManifestEntry struct {
	SHA256 string
	Size   int64
	MTime  int64
	Path   string
	Stored string
}

// ManifestFile is the parsed result plus the integrity of the file itself.
type ManifestFile struct {
	Path        string `json:"path"`
	Exists      bool   `json:"exists"`
	Parses      bool   `json:"parses"`
	ParseError  string `json:"parse_error,omitempty"`
	Count       int    `json:"count"`
	TotalBytes  int64  `json:"total_bytes"`
	BodyDigest  string `json:"body_digest,omitempty"`
	TrailerOK   bool   `json:"trailer_ok"`
	FileSHA256  string `json:"file_sha256,omitempty"`
	entriesByRel map[string]ManifestEntry
}

// Entry looks a stored path up.
func (m *ManifestFile) Entry(stored string) (ManifestEntry, bool) {
	e, ok := m.entriesByRel[stored]
	return e, ok
}

// ReadInstallerManifest parses <dest>/_auros/manifest.tsv without using any of
// the installer's code.
func ReadInstallerManifest(destRoot string) (*ManifestFile, error) {
	p := filepath.Join(destRoot, MetaDirName, "manifest.tsv")
	out := &ManifestFile{Path: p, entriesByRel: map[string]ManifestEntry{}}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	out.Exists = true
	sum := sha256.Sum256(b)
	out.FileSHA256 = hex.EncodeToString(sum[:])

	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || lines[0] != "auros-manifest/1" {
		out.ParseError = "bad or missing header"
		return out, nil
	}
	// The trailer is "end\t<count>\t<bytes>\t<sha256 of everything above it>".
	var body strings.Builder
	body.WriteString(lines[0])
	body.WriteString("\n")
	var trailer string
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			if i == len(lines)-1 {
				break // the file ends with a newline, as it must
			}
			out.ParseError = fmt.Sprintf("empty line %d", i+1)
			return out, nil
		}
		if strings.ContainsRune(line, '\r') {
			out.ParseError = "CR in the manifest: the file has been through a text-mode round trip"
			return out, nil
		}
		if strings.HasPrefix(line, "end\t") {
			trailer = line
			if i != len(lines)-2 {
				out.ParseError = "content after the trailer"
				return out, nil
			}
			break
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 {
			out.ParseError = fmt.Sprintf("line %d has %d fields, want 5", i+1, len(f))
			return out, nil
		}
		size, serr := strconv.ParseInt(f[1], 10, 64)
		mt, merr := strconv.ParseInt(f[2], 10, 64)
		if serr != nil || merr != nil {
			out.ParseError = fmt.Sprintf("line %d: unparsable size or mtime", i+1)
			return out, nil
		}
		e := ManifestEntry{SHA256: f[0], Size: size, MTime: mt, Path: f[3], Stored: f[4]}
		out.entriesByRel[e.Stored] = e
		out.Count++
		out.TotalBytes += size
		body.WriteString(line)
		body.WriteString("\n")
	}
	if trailer == "" {
		out.ParseError = "truncated: the trailer line is missing"
		return out, nil
	}
	tf := strings.Split(strings.TrimPrefix(trailer, "end\t"), "\t")
	if len(tf) != 3 {
		out.ParseError = "trailer does not have three fields"
		return out, nil
	}
	count, cerr := strconv.Atoi(tf[0])
	total, terr := strconv.ParseInt(tf[1], 10, 64)
	if cerr != nil || terr != nil {
		out.ParseError = "unparsable trailer"
		return out, nil
	}
	bodySum := sha256.Sum256([]byte(body.String()))
	out.BodyDigest = hex.EncodeToString(bodySum[:])
	out.TrailerOK = count == out.Count && total == out.TotalBytes && out.BodyDigest == tf[2]
	out.Parses = out.TrailerOK
	if !out.TrailerOK {
		out.ParseError = fmt.Sprintf("trailer disagrees with the body: claims %d files / %d bytes / %s, "+
			"body has %d / %d / %s", count, total, tf[2], out.Count, out.TotalBytes, out.BodyDigest)
	}
	return out, nil
}

// QuarantineReport is the installer's own list of files it could not handle.
type QuarantineReport struct {
	Exists bool     `json:"exists"`
	Lines  int      `json:"lines"`
	Head   []string `json:"head,omitempty"`
}

// ReadQuarantineReport reads <dest>/_auros/quarantine.txt.
func ReadQuarantineReport(destRoot string) *QuarantineReport {
	p := filepath.Join(destRoot, MetaDirName, "quarantine.txt")
	out := &QuarantineReport{}
	b, err := os.ReadFile(p)
	if err != nil {
		return out
	}
	out.Exists = true
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		out.Lines++
		if len(out.Head) < 20 {
			out.Head = append(out.Head, line)
		}
	}
	return out
}

// InventoryLines are the "  Documents        C:\...\Documents" lines the
// installer prints in phase 1. They are the installer's account of WHERE it
// looked, and the harness checks them because the whole known-folder
// arrangement fails silently otherwise: an installer that resolved
// %USERPROFILE%\Documents instead of asking Windows would find an empty folder,
// copy nothing from it, and be indistinguishable from one that had nothing to
// copy.
func InventoryLines(stdout string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "   ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		label := fields[0]
		rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), label))
		if len(rest) < 3 || rest[1] != ':' {
			continue
		}
		known := false
		for _, kf := range knownFolderRoots {
			if kf.Label == label {
				known = true
				break
			}
		}
		if known {
			out[label] = rest
		}
	}
	return out
}

// walkCount is a cheap file count, for the summary lines.
func walkCount(root string) int {
	n := 0
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}
