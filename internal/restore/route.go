package restore

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/labels"
)

// Disposition is what the plan decided to do with one manifest entry. There is
// no "ignore": every entry gets one of these and every one of them appears in
// the report.
type Disposition string

const (
	// DispFile means: write these bytes to a path in the home directory.
	DispFile Disposition = "file"
	// DispWiFi means: this is an exported wireless profile, handed to
	// internal/netprofile rather than copied.
	DispWiFi Disposition = "wifi-profile"
	// DispPrinters means: this is the printer inventory, handed to
	// internal/printers rather than copied.
	DispPrinters Disposition = "printer-inventory"
	// DispWithheld means: we are deliberately NOT restoring this, and the
	// reason is a product decision the user is told about. D15: Chrome and
	// Edge passwords, cookies and payment data do not migrate.
	DispWithheld Disposition = "withheld"
)

// Route is the decision for one entry.
type Route struct {
	Disposition Disposition
	// Target is the absolute destination path for DispFile.
	Target string
	// DirMode and FileMode are the permissions for created directories and
	// files. A browser profile is 0700/0600; a document is 0755/0644.
	DirMode  uint32
	FileMode uint32
	// Why is shown in the report for DispWithheld, and in the verbose listing
	// otherwise. It names the rule, not a vague category.
	Why string
	// Bucket groups entries in the report: "Documents", "Firefox", ...
	Bucket string
}

// Router maps a manifest entry's original path onto this machine.
type Router struct {
	L *Layout

	// override replaces the routing table. It is UNEXPORTED and exists for one
	// reason: BuildPlan's assertion that a target lands inside the home
	// directory was UNREACHABLE, because manifest.CleanRel rejects an escaping
	// path several lines earlier and the plan never got that far. A check that
	// cannot be reached cannot fail, and a check that cannot fail is not a
	// check — the prove-red harness found this by disabling the assertion and
	// watching the suite stay green.
	//
	// The assertion is worth keeping: it guards the OUTPUT of the routing
	// table rather than its input, so it survives someone adding a rule that
	// points somewhere new. This seam is how that future rule is simulated
	// today, so the guard is exercised rather than merely present.
	override func(logicalPath string) (Route, bool)
}

// browserKeep is the ALLOW-list of Chrome/Edge profile files that migrate.
//
// An allow-list, not a deny-list, and the direction is the whole point. D15
// says bookmarks and history migrate and that passwords, cookies and payment
// data do not. A deny-list means the next file Google adds to a profile
// migrates by default and somebody has to notice; an allow-list means it does
// not migrate until somebody decides it should. On this product the second
// failure mode is the survivable one.
//
// Matching is on the STEM: "History", "History-journal", "History-wal" and
// "History-shm" share the stem "History". The sidecars travel with their
// database or the database is unreadable.
var browserKeep = map[string]string{
	"Bookmarks": "your bookmarks",
	"History":   "your browsing history",
	"Favicons":  "the site icons your history displays",
}

// browserSidecars are the SQLite companions permitted alongside a kept stem.
var browserSidecars = []string{"", ".bak", "-journal", "-wal", "-shm"}

// Route decides what happens to one entry. logicalPath is manifest.Entry.Path:
// "<Label>/<path as it was on Windows>", already cleaned by CleanRel at copy
// time and re-validated by the caller before this is called.
func (r *Router) Route(logicalPath string) (Route, error) {
	if r.override != nil {
		if rt, ok := r.override(logicalPath); ok {
			return rt, nil
		}
	}
	label, rest, ok := strings.Cut(logicalPath, "/")
	if !ok || rest == "" {
		return Route{}, fmt.Errorf("restore: %q has no path under its label", logicalPath)
	}

	// Browser profiles are not labels. The Windows half copies known folders,
	// and a profile travels INSIDE the AppData ones, so it is recognised by
	// where the browser keeps it — before the label switch, or it falls
	// through to "Restored from Windows" with its passwords (§2.7).
	if browser, rest, ok := browserProfile(logicalPath); ok {
		return r.routeBrowser(browser, rest), nil
	}

	switch label {
	case labels.Desktop, labels.Documents, labels.Downloads, labels.Music, labels.Pictures, labels.Videos:
		key := "XDG_" + strings.ToUpper(label) + "_DIR"
		if label == labels.Downloads {
			key = "XDG_DOWNLOAD_DIR" // singular, per the xdg-user-dirs spec
		}
		dir, src := r.L.Dir(key)
		if dir == "" {
			return Route{}, fmt.Errorf("restore: no directory resolved for %s (%s)", key, src)
		}
		return Route{
			Disposition: DispFile,
			Target:      filepath.Join(dir, filepath.FromSlash(rest)),
			DirMode:     0o755, FileMode: 0o644,
			Why:    key + " = " + dir + " (" + src + ")",
			Bucket: label,
		}, nil

	case labels.WiFi:
		return Route{Disposition: DispWiFi, Why: "exported wireless profile", Bucket: "Wi-Fi"}, nil

	case labels.Printers:
		return Route{Disposition: DispPrinters, Why: "printer inventory", Bucket: "Printers"}, nil

	default:
		// An unfamiliar label is NOT dropped and is NOT guessed into a system
		// location. It lands in one visible folder with its label intact, so
		// the user can see exactly what arrived and move it themselves.
		return Route{
			Disposition: DispFile,
			Target: filepath.Join(r.L.Home, FallbackDirName, filepath.FromSlash(label),
				filepath.FromSlash(rest)),
			DirMode: 0o755, FileMode: 0o644,
			Why:    fmt.Sprintf("no rule for the label %q; kept together rather than guessed at", label),
			Bucket: "Other (" + label + ")",
		}, nil
	}
}

// browserRoots are where each browser keeps its profiles inside the AppData
// labels. Matched case-insensitively, because Windows paths are: a folder
// spelled "user data" is the same folder, and missing it would restore the
// password database as an ordinary file.
var browserRoots = []struct{ prefix, name string }{
	{labels.ChromeUserData, "Chrome"},
	{labels.EdgeUserData, "Edge"},
	{labels.FirefoxRoot, "Firefox"},
}

// browserProfile reports which browser's profile tree logicalPath is in, and
// its path relative to that browser's root.
func browserProfile(logicalPath string) (browser, rest string, ok bool) {
	for _, b := range browserRoots {
		n := len(b.prefix)
		if len(logicalPath) > n+1 && logicalPath[n] == '/' && strings.EqualFold(logicalPath[:n], b.prefix) {
			return b.name, logicalPath[n+1:], true
		}
	}
	return "", "", false
}

// routeBrowser places one file of a browser profile. rest is relative to the
// browser's root: "Default/Bookmarks" for Chrome and Edge ("User Data" on
// Windows is ~/.config/google-chrome on Linux), "Profiles/x/places.sqlite" or
// "profiles.ini" for Firefox.
func (r *Router) routeBrowser(label, rest string) Route {
	if label == "Firefox" {
		// Firefox's own profiles.ini uses forward-slash relative paths with
		// IsRelative=1, so the Windows tree ("Profiles/xxxx.default-release")
		// is valid unchanged under ~/.mozilla/firefox. 0700: a Firefox profile
		// holds saved sessions and history.
		return Route{
			Disposition: DispFile,
			Target:      filepath.Join(r.L.Home, ".mozilla", "firefox", filepath.FromSlash(rest)),
			DirMode:     0o700, FileMode: 0o600,
			Why:    "Firefox profiles live in ~/.mozilla/firefox on Linux",
			Bucket: "Firefox",
		}
	}
	dir := ".config/google-chrome"
	if label == "Edge" {
		dir = ".config/microsoft-edge"
	}
	base := filepath.Base(rest)
	keep, why := browserAllowed(base)
	if !keep {
		return Route{
			Disposition: DispWithheld,
			Why: "D15: " + label + " passwords, cookies and payment data are sealed by " +
				"App-Bound Encryption and cannot be moved to another machine. " +
				"Only bookmarks and history come across. This file is not one of them.",
			Bucket: label,
		}
	}
	return Route{
		Disposition: DispFile,
		Target:      filepath.Join(r.L.Home, filepath.FromSlash(dir), filepath.FromSlash(rest)),
		DirMode:     0o700, FileMode: 0o600,
		Why:    why,
		Bucket: label,
	}
}

// FallbackDirName is where an unrecognised label lands. Spelled in words a
// non-engineer reads, per the product directive: this folder appears on a
// stranger's desktop machine and has to explain itself.
const FallbackDirName = "Restored from Windows"

// browserAllowed reports whether a Chrome/Edge profile file migrates, and why.
func browserAllowed(base string) (bool, string) {
	for stem, why := range browserKeep {
		for _, suffix := range browserSidecars {
			if base == stem+suffix {
				if suffix == "" {
					return true, why
				}
				return true, why + " (" + suffix + " belongs to it)"
			}
		}
	}
	return false, ""
}
