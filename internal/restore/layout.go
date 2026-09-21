package restore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Layout answers "where on this machine does a file labelled X belong".
//
// Every answer is PROBED, never remembered. The XDG directories come from the
// user's own user-dirs.dirs — a Marathi-locale school laptop has
// XDG_DOCUMENTS_DIR="$HOME/दस्तऐवज", and a restore that wrote to ~/Documents
// would put every file in a folder the user's file manager does not show.
type Layout struct {
	Home string

	// dirs is the resolved XDG map, keyed by the spec's variable names.
	dirs map[string]string
	// source records where each answer came from, so the report can say
	// "Documents -> /home/u/Documenten (from ~/.config/user-dirs.dirs)".
	source map[string]string
}

// xdgKeys are the user-dirs variables this restore can target. The names are
// the xdg-user-dirs ones exactly, including the singular XDG_DOWNLOAD_DIR,
// which is the one everybody misremembers as DOWNLOADS.
var xdgKeys = []string{
	"XDG_DESKTOP_DIR",
	"XDG_DOCUMENTS_DIR",
	"XDG_DOWNLOAD_DIR",
	"XDG_MUSIC_DIR",
	"XDG_PICTURES_DIR",
	"XDG_VIDEOS_DIR",
}

// xdgDefaults are the fallbacks the spec gives when a key is absent.
var xdgDefaults = map[string]string{
	"XDG_DESKTOP_DIR":   "Desktop",
	"XDG_DOCUMENTS_DIR": "Documents",
	"XDG_DOWNLOAD_DIR":  "Downloads",
	"XDG_MUSIC_DIR":     "Music",
	"XDG_PICTURES_DIR":  "Pictures",
	"XDG_VIDEOS_DIR":    "Videos",
}

// ErrDirOutsideHome is returned when a configured user directory resolves
// outside the home directory. It is a refusal, not a warning: this program
// writes a stranger's files, and the only place it is willing to write them is
// inside the account it is running as.
var ErrDirOutsideHome = errors.New("restore: a configured user directory is outside the home directory")

// NewLayout resolves the layout for home. configHome is $XDG_CONFIG_HOME; empty
// means <home>/.config. env may be nil, in which case os.Getenv is used —
// tests pass their own so the environment of the machine running the test
// cannot change the answer.
func NewLayout(home, configHome string, env func(string) string) (*Layout, error) {
	if env == nil {
		env = os.Getenv
	}
	if home == "" {
		return nil, errors.New("restore: no home directory")
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return nil, fmt.Errorf("restore: resolving home %q: %w", home, err)
	}
	home = filepath.Clean(abs)
	if configHome == "" {
		if c := env("XDG_CONFIG_HOME"); c != "" {
			configHome = c
		} else {
			configHome = filepath.Join(home, ".config")
		}
	}

	l := &Layout{Home: home, dirs: map[string]string{}, source: map[string]string{}}

	fromFile, fileErr := readUserDirs(filepath.Join(configHome, "user-dirs.dirs"), home)
	for _, k := range xdgKeys {
		switch {
		case env(k) != "":
			l.dirs[k], l.source[k] = env(k), "environment "+k
		case fromFile[k] != "":
			l.dirs[k], l.source[k] = fromFile[k], filepath.Join(configHome, "user-dirs.dirs")
		default:
			l.dirs[k] = filepath.Join(home, xdgDefaults[k])
			if fileErr != nil {
				l.source[k] = "default (no user-dirs.dirs: " + fileErr.Error() + ")"
			} else {
				l.source[k] = "default (not set in user-dirs.dirs)"
			}
		}
	}

	// Refuse before planning, not during writing. A directory outside home is
	// either a misconfiguration or an attack, and either way this program is
	// the wrong thing to resolve it.
	var bad []string
	for _, k := range xdgKeys {
		p := filepath.Clean(l.dirs[k])
		l.dirs[k] = p
		if !underPath(p, home) {
			bad = append(bad, fmt.Sprintf("%s=%s (from %s)", k, p, l.source[k]))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return nil, fmt.Errorf("%w: home is %s, but %s", ErrDirOutsideHome, home, strings.Join(bad, "; "))
	}
	return l, nil
}

// Dir returns the resolved directory for an XDG key, and where the answer came
// from. An unknown key is a programming error and says so rather than
// returning a plausible-looking path.
func (l *Layout) Dir(key string) (string, string) {
	d, ok := l.dirs[key]
	if !ok {
		return "", "unknown key " + key
	}
	return d, l.source[key]
}

// readUserDirs parses ~/.config/user-dirs.dirs. The format is shell-ish but is
// NOT shell: xdg-user-dirs writes KEY="value" with $HOME as the only expansion,
// and reading it with a real shell would execute a stranger's file as root-ish
// code on first boot. So it is parsed as data.
func readUserDirs(path, home string) (map[string]string, error) {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		switch {
		case v == "$HOME" || v == "$HOME/":
			v = home
		case strings.HasPrefix(v, "$HOME/"):
			v = filepath.Join(home, v[len("$HOME/"):])
		case v == "":
			continue
		}
		out[k] = v
	}
	return out, nil
}

// underPath reports whether p is root or lies inside it, comparing whole
// segments so that /home/user2 is not treated as being inside /home/user.
func underPath(p, root string) bool {
	p, root = filepath.Clean(p), filepath.Clean(root)
	if p == root {
		return true
	}
	return strings.HasPrefix(p, strings.TrimSuffix(root, string(filepath.Separator))+string(filepath.Separator))
}
