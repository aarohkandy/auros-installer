package restore

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/manifest"
)

var (
	// ErrPathEscape means a manifest entry's destination would land outside the
	// home directory. It refuses the WHOLE run, before the first byte is
	// written, because an archive containing one such path is an archive we
	// cannot reason about and this program's only safe move is to stop.
	ErrPathEscape = errors.New("restore: an entry would be written outside the home directory")
	// ErrTargetCollision means two entries resolve to the same destination.
	ErrTargetCollision = errors.New("restore: two entries want the same destination path")
	// ErrPlanEmpty means the manifest has no entries. A restore of nothing is
	// not a successful restore; it is a sign that the wrong directory was
	// identified as an archive.
	ErrPlanEmpty = errors.New("restore: the manifest is empty")
)

// Item is one manifest entry with its decision attached.
type Item struct {
	Entry  manifest.Entry
	Route  Route
	Source string // absolute path of the file inside the archive
}

// Plan is every decision, made and validated before anything is written.
//
// Building a plan reads the manifest and the layout and NOTHING ELSE. It
// creates no directory, opens no file for writing and touches nothing. That is
// deliberate: the expensive validation — every path, every collision, every
// escape — happens while an abort is still just a process exit.
type Plan struct {
	Archive  *Archive
	Layout   *Layout
	Files    []*Item
	WiFi     []*Item
	Printers []*Item
	Withheld []*Item
}

// Count is the number of manifest entries the plan accounts for. It must equal
// the manifest's own count or the plan is not a plan.
func (p *Plan) Count() int {
	return len(p.Files) + len(p.WiFi) + len(p.Printers) + len(p.Withheld)
}

// BuildPlan maps every manifest entry onto this machine and validates the lot.
func BuildPlan(a *Archive, l *Layout) (*Plan, error) {
	return buildPlanWith(a, l, &Router{L: l})
}

// buildPlanWith is BuildPlan with the routing table supplied. Unexported: the
// only caller that passes anything but the real router is the test that proves
// the home-directory assertion can go red.
func buildPlanWith(a *Archive, l *Layout, r *Router) (*Plan, error) {
	if a == nil || a.Manifest == nil {
		return nil, errors.New("restore: no archive")
	}
	if l == nil {
		return nil, errors.New("restore: no layout")
	}
	entries := a.Manifest.Entries()
	if len(entries) == 0 {
		return nil, ErrPlanEmpty
	}

	if r == nil {
		r = &Router{L: l}
	}
	p := &Plan{Archive: a, Layout: l}
	targets := make(map[string]string, len(entries)) // target -> entry path
	var escapes []string

	for _, e := range entries {
		// Re-validate the path rather than trusting it. The manifest was
		// written by another program, on another machine, possibly years ago,
		// and the file it lives in has been carried around on a USB stick. The
		// digest says the bytes are the bytes that were written; it does not
		// say the program that wrote them had no bugs.
		clean, err := manifest.CleanRel(e.Path)
		if err != nil {
			escapes = append(escapes, fmt.Sprintf("%q: %v", e.Path, err))
			continue
		}
		if clean != e.Path {
			escapes = append(escapes, fmt.Sprintf("%q normalises to %q, so it is not the path it claims to be", e.Path, clean))
			continue
		}
		if _, err := manifest.CleanRel(e.Stored); err != nil {
			escapes = append(escapes, fmt.Sprintf("stored path %q: %v", e.Stored, err))
			continue
		}

		route, err := r.Route(e.Path)
		if err != nil {
			return nil, err
		}
		item := &Item{
			Entry:  e,
			Route:  route,
			Source: filepath.Join(a.Root, filepath.FromSlash(e.Stored)),
		}

		switch route.Disposition {
		case DispFile:
			target := filepath.Clean(route.Target)
			// The belt to CleanRel's braces. CleanRel already refuses "..",
			// but this asserts the RESULT rather than the input, which is the
			// assertion that survives someone changing the routing table.
			if !underPath(target, l.Home) {
				escapes = append(escapes, fmt.Sprintf("%q would be written to %s, which is not inside %s",
					e.Path, target, l.Home))
				continue
			}
			if prev, dup := targets[target]; dup {
				return nil, fmt.Errorf("%w: %s — wanted by both %q and %q",
					ErrTargetCollision, target, prev, e.Path)
			}
			targets[target] = e.Path
			item.Route.Target = target
			p.Files = append(p.Files, item)
		case DispWiFi:
			p.WiFi = append(p.WiFi, item)
		case DispPrinters:
			p.Printers = append(p.Printers, item)
		case DispWithheld:
			p.Withheld = append(p.Withheld, item)
		default:
			return nil, fmt.Errorf("restore: %q got an unknown disposition %q", e.Path, route.Disposition)
		}
	}

	if len(escapes) > 0 {
		sort.Strings(escapes)
		return nil, fmt.Errorf("%w — home is %s; refusing the whole restore:\n  %s",
			ErrPathEscape, l.Home, strings.Join(escapes, "\n  "))
	}
	if p.Count() != len(entries) {
		// Unreachable unless a case above forgets to file its item. Asserted
		// rather than assumed, because the number this program reports to the
		// user is the whole product and an entry that fell out of the plan
		// would make it a lie.
		return nil, fmt.Errorf("restore: internal error: planned %d of %d entries", p.Count(), len(entries))
	}
	return p, nil
}
