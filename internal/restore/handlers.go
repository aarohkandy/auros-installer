package restore

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/netprofile"
	"github.com/aarohkandy/auros-installer/internal/printers"
)

// WiFiHandler turns the archive's exported wireless profiles into
// NetworkManager connections.
type WiFiHandler struct {
	// StagingDir is where connections go when we are not root.
	StagingDir string
	// AsRoot is os.Geteuid() == 0, passed in so a test can drive both paths.
	AsRoot bool
	// SystemDirFor may be nil; it exists so a test can point the "system"
	// directory somewhere writable instead of /etc.
	SystemDirFor func(asRoot bool, staging string) (dir string, installed bool, why string)
	// MaxBytes refuses a profile file that is implausibly large for one.
	MaxBytes int64
}

const defaultProfileMaxBytes = 1 << 20 // 1 MiB: a wireless profile is ~2 KB

// Handle implements Handler.
func (h *WiFiHandler) Handle(_ context.Context, items []*Item) (*HandlerReport, error) {
	rep := &HandlerReport{Title: "Wi-Fi networks"}
	if len(items) == 0 {
		return rep, nil
	}
	maxBytes := h.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultProfileMaxBytes
	}
	resolve := h.SystemDirFor
	if resolve == nil {
		resolve = netprofile.ResolveSystemDir
	}
	dir, installed, why := resolve(h.AsRoot, h.StagingDir)

	var profiles []*netprofile.Profile
	for _, it := range items {
		// Only the XML exports are profiles. Anything else under the label is
		// reported, not parsed: a silent skip here is a network the user thinks
		// came across and did not.
		base := filepath.Base(it.Entry.Path)
		if !strings.EqualFold(filepath.Ext(base), ".xml") {
			rep.Skipped++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s not a wireless profile, left alone", base))
			continue
		}
		if it.Entry.Size > maxBytes {
			rep.Skipped++
			rep.Problems = append(rep.Problems, fmt.Sprintf(
				"%s is %d bytes, which is far too big for a wireless profile; it was not read",
				base, it.Entry.Size))
			continue
		}
		b, err := os.ReadFile(it.Source)
		if err != nil {
			rep.Skipped++
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s could not be read: %v", base, err))
			continue
		}
		p, err := netprofile.Parse(b)
		if err != nil {
			rep.Skipped++
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s is not a wireless profile this can read: %v", base, err))
			continue
		}
		profiles = append(profiles, p)
	}

	written, err := netprofile.Write(dir, profiles, h.AsRoot && installed)
	if err != nil {
		rep.Problems = append(rep.Problems, err.Error())
		return rep, nil
	}
	for _, w := range written {
		switch {
		case w.Problem != "":
			rep.Skipped++
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %s", w.Profile.SSID, w.Problem))
		case w.Verdict == netprofile.VerdictWrite:
			rep.Done++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s ready — %s", w.Profile.SSID, w.Why))
		default:
			rep.Skipped++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s NOT added — %s", w.Profile.SSID, w.Why))
		}
	}
	rep.Lines = append(rep.Lines, "")
	rep.Lines = append(rep.Lines, "Where they went: "+why)
	if !installed && rep.Done > 0 {
		// Said as a fact about this machine rather than as an apology. A user
		// who is told "Wi-Fi migrated" and then cannot connect has been lied
		// to; a user who is told it takes a restart has been told the truth.
		rep.Lines = append(rep.Lines,
			"These are not switched on yet: putting a Wi-Fi password where NetworkManager reads it "+
				"needs administrator rights, which this step does not have. They are saved and ready.")
	}
	if installed && rep.Done > 0 {
		rep.Lines = append(rep.Lines,
			"NetworkManager reads these when it starts, so they are available after the next restart.")
	}
	return rep, nil
}

// PrinterHandler classifies the Windows printer inventory.
type PrinterHandler struct {
	// PlanPath is where the staged plan is written. Empty means no plan file
	// is written and the decisions are reported only.
	PlanPath string
}

// Handle implements Handler.
func (h *PrinterHandler) Handle(_ context.Context, items []*Item) (*HandlerReport, error) {
	rep := &HandlerReport{Title: "Printers"}
	if len(items) == 0 {
		return rep, nil
	}
	var all []printers.Printer
	for _, it := range items {
		base := filepath.Base(it.Entry.Path)
		if base != printers.FileName {
			rep.Skipped++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s not the printer list, left alone", base))
			continue
		}
		b, err := os.ReadFile(it.Source)
		if err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s could not be read: %v", base, err))
			continue
		}
		ps, err := printers.Parse(b)
		if err != nil {
			rep.Problems = append(rep.Problems, fmt.Sprintf("%s: %v", base, err))
			continue
		}
		all = append(all, ps...)
	}
	if len(all) == 0 && len(rep.Problems) == 0 {
		rep.Lines = append(rep.Lines, "the old computer had no printers set up.")
		return rep, nil
	}

	decisions := make([]printers.Decision, 0, len(all))
	for _, p := range all {
		decisions = append(decisions, printers.Decide(p))
	}
	sort.Slice(decisions, func(i, j int) bool { return decisions[i].Printer.Name < decisions[j].Printer.Name })

	var ready int
	for _, d := range decisions {
		switch d.Disp {
		case printers.DispNetworkQueue:
			ready++
			rep.Done++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s %s", d.Printer.Name, d.Note))
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s   queue %q at %s", "", d.QueueName, d.DeviceURI))
		default:
			rep.Skipped++
			rep.Lines = append(rep.Lines, fmt.Sprintf("%-28s %s", d.Printer.Name, d.Note))
		}
	}

	if h.PlanPath != "" && ready > 0 {
		if err := os.MkdirAll(filepath.Dir(h.PlanPath), 0o700); err != nil {
			rep.Problems = append(rep.Problems, "could not save the printer plan: "+err.Error())
		} else if err := os.WriteFile(h.PlanPath, []byte(printers.RenderPlan(decisions)), 0o600); err != nil {
			rep.Problems = append(rep.Problems, "could not save the printer plan: "+err.Error())
		}
	}
	rep.Lines = append(rep.Lines, "")
	if ready > 0 {
		// The honest sentence. Nothing in this program adds a CUPS queue,
		// because adding one needs administrator rights, and a report that
		// said "printers migrated" would be false in the way SPEC §4.2
		// forbids.
		rep.Lines = append(rep.Lines, fmt.Sprintf(
			"%d printer(s) can be added automatically, and this step has written down exactly how. "+
				"Nothing has been added yet — that needs administrator rights. You can also add any "+
				"of them yourself in Print Settings.", ready))
		if h.PlanPath != "" {
			rep.Lines = append(rep.Lines, "The details are in "+h.PlanPath)
		}
	} else {
		rep.Lines = append(rep.Lines,
			"None of the old printers could be set up from the backup alone. Each one is listed above "+
				"with the reason.")
	}
	return rep, nil
}
