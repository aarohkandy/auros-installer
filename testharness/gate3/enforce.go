package gate3

import (
	"fmt"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// C1 BY ENFORCEMENT (owner decision 2026-09-21, amending D27)
//
// "The installer writes nothing to the system disk" is no longer proved by
// diffing C: before and after: Windows' own servicing (Store, Security updates,
// the Entra broker) writes C: on a shared runner whatever the installer does,
// so the diff never converged. It is proved the other way round:
//
//  1. The installer's process tree runs at LOW mandatory integrity. Windows
//     treats an object with no integrity label as Medium, and the default
//     policy is NO_WRITE_UP: a Low process is refused write access to it before
//     its DACL is even consulted (learn.microsoft.com/windows/win32/secauthz/
//     mandatory-integrity-control). Nothing is written to C:'s ACLs, so there is
//     no propagation and no protected DACL (C:\ProgramData, C:\Windows, …) to
//     escape it — the first design, a deny ACE on C:\, measured 282 s to apply
//     and never reached C:\ProgramData (run 35656850124). Reading is untouched:
//     NO_READ_UP is not the default for files. Only the harness's own
//     destination volumes and work directory are labelled Low, so the installer
//     can write there and nowhere else it was not already allowed to.
//  2. The ETW trace across the run is read for the installer's process tree.
//     C1 fails on any write-class operation on C: outside the exemptions — which
//     is how a write to something Windows itself labels Low (LocalLow) is still
//     caught — on any open refused with STATUS_ACCESS_DENIED, and whenever the
//     enforcement could not be applied or verified.
//
// The change-journal diff survives only as a report line; it never gates.
// ─────────────────────────────────────────────────────────────────────────────

// LowIntegritySID is the Low mandatory level (learn.microsoft.com/windows/win32/
// secauthz/well-known-sids: SECURITY_MANDATORY_LOW_RID 0x1000).
const LowIntegritySID = "S-1-16-4096"

// Enforcement is how the installer was kept off C:, as applied and proved.
type Enforcement struct {
	Mechanism  string   `json:"mechanism"`
	Integrity  string   `json:"installer_integrity_sid"`
	Policy     string   `json:"policy"`
	LabeledLow []string `json:"labelled_low"` // (OI)(CI) Low labels the harness set, off C:
	Exemptions []string `json:"exemptions"`
	ExemptWhy  string   `json:"exemptions_why"`
	Probes     []string `json:"probes,omitempty"`
	Verified   bool     `json:"verified"`
	Error      string   `json:"error,omitempty"`
}

// Why says why the enforcement cannot vouch for a run; "" when it can.
func (e *Enforcement) Why() string {
	switch {
	case e == nil:
		return "the installer was not run under any enforcement, so nothing stopped it writing to C:"
	case e.Error != "":
		return "the enforcement could not be applied or verified: " + e.Error
	case !e.Verified:
		return "the enforcement was never verified"
	}
	return ""
}

// WriteAudit is what the installer's process tree did to C:, from the trace.
type WriteAudit struct {
	Events int      `json:"installer_file_events"`
	Writes []string `json:"writes_outside_exemptions,omitempty"`
	Denied []string `json:"denied_attempts,omitempty"`
	Exempt []string `json:"writes_inside_exemptions,omitempty"`
	Error  string   `json:"error,omitempty"`
}

var opNames = map[int]string{12: "create", 16: "write", 17: "set-information", 18: "set-delete",
	19: "rename", 26: "delete-path", 27: "rename-path", 30: "create-new-file"}

// AuditWrites classifies the installer tree's write-class operations and
// denied opens on C: against the exemptions (C:\… directories). It is a pure
// function of the parsed trace. A write through a handle the trace never named
// cannot be placed on a volume, so it counts as a write to C: (fail closed); so
// does a Create whose CreateOptions are missing. A denied open counts whatever
// it asked for: the trace does not carry the access requested.
func (a *Attribution) AuditWrites(exempt []string) *WriteAudit {
	w := &WriteAudit{}
	if a.Err != "" {
		w.Error = a.Err
		return w
	}
	var ex []string
	for _, e := range exempt {
		p := strings.ToLower(strings.TrimRight(e, `\`))
		if len(p) >= 2 && p[1] == ':' && strings.EqualFold(p[:2], "c:") {
			ex = append(ex, a.device+p[2:])
		}
	}
	writes, denied, exempted := map[string]int{}, map[string]int{}, map[string]int{}
	for _, op := range a.ops {
		if !a.installer[op.pid] {
			continue
		}
		w.Events++
		if !op.write && !op.denied {
			continue
		}
		what := opNames[op.id]
		switch {
		case op.denied:
			what += " refused with STATUS_ACCESS_DENIED"
		case op.unknown:
			what += " whose CreateOptions the trace did not carry"
		}
		who := fmt.Sprintf("%s by %s(%d)", what, a.image(op.pid), op.pid)
		if op.path == "" {
			writes["«a file the trace never named» — "+who]++
			continue
		}
		if !strings.HasPrefix(op.path, a.device+`\`) {
			continue
		}
		line := "C:" + op.path[len(a.device):] + " — " + who
		switch {
		case under(op.path, ex):
			exempted[line]++
		case op.denied:
			denied[line]++
		default:
			writes[line]++
		}
	}
	w.Writes, w.Denied, w.Exempt = tally(writes), tally(denied), tally(exempted)
	return w
}

func under(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+`\`) {
			return true
		}
	}
	return false
}

func tally(m map[string]int) []string {
	var out []string
	for k, n := range m {
		if n > 1 {
			k = fmt.Sprintf("%s (x%d)", k, n)
		}
		out = append(out, k)
	}
	return capList(out, 50)
}

func capList(l []string, n int) []string {
	sort.Strings(l)
	if len(l) > n {
		l = append(l[:n:n], fmt.Sprintf("… and %d more", len(l)-n))
	}
	return l
}

// SystemDiskVerdict is C1.
func SystemDiskVerdict(e *Enforcement, w *WriteAudit) (bool, string) {
	if why := e.Why(); why != "" {
		return false, why
	}
	switch {
	case w == nil:
		return false, "the installer's file activity was never traced"
	case w.Error != "":
		return false, "the trace cannot vouch for the run: " + w.Error
	case len(w.Denied) > 0:
		return false, fmt.Sprintf("the installer tree TRIED to write to C: and Windows refused it: "+
			"%d attempt(s), first: %s", len(w.Denied), w.Denied[0])
	case len(w.Writes) > 0:
		return false, fmt.Sprintf("the installer tree performed %d write-class operation(s) on C: outside "+
			"the exemptions, first: %s", len(w.Writes), w.Writes[0])
	}
	return true, fmt.Sprintf("the installer tree ran at %s (%s); %d of its file events traced, no "+
		"write-class operation and no refused attempt on C: outside %s (%d inside it)",
		e.Integrity, e.Mechanism, w.Events, strings.Join(e.Exemptions, ", "), len(w.Exempt))
}
