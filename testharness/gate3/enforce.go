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
//  1. Before each run the migration account is DENIED every write-class right
//     on C:\, inherited by everything under it, except its own profile
//     directory. Windows now refuses the installer any write there.
//  2. The ETW trace across the run is read for the installer's process tree.
//     C1 fails on any write-class operation on C: outside the exemptions, on
//     any open the deny refused (STATUS_ACCESS_DENIED), and whenever the ACE
//     could not be applied, verified or removed.
//
// The change-journal diff survives only as a report line; it never gates.
// ─────────────────────────────────────────────────────────────────────────────

// The denied rights, by their access-mask names. File-specific rights from
// "File Access Rights Constants" (learn.microsoft.com/windows/win32/fileio/
// file-access-rights-constants), DELETE from "Standard Access Rights"
// (learn.microsoft.com/windows/win32/secauthz/standard-access-rights); values
// from winnt.h. On a directory WRITE_DATA is FILE_ADD_FILE and APPEND_DATA is
// FILE_ADD_SUBDIRECTORY. WRITE_DAC and WRITE_OWNER are not write-class data
// rights and are not denied; the trace still sees any write they would enable.
const (
	fileWriteData       = 0x00000002 // FILE_WRITE_DATA / FILE_ADD_FILE
	fileAppendData      = 0x00000004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
	fileWriteEA         = 0x00000010 // FILE_WRITE_EA
	fileDeleteChild     = 0x00000040 // FILE_DELETE_CHILD
	fileWriteAttributes = 0x00000100 // FILE_WRITE_ATTRIBUTES
	accessDelete        = 0x00010000 // DELETE

	// DenyMask is the ACE's ACCESS_MASK: 0x00010156.
	DenyMask uint32 = fileWriteData | fileAppendData | fileWriteEA | fileDeleteChild | fileWriteAttributes | accessDelete

	// DenyInherit is OBJECT_INHERIT_ACE (0x1) | CONTAINER_INHERIT_ACE (0x2)
	// (learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header): files
	// and directories below C:\ inherit it, and it applies to C:\ itself.
	DenyInherit byte = 0x1 | 0x2

	// DenyIcacls is the same ACE in icacls' vocabulary (learn.microsoft.com/
	// windows-server/administration/windows-commands/icacls): WD write data/add
	// file, AD append data/add subdirectory, WA write attributes, WEA write
	// extended attributes, D delete, DC delete child; (OI)(CI) as above.
	DenyIcacls = "(OI)(CI)(WD,AD,WA,WEA,D,DC)"
)

// DenyMaskNames is DenyMask spelled out, for the result.
var DenyMaskNames = []string{"FILE_WRITE_DATA", "FILE_APPEND_DATA", "FILE_WRITE_ATTRIBUTES",
	"FILE_WRITE_EA", "DELETE", "FILE_DELETE_CHILD"}

// Enforcement is the deny ACE, as applied, read back and removed.
type Enforcement struct {
	Path        string   `json:"path"`
	Trustee     string   `json:"trustee"`
	SID         string   `json:"sid"`
	Command     string   `json:"command"`
	ACE         string   `json:"ace_read_back"` // SDDL form of the ACE found on Path after applying
	Mask        uint32   `json:"access_mask"`
	MaskNames   []string `json:"access_mask_names"`
	Inheritance string   `json:"inheritance"`
	Exemptions  []string `json:"exemptions"`
	ExemptWhy   string   `json:"exemptions_why"`
	Probes      []string `json:"probes,omitempty"`
	ApplySec    float64  `json:"apply_seconds"`
	RemoveSec   float64  `json:"remove_seconds"`
	Applied     bool     `json:"applied"`
	Verified    bool     `json:"verified"`
	Removed     bool     `json:"removed"`
	Error       string   `json:"error,omitempty"`
	RemoveError string   `json:"remove_error,omitempty"`
}

// Why says why the enforcement cannot vouch for a run; "" when it can.
func (e *Enforcement) Why() string {
	switch {
	case e == nil:
		return "no deny ACE was applied to C:, so nothing stopped the installer writing there"
	case e.Error != "":
		return "the deny ACE could not be applied or verified: " + e.Error
	case !e.Applied || !e.Verified:
		return "the deny ACE was never verified on " + e.Path
	case e.RemoveError != "":
		return "the deny ACE could not be removed after the run: " + e.RemoveError
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
		return false, fmt.Sprintf("the installer tree TRIED to write to C: and the deny ACE refused it: "+
			"%d attempt(s), first: %s", len(w.Denied), w.Denied[0])
	case len(w.Writes) > 0:
		return false, fmt.Sprintf("the installer tree performed %d write-class operation(s) on C: outside "+
			"the exemptions, first: %s", len(w.Writes), w.Writes[0])
	}
	return true, fmt.Sprintf("deny ACE %s held on %s for the whole run; %d file events from the installer "+
		"tree traced, no write-class operation and no refused attempt on C: outside %s (%d inside it)",
		e.ACE, e.Path, w.Events, strings.Join(e.Exemptions, ", "), len(w.Exempt))
}
