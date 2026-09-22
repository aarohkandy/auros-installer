package gate3

import (
	"fmt"
	"sort"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// C1 BY ENFORCEMENT (owner decision 2026-09-21, amending D27)
//
// "The installer writes nothing to the system disk" is not proved by diffing C:
// before and after: Windows' own servicing writes C: on a shared runner whatever
// the installer does, so the diff never converged. It is proved the other way
// round, and every step below was chosen by measurement on a runner:
//
//  1. The installer runs on a STANDARD user's token: the migration account is
//     not an administrator, and the token is checked (not elevated, no enabled
//     Administrators group) before anything else. A deny ACE inherited from C:\
//     took 282 s and never reached protected DACLs (run 35656850124); Low
//     integrity blocked C: but also refused every file create on the NTFS
//     destination (run 35667867089). A standard token is refused most of C: by
//     its ordinary DACLs already.
//  2. The rest is enumerated, not remembered: every directory on C: is checked
//     with the account's own token (an open for MAXIMUM_ALLOWED, whose granted
//     mask is read back), and each directory where it holds any write-class
//     right gets an explicit, non-inheritable deny ACE for the account, set on
//     that directory alone (SetKernelObjectSecurity does not propagate). The
//     list, its roots and the time it took are in the result. The ACEs are
//     removed after the run by restoring each directory's saved descriptor.
//  3. Before the run the deny is proved: the granted mask is re-read for every
//     denied directory, a real create (directory and file) is attempted as the
//     account at a sample of them and must be refused, and the installer's own
//     write patterns on the destination must succeed.
//  4. The ETW trace across the run is read for the installer's process tree. C1
//     fails on any write-class operation on C:, on any open Windows refused
//     (STATUS_ACCESS_DENIED: the installer TRIED), and whenever the enforcement
//     could not be applied or verified.
//
// The change-journal diff survives only as a report line; it never gates.
// ─────────────────────────────────────────────────────────────────────────────

// LowIntegritySID is the Low mandatory level (learn.microsoft.com/windows/win32/
// secauthz/well-known-sids: SECURITY_MANDATORY_LOW_RID 0x1000). Only prove-red,
// which exercises C1's classification, still uses it.
const LowIntegritySID = "S-1-16-4096"

// DenyMask is every right that changes a directory or what is in it
// (learn.microsoft.com/windows/win32/fileio/file-access-rights-constants and
// .../secauthz/standard-access-rights): FILE_ADD_FILE 0x2, FILE_ADD_SUBDIRECTORY
// 0x4, FILE_WRITE_EA 0x10, FILE_DELETE_CHILD 0x40, FILE_WRITE_ATTRIBUTES 0x100,
// DELETE 0x10000, WRITE_DAC 0x40000, WRITE_OWNER 0x80000.
const DenyMask uint32 = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000

// OwnerImplicit is WRITE_DAC: an object's owner is granted it whatever the DACL
// says, unless an OWNER RIGHTS (S-1-3-4) ACE is present (learn.microsoft.com/
// windows/win32/secauthz/sid-strings, "Owner Rights"), so a deny cannot remove
// it from a directory the account owns. Verification does not demand it.
// ponytail: an installer that rewrote a DACL it owns could then write; the ETW
// audit still fails the write itself.
const OwnerImplicit uint32 = 0x40000

var rightNames = []struct {
	bit  uint32
	name string
}{{0x2, "add-file"}, {0x4, "add-subdirectory"}, {0x10, "write-ea"}, {0x40, "delete-child"},
	{0x100, "write-attributes"}, {0x10000, "delete"}, {0x40000, "write-dac"}, {0x80000, "write-owner"}}

// WriteRights names the write-class rights in granted.
func WriteRights(granted uint32) []string {
	var out []string
	for _, r := range rightNames {
		if granted&r.bit != 0 {
			out = append(out, r.name)
		}
	}
	return out
}

// DenySDDL returns sddl (a DACL-only SDDL string) with an explicit,
// non-inheritable deny ACE for sid placed first, the canonical position for an
// explicit deny. The DACL's flags (P, AI, AR) and every existing ACE, inherited
// ones included, are kept verbatim. A NULL DACL (NO_ACCESS_CONTROL) or a string
// without a DACL is refused: prepending to it would REMOVE everyone's access.
func DenySDDL(sddl, sid string) (string, error) {
	i := strings.Index(sddl, "D:")
	if i < 0 {
		return "", fmt.Errorf("no DACL in %q", sddl)
	}
	j := i + 2
	for j < len(sddl) && sddl[j] != '(' && sddl[j] != 'S' {
		j++
	}
	flags := sddl[i+2 : j]
	if strings.HasPrefix(sddl[i+2:], "NO_ACCESS_CONTROL") {
		return "", fmt.Errorf("a NULL DACL (%q) cannot take a deny ACE without losing every grant", sddl)
	}
	if strings.Trim(flags, "PAIR") != "" {
		return "", fmt.Errorf("unexpected DACL flags %q in %q", flags, sddl)
	}
	return sddl[:j] + fmt.Sprintf("(D;;0x%x;;;%s)", DenyMask, sid) + sddl[j:], nil
}

// WritableRoots reduces a list of directories to those whose parent is not in
// it, each with how many listed directories lie under it: the shape of what
// the account could write, in a result a human can read.
func WritableRoots(dirs []string) []string {
	in := map[string]bool{}
	for _, d := range dirs {
		in[strings.ToLower(strings.TrimRight(d, `\`))] = true
	}
	count := map[string]int{}
	var roots []string
	for _, d := range dirs {
		k := strings.ToLower(strings.TrimRight(d, `\`))
		root := k
		for p := parentDir(k); p != ""; p = parentDir(p) {
			if in[p] {
				root = p
			}
		}
		if root == k {
			roots = append(roots, d)
		}
		count[root]++
	}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		out = append(out, fmt.Sprintf("%s (%d)", r, count[strings.ToLower(strings.TrimRight(r, `\`))]))
	}
	return capList(out, 200)
}

func parentDir(p string) string {
	i := strings.LastIndex(p, `\`)
	if i <= 2 { // C:\x's parent is C:, which is listed as "c:"
		if len(p) > 2 && i == 2 {
			return p[:2]
		}
		return ""
	}
	return p[:i]
}

// Enforcement is how the installer was kept off C:, as applied and proved.
type Enforcement struct {
	Mechanism string `json:"mechanism"`
	// Token is what the installer ran as, as read back from the token itself.
	Token string `json:"installer_token"`
	// Scanned directories on C:, the Writable ones (the account held a
	// write-class right), and WritableRoots, their tops with a count each.
	Scanned       int      `json:"scanned_dirs"`
	Writable      []string `json:"writable_dirs"`
	WritableRoots []string `json:"writable_roots"`
	// Unlisted are directories the harness could not list, so their children
	// were not checked; the ETW audit still covers them.
	Unlisted    []string `json:"unlisted_dirs,omitempty"`
	ScanSeconds float64  `json:"scan_seconds"`
	DenyMask    string   `json:"deny_mask"`
	Exemptions  []string `json:"exemptions"`
	ExemptWhy   string   `json:"exemptions_why"`
	Probes      []string `json:"probes,omitempty"`
	Diagnostics []string `json:"diagnostics,omitempty"`
	Verified    bool     `json:"verified"`
	Error       string   `json:"error,omitempty"`
	// Restored says whether every deny ACE was taken off again after the run.
	Restored string `json:"restored,omitempty"`
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
	ex := "no exemptions"
	if len(e.Exemptions) > 0 {
		ex = "outside " + strings.Join(e.Exemptions, ", ")
	}
	return true, fmt.Sprintf("the installer tree ran as %s (%s); %d of its file events traced, no "+
		"write-class operation and no refused attempt on C: (%s; %d inside them)",
		e.Token, e.Mechanism, w.Events, ex, len(w.Exempt))
}
