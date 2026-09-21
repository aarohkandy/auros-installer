// Package printers maps a Windows printer inventory onto CUPS, and is
// deliberately unambitious about it.
//
// SPEC §4.2 forbids claiming something migrates when it does not, and printers
// are where that temptation is strongest: it is easy to create a CUPS queue for
// every row in the inventory and report "5 printers migrated", and four of them
// will not print. A queue that exists and does not work is worse than no queue,
// because the user believes the problem is their document.
//
// So there are exactly four outcomes, and three of them are "no".
//
//	Network printer, reachable by name or address   → a real driverless queue
//	Shared on a Windows server (\\server\queue)     → named, NOT created
//	Plugged in by USB                               → named, NOT created
//	Print-to-PDF, XPS, Fax and friends              → named, not needed here
//
// A network queue is created as IPP Everywhere (driverless). The WINDOWS DRIVER
// DOES NOT COME ACROSS and cannot: it is a signed Windows binary. Driverless
// IPP is what most post-2010 network printers speak, and when a printer does
// not, the report says the model has to be picked in Print Settings rather than
// pretending the queue is finished.
//
// # This package creates nothing
//
// Adding a CUPS queue is a root action. auros-restore runs as the user. So this
// package decides and WRITES A PLAN; installing it is a privileged step, and
// until that step exists the report says in plain words that the printers were
// not added. It does not say "migrated".
package printers

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Disposition is what we decided about one printer.
type Disposition string

const (
	// DispNetworkQueue: a driverless IPP queue can honestly be described.
	DispNetworkQueue Disposition = "network printer"
	// DispWindowsShare: shared from a Windows machine. Needs a server that may
	// not exist any more and credentials that are not in the archive.
	DispWindowsShare Disposition = "shared from a Windows computer"
	// DispLocal: attached by USB or a parallel port.
	DispLocal Disposition = "plugged in with a cable"
	// DispVirtual: not a printer. Print to PDF, XPS, Fax.
	DispVirtual Disposition = "not a real printer"
	// DispUnknown: the port does not say enough to act on.
	DispUnknown Disposition = "could not tell"
)

// Printer is one row of the Windows inventory.
type Printer struct {
	Name     string
	Port     string
	Driver   string
	Default  bool
	Location string
	Comment  string
}

// Decision is a printer plus what happens to it.
type Decision struct {
	Printer   Printer
	Disp      Disposition
	DeviceURI string // non-empty ONLY for DispNetworkQueue
	QueueName string // the CUPS queue name, for DispNetworkQueue
	Note      string // shown to the user, in their words
}

// Header is the first line of the inventory file the Windows side writes.
const Header = "auros-printers/1"

// FileName is the inventory's name inside the archive's Printers label.
const FileName = "printers.tsv"

var (
	// ErrBadHeader means the file is not a printer inventory.
	ErrBadHeader = errors.New("printers: bad or missing header")
	// ErrCorrupt means the file is one, and is damaged.
	ErrCorrupt = errors.New("printers: corrupt inventory")
)

// columns is the exact column line, so a file written by a future version with
// a different shape is REFUSED rather than parsed into the wrong fields.
const columns = "name\tport\tdriver\tdefault\tlocation\tcomment"

// Parse reads the inventory. Like the manifest, it refuses CR: a file that has
// been through a Windows text editor no longer says what it said.
func Parse(b []byte) ([]Printer, error) {
	s := string(b)
	if strings.ContainsRune(s, '\r') {
		return nil, fmt.Errorf("%w: CR in the file (CRLF line endings)", ErrCorrupt)
	}
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if len(lines) == 0 || lines[0] != Header {
		got := ""
		if len(lines) > 0 {
			got = lines[0]
		}
		return nil, fmt.Errorf("%w: first line is %q, expected %q", ErrBadHeader, got, Header)
	}
	if len(lines) < 2 || lines[1] != columns {
		got := ""
		if len(lines) > 1 {
			got = lines[1]
		}
		return nil, fmt.Errorf("%w: column line is %q, expected %q", ErrCorrupt, got, columns)
	}
	var out []Printer
	for i, line := range lines[2:] {
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			return nil, fmt.Errorf("%w: line %d has %d fields, want 6", ErrCorrupt, i+3, len(f))
		}
		if f[3] != "0" && f[3] != "1" {
			return nil, fmt.Errorf("%w: line %d default column is %q, want 0 or 1", ErrCorrupt, i+3, f[3])
		}
		if strings.TrimSpace(f[0]) == "" {
			return nil, fmt.Errorf("%w: line %d has no printer name", ErrCorrupt, i+3)
		}
		out = append(out, Printer{
			Name: f[0], Port: f[1], Driver: f[2],
			Default: f[3] == "1", Location: f[4], Comment: f[5],
		})
	}
	if len(out) == 0 {
		// A valid file with no rows is a real answer — the machine had no
		// printers — and is not an error. The caller reports "none found".
		return nil, nil
	}
	return out, nil
}

// virtualMarkers are names and drivers that are not printers. Matched case
// insensitively on a substring, because the localised names vary
// ("Microsoft Drucken als PDF") while the English stem does not.
var virtualMarkers = []string{
	"print to pdf", "xps document writer", "onenote", "fax",
	"microsoft print", "pdfcreator", "cutepdf", "send to",
}

// virtualPorts are Windows ports that never correspond to hardware.
var virtualPorts = []string{"portprompt:", "shrfax:", "nul:", "file:", "xpsport:"}

// Decide classifies one printer. Every branch returns a Note in words a
// non-engineer can act on, because the report is read by the person whose
// printer it is.
func Decide(p Printer) Decision {
	d := Decision{Printer: p}
	lowName, lowDriver, lowPort := strings.ToLower(p.Name), strings.ToLower(p.Driver), strings.ToLower(strings.TrimSpace(p.Port))

	for _, m := range virtualPorts {
		if lowPort == m {
			d.Disp = DispVirtual
			d.Note = "this was not a real printer. This computer can already save anything as a PDF."
			return d
		}
	}
	for _, m := range virtualMarkers {
		if strings.Contains(lowName, m) || strings.Contains(lowDriver, m) {
			d.Disp = DispVirtual
			d.Note = "this was not a real printer. This computer can already save anything as a PDF."
			return d
		}
	}
	if strings.HasPrefix(p.Port, `\\`) {
		server, queue := splitUNC(p.Port)
		d.Disp = DispWindowsShare
		d.Note = fmt.Sprintf(
			"this printer was shared from a Windows computer called %q. It was not set up here: "+
				"that needs a password nobody put in the backup, and the Windows computer sharing "+
				"it may be the one that was just replaced.", server)
		if queue != "" {
			d.Note += fmt.Sprintf(" The share was called %q.", queue)
		}
		return d
	}
	// Local ports are decided FIRST. "USB001" is alphanumeric, so a
	// host-shaped test accepts it and produces ipp://USB001/ipp/print — a
	// queue pointing at a machine that does not exist, created by the very
	// function whose job is to refuse fabricated addresses. That happened
	// here. Order is the fix; the prefix refusal inside networkHost is the
	// second one, because relying on the order alone puts the guarantee in
	// the caller.
	if isLocalPort(lowPort) {
		d.Disp = DispLocal
		d.Note = "this printer was plugged in with a cable. Plug it into this computer and it is " +
			"detected on its own; there is nothing in the backup that would help."
		return d
	}
	if host, ok := networkHost(p.Port); ok {
		d.Disp = DispNetworkQueue
		d.QueueName = cupsName(p.Name)
		d.DeviceURI = "ipp://" + host + "/ipp/print"
		d.Note = fmt.Sprintf(
			"a network printer at %s. The Windows driver does not come across — nothing can move "+
				"a Windows driver to Linux — so this queue is set up driverless, which most printers "+
				"made after about 2010 support. If it prints blank pages, pick the model in Print Settings.", host)
		return d
	}
	d.Disp = DispUnknown
	d.Note = fmt.Sprintf("Windows recorded its connection as %q, which does not say where the printer is. "+
		"It was not set up. Add it in Print Settings.", p.Port)
	return d
}

func splitUNC(port string) (server, queue string) {
	t := strings.TrimPrefix(port, `\\`)
	parts := strings.SplitN(t, `\`, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return t, ""
}

// networkHost extracts a host from a Windows port name, and returns false when
// it cannot. Windows writes these as "IP_192.168.1.50", "192.168.1.50",
// "IP_printer.school.local" or, on some drivers, "WSD-<guid>".
//
// It refuses anything it is not sure about. A fabricated host produces a queue
// that fails on the first print job, at which point the user has no way to know
// the address was invented.
func networkHost(port string) (string, bool) {
	h := strings.TrimSpace(port)
	h = strings.TrimSuffix(h, ":")
	for _, prefix := range []string{"IP_", "ip_", "TCPPort:", "Standard TCP/IP Port:"} {
		h = strings.TrimPrefix(h, prefix)
	}
	if h == "" || len(h) > 253 {
		return "", false
	}
	// A WSD port is a GUID, not an address. It is discovered on the network at
	// runtime and cannot be turned into a URI from the archive alone.
	if strings.HasPrefix(strings.ToUpper(h), "WSD") {
		return "", false
	}
	// Windows local-port names are alphanumeric and would otherwise sail
	// through the character test below as perfectly good host names. This is
	// the defect this function exists to prevent, caught here as well as by
	// the ordering in Decide.
	if isLocalPort(strings.ToLower(h)) {
		return "", false
	}
	hasAlnum := false
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasAlnum = true
		case c == '.' || c == '-' || c == ':':
			// ':' allows a literal IPv6 or a host:port; both are legal in the URI.
		default:
			return "", false
		}
	}
	if !hasAlnum {
		return "", false
	}
	return h, true
}

func isLocalPort(lowPort string) bool {
	for _, p := range []string{"usb", "lpt", "com", "dot4", "ptr", "parallel"} {
		if strings.HasPrefix(lowPort, p) {
			return true
		}
	}
	return false
}

// cupsName makes a legal CUPS queue name. CUPS forbids space, '/', '#' and '@'
// in a printer name and is limited to 127 characters.
func cupsName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == ' ' || r == '/' || r == '#' || r == '@' || r < 0x20 || r == 0x7f:
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		out = "printer"
	}
	if len(out) > 127 {
		out = out[:127]
	}
	return out
}

// PlanHeader is the first line of the staged plan.
const PlanHeader = "auros-printer-plan/1"

// RenderPlan writes the queues a privileged step should create, in a format
// that is a list of facts rather than a script.
//
// It is NOT a shell script on purpose. A script staged in a user's home
// directory and run later as root is a privilege-escalation hole wearing a
// convenience costume: anyone who can write that file gets root. A data file
// that a fixed program reads cannot do that.
func RenderPlan(decisions []Decision) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", PlanHeader)
	fmt.Fprintf(&b, "queue\tdevice-uri\tmodel\tdefault\tlocation\tdescription\n")
	sorted := append([]Decision(nil), decisions...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].QueueName < sorted[j].QueueName })
	for _, d := range sorted {
		if d.Disp != DispNetworkQueue {
			continue
		}
		fmt.Fprintf(&b, "%s\t%s\teverywhere\t%s\t%s\t%s\n",
			tabSafe(d.QueueName), tabSafe(d.DeviceURI),
			map[bool]string{true: "1", false: "0"}[d.Printer.Default],
			tabSafe(d.Printer.Location), tabSafe(d.Printer.Name))
	}
	return b.String()
}

// tabSafe replaces the framing characters. A field that contained one would
// shift every later column, which is how a device URI ends up in the model
// column and a queue is created pointing at nothing.
func tabSafe(s string) string {
	r := strings.NewReplacer("\t", " ", "\n", " ", "\r", " ")
	return r.Replace(s)
}
