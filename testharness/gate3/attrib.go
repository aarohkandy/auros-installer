package gate3

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// ATTRIBUTION
//
// The change journal is complete — every change to C: in the window — but it
// cannot say which process made a change. Until now the only answer was a path
// noise list, and every run on a fresh runner surfaced a new background writer
// (a servicing scan, the Entra token broker, …), so the list grew run by run.
// Each rule excused a path for EVERY process, the installer included.
//
// Attribution replaces that treadmill with a per-run measurement. An ETW trace
// (Microsoft-Windows-Kernel-File opens, creates, deletes and renames, plus
// Microsoft-Windows-Kernel-Process starts) runs across the same window. Every
// journal change the noise list does not excuse is then classified:
//
//   - opened by the installer's process tree          → FAIL (a write by the tool)
//   - opened by no process the trace saw               → FAIL (cannot be accounted for)
//   - opened ONLY by processes outside the installer's tree
//                                                      → excused, and listed by
//                                                        image name in the result
//
// It fails closed: no trace, an unreadable trace, or a trace in which the
// installer's own tree has no file events at all means attribution is off and
// every unexplained change fails, exactly as before.
//
// What it cannot see — stated, not hidden: a write the installer asks an
// already-running service to make on its behalf (RPC, COM, WMI) is attributed
// to that service. The path noise list had the same blindness for every path it
// covered, and for every process; attribution is strictly narrower. A lost ETW
// event can only turn a change into "unattributed", which fails.
// ─────────────────────────────────────────────────────────────────────────────

// admxEnabledDecimal reads <enabledValue><decimal value="N"/> from the named
// policy in an ADMX file, so a policy is set to the value Windows itself defines.
func admxEnabledDecimal(admx, policy string) (uint32, error) {
	start := strings.Index(admx, `name="`+policy+`"`)
	if start < 0 {
		return 0, fmt.Errorf("policy %s not in the ADMX", policy)
	}
	rest := admx[start:]
	if end := strings.Index(rest, "</policy>"); end >= 0 {
		rest = rest[:end]
	}
	m := admxEnabled.FindStringSubmatch(rest)
	if m == nil {
		return 0, fmt.Errorf("policy %s has no decimal enabledValue", policy)
	}
	v, err := strconv.ParseUint(m[1], 10, 32)
	return uint32(v), err
}

var admxEnabled = regexp.MustCompile(`<enabledValue>\s*<decimal\s+value="(\d+)"\s*/>`)

// Attribution is one trace, parsed.
type Attribution struct {
	device    string                     // C:'s NT device path, lowercased
	opens     map[string]map[uint32]bool // path under the device, lowercased -> pids
	parent    map[uint32]uint32
	images    map[uint32]string
	installer map[uint32]bool
	byPID     map[uint32]int // file events per pid, any volume
	Events    map[string]int // provider/event-id histogram, for the log
	Err       string

	// A write through a handle opened BEFORE the trace has no Create event.
	// Its Write/SetInformation/SetDelete/Rename events carry a FileKey, and a
	// FileKey is named by any event carrying both it and a FileName (NameCreate,
	// or the name rundown StartTrace requests). keyed collects the writers per
	// FileKey until the end of the trace, when the names are known.
	keyName map[string]string            // FileKey -> full lowercased NT path
	keyed   map[string]map[uint32]string // FileKey -> pid -> event id
	Schema  map[string]string            // event id -> its data field names, for the log
	// Unresolved lists handle-based writes whose FileKey no event named: the
	// evidence for an unattributed change, printed rather than guessed at.
	Unresolved []string
}

// Kernel-File events that name a path in the caller's context: Create (12),
// DeletePath (26), RenamePath (27), CreateNewFile (30). NameCreate (10) and
// friends are rundown events and are NOT the opener, so they are not counted.
var fileEventIDs = map[int]bool{12: true, 26: true, 27: true, 30: true}

// Kernel-File events that change a file through an open handle, keyed by
// FileKey: Write (16), SetInformation (17, timestamps and attributes among
// them), SetDelete (18), Rename (19).
var handleEventIDs = map[int]bool{16: true, 17: true, 18: true, 19: true}

type etwEvent struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID   int `xml:"EventID"`
		Execution struct {
			ProcessID string `xml:"ProcessID,attr"`
		} `xml:"Execution"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

// ParseTrace reads tracerpt's XML rendering. device is C:'s NT device path
// (\Device\HarddiskVolumeN); roots are the process ids the installer's tree
// starts from; images maps pids to image names for processes that were already
// running (a process started in the window is named by its start event).
func ParseTrace(r io.Reader, device string, roots []uint32, images map[uint32]string) *Attribution {
	a := &Attribution{
		device: strings.TrimSuffix(strings.ToLower(device), `\`),
		opens:  map[string]map[uint32]bool{}, parent: map[uint32]uint32{},
		images: map[uint32]string{}, installer: map[uint32]bool{},
		byPID: map[uint32]int{}, Events: map[string]int{},
		keyName: map[string]string{}, keyed: map[string]map[uint32]string{}, Schema: map[string]string{},
	}
	for k, v := range images {
		a.images[k] = v
	}
	if a.device == "" {
		a.Err = "C:'s device path is unknown, so no traced path can be matched to a journal record"
		return a
	}
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			a.Err = "the trace could not be read: " + err.Error()
			return a
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "Event" {
			continue
		}
		var ev etwEvent
		if err := dec.DecodeElement(&ev, &se); err != nil {
			a.Err = "the trace could not be read: " + err.Error()
			return a
		}
		a.add(ev)
	}
	a.resolveKeys()
	a.closeTree(roots)
	n := 0
	for pid := range a.installer {
		n += a.byPID[pid]
	}
	if n == 0 {
		a.Err = fmt.Sprintf("the trace holds no file events from the installer's process tree (roots %v, "+
			"%d processes): it did not see the run, so it cannot vouch for anything", roots, len(a.installer))
	}
	return a
}

func (a *Attribution) add(ev etwEvent) {
	a.Events[fmt.Sprintf("%s/%d", ev.System.Provider.Name, ev.System.EventID)]++
	data := map[string]string{}
	for _, d := range ev.Data {
		data[d.Name] = strings.TrimSpace(d.Value)
	}
	switch {
	case strings.EqualFold(ev.System.Provider.Name, "Microsoft-Windows-Kernel-Process") && ev.System.EventID == 1:
		pid, perr := parseUint(data["ProcessID"])
		ppid, qerr := parseUint(data["ParentProcessID"])
		if perr == nil && qerr == nil {
			a.parent[pid] = ppid
			if img := data["ImageName"]; img != "" {
				a.images[pid] = img[strings.LastIndex(img, `\`)+1:]
			}
		}
	case strings.EqualFold(ev.System.Provider.Name, "Microsoft-Windows-Kernel-File") &&
		!fileEventIDs[ev.System.EventID]:
		id := strconv.Itoa(ev.System.EventID)
		if _, seen := a.Schema[id]; !seen {
			var names []string
			for _, d := range ev.Data {
				names = append(names, d.Name)
			}
			a.Schema[id] = strings.Join(names, ",")
		}
		key := strings.ToLower(data["FileKey"])
		if key == "" {
			return
		}
		if name := data["FileName"]; name != "" {
			a.keyName[key] = strings.ToLower(name)
		}
		if handleEventIDs[ev.System.EventID] {
			pid, err := parseUint(ev.System.Execution.ProcessID)
			if err != nil {
				return
			}
			a.byPID[pid]++
			if a.keyed[key] == nil {
				a.keyed[key] = map[uint32]string{}
			}
			a.keyed[key][pid] = id
		}
	case strings.EqualFold(ev.System.Provider.Name, "Microsoft-Windows-Kernel-File"):
		p := data["FileName"]
		if p == "" {
			p = data["FilePath"]
		}
		pid, err := parseUint(ev.System.Execution.ProcessID)
		if err != nil {
			return
		}
		a.byPID[pid]++
		a.open(strings.ToLower(p), pid)
	}
}

// open records that pid acted on a full NT path, if that path is on C:.
func (a *Attribution) open(p string, pid uint32) {
	if !strings.HasPrefix(p, a.device+`\`) {
		return
	}
	p = strings.TrimPrefix(p, a.device)
	if a.opens[p] == nil {
		a.opens[p] = map[uint32]bool{}
	}
	a.opens[p][pid] = true
}

// resolveKeys turns handle-based writes into path attributions once every
// FileKey the trace named is known. A key nobody named is kept as evidence.
func (a *Attribution) resolveKeys() {
	for key, pids := range a.keyed {
		name, ok := a.keyName[key]
		for pid, id := range pids {
			if ok {
				a.open(name, pid)
			} else {
				a.Unresolved = append(a.Unresolved, fmt.Sprintf("event %s by %s(%d) on FileKey %s", id, a.image(pid), pid, key))
			}
		}
	}
	sort.Strings(a.Unresolved)
}

// ProcessStart ids are decimal in tracerpt's rendering; accept hex too.
func parseUint(s string) (uint32, error) {
	v, err := strconv.ParseUint(s, 0, 32)
	return uint32(v), err
}

func (a *Attribution) closeTree(roots []uint32) {
	for _, r := range roots {
		a.installer[r] = true
	}
	for changed := true; changed; {
		changed = false
		for pid, ppid := range a.parent {
			if a.installer[ppid] && !a.installer[pid] {
				a.installer[pid] = true
				changed = true
			}
		}
	}
}

// Attribution verdicts.
const (
	ByInstaller  = "installer"
	Unattributed = "unattributed"
	Background   = "background"
)

// Classify says who opened a C: path (C:\…) during the window.
func (a *Attribution) Classify(cPath string) (kind, who string) {
	p := strings.ToLower(cPath)
	p = strings.TrimPrefix(p, `\\?\`)
	if len(p) < 2 || p[1] != ':' {
		return Unattributed, "not a drive path"
	}
	pids := a.opens[p[2:]]
	if len(pids) == 0 {
		return Unattributed, "no process in the trace opened it or wrote to it"
	}
	var mine, others []string
	for pid := range pids {
		name := fmt.Sprintf("%s(%d)", a.image(pid), pid)
		if a.installer[pid] {
			mine = append(mine, name)
		} else {
			others = append(others, name)
		}
	}
	sort.Strings(mine)
	sort.Strings(others)
	if len(mine) > 0 {
		return ByInstaller, "opened by the installer's process tree: " + strings.Join(mine, ", ")
	}
	return Background, "opened only by " + strings.Join(others, ", ")
}

// ClassifyAny classifies one change known by several paths (see candidates in
// usn_windows.go): the installer on any of them wins, then any background
// writer; only a change no path of which the trace saw is unattributed.
func (a *Attribution) ClassifyAny(paths []string) (kind, who string) {
	kind, who = Unattributed, "no process in the trace opened it or wrote to it"
	for _, p := range paths {
		k, w := a.Classify(p)
		if len(paths) > 1 && k != Unattributed {
			w += " (as " + p + ")"
		}
		switch {
		case k == ByInstaller:
			return k, w
		case k == Background && kind == Unattributed:
			kind, who = k, w
		}
	}
	return kind, who
}

// SameName lists traced C: paths ending in the same file name, as evidence
// for a change that stayed unattributed.
func (a *Attribution) SameName(cPath string) []string {
	base := strings.ToLower(cPath[strings.LastIndex(cPath, `\`)+1:])
	var out []string
	for p, pids := range a.opens {
		if strings.HasSuffix(p, `\`+base) && len(out) < 5 {
			var ids []string
			for pid := range pids {
				ids = append(ids, fmt.Sprintf("%s(%d)", a.image(pid), pid))
			}
			sort.Strings(ids)
			out = append(out, "C:"+p+" by "+strings.Join(ids, ","))
		}
	}
	sort.Strings(out)
	return out
}

func (a *Attribution) image(pid uint32) string {
	if s := a.images[pid]; s != "" {
		return s
	}
	return "pid"
}
