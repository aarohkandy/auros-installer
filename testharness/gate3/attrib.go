package gate3

import (
	"encoding/xml"
	"fmt"
	"io"
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
}

// Kernel-File events that name a path in the caller's context: Create (12),
// DeletePath (26), RenamePath (27), CreateNewFile (30). NameCreate (10) and
// friends are rundown events and are NOT the opener, so they are not counted.
var fileEventIDs = map[int]bool{12: true, 26: true, 27: true, 30: true}

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
	case strings.EqualFold(ev.System.Provider.Name, "Microsoft-Windows-Kernel-File") && fileEventIDs[ev.System.EventID]:
		p := data["FileName"]
		if p == "" {
			p = data["FilePath"]
		}
		pid, err := parseUint(ev.System.Execution.ProcessID)
		if err != nil {
			return
		}
		a.byPID[pid]++
		p = strings.ToLower(p)
		if !strings.HasPrefix(p, a.device+`\`) {
			return
		}
		p = strings.TrimPrefix(p, a.device)
		if a.opens[p] == nil {
			a.opens[p] = map[uint32]bool{}
		}
		a.opens[p][pid] = true
	}
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
		return Unattributed, "no process in the trace opened it"
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

func (a *Attribution) image(pid uint32) string {
	if s := a.images[pid]; s != "" {
		return s
	}
	return "pid"
}
