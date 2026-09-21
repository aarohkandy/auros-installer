package gate3

import (
	"encoding/csv"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Two ETW sessions, driven by the inbox logman and tracerpt, so the harness
// needs nothing installed. See attrib.go for what the trace is for.
//
// Kernel-File keywords: 0x10 FILENAME, 0x80 CREATE, 0x400 DELETE_PATH,
// 0x800 RENAME_SETLINK_PATH, 0x1000 CREATE_NEW_FILE. No READ or WRITE: the
// opener is what attribution needs, and 18,000 files of read/write events would
// only slow tracerpt down. Kernel-Process 0x10 is WINEVENT_KEYWORD_PROCESS.
// `logman query providers <name>` is printed by StartTrace so the keyword
// table the runner actually has is in every job log.
var traceProviders = []struct{ session, provider, keywords string }{
	{"gate3-file", "Microsoft-Windows-Kernel-File", "0x1C90"},
	{"gate3-proc", "Microsoft-Windows-Kernel-Process", "0x10"},
}

// Trace is a running pair of ETW sessions.
type Trace struct {
	dir  string
	etls []string
}

// StartTrace starts the sessions, writing their files under dir.
func StartTrace(dir string) (*Trace, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	t := &Trace{dir: dir}
	for _, p := range traceProviders {
		_ = exec.Command("logman", "stop", p.session, "-ets").Run() // a leftover from the previous run
		etl := filepath.Join(dir, p.session+".etl")
		os.Remove(etl)
		out, err := exec.Command("logman", "start", p.session, "-p", p.provider, p.keywords, "0x5",
			"-o", etl, "-bs", "1024", "-nb", "128", "512", "-ets").CombinedOutput()
		if err != nil {
			t.Stop()
			return nil, fmt.Errorf("logman start %s: %v: %s", p.session, err, strings.TrimSpace(string(out)))
		}
		t.etls = append(t.etls, etl)
	}
	return t, nil
}

// Stop ends the sessions. Safe to call twice.
func (t *Trace) Stop() {
	for _, p := range traceProviders {
		_ = exec.Command("logman", "stop", p.session, "-ets").Run()
	}
}

// Attribute stops the trace, renders it and parses it. It never returns nil:
// a failure is an Attribution whose Err says why, and the caller fails closed.
func (t *Trace) Attribute(roots []uint32) *Attribution {
	t.Stop()
	xmlPath := filepath.Join(t.dir, "trace.xml")
	os.Remove(xmlPath)
	args := append(append([]string{}, t.etls...), "-o", xmlPath, "-of", "XML", "-y")
	if out, err := exec.Command("tracerpt", args...).CombinedOutput(); err != nil {
		return &Attribution{Err: fmt.Sprintf("tracerpt: %v: %s", err, tail(string(out), 400))}
	}
	defer func() {
		for _, e := range t.etls {
			os.Remove(e)
		}
		os.Remove(xmlPath)
	}()
	f, err := os.Open(xmlPath)
	if err != nil {
		return &Attribution{Err: "the rendered trace is missing: " + err.Error()}
	}
	defer f.Close()
	dev, err := dosDevice("C:")
	if err != nil {
		return &Attribution{Err: "QueryDosDevice(C:): " + err.Error()}
	}
	return ParseTrace(f, dev, roots, runningImages())
}

// ProviderKeywords is `logman query providers` for each provider, for the log.
func ProviderKeywords() string {
	var b strings.Builder
	for _, p := range traceProviders {
		out, _ := exec.Command("logman", "query", "providers", p.provider).CombinedOutput()
		b.WriteString(tail(string(out), 3000))
	}
	return b.String()
}

var procQueryDosDeviceW = modkernel32.NewProc("QueryDosDeviceW")

func dosDevice(drive string) (string, error) {
	name, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, 1024)
	n, _, e := procQueryDosDeviceW.Call(uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return "", e
	}
	return syscall.UTF16ToString(buf), nil
}

// runningImages names the processes alive now; processes that started inside
// the window are named by their start events instead.
func runningImages() map[uint32]string {
	m := map[uint32]string{}
	out, err := exec.Command("tasklist", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return m
	}
	rows, _ := csv.NewReader(strings.NewReader(string(out))).ReadAll()
	for _, r := range rows {
		if len(r) >= 2 {
			if pid, err := strconv.ParseUint(r[1], 10, 32); err == nil {
				m[uint32(pid)] = r[0]
			}
		}
	}
	return m
}
