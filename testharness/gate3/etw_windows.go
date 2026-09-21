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
// Kernel-File keywords, as `logman query providers` printed them on the runner
// (runs 35565779074, 35639286740): 0x10 FILENAME, 0x20 FILEIO (SetInformation,
// SetDelete, Rename), 0x40 OP_END (OperationEnd: the status C1 reads a denied
// open from), 0x80 CREATE, 0x200 WRITE, 0x400 DELETE_PATH, 0x800
// RENAME_SETLINK_PATH, 0x1000 CREATE_NEW_FILE. No READ. FILEIO and WRITE are
// there for writes through handles opened before the trace (see attrib.go).
// Kernel-Process 0x10 is WINEVENT_KEYWORD_PROCESS.
var traceProviders = []struct{ session, provider, keywords string }{
	{"gate3-file", "Microsoft-Windows-Kernel-File", "0x1EF0"},
	{"gate3-proc", "Microsoft-Windows-Kernel-Process", "0x10"},
}

// Microsoft-Windows-Kernel-File, as `logman query providers` printed it.
var kernelFileGUID = syscall.GUID{Data1: 0xEDD08927, Data2: 0x9CC4, Data3: 0x4E65,
	Data4: [8]byte{0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}}

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
	// Ask Kernel-File to name what is already open, so a write through a handle
	// that predates the trace can be tied to a path. If the provider has no
	// rundown this names nothing, those writes stay unattributed, and they fail.
	if err := captureState("gate3-file", &kernelFileGUID, 0x1EF0); err != nil {
		fmt.Printf("gate3: Kernel-File name rundown not requested: %v\n", err)
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
	// A lost event could hide an installer write behind someone else's, so a
	// session that dropped anything cannot vouch for the window.
	for _, p := range traceProviders {
		lost, err := eventsLost(p.session)
		if err != nil {
			t.Stop()
			return &Attribution{Err: fmt.Sprintf("querying %s: %v", p.session, err)}
		}
		if lost > 0 {
			t.Stop()
			return &Attribution{Err: fmt.Sprintf("the %s session lost %d events or buffers", p.session, lost)}
		}
	}
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

var (
	procControlTraceW  = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modadvapi32.NewProc("EnableTraceEx2")
)

// eventTraceProperties is EVENT_TRACE_PROPERTIES (evntrace.h), 120 bytes on
// amd64, followed by room for the two names ControlTrace writes back.
type eventTraceProperties struct {
	BufferSize          uint32 // WNODE_HEADER from here
	ProviderID          uint32
	HistoricalContext   uint64
	TimeStamp           int64
	GUID                syscall.GUID
	ClientContext       uint32
	Flags               uint32
	BufferSizeKB        uint32 // EVENT_TRACE_PROPERTIES from here
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
	names               [2048]uint16
}

func querySession(name string) (*eventTraceProperties, error) {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	p := &eventTraceProperties{}
	p.BufferSize = uint32(unsafe.Sizeof(*p))
	p.LoggerNameOffset = uint32(unsafe.Offsetof(p.names))
	p.LogFileNameOffset = p.LoggerNameOffset + 1024*2
	const eventTraceControlQuery = 0
	if r, _, _ := procControlTraceW.Call(0, uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(p)),
		eventTraceControlQuery); r != 0 {
		return nil, syscall.Errno(r)
	}
	return p, nil
}

func eventsLost(session string) (uint32, error) {
	p, err := querySession(session)
	if err != nil {
		return 0, err
	}
	return p.EventsLost + p.LogBuffersLost + p.RealTimeBuffersLost, nil
}

// captureState is EnableTraceEx2(EVENT_CONTROL_CODE_CAPTURE_STATE). The 64-bit
// handle and keyword are passed as single registers: amd64 only, which is the
// only architecture gate3.exe is built for.
func captureState(session string, provider *syscall.GUID, keywords uint64) error {
	p, err := querySession(session)
	if err != nil {
		return err
	}
	const eventControlCodeCaptureState = 2
	if r, _, _ := procEnableTraceEx2.Call(uintptr(p.HistoricalContext), uintptr(unsafe.Pointer(provider)),
		eventControlCodeCaptureState, 5, uintptr(keywords), 0, 0, 0); r != 0 {
		return syscall.Errno(r)
	}
	return nil
}
