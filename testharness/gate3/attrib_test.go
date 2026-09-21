package gate3

import (
	"fmt"
	"strings"
	"testing"
)

// tracerpt's XML rendering, reduced to the fields ParseTrace reads.
func etwXML(events ...string) string {
	return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Events>\n" + strings.Join(events, "\n") + "\n</Events>"
}

func fileEv(id int, pid string, field, path string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`+
		`<Provider Name="Microsoft-Windows-Kernel-File" Guid="{edd08927-9cc4-4e65-b970-c2560fb5c289}" />`+
		`<EventID>%d</EventID><Execution ProcessID="%s" ThreadID="1" /></System>`+
		`<EventData><Data Name="Irp">0xffff</Data><Data Name="%s">%s</Data></EventData></Event>`, id, pid, field, path)
}

func startEv(pid, ppid int, image string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`+
		`<Provider Name="Microsoft-Windows-Kernel-Process" /><EventID>1</EventID>`+
		`<Execution ProcessID="%d" ThreadID="1" /></System><EventData>`+
		`<Data Name="ProcessID">%d</Data><Data Name="ParentProcessID">%d</Data>`+
		`<Data Name="ImageName">\Device\HarddiskVolume3\Tools\%s</Data></EventData></Event>`, ppid, pid, ppid, image)
}

const cDev = `\Device\HarddiskVolume3`

func TestAttributionNamesTheWriterAndExcusesOnlyOtherProcesses(t *testing.T) {
	x := etwXML(
		startEv(200, 100, "auros-migrate.exe"), // the installer, child of the cmd.exe root
		startEv(300, 200, "manage-bde.exe"),    // and ITS child
		fileEv(12, "200", "FileName", cDev+`\Windows\auros-scratch.tmp`),
		fileEv(30, "300", "FileName", cDev+`\ProgramData\x\state.bin`),
		fileEv(12, "0x1f4", "FileName", cDev+`\ProgramData\Microsoft\Windows\AppRepository\a.dat`), // pid 500
		fileEv(12, "500", "FileName", cDev+`\Windows\auros-scratch.tmp`),
		fileEv(12, "200", "FileName", `\Device\HarddiskVolume4\auros-archive\a.txt`),
		fileEv(12, "500", "FileName", `\Device\HarddiskVolume4\Windows\only-on-d.txt`),
		fileEv(10, "500", "FileName", cDev+`\Windows\rundown-only.txt`), // NameCreate: not an opener
		fileEv(27, "500", "FilePath", cDev+`\Windows\renamed.old`),
	)
	a := ParseTrace(strings.NewReader(x), cDev, []uint32{100}, map[uint32]string{500: "svchost.exe"})
	if a.Err != "" {
		t.Fatalf("attribution failed: %s", a.Err)
	}
	for path, want := range map[string]string{
		`C:\Windows\auros-scratch.tmp`:                         ByInstaller, // opened by both: the installer's open wins
		`C:\ProgramData\x\state.bin`:                           ByInstaller, // a grandchild of the root
		`C:\ProgramData\Microsoft\Windows\AppRepository\a.dat`: Background,
		`C:\Windows\renamed.old`:                               Background,
		`C:\Windows\only-on-d.txt`:                             Unattributed, // same suffix on another volume is not C:
		`C:\Windows\rundown-only.txt`:                          Unattributed,
		`C:\Windows\never-opened.txt`:                          Unattributed,
	} {
		if got, who := a.Classify(path); got != want {
			t.Errorf("%s: got %s (%s), want %s", path, got, who, want)
		}
	}
	if _, who := a.Classify(`C:\ProgramData\Microsoft\Windows\AppRepository\a.dat`); !strings.Contains(who, "svchost.exe(500)") {
		t.Errorf("a background change must name its writer, got %q", who)
	}
}

func TestAttributionFailsClosed(t *testing.T) {
	other := etwXML(fileEv(12, "500", "FileName", cDev+`\Windows\a.txt`))
	for name, a := range map[string]*Attribution{
		"no installer events": ParseTrace(strings.NewReader(other), cDev, []uint32{100}, nil),
		"unreadable trace":    ParseTrace(strings.NewReader("<Events><Event>"), cDev, []uint32{100}, nil),
		"unknown device":      ParseTrace(strings.NewReader(other), "", []uint32{100}, nil),
	} {
		if a.Err == "" {
			t.Errorf("%s: attribution came on; it must fail closed", name)
		}
	}
}
