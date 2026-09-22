package gate3

import (
	"fmt"
	"strings"
	"testing"
)

func kfEv(id int, pid string, data ...string) string {
	var b strings.Builder
	for i := 0; i+1 < len(data); i += 2 {
		fmt.Fprintf(&b, `<Data Name="%s">%s</Data>`, data[i], data[i+1])
	}
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>`+
		`<Provider Name="Microsoft-Windows-Kernel-File" /><EventID>%d</EventID>`+
		`<Execution ProcessID="%s" ThreadID="1" /></System><EventData>%s</EventData></Event>`, id, pid, b.String())
}

// create is Kernel-File Create (12) with disposition disp in CreateOptions' high byte.
func create(pid, irp, fo string, disp uint32, path string) string {
	return kfEv(12, pid, "Irp", irp, "FileObject", fo, "CreateOptions", fmt.Sprintf("0x%x", disp<<24|0x20),
		"FileName", path)
}

func opEnd(irp, status string) string { return kfEv(24, "4", "Irp", irp, "Status", status) }

const exemptProfile = `C:\Users\auros-gate3`

// The red cases, each alone in an otherwise clean trace.
func TestAuditWritesCatchesEveryInstallerWriteToC(t *testing.T) {
	base := []string{
		startEv(200, 100, "auros-migrate.exe"),
		create("200", "0xa0", "0xf0", 1, cDev+`\gate3\corpus\Documents\a.docx`), // a read: FILE_OPEN
		opEnd("0xa0", "0x0"),
	}
	for name, c := range map[string]struct {
		events []string
		bucket func(*WriteAudit) []string
		want   string
	}{
		"a created file": {[]string{create("200", "0xa1", "0xf1", 2, cDev+`\ProgramData\auros\x.tmp`),
			opEnd("0xa1", "0x0")}, writesOf, `C:\programdata\auros\x.tmp — create by auros-migrate.exe(200)`},
		"an overwrite by a grandchild": {[]string{startEv(300, 200, "helper.exe"),
			create("300", "0xa2", "0xf2", 5, cDev+`\Windows\x.ini`), opEnd("0xa2", "0x0")}, writesOf, `c:\windows\x.ini`},
		"a write through an opened handle": {[]string{create("200", "0xa3", "0xf3", 1, cDev+`\gate3\corpus\b.txt`),
			opEnd("0xa3", "0x0"), kfEv(16, "200", "Irp", "0xa4", "FileObject", "0xf3", "FileKey", "0xk3")},
			writesOf, `c:\gate3\corpus\b.txt — write by`},
		"a delete on close": {[]string{kfEv(12, "200", "Irp", "0xa5", "FileObject", "0xf5",
			"CreateOptions", "0x01001000", "FileName", cDev+`\x.tmp`)}, writesOf, `c:\x.tmp`},
		"a rename": {[]string{kfEv(27, "200", "Irp", "0xa6", "FileKey", "0xk6", "FilePath", cDev+`\y.tmp`)},
			writesOf, `c:\y.tmp — rename-path`},
		"a write the trace never named": {[]string{kfEv(17, "200", "Irp", "0xa7", "FileObject", "0xf7",
			"FileKey", "0xk7")}, writesOf, "never named"},
		"a sibling that only shares the exemption's prefix": {[]string{
			create("200", "0xab", "0xfb", 2, cDev+`\Users\auros-gate3x\z`)}, writesOf, `c:\users\auros-gate3x\z`},
		"a Create with no CreateOptions": {[]string{kfEv(12, "200", "Irp", "0xa8", "FileName", cDev+`\z.tmp`)},
			writesOf, "did not carry"},
		"an open Windows refused": {[]string{create("200", "0xa9", "0xf9", 1, cDev+`\gate3\corpus\c.txt`),
			opEnd("0xa9", "0xC0000022")}, deniedOf, `c:\gate3\corpus\c.txt — create refused with status_access_denied`},
		"a create Windows refused, status in decimal": {[]string{create("200", "0xaa", "0xfa", 2, cDev+`\ProgramData\q`),
			opEnd("0xaa", "3221225506")}, deniedOf, `c:\programdata\q`},
	} {
		a := ParseTrace(strings.NewReader(etwXML(append(append([]string{}, base...), c.events...)...)),
			cDev, []uint32{100}, nil)
		w := a.AuditWrites([]string{exemptProfile})
		if !contains(c.bucket(w), c.want) {
			t.Errorf("%s: %q not found in %+v", name, c.want, w)
		}
		enf := &Enforcement{Token: "standard", Verified: true, Exemptions: []string{exemptProfile}}
		if ok, detail := SystemDiskVerdict(enf, w); ok {
			t.Errorf("%s: C1 passed: %s", name, detail)
		}
	}
}

// The green case: reads, the exemption, other processes and other volumes.
func TestAuditWritesPassesWhatIsNotTheInstallerWritingToC(t *testing.T) {
	x := etwXML(
		startEv(200, 100, "auros-migrate.exe"),
		create("200", "0xb0", "0xe0", 1, cDev+`\gate3\corpus\Documents\a.docx`),
		opEnd("0xb0", "0x0"),
		create("200", "0xb1", "0xe1", 5, `\Device\HarddiskVolume4\auros-archive\a.docx`),
		kfEv(16, "200", "Irp", "0xb2", "FileObject", "0xe1", "FileKey", "0xk1"),
		create("200", "0xb3", "0xe3", 5, cDev+`\Users\auros-gate3\AppData\Local\Temp\t.tmp`),
		create("200", "0xb4", "0xe4", 1, cDev+`\Users\auros-gate3\NTUSER.DAT`),
		opEnd("0xb4", "0xC0000022"), // refused, but inside the exemption: listed, not failed
		create("500", "0xb5", "0xe5", 5, cDev+`\Windows\System32\SecurityHealth\x`), // svchost
		kfEv(16, "500", "Irp", "0xb6", "FileObject", "0xe5", "FileKey", "0xk5"),
		create("0x1f4", "0xb7", "0xe7", 2, cDev+`\ProgramData\Microsoft\y`),
		opEnd("0xb7", "0xC0000022"),
		create("200", "0xb8", "0xe8", 1, cDev+`\Users\auros-gate3x\z`), // a prefix, not the exemption
		opEnd("0xb8", "0x0"),
	)
	a := ParseTrace(strings.NewReader(x), cDev, []uint32{100}, map[uint32]string{500: "svchost.exe"})
	w := a.AuditWrites([]string{exemptProfile + `\`})
	if len(w.Writes) != 0 || len(w.Denied) != 0 || w.Error != "" {
		t.Fatalf("a clean trace was not clean: %+v", w)
	}
	if len(w.Exempt) != 2 || !contains(w.Exempt, `\appdata\local\temp\t.tmp`) {
		t.Fatalf("writes inside the exemption must be listed, got %v", w.Exempt)
	}
	enf := &Enforcement{Token: "standard", Verified: true, Exemptions: []string{exemptProfile}}
	if ok, detail := SystemDiskVerdict(enf, w); !ok {
		t.Fatalf("C1 failed a clean trace: %s", detail)
	}
}

func TestEnforcementFailsClosed(t *testing.T) {
	for name, e := range map[string]*Enforcement{
		"none":       nil,
		"unverified": {Token: "standard"},
		"a probe that wrote to C:": {Token: "standard", Verified: true,
			Error: `md C:\ProgramData\x at Low: exit 0, created true`},
	} {
		if ok, _ := SystemDiskVerdict(e, &WriteAudit{Events: 5}); ok {
			t.Errorf("%s: C1 passed", name)
		}
	}
}

func writesOf(w *WriteAudit) []string { return w.Writes }
func deniedOf(w *WriteAudit) []string { return w.Denied }

func contains(l []string, s string) bool {
	for _, x := range l {
		if strings.Contains(strings.ToLower(x), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

func TestDenySDDLPrependsAndRefusesANullDACL(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	deny := "(D;;0xd0156;;;" + sid + ")"
	for in, want := range map[string]string{
		"D:PAI(A;OICI;FA;;;SY)(A;;0x1200a9;;;BU)": "D:PAI" + deny + "(A;OICI;FA;;;SY)(A;;0x1200a9;;;BU)",
		"D:AI(A;ID;FA;;;BA)":                      "D:AI" + deny + "(A;ID;FA;;;BA)",
		"D:(A;;FA;;;SY)":                          "D:" + deny + "(A;;FA;;;SY)",
		"D:P":                                     "D:P" + deny,
		"O:BAD:ARAI(A;;FA;;;SY)S:AI":              "O:BAD:ARAI" + deny + "(A;;FA;;;SY)S:AI",
	} {
		got, err := DenySDDL(in, sid)
		if err != nil || got != want {
			t.Errorf("DenySDDL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"D:NO_ACCESS_CONTROL", "O:BAG:SY", "D:X(A;;FA;;;SY)"} {
		if got, err := DenySDDL(bad, sid); err == nil {
			t.Errorf("DenySDDL(%q) = %q, want a refusal", bad, got)
		}
	}
}

func TestDenyMaskNeverCountsAReadRight(t *testing.T) {
	if DenyMask != 0xd0156 {
		t.Fatalf("DenyMask = 0x%x", DenyMask)
	}
	if got := strings.Join(WriteRights(0x1200a9|0x2|0x40000), ","); got != "add-file,write-dac" {
		t.Fatalf("WriteRights = %q: read rights must not count, write rights must", got)
	}
	if len(WriteRights(0x1200a9)) != 0 {
		t.Fatal("read-and-execute counted as writable")
	}
}

func TestWritableRootsNeverSplitASubtree(t *testing.T) {
	got := WritableRoots([]string{`C:\ProgramData\a`, `C:\ProgramData\a\b`, `C:\ProgramData\a\b\c`,
		`C:\Windows\Temp`, `C:\hostedtoolcache\x`, `C:\hostedtoolcache\x\y`, `C:\ProgramData\ab`})
	want := []string{`C:\ProgramData\a (3)`, `C:\ProgramData\ab (1)`, `C:\Windows\Temp (1)`, `C:\hostedtoolcache\x (2)`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("WritableRoots = %v, want %v", got, want)
	}
	if got := WritableRoots([]string{`C:\`, `C:\x`, `C:\x\y`}); len(got) != 1 || got[0] != `C:\ (3)` {
		t.Fatalf("a writable C:\\ must be the one root: %v", got)
	}
}
