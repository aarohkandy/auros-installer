package printers

import (
	"errors"
	"strings"
	"testing"
)

func inventory(rows ...string) []byte {
	return []byte(Header + "\n" + columns + "\n" + strings.Join(rows, "\n") + "\n")
}

func TestParse_RefusesEverythingItCannotVouchFor(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"empty file", "", ErrBadHeader},
		{"not our file", "hello\n", ErrBadHeader},
		{"right header, wrong columns", Header + "\nname\tport\n", ErrCorrupt},
		{"CRLF", strings.ReplaceAll(Header+"\n"+columns+"\n", "\n", "\r\n"), ErrCorrupt},
		{"too few fields", Header + "\n" + columns + "\nHP\tIP_10.0.0.1\tdrv\t1\n", ErrCorrupt},
		{"too many fields", Header + "\n" + columns + "\nHP\tIP_10.0.0.1\tdrv\t1\tloc\tcom\textra\n", ErrCorrupt},
		{"default column is not a flag", Header + "\n" + columns + "\nHP\tIP_10.0.0.1\tdrv\tyes\tloc\tcom\n", ErrCorrupt},
		{"nameless printer", Header + "\n" + columns + "\n \tIP_10.0.0.1\tdrv\t0\t\t\n", ErrCorrupt},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(c.in))
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestParse_AValidFileWithNoPrintersIsNotAnError(t *testing.T) {
	// A machine with no printers is a real answer, and treating it as a
	// corrupt file would make the report say something is wrong when nothing
	// is.
	got, err := Parse([]byte(Header + "\n" + columns + "\n"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d printers", len(got))
	}
}

func TestDecide_OnlyARealNetworkPrinterGetsAQueue(t *testing.T) {
	cases := []struct {
		name    string
		p       Printer
		want    Disposition
		wantURI string
	}{
		{"standard TCP/IP port", Printer{Name: "HP LaserJet 4250", Port: "IP_192.168.1.50"},
			DispNetworkQueue, "ipp://192.168.1.50/ipp/print"},
		{"bare address", Printer{Name: "Brother", Port: "10.0.0.7"},
			DispNetworkQueue, "ipp://10.0.0.7/ipp/print"},
		{"hostname", Printer{Name: "Staffroom", Port: "IP_printer.school.local"},
			DispNetworkQueue, "ipp://printer.school.local/ipp/print"},
		{"windows share", Printer{Name: "Office", Port: `\\SERVER01\HP4250`}, DispWindowsShare, ""},
		{"usb", Printer{Name: "Canon", Port: "USB001"}, DispLocal, ""},
		{"parallel", Printer{Name: "Ancient", Port: "LPT1:"}, DispLocal, ""},
		{"print to pdf", Printer{Name: "Microsoft Print to PDF", Port: "PORTPROMPT:"}, DispVirtual, ""},
		{"xps", Printer{Name: "Microsoft XPS Document Writer", Port: "XPSPort:"}, DispVirtual, ""},
		{"fax", Printer{Name: "Fax", Port: "SHRFAX:"}, DispVirtual, ""},
		{"onenote", Printer{Name: "Send To OneNote 2016", Port: "nul:"}, DispVirtual, ""},
		{"WSD, which is a GUID not an address", Printer{Name: "Epson", Port: "WSD-1a2b3c4d"}, DispUnknown, ""},
		{"nothing useful", Printer{Name: "Mystery", Port: ""}, DispUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.p)
			if d.Disp != c.want {
				t.Fatalf("disposition = %q, want %q (note: %s)", d.Disp, c.want, d.Note)
			}
			if d.DeviceURI != c.wantURI {
				t.Fatalf("device URI = %q, want %q", d.DeviceURI, c.wantURI)
			}
			if d.Note == "" {
				t.Error("no note: the user is told nothing about this printer")
			}
			if c.want != DispNetworkQueue && d.DeviceURI != "" {
				t.Errorf("a %q printer was given a device URI it cannot honour", c.want)
			}
		})
	}
}

func TestDecide_ANetworkQueueSaysTheDriverDoesNotComeAcross(t *testing.T) {
	// SPEC §4.2. A queue created driverless that the report describes as
	// "migrated" is a claim that the printer works, and it may not.
	d := Decide(Printer{Name: "HP LaserJet 4250", Port: "IP_192.168.1.50", Driver: "HP Universal PCL6"})
	for _, want := range []string{"driver does not come across", "Print Settings"} {
		if !strings.Contains(d.Note, want) {
			t.Errorf("the note does not say %q:\n%s", want, d.Note)
		}
	}
}

func TestDecide_QueueNamesAreLegalForCUPS(t *testing.T) {
	for _, name := range []string{
		"HP LaserJet 4250", "printer/with/slashes", "has#hash", "at@sign", "   ", "",
	} {
		d := Decide(Printer{Name: name, Port: "IP_10.0.0.1"})
		for _, bad := range []string{" ", "/", "#", "@"} {
			if strings.Contains(d.QueueName, bad) {
				t.Errorf("queue name %q from %q contains %q, which CUPS rejects", d.QueueName, name, bad)
			}
		}
		if d.QueueName == "" {
			t.Errorf("printer %q produced an empty queue name", name)
		}
	}
}

func TestRenderPlan_HoldsOnlyTheQueuesThatCanHonestlyBeCreated(t *testing.T) {
	ps, err := Parse(inventory(
		"HP LaserJet 4250\tIP_192.168.1.50\tHP PCL6\t1\tStaff room\tthe good one",
		"Office Share\t\\\\SERVER01\\HP4250\tHP PCL6\t0\t\t",
		"Microsoft Print to PDF\tPORTPROMPT:\tMicrosoft\t0\t\t",
		"Canon MG3000\tUSB001\tCanon\t0\t\t",
	))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var ds []Decision
	for _, p := range ps {
		ds = append(ds, Decide(p))
	}
	plan := RenderPlan(ds)
	if !strings.HasPrefix(plan, PlanHeader+"\n") {
		t.Fatalf("plan does not start with its header:\n%s", plan)
	}
	if !strings.Contains(plan, "ipp://192.168.1.50/ipp/print") {
		t.Errorf("the network printer is missing from the plan:\n%s", plan)
	}
	for _, mustNot := range []string{"PORTPROMPT", "USB001", "SERVER01"} {
		if strings.Contains(plan, mustNot) {
			t.Errorf("the plan contains %q, which cannot be created from the backup:\n%s", mustNot, plan)
		}
	}
	// One header line, one column line, one queue.
	if n := len(strings.Split(strings.TrimSuffix(plan, "\n"), "\n")); n != 3 {
		t.Errorf("the plan has %d lines, want 3:\n%s", n, plan)
	}
}

func TestRenderPlan_AFieldWithATabCannotShiftTheColumns(t *testing.T) {
	// A printer whose LOCATION contains a tab would otherwise push the device
	// URI into the model column, and a queue would be created pointing at
	// nothing.
	d := Decide(Printer{Name: "HP\tWeird", Port: "IP_10.0.0.1", Location: "Room\t3"})
	plan := RenderPlan([]Decision{d})
	for _, line := range strings.Split(strings.TrimSuffix(plan, "\n"), "\n")[2:] {
		if n := strings.Count(line, "\t"); n != 5 {
			t.Fatalf("a data line has %d tabs, want 5:\n%q", n, line)
		}
	}
}

func TestNetworkHost_RefusesAnythingItWouldHaveToInvent(t *testing.T) {
	for _, port := range []string{
		"", "WSD-1a2b", "wsd-anything", "has space", `\\unc\path`, "semi;colon", "quote\"mark",
	} {
		if h, ok := networkHost(port); ok {
			t.Errorf("networkHost(%q) = %q, true — a fabricated address produces a queue that "+
				"fails on the first print job with no way for the user to know why", port, h)
		}
	}
	for _, port := range []string{"IP_10.0.0.1", "10.0.0.1", "printer.local", "host:9100"} {
		if _, ok := networkHost(port); !ok {
			t.Errorf("networkHost(%q) refused a usable address", port)
		}
	}
}
