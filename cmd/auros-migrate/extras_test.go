package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/labels"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/netprofile"
	"github.com/aarohkandy/auros-installer/internal/printers"
	"github.com/aarohkandy/auros-installer/internal/restore"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

const secretKey = "Correct-Horse-9281"

// wlanXML is a WlanGetProfile result in the WLAN_profile schema. declUTF16
// reproduces a prolog that still names the API's UTF-16 encoding.
func wlanXML(name, auth, enc string, protected, oneX bool, key string, declUTF16 bool) string {
	decl := `<?xml version="1.0"?>`
	if declUTF16 {
		decl = `<?xml version="1.0" encoding="UTF-16"?>`
	}
	return fmt.Sprintf(`%s
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>%s</name>
	<SSIDConfig><SSID><name>%s</name></SSID></SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM><security>
		<authEncryption><authentication>%s</authentication><encryption>%s</encryption><useOneX>%v</useOneX></authEncryption>
		<sharedKey><keyType>passPhrase</keyType><protected>%v</protected><keyMaterial>%s</keyMaterial></sharedKey>
	</security></MSM>
</WLANProfile>`, decl, name, name, auth, enc, oneX, protected, key)
}

// syntheticMachine is a school laptop as the Windows half would read it: one
// network whose key an administrator run got in plain text (and whose prolog
// still says UTF-16), one whose key came back sealed, one 802.1X network, and
// one printer of each kind.
func syntheticMachine() winenv.Env {
	return winenv.NewSynthetic(winenv.SyntheticConfig{
		WiFi: []winenv.WiFiProfile{
			{Name: "SchoolNet", XML: wlanXML("SchoolNet", "WPA2PSK", "AES", false, false, secretKey, true)},
			{Name: "HomeNet", XML: wlanXML("HomeNet", "WPA2PSK", "AES", true, false, "01000000D08C9DDF0115D1118C7A00C04FC297EB", false)},
			{Name: "eduroam", XML: wlanXML("eduroam", "WPA2", "AES", false, true, "", false)},
		},
		Printers: []printers.Printer{
			{Name: "Office Laser", Port: "10.0.0.5", Driver: "HP Universal Printing PCL 6", Default: true, Location: "Room 4"},
			{Name: `\\printsrv\Library`, Port: `\\printsrv\Library`, Driver: "Xerox"},
			{Name: "Desk Inkjet", Port: "USB001", Driver: "Canon"},
		},
	})
}

// The join for the two things that are not files. The Windows half reads the
// machine (synthetic here: the Win32 calls are the one part only a Windows
// machine can run), stages its exports, and the REAL copy engine puts them in
// the archive under labels.WiFi and labels.Printers. The REAL Linux router,
// planner and handlers then consume that archive.
func TestJoin_WiFiAndPrintersReachTheLinuxConsumers(t *testing.T) {
	x := gatherExtras(syntheticMachine())
	stick := filepath.Join(t.TempDir(), manifest.ArchiveSubdir)
	exportDir := filepath.Join(stick, manifest.MetaDir, exportDirName)
	sources, err := x.stage(exportDir)
	if err != nil {
		t.Fatal(err)
	}
	res, err := copyengine.Run(context.Background(), copyengine.Options{Sources: sources, DestRoot: stick})
	if err != nil || res.Quarantined != 0 {
		t.Fatalf("copy: err=%v quarantined=%d", err, res.Quarantined)
	}
	f, err := os.Open(filepath.Join(stick, manifest.MetaDir, manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Read(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	lay, err := restore.NewLayout(home, filepath.Join(home, ".config"), func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	plan, err := restore.BuildPlan(&restore.Archive{Root: stick, Manifest: m}, lay)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.WiFi) != 3 || len(plan.Printers) != 1 || len(plan.Files) != 0 {
		t.Fatalf("routed wifi=%d printers=%d files=%d, want 3, 1, 0: the labels do not join",
			len(plan.WiFi), len(plan.Printers), len(plan.Files))
	}

	// Wi-Fi: only the network whose key came across becomes a keyfile, with
	// that key, at 0600. The sealed one and the 802.1X one are named, not made.
	staging := filepath.Join(home, "nm")
	wrep, err := (&restore.WiFiHandler{StagingDir: staging}).Handle(context.Background(), plan.WiFi)
	if err != nil || len(wrep.Problems) != 0 {
		t.Fatalf("wifi handler: err=%v problems=%v", err, wrep.Problems)
	}
	if wrep.Done != 1 || wrep.Skipped != 2 {
		t.Fatalf("wifi done=%d skipped=%d, want 1 and 2:\n%s", wrep.Done, wrep.Skipped, strings.Join(wrep.Lines, "\n"))
	}
	kf := filepath.Join(staging, "SchoolNet.nmconnection")
	b, err := os.ReadFile(kf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "psk="+secretKey) {
		t.Errorf("the keyfile does not carry the key that came across:\n%s", b)
	}
	if st, _ := os.Stat(kf); st.Mode().Perm() != netprofile.Mode {
		t.Errorf("keyfile mode %04o, want %04o", st.Mode().Perm(), netprofile.Mode)
	}
	for _, n := range []string{"HomeNet.nmconnection", "eduroam.nmconnection"} {
		if _, err := os.Stat(filepath.Join(staging, n)); err == nil {
			t.Errorf("%s was written, but its credentials never came across", n)
		}
	}

	// Printers: exactly one driverless queue, at the address Windows printed to.
	planPath := filepath.Join(home, "printers.plan")
	prep, err := (&restore.PrinterHandler{PlanPath: planPath}).Handle(context.Background(), plan.Printers)
	if err != nil || len(prep.Problems) != 0 {
		t.Fatalf("printer handler: err=%v problems=%v", err, prep.Problems)
	}
	if prep.Done != 1 || prep.Skipped != 2 {
		t.Fatalf("printers done=%d skipped=%d, want 1 and 2", prep.Done, prep.Skipped)
	}
	pb, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pb), "Office_Laser\tipp://10.0.0.5/ipp/print\teverywhere\t1\tRoom 4") {
		t.Errorf("printer plan:\n%s", pb)
	}
}

// §4.2: the disclosure says, per network and per printer, what this run will
// actually carry — and never prints a key.
func TestDisclosure_SaysExactlyWhatComesAcross(t *testing.T) {
	var out bytes.Buffer
	printDisclosure(&out, nil, gatherExtras(syntheticMachine()))
	s := out.String()

	for _, want := range []string{
		"SchoolNet: comes across, WITH its password",
		"HomeNet: name only, password does NOT come across: Windows gives the password only to an administrator",
		"eduroam: name only, does NOT come across",
		"1 Wi-Fi password(s) will be written to the backup drive IN PLAIN TEXT",
		"Office Laser: its address comes across (ipp://10.0.0.5/ipp/print)",
		"supports IPP Everywhere",
		`\\printsrv\Library: does NOT come across`,
		"Desk Inkjet: does NOT come across",
		"account name does NOT come across",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("disclosure is missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, secretKey) {
		t.Fatal("the disclosure printed a Wi-Fi key")
	}
	if strings.Contains(s, "Wi-Fi networks, printers and") {
		t.Error("the old blanket claim is back")
	}
}

func TestDisclosure_NoWirelessServiceIsNotNoNetworks(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("%w (stopped)", winenv.ErrNoWLAN), "wireless service is not available"},
		{errors.New("WlanEnumInterfaces: RPC failed"), "could not be read (WlanEnumInterfaces: RPC failed)"},
	} {
		var out bytes.Buffer
		printDisclosure(&out, nil, gatherExtras(winenv.NewSynthetic(winenv.SyntheticConfig{WiFiErr: c.err})))
		if !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), "no saved Wi-Fi networks") {
			t.Errorf("%v: a machine we could not ask was not reported as such:\n%s", c.err, out.String())
		}
	}
}

// The API hands back UTF-16, the export is UTF-8, and a prolog that still says
// UTF-16 makes encoding/xml on the Linux side refuse the profile outright.
func TestUTF8Prolog_TheLinuxParserAcceptsWhatWeWrite(t *testing.T) {
	raw := "\ufeff" + wlanXML("SchoolNet", "WPA2PSK", "AES", false, false, secretKey, true)
	if _, err := netprofile.Parse([]byte(raw)); err == nil {
		t.Fatal("precondition: the unmodified prolog should be refused, or this test proves nothing")
	}
	p, err := netprofile.Parse([]byte(utf8Prolog(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if p.SSID != "SchoolNet" || p.KeyMaterial != secretKey {
		t.Errorf("parsed %q / key ok=%v", p.SSID, p.KeyMaterial == secretKey)
	}
}

func TestProfileFileName_SafeAndUnique(t *testing.T) {
	used := map[string]bool{}
	got := []string{
		profileFileName(`Cafe: "Free"/WiFi?`, used),
		profileFileName("home", used),
		profileFileName("HOME", used),
		profileFileName("..", used),
	}
	want := []string{`Cafe_ _Free__WiFi_.xml`, "home.xml", "HOME-2.xml", "network.xml"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %q, want %q", i, got[i], want[i])
		}
	}
	if _, err := manifest.CleanRel(labels.WiFi + "/" + got[0]); err != nil {
		t.Error(err)
	}
}
