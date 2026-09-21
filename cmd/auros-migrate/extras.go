package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/labels"
	"github.com/aarohkandy/auros-installer/internal/netprofile"
	"github.com/aarohkandy/auros-installer/internal/printers"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// extras are the two things that are not files: saved Wi-Fi networks and
// printers (SYSTEM-REVIEW §2.8). They are read in phase 1, disclosed network by
// network in phase 2, and written into the archive in phase 4 under
// labels.WiFi and labels.Printers — the segments the Linux router hands to
// internal/netprofile and internal/printers. The decisions shown in the
// disclosure are made by those same two packages, so the Windows screen and
// the Linux report cannot disagree about what came across.
type extras struct {
	wifi        []winenv.WiFiProfile
	wifiErr     error
	printers    []printers.Printer
	printersErr error
}

func gatherExtras(env winenv.Env) extras {
	var x extras
	x.wifi, x.wifiErr = env.WiFiProfiles()
	x.printers, x.printersErr = env.Printers()
	return x
}

// exportMode is the mode of every staged export file. On NTFS Go maps it to
// "not read-only" and nothing more, and a FAT or exFAT stick has no
// permissions at all — which is why the disclosure says the stick itself
// holds the passwords, rather than implying a file mode protects them.
const exportMode os.FileMode = 0o600

// exportDirName sits under the metadata directory, which verify excludes from
// its count, so the staging copy is never mistaken for archive content.
const exportDirName = "export"

// stage writes the exports under root (on the DESTINATION volume) and returns
// them as copy sources. The copy engine then hashes, records and verifies them
// like any other file. Nothing is written anywhere else: phase 4 may write
// only to the destination.
func (x extras) stage(root string) ([]copyengine.Source, error) {
	var out []copyengine.Source
	if len(x.wifi) > 0 {
		dir := filepath.Join(root, labels.WiFi)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		used := make(map[string]bool)
		for _, p := range x.wifi {
			name := profileFileName(p.Name, used)
			if err := writeSecret(filepath.Join(dir, name), []byte(utf8Prolog(p.XML))); err != nil {
				// The error names the file, never the contents.
				return nil, fmt.Errorf("staging Wi-Fi profile %q: %w", p.Name, err)
			}
		}
		out = append(out, copyengine.Source{Root: dir, Label: labels.WiFi})
	}
	if len(x.printers) > 0 {
		dir := filepath.Join(root, labels.Printers)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := writeSecret(filepath.Join(dir, printers.FileName), printers.Render(x.printers)); err != nil {
			return nil, fmt.Errorf("staging the printer list: %w", err)
		}
		out = append(out, copyengine.Source{Root: dir, Label: labels.Printers})
	}
	return out, nil
}

func writeSecret(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, exportMode)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// profileFileName makes a profile name a file name that FAT, exFAT and NTFS
// all accept, unique within the export. The Linux side reads the SSID from the
// XML, not from this name.
func profileFileName(name string, used map[string]bool) string {
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`<>:"/\|?*`, r) {
			r = '_'
		}
		b.WriteRune(r)
	}
	base := strings.Trim(b.String(), " .")
	if base == "" {
		base = "network"
	}
	cand := base + ".xml"
	for i := 2; used[strings.ToLower(cand)]; i++ {
		cand = fmt.Sprintf("%s-%d.xml", base, i)
	}
	used[strings.ToLower(cand)] = true
	return cand
}

// utf8Prolog makes the XML declaration true of the bytes we write. The API
// returns UTF-16, we write UTF-8, and a prolog still saying encoding="UTF-16"
// makes Go's encoding/xml on the Linux side refuse the whole profile.
func utf8Prolog(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	if strings.HasPrefix(s, "<?xml") {
		if end := strings.Index(s, "?>"); end >= 0 {
			return `<?xml version="1.0" encoding="UTF-8"?>` + s[end+2:]
		}
	}
	return s
}

// wifiLine is one network's line in the disclosure, from netprofile's own
// decision. It never contains key material.
func wifiLine(p winenv.WiFiProfile) (ssid, what string, carriesKey bool) {
	np, err := netprofile.Parse([]byte(utf8Prolog(p.XML)))
	if err != nil {
		return p.Name, "does NOT come across — Windows returned a profile this tool cannot read", false
	}
	v, why := np.Decide()
	switch v {
	case netprofile.VerdictWrite:
		if np.KeyMaterial != "" {
			return np.SSID, "comes across, WITH its password — " + why, true
		}
		return np.SSID, "comes across — " + why, false
	case netprofile.VerdictNoCredentials:
		if np.KeyProtected {
			return np.SSID, "name only, password does NOT come across: Windows gives the password only " +
				"to an administrator (run this tool as administrator to include it)", false
		}
		return np.SSID, "name only, password does NOT come across — " + why, false
	default:
		return np.SSID, "name only, does NOT come across — " + why, false
	}
}

// printDisclosure is prohibition §4.2 and SAFETY.md phase 2. It prints the
// actual installed-programs list by name, and — for Wi-Fi and printers — what
// happens to each one, by name. Nothing is described as coming across unless
// this run will actually put it in the archive.
func printDisclosure(w io.Writer, programs []winenv.Program, x extras) {
	fmt.Fprintf(w, "\n  WHAT DOES NOT COME ACROSS\n")
	fmt.Fprintf(w, "  Windows programs do not migrate. Not any of them. These %d will be gone:\n\n", len(programs))
	names := make([]string, 0, len(programs))
	for _, p := range programs {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(w, "    - %s\n", n)
	}

	fmt.Fprintf(w, "\n  WI-FI NETWORKS\n")
	withKey := 0
	switch {
	case errors.Is(x.wifiErr, winenv.ErrNoWLAN) && len(x.wifi) == 0:
		fmt.Fprintf(w, "  None come across: this computer's wireless service is not available, so no\n"+
			"  saved networks could be read.\n")
	case x.wifiErr != nil && len(x.wifi) == 0:
		fmt.Fprintf(w, "  None come across: the saved networks could not be read (%v).\n", x.wifiErr)
	case len(x.wifi) == 0:
		fmt.Fprintf(w, "  This computer has no saved Wi-Fi networks.\n")
	default:
		for _, p := range x.wifi {
			ssid, what, key := wifiLine(p)
			if key {
				withKey++
			}
			fmt.Fprintf(w, "    - %s: %s\n", ssid, what)
		}
		if x.wifiErr != nil {
			fmt.Fprintf(w, "  Some saved networks could not be read and do NOT come across (%v).\n", x.wifiErr)
		}
		fmt.Fprintf(w, "  On the new computer these are saved but not switched on until someone with\n"+
			"  administrator rights there installs them.\n")
	}
	if withKey > 0 {
		fmt.Fprintf(w, "  %d Wi-Fi password(s) will be written to the backup drive IN PLAIN TEXT.\n"+
			"  Anyone holding the drive can read them. Keep it safe, and wipe it once the new\n"+
			"  computer is set up.\n", withKey)
	}

	fmt.Fprintf(w, "\n  PRINTERS\n")
	switch {
	case x.printersErr != nil:
		fmt.Fprintf(w, "  None come across: the printer list could not be read (%v).\n", x.printersErr)
	case len(x.printers) == 0:
		fmt.Fprintf(w, "  This computer has no printers set up.\n")
	default:
		for _, p := range x.printers {
			d := printers.Decide(p)
			if d.Disp == printers.DispNetworkQueue {
				fmt.Fprintf(w, "    - %s: its address comes across (%s). The Windows driver does not; the\n"+
					"      new computer sets it up driverless, which works only if the printer\n"+
					"      supports IPP Everywhere. It is not added until someone with administrator\n"+
					"      rights there does so.\n", p.Name, d.DeviceURI)
				continue
			}
			fmt.Fprintf(w, "    - %s: does NOT come across (%s).\n", p.Name, d.Disp)
		}
	}

	fmt.Fprintf(w, "\n  Your files and browser bookmarks and history come across.\n")
	fmt.Fprintf(w, "  Your account name does NOT come across: you create it on the new computer.\n")
	fmt.Fprintf(w, "  Saved passwords, cookies and payment details in Chrome and Edge DO NOT.\n")
	fmt.Fprintf(w, "  Export or sync them before you start.\n")
}
