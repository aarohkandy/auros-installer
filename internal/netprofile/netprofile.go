// Package netprofile turns a Windows wireless profile into a NetworkManager
// connection, and refuses to turn the ones that do not map.
//
// # What a Windows export actually contains
//
// `netsh wlan export profile key=clear` writes one XML file per saved network.
// With key=clear the pre-shared key is in the file in plain text. WITHOUT it,
// <protected>true</protected> and the key material is DPAPI-sealed to the old
// machine's account — unreadable here, and we say so rather than writing a
// connection that silently will not associate.
//
// # What does not map, and is not attempted
//
// 802.1X / enterprise networks (WPA2-Enterprise, the "log in with your school
// account" kind) keep their credentials in the Windows credential vault and the
// certificate store, NOT in the exported profile. There is nothing in the
// archive to migrate. The network is NAMED in the report so the user knows to
// reconnect, and no connection file is written, because a connection file that
// cannot possibly work is worse than no file: it fails at a moment when the
// user has no idea why.
//
// # Why the file mode is a hard check and not a chmod
//
// A NetworkManager keyfile holds the Wi-Fi password in clear text. NM itself
// REFUSES to load a system connection that is group- or world-readable, so a
// wrong mode is both a real disclosure and a silent failure to connect. This
// package writes 0600, then reads the mode back off the disk and fails the
// profile if it is not 0600. A chmod whose result is never checked is the kind
// of check this project has already been burned by.
package netprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Profile is a parsed Windows wireless profile.
type Profile struct {
	Name           string
	SSID           string
	SSIDHex        string
	NonBroadcast   bool
	ConnectionType string // ESS (infrastructure) or IBSS (ad-hoc)
	ConnectionMode string // auto or manual
	Authentication string
	Encryption     string
	UseOneX        bool
	KeyType        string // passPhrase or networkKey
	KeyProtected   bool
	KeyMaterial    string
}

// Verdict is what we decided about one profile.
type Verdict string

const (
	// VerdictWrite means a NetworkManager connection was produced.
	VerdictWrite Verdict = "migrated"
	// VerdictNoCredentials means the network is real but its credentials are
	// not in the archive and cannot be.
	VerdictNoCredentials Verdict = "network named, password not in the backup"
	// VerdictEnterprise means 802.1X: nothing to migrate, by construction.
	VerdictEnterprise Verdict = "802.1X — sign in again on this machine"
	// VerdictUnsupported means the profile is something this code will not
	// pretend to understand.
	VerdictUnsupported Verdict = "not migrated"
)

var errNoSSID = errors.New("netprofile: profile has no SSID")

// wlanProfile mirrors the XML. Only the fields we act on are decoded; anything
// else in the file is ignored rather than guessed at.
type wlanProfile struct {
	XMLName    xml.Name `xml:"WLANProfile"`
	Name       string   `xml:"name"`
	SSIDConfig struct {
		SSID []struct {
			Hex  string `xml:"hex"`
			Name string `xml:"name"`
		} `xml:"SSID"`
		NonBroadcast string `xml:"nonBroadcast"`
	} `xml:"SSIDConfig"`
	ConnectionType string `xml:"connectionType"`
	ConnectionMode string `xml:"connectionMode"`
	MSM            struct {
		Security struct {
			AuthEncryption struct {
				Authentication string `xml:"authentication"`
				Encryption     string `xml:"encryption"`
				UseOneX        string `xml:"useOneX"`
			} `xml:"authEncryption"`
			SharedKey struct {
				KeyType     string `xml:"keyType"`
				Protected   string `xml:"protected"`
				KeyMaterial string `xml:"keyMaterial"`
			} `xml:"sharedKey"`
		} `xml:"security"`
	} `xml:"MSM"`
}

// Parse reads one exported profile.
func Parse(b []byte) (*Profile, error) {
	var w wlanProfile
	if err := xml.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("netprofile: %w", err)
	}
	p := &Profile{
		Name:           strings.TrimSpace(w.Name),
		NonBroadcast:   isTrue(w.SSIDConfig.NonBroadcast),
		ConnectionType: strings.TrimSpace(w.ConnectionType),
		ConnectionMode: strings.TrimSpace(w.ConnectionMode),
		Authentication: strings.TrimSpace(w.MSM.Security.AuthEncryption.Authentication),
		Encryption:     strings.TrimSpace(w.MSM.Security.AuthEncryption.Encryption),
		UseOneX:        isTrue(w.MSM.Security.AuthEncryption.UseOneX),
		KeyType:        strings.TrimSpace(w.MSM.Security.SharedKey.KeyType),
		KeyProtected:   isTrue(w.MSM.Security.SharedKey.Protected),
		KeyMaterial:    w.MSM.Security.SharedKey.KeyMaterial,
	}
	for _, s := range w.SSIDConfig.SSID {
		if s.Name != "" && p.SSID == "" {
			p.SSID = s.Name
		}
		if s.Hex != "" && p.SSIDHex == "" {
			p.SSIDHex = strings.TrimSpace(s.Hex)
		}
	}
	// The <hex> form is authoritative when present: an SSID is a byte string,
	// not text, and Windows writes <name> as a best-effort decoding of it.
	if p.SSIDHex != "" {
		if raw, err := hex.DecodeString(p.SSIDHex); err == nil && len(raw) > 0 {
			p.SSID = string(raw)
		}
	}
	if p.SSID == "" {
		p.SSID = p.Name
	}
	if p.SSID == "" {
		return nil, errNoSSID
	}
	return p, nil
}

func isTrue(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "true") }

// Decide classifies a profile. It is separated from rendering so a test can
// assert the DECISION for each authentication mode without writing a file.
func (p *Profile) Decide() (Verdict, string) {
	auth := strings.ToUpper(p.Authentication)
	switch {
	case p.UseOneX || auth == "WPA" || auth == "WPA2" || auth == "WPA3ENT" || auth == "WPA3ENT192":
		return VerdictEnterprise, "this network signs you in with an account, and Windows kept " +
			"those details somewhere the backup could not reach"
	case auth == "OPEN" && strings.EqualFold(p.Encryption, "none"):
		return VerdictWrite, "open network, no password"
	case auth == "OPEN" || auth == "SHARED":
		// WEP. Ancient and broken, and still what some school projectors run on.
		if p.KeyProtected || p.KeyMaterial == "" {
			return VerdictNoCredentials, "the password was not included in the backup"
		}
		return VerdictWrite, "WEP — this network's security is obsolete and anyone nearby can read it"
	case auth == "WPAPSK" || auth == "WPA2PSK" || auth == "WPA3SAE":
		if p.KeyProtected {
			return VerdictNoCredentials, "the password was sealed to the old computer and is not in the backup"
		}
		if p.KeyMaterial == "" {
			return VerdictNoCredentials, "the password was not included in the backup"
		}
		return VerdictWrite, "password came across"
	default:
		return VerdictUnsupported, fmt.Sprintf("unrecognised security setting %q/%q", p.Authentication, p.Encryption)
	}
}

// keyMgmt maps the Windows authentication string onto NetworkManager's.
func (p *Profile) keyMgmt() string {
	switch strings.ToUpper(p.Authentication) {
	case "WPA3SAE":
		return "sae"
	case "WPAPSK", "WPA2PSK":
		return "wpa-psk"
	case "OPEN", "SHARED":
		if strings.EqualFold(p.Encryption, "none") {
			return ""
		}
		return "none" // NM's spelling for static WEP
	}
	return ""
}

// UUID is derived from the SSID and the key management, never random.
//
// That is what makes a re-run idempotent: the same network produces the same
// UUID, so NetworkManager replaces the connection instead of accumulating
// "SchoolWiFi 1", "SchoolWiFi 2", "SchoolWiFi 3" every time somebody runs the
// restore again.
func (p *Profile) UUID() string {
	sum := sha256.Sum256([]byte("auros-wifi\x00" + p.SSID + "\x00" + p.keyMgmt()))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4 shape
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// Keyfile renders the NetworkManager connection.
func (p *Profile) Keyfile() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	w("# Written by auros-restore from a Windows wireless profile.")
	w("# Original Windows profile name: %s", gkeyEscape(p.Name))
	w("[connection]")
	w("id=%s", gkeyEscape(p.SSID))
	w("uuid=%s", p.UUID())
	w("type=wifi")
	if strings.EqualFold(p.ConnectionMode, "manual") {
		w("autoconnect=false")
	} else {
		w("autoconnect=true")
	}
	w("")
	w("[wifi]")
	if strings.EqualFold(p.ConnectionType, "IBSS") {
		w("mode=adhoc")
	} else {
		w("mode=infrastructure")
	}
	w("ssid=%s", ssidValue(p.SSID))
	if p.NonBroadcast {
		w("hidden=true")
	}

	if km := p.keyMgmt(); km != "" {
		w("")
		w("[wifi-security]")
		w("key-mgmt=%s", km)
		switch km {
		case "none":
			w("wep-key0=%s", gkeyEscape(p.KeyMaterial))
			if strings.EqualFold(p.KeyType, "passPhrase") {
				w("wep-key-type=2") // passphrase
			} else {
				w("wep-key-type=1") // hexadecimal or ASCII key
			}
			w("auth-alg=%s", map[bool]string{true: "shared", false: "open"}[strings.EqualFold(p.Authentication, "shared")])
		default:
			w("psk=%s", gkeyEscape(p.KeyMaterial))
		}
	}

	w("")
	w("[ipv4]")
	w("method=auto")
	w("")
	w("[ipv6]")
	w("method=auto")
	return b.String()
}

// ssidValue renders the SSID for the keyfile.
//
// An SSID is a byte string, and plenty of them are not valid UTF-8 or contain
// the characters GKeyFile treats specially. When the plain form would be
// ambiguous, the byte-array form is used instead — NetworkManager accepts both
// and the byte array cannot be misread.
func ssidValue(ssid string) string {
	plain := true
	for i := 0; i < len(ssid); i++ {
		c := ssid[i]
		if c < 0x20 || c > 0x7e || c == ';' || c == '\\' {
			plain = false
			break
		}
	}
	if plain && ssid != "" && ssid[0] != ' ' && ssid[len(ssid)-1] != ' ' {
		return ssid
	}
	parts := make([]string, 0, len(ssid))
	for i := 0; i < len(ssid); i++ {
		parts = append(parts, fmt.Sprintf("%d", ssid[i]))
	}
	return strings.Join(parts, ";") + ";"
}

// gkeyEscape escapes a GKeyFile string value. NetworkManager's keyfile parser
// is GKeyFile's, so a backslash or a leading space written literally comes back
// as something else — and "something else" for a psk= line is a password that
// does not work, on a first boot, with no clue why.
func gkeyEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case ' ':
			if i == 0 || i == len(s)-1 {
				b.WriteString(`\s`)
			} else {
				b.WriteByte(c)
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// FileName is the keyfile's name on disk. NetworkManager does not care what it
// is called; a human reading /etc/NetworkManager/system-connections does.
func (p *Profile) FileName() string {
	safe := make([]rune, 0, len(p.SSID))
	for _, r := range p.SSID {
		switch {
		case r == '/' || r == 0 || r < 0x20:
			safe = append(safe, '_')
		default:
			safe = append(safe, r)
		}
	}
	name := strings.TrimSpace(string(safe))
	if name == "" || strings.HasPrefix(name, ".") {
		name = "network-" + p.UUID()[:8]
	}
	return name + ".nmconnection"
}

// Written is one profile's fate on disk.
type Written struct {
	Profile *Profile
	Verdict Verdict
	Why     string
	Path    string // empty unless a file was written
	Problem string // non-empty means the file was NOT left in place
}

// Mode is the only permission a wireless keyfile may have.
const Mode os.FileMode = 0o600

// modeAfterWrite is a test seam. It reports the mode a freshly written file
// actually has. Tests replace it to prove that the permission check below can
// go red — a check whose failure branch has never been executed is not a check
// (DECISIONS.md D34).
var modeAfterWrite = func(path string) (os.FileMode, error) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return st.Mode().Perm(), nil
}

// Write renders profiles into dir. asRoot chowns each file to root:root, which
// is what NetworkManager requires of a system connection; when false the files
// are staged for a privileged step to install and the caller says so.
//
// Every file is written, then READ BACK, and a file whose mode is not exactly
// 0600 is DELETED and reported. Leaving a world-readable Wi-Fi password on disk
// while reporting success is a real defect, not a cosmetic one.
func Write(dir string, profiles []*Profile, asRoot bool) ([]Written, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	out := make([]Written, 0, len(profiles))
	for _, p := range profiles {
		v, why := p.Decide()
		rec := Written{Profile: p, Verdict: v, Why: why}
		if v != VerdictWrite {
			out = append(out, rec)
			continue
		}
		path := filepath.Join(dir, p.FileName())
		// O_WRONLY|O_CREATE|O_TRUNC with an explicit mode, so the file is never
		// briefly 0644 between creation and a chmod.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, Mode)
		if err != nil {
			rec.Problem = "could not write it: " + err.Error()
			out = append(out, rec)
			continue
		}
		_, werr := f.WriteString(p.Keyfile())
		cerr := f.Close()
		if werr == nil {
			werr = cerr
		}
		if werr != nil {
			os.Remove(path)
			rec.Problem = "could not write it: " + werr.Error()
			out = append(out, rec)
			continue
		}
		// An existing file keeps its old mode through O_CREATE, so set it
		// explicitly rather than trusting the create.
		if err := os.Chmod(path, Mode); err != nil {
			os.Remove(path)
			rec.Problem = "could not set the permissions: " + err.Error()
			out = append(out, rec)
			continue
		}
		got, merr := modeAfterWrite(path)
		if merr != nil {
			os.Remove(path)
			rec.Problem = "could not check the permissions: " + merr.Error()
			out = append(out, rec)
			continue
		}
		if got != Mode {
			os.Remove(path)
			rec.Problem = fmt.Sprintf(
				"REFUSED: the Wi-Fi password file came out as %04o instead of %04o, which would let "+
					"any account on this computer read it. The file was deleted and the network was not added.",
				got, Mode)
			out = append(out, rec)
			continue
		}
		if asRoot {
			if err := os.Chown(path, 0, 0); err != nil {
				os.Remove(path)
				rec.Problem = "could not give the file to root, which NetworkManager requires: " + err.Error()
				out = append(out, rec)
				continue
			}
		}
		rec.Path = path
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Profile.SSID < out[j].Profile.SSID })
	return out, nil
}

// SystemConnectionsDir is where NetworkManager reads system connections from.
// Probed, not assumed: see netprofile.ResolveSystemDir.
const SystemConnectionsDir = "/etc/NetworkManager/system-connections"

// ResolveSystemDir answers where the keyfiles should go on THIS machine, and
// says why. It never returns a path it has not looked at.
func ResolveSystemDir(asRoot bool, stagingDir string) (dir string, installed bool, why string) {
	if !asRoot {
		return stagingDir, false, "not running as root, so the connections are staged in " + stagingDir +
			" for the system to install"
	}
	st, err := os.Stat(SystemConnectionsDir)
	if err != nil {
		return stagingDir, false, fmt.Sprintf(
			"%s is not there (%v), so the connections are staged in %s instead",
			SystemConnectionsDir, err, stagingDir)
	}
	if !st.IsDir() {
		return stagingDir, false, fmt.Sprintf(
			"%s is a %s, not a directory, so the connections are staged in %s instead",
			SystemConnectionsDir, st.Mode().String(), stagingDir)
	}
	return SystemConnectionsDir, true, "installed straight into " + SystemConnectionsDir
}
