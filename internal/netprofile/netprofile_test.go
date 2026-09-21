package netprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// wlan renders an export in the shape `netsh wlan export profile` produces.
func wlan(name, ssidHex, auth, enc, keyType, key string, protected, nonBroadcast, oneX bool) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
	<name>%s</name>
	<SSIDConfig>
		<SSID><hex>%s</hex><name>%s</name></SSID>
		<nonBroadcast>%v</nonBroadcast>
	</SSIDConfig>
	<connectionType>ESS</connectionType>
	<connectionMode>auto</connectionMode>
	<MSM>
		<security>
			<authEncryption>
				<authentication>%s</authentication>
				<encryption>%s</encryption>
				<useOneX>%v</useOneX>
			</authEncryption>
			<sharedKey>
				<keyType>%s</keyType>
				<protected>%v</protected>
				<keyMaterial>%s</keyMaterial>
			</sharedKey>
		</security>
	</MSM>
</WLANProfile>`, name, ssidHex, name, nonBroadcast, auth, enc, oneX, keyType, protected, key)
}

func hexOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%02X", s[i])
	}
	return b.String()
}

func TestDecide_TheWholeMatrix(t *testing.T) {
	cases := []struct {
		name        string
		auth, enc   string
		key         string
		protected   bool
		oneX        bool
		want        Verdict
		mustMention string
	}{
		{"WPA2 personal with the password", "WPA2PSK", "AES", "hunter2hunter2", false, false, VerdictWrite, "password"},
		{"WPA3 personal", "WPA3SAE", "AES", "hunter2hunter2", false, false, VerdictWrite, "password"},
		{"WPA personal", "WPAPSK", "TKIP", "hunter2hunter2", false, false, VerdictWrite, "password"},
		{"open network", "open", "none", "", false, false, VerdictWrite, "no password"},
		{"WEP with a key", "open", "WEP", "abcde", false, false, VerdictWrite, "obsolete"},
		{"exported WITHOUT key=clear", "WPA2PSK", "AES", "AE11FF", true, false, VerdictNoCredentials, "sealed"},
		{"no key material at all", "WPA2PSK", "AES", "", false, false, VerdictNoCredentials, "not included"},
		{"WPA2 enterprise", "WPA2", "AES", "", false, false, VerdictEnterprise, "account"},
		{"802.1X flag set on a PSK profile", "WPA2PSK", "AES", "x", false, true, VerdictEnterprise, "account"},
		{"something from the future", "WPA9QUANTUM", "PQC", "x", false, false, VerdictUnsupported, "unrecognised"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse([]byte(wlan("Net", hexOf("Net"), c.auth, c.enc, "passPhrase", c.key, c.protected, false, c.oneX)))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, why := p.Decide()
			if got != c.want {
				t.Fatalf("verdict = %q (%s), want %q", got, why, c.want)
			}
			if !strings.Contains(why, c.mustMention) {
				t.Errorf("the reason %q does not mention %q, so the user cannot act on it", why, c.mustMention)
			}
		})
	}
}

func TestWrite_EnterpriseAndSealedProfilesProduceNoFile(t *testing.T) {
	// "Nothing that does not map honestly." A connection file that cannot
	// possibly associate is worse than no file, because it fails later, in
	// front of a classroom, for no visible reason.
	dir := t.TempDir()
	var profiles []*Profile
	for _, x := range []struct {
		auth, key       string
		protected, oneX bool
	}{
		{"WPA2", "", false, false},
		{"WPA3ENT", "", false, false},
		{"WPA2PSK", "AE11FF", true, false},
		{"WPA2PSK", "", false, false},
	} {
		p, err := Parse([]byte(wlan("Net"+x.auth, hexOf("Net"+x.auth), x.auth, "AES", "passPhrase", x.key, x.protected, false, x.oneX)))
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	written, err := Write(dir, profiles, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range written {
		if w.Path != "" {
			t.Errorf("%s produced a file at %s, and it could never have worked", w.Profile.SSID, w.Path)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("%d file(s) were written: %v", len(ents), ents)
	}
}

func TestWrite_TheKeyfileIsSixHundredAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	p, err := Parse([]byte(wlan("StaffWiFi", hexOf("StaffWiFi"), "WPA2PSK", "AES", "passPhrase", "correct horse battery", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	written, err := Write(dir, []*Profile{p}, false)
	if err != nil {
		t.Fatal(err)
	}
	if written[0].Path == "" {
		t.Fatalf("no file written: %s", written[0].Problem)
	}
	st, err := os.Stat(written[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != Mode {
		t.Fatalf("mode = %04o, want %04o — this file holds a Wi-Fi password in clear text",
			st.Mode().Perm(), Mode)
	}
	body, err := os.ReadFile(written[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"[connection]", "id=StaffWiFi", "type=wifi",
		"[wifi]", "mode=infrastructure", "ssid=StaffWiFi",
		"[wifi-security]", "key-mgmt=wpa-psk", "psk=correct horse battery",
		"[ipv4]", "method=auto",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the keyfile is missing %q:\n%s", want, body)
		}
	}
}

func TestWrite_AWorldReadableKeyfileIsRefusedAndDeleted(t *testing.T) {
	// D34: a check nobody has watched fail is not a check. This drives the
	// permission check into its failure branch on purpose. Without it, the
	// sentence "we verify the mode" has never once been true in a red state.
	dir := t.TempDir()
	p, err := Parse([]byte(wlan("StaffWiFi", hexOf("StaffWiFi"), "WPA2PSK", "AES", "passPhrase", "secret", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	orig := modeAfterWrite
	modeAfterWrite = func(path string) (os.FileMode, error) {
		// Pretend the filesystem gave us 0644 — which is exactly what happens
		// on a vfat or exFAT mount, where POSIX modes are a mount option and
		// not a property of the file.
		_ = path
		return 0o644, nil
	}
	defer func() { modeAfterWrite = orig }()

	written, err := Write(dir, []*Profile{p}, false)
	if err != nil {
		t.Fatal(err)
	}
	if written[0].Path != "" {
		t.Fatal("a Wi-Fi password file with the wrong permissions was left in place")
	}
	if !strings.Contains(written[0].Problem, "REFUSED") {
		t.Fatalf("problem = %q, want a refusal", written[0].Problem)
	}
	if !strings.Contains(written[0].Problem, "read it") {
		t.Errorf("the refusal does not say what the consequence would be: %q", written[0].Problem)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".nmconnection") {
			t.Fatalf("the offending file is still on disk: %s", e.Name())
		}
	}
}

func TestWrite_AnExistingFileDoesNotKeepItsOldPermissions(t *testing.T) {
	// O_CREATE does not change the mode of a file that already exists, which
	// is how a second run silently keeps a 0644 left by a first one.
	dir := t.TempDir()
	p, err := Parse([]byte(wlan("StaffWiFi", hexOf("StaffWiFi"), "WPA2PSK", "AES", "passPhrase", "secret", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	pre := filepath.Join(dir, p.FileName())
	if err := os.WriteFile(pre, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, []*Profile{p}, false); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(pre)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != Mode {
		t.Fatalf("mode = %04o after rewriting an existing 0644 file, want %04o", st.Mode().Perm(), Mode)
	}
}

func TestUUID_IsDerivedSoRerunsDoNotDuplicate(t *testing.T) {
	a, err := Parse([]byte(wlan("Net", hexOf("Net"), "WPA2PSK", "AES", "passPhrase", "k1", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(wlan("Net", hexOf("Net"), "WPA2PSK", "AES", "passPhrase", "k2", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	if a.UUID() != b.UUID() {
		t.Error("the same network produced two UUIDs, so a re-run adds a duplicate connection")
	}
	c, err := Parse([]byte(wlan("Other", hexOf("Other"), "WPA2PSK", "AES", "passPhrase", "k1", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	if a.UUID() == c.UUID() {
		t.Error("two different networks share a UUID, so one would replace the other")
	}
	if len(a.UUID()) != 36 || strings.Count(a.UUID(), "-") != 4 {
		t.Errorf("UUID %q is not in the canonical form NetworkManager expects", a.UUID())
	}
}

func TestSSID_AwkwardBytesUseTheUnambiguousForm(t *testing.T) {
	cases := map[string]string{
		"School WiFi": "School WiFi", // plain ASCII: written as-is
		"a;b":         "97;59;98;",   // a semicolon is a list separator in a keyfile
		"back\\slash": "98;97;99;107;92;115;108;97;115;104;",
		" leading":    "32;108;101;97;100;105;110;103;",
	}
	for in, want := range cases {
		if got := ssidValue(in); got != want {
			t.Errorf("ssidValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSSID_ComesFromTheHexNotTheDecodedName(t *testing.T) {
	// The <name> Windows writes is a best-effort decoding. The bytes are the
	// truth, and an SSID that differs by one byte associates with nothing.
	raw := "caf\xc3\xa9"
	x := wlan("cafe-mojibake", hexOf(raw), "open", "none", "passPhrase", "", false, false, false)
	p, err := Parse([]byte(x))
	if err != nil {
		t.Fatal(err)
	}
	if p.SSID != raw {
		t.Errorf("SSID = %q, want the hex-decoded %q", p.SSID, raw)
	}
}

func TestGkeyEscape_TheCharactersThatBreakAKeyfile(t *testing.T) {
	cases := map[string]string{
		`plain`:        `plain`,
		`back\slash`:   `back\\slash`,
		" lead":        `\slead`,
		"trail ":       `trail\s`,
		"tab\there":    `tab\there`,
		"nl\nhere":     `nl\nhere`,
		"mid space ok": "mid space ok",
	}
	for in, want := range cases {
		if got := gkeyEscape(in); got != want {
			t.Errorf("gkeyEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParse_MalformedXMLIsRefused(t *testing.T) {
	for _, bad := range []string{
		"",
		"not xml at all",
		"<WLANProfile><name>unclosed",
		`<?xml version="1.0"?><WLANProfile></WLANProfile>`, // no SSID anywhere
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestFileName_NeverEscapesItsDirectory(t *testing.T) {
	for _, ssid := range []string{"../../etc/passwd", "/absolute", ".hidden", "", "with/slash"} {
		p := &Profile{SSID: ssid, Authentication: "WPA2PSK"}
		n := p.FileName()
		if strings.Contains(n, "/") {
			t.Errorf("FileName() for %q is %q, which contains a path separator", ssid, n)
		}
		if strings.HasPrefix(n, ".") {
			t.Errorf("FileName() for %q is %q, which is a hidden file", ssid, n)
		}
	}
}

func TestResolveSystemDir_NeverClaimsADirectoryItHasNotLookedAt(t *testing.T) {
	staging := t.TempDir()
	dir, installed, why := ResolveSystemDir(false, staging)
	if installed || dir != staging {
		t.Errorf("as a normal user: dir=%s installed=%v, want the staging directory", dir, installed)
	}
	if !strings.Contains(why, "root") {
		t.Errorf("the reason does not say why: %q", why)
	}
	// As "root" on a machine with no NetworkManager: it must NOT claim the
	// system directory, because it is not there.
	dir, installed, why = ResolveSystemDir(true, staging)
	if _, err := os.Stat(SystemConnectionsDir); err != nil {
		if installed || dir != staging {
			t.Errorf("with no %s present: dir=%s installed=%v", SystemConnectionsDir, dir, installed)
		}
		if !strings.Contains(why, SystemConnectionsDir) {
			t.Errorf("the reason does not name what it looked for: %q", why)
		}
	}
}

func TestKeyfile_AHiddenNetworkIsMarkedHidden(t *testing.T) {
	p, err := Parse([]byte(wlan("Hidden", hexOf("Hidden"), "WPA2PSK", "AES", "passPhrase", "k", false, true, false)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Keyfile(), "hidden=true") {
		t.Errorf("a non-broadcast network is not marked hidden:\n%s", p.Keyfile())
	}
}

func TestKeyfile_AnOpenNetworkHasNoSecuritySection(t *testing.T) {
	p, err := Parse([]byte(wlan("Guest", hexOf("Guest"), "open", "none", "", "", false, false, false)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p.Keyfile(), "[wifi-security]") {
		t.Errorf("an open network got a security section:\n%s", p.Keyfile())
	}
}
