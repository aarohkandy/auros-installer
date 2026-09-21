//go:build windows

package gate3

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE KNOWN-FOLDERS PROBLEM, AND HOW THIS HARNESS SOLVES IT
//
// `auros-migrate` always inventories the known folders of the account running
// it. That is not a flag and it must not become one: SAFETY.md phase 1 exists
// because a migration tool that can be told to skip the user's real folders is
// a migration tool that will one day skip them.
//
// On a hosted runner that means the CI account's own Documents, Desktop,
// Pictures, Downloads and AppData would be copied along with the corpus, and a
// comparison against a golden manifest would either fail for a reason that has
// nothing to do with the installer, or — much worse — pass while measuring files
// nobody generated.
//
// Three ways out were available. This is the one taken, and why:
//
//  1. CHOSEN: a dedicated local account whose known folders are REDIRECTED to
//     the synthetic corpus, and the installer runs as that account.
//
//     Folder redirection is not a trick invented for the test. It is the exact
//     configuration SAFETY.md phase 1 names — "Documents is redirected far more
//     often than people expect, and a school laptop is exactly where that
//     happens" — so the test is not merely convenient, it is more faithful than
//     an ordinary profile would have been. It also gives the harness something
//     it otherwise could not check: an installer that built its paths from
//     %USERPROFILE% instead of asking Windows would inventory empty folders and
//     the run would go red, which is check C9.
//
//  2. Rejected: a dedicated account whose PROFILE DIRECTORY is the corpus, with
//     no redirection. Closer to a stock machine, but the account's own hive
//     files (NTUSER.DAT, UsrClass.dat) then live inside the inventoried folders,
//     are held open by the kernel for as long as the user is logged on, and are
//     quarantined by the installer on every run — so every clean run would fail
//     for a reason that has nothing to do with the property under test. That IS
//     a real finding about the product and it is reported separately, as a
//     finding, rather than by making the whole suite red.
//
//  3. Rejected: a build-tagged switch in the installer that restricts the
//     inventory to --source. The brief allowed it behind a build tag with a wall
//     test. It was still the wrong trade: it puts a code path that skips the
//     user's real folders into the repository, where the next person to need a
//     quick test finds it, and buys nothing that (1) does not already give.
//
// Nothing in internal/ or cmd/ was changed to make this harness work.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// MigrationUser is the account whose known folders are the corpus. Its name
	// appears in the change-journal noise list, so changing it here means
	// changing it there.
	MigrationUser = "auros-gate3"

	hkeyUsers = 0x80000003
	keyWrite  = 0x20006 // KEY_WRITE
	regSZ     = 1
)

var (
	modnetapi32                 = syscall.NewLazyDLL("netapi32.dll")
	procNetUserAdd              = modnetapi32.NewProc("NetUserAdd")
	procNetUserDel              = modnetapi32.NewProc("NetUserDel")
	procNetLocalGroupAddMembers = modnetapi32.NewProc("NetLocalGroupAddMembers")
	procRegCreateKeyExW         = modadvapi32.NewProc("RegCreateKeyExW")
	procRegSetValueExW          = modadvapi32.NewProc("RegSetValueExW")
	procRegCloseKeyP            = modadvapi32.NewProc("RegCloseKey")
)

type userInfo1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type localgroupMembersInfo3 struct {
	DomainAndName *uint16
}

// NewPassword returns a random password for the migration account.
//
// It is generated on the machine, never printed, never written to the workflow
// log and never put on a command line: the account exists for the length of one
// CI job on a machine that is destroyed afterwards, and it is still not an
// excuse to put a password where a log can keep it.
func NewPassword() (string, error) {
	var b [30]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "Aa1!" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// CreateMigrationUser creates the local account, or reuses it if a previous step
// in the same job already made it.
func CreateMigrationUser(name, password string) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	p, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return err
	}
	c, _ := syscall.UTF16PtrFromString("Auros Gate 3 harness: the account whose known folders are the synthetic corpus")
	ui := userInfo1{
		Name: n, Password: p, Priv: 1, Comment: c,
		Flags: 0x0001 | 0x10000, // UF_SCRIPT | UF_DONT_EXPIRE_PASSWD
	}
	var parmErr uint32
	r1, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&ui)), uintptr(unsafe.Pointer(&parmErr)))
	switch r1 {
	case 0: // NERR_Success
	case 2224: // NERR_UserExists
	default:
		return fmt.Errorf("gate3: NetUserAdd(%s) failed with %d (parm %d)", name, r1, parmErr)
	}

	// Administrators, because the installer is a program that needs
	// administrative rights at the wall and the run must not be a test of a
	// weaker program than the one that ships. It also makes the invariant check
	// meaningful: a process that could not write to C: anyway proves much less
	// by not writing to it.
	member, err := syscall.UTF16PtrFromString(hostname() + `\` + name)
	if err != nil {
		return err
	}
	mi := localgroupMembersInfo3{DomainAndName: member}
	grp, _ := syscall.UTF16PtrFromString("Administrators")
	r1, _, _ = procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(grp)), 3,
		uintptr(unsafe.Pointer(&mi)), 1)
	switch r1 {
	case 0, 1378: // NERR_Success, ERROR_MEMBER_IN_ALIAS
	default:
		return fmt.Errorf("gate3: NetLocalGroupAddMembers(%s) failed with %d", name, r1)
	}
	return nil
}

// DeleteMigrationUser removes the account. The runner is thrown away either way;
// this exists so the same machine can be reused during development.
func DeleteMigrationUser(name string) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	r1, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(n)))
	if r1 != 0 && r1 != 2221 { // NERR_UserNotFound
		return fmt.Errorf("gate3: NetUserDel(%s) failed with %d", name, r1)
	}
	return nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "."
	}
	return h
}

// RedirectKnownFolders points the migration user's known folders at the corpus,
// by writing the redirection into that user's own hive.
//
// This is what Windows itself does for folder redirection, and it is what
// SHGetKnownFolderPath reads. Both the modern key and the legacy cache are
// written, because Explorer maintains both and a tool that read the stale one
// would otherwise silently see the old path.
func RedirectKnownFolders(s *UserSession, corpusRoot string) (map[string]string, error) {
	if s.SID == "" {
		return nil, fmt.Errorf("gate3: the migration user's SID is unknown, so its hive cannot be found")
	}
	corpusRoot = strings.TrimRight(corpusRoot, `\`)
	// name in the registry -> corpus subdirectory
	targets := []struct{ value, sub string }{
		{"Desktop", "Desktop"},
		{"Personal", "Documents"},
		{"{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"},
		{"My Pictures", "Pictures"},
		{"My Music", "Music"},
		{"My Video", "Videos"},
		{"AppData", `AppData\Roaming`},
		{"Local AppData", `AppData\Local`},
	}
	out := map[string]string{}
	for _, keyPath := range []string{
		s.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`,
		s.SID + `\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`,
	} {
		h, err := regCreateKey(hkeyUsers, keyPath)
		if err != nil {
			return nil, err
		}
		for _, t := range targets {
			full := corpusRoot + `\` + t.sub
			if err := os.MkdirAll(full, 0o755); err != nil {
				regCloseKey(h)
				return nil, err
			}
			if err := regSetString(h, t.value, full); err != nil {
				regCloseKey(h)
				return nil, fmt.Errorf("gate3: setting %s: %w", t.value, err)
			}
			out[t.value] = full
		}
		regCloseKey(h)
	}
	return out, nil
}

func regCreateKey(root uintptr, path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	var disp uint32
	r1, _, _ := procRegCreateKeyExW.Call(root, uintptr(unsafe.Pointer(p)), 0, 0, 0,
		keyWrite, 0, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disp)))
	if r1 != 0 {
		return 0, fmt.Errorf("gate3: RegCreateKeyEx(%s): %d", path, r1)
	}
	return h, nil
}

func regSetString(h syscall.Handle, name, value string) error {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	v, err := syscall.UTF16FromString(value)
	if err != nil {
		return err
	}
	r1, _, _ := procRegSetValueExW.Call(uintptr(h), uintptr(unsafe.Pointer(n)), 0, regSZ,
		uintptr(unsafe.Pointer(&v[0])), uintptr(len(v)*2))
	if r1 != 0 {
		return fmt.Errorf("RegSetValueEx(%s): %d", name, r1)
	}
	return nil
}

func regCloseKey(h syscall.Handle) { procRegCloseKeyP.Call(uintptr(h)) }

// GrantFullControl gives the migration user full control of a directory the
// harness owns — the work directory the installer's output is redirected into.
// icacls rather than a hand-rolled ACL: this is harness plumbing on a throwaway
// machine, and a wrong ACL built by hand is a debugging afternoon.
func GrantFullControl(dir, user string) error {
	cmd := exec.Command("icacls", dir, "/grant", user+":(OI)(CI)F", "/T")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gate3: icacls %s: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// WarmProfile runs a trivial command as the migration user so that everything
// Windows does on a first logon — creating the profile from C:\Users\Default,
// writing the hive, seeding AppData — happens BEFORE any run is measured.
func WarmProfile(s *UserSession, workDir string) error {
	out := filepath.Join(workDir, "warm.txt")
	p, err := StartInstaller(s, filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe"),
		[]string{"/all"}, out, workDir)
	if err != nil {
		return err
	}
	defer p.Close()
	code, timedOut := p.Wait(120e9)
	if timedOut {
		p.Kill()
		return fmt.Errorf("gate3: the migration user's first logon did not finish in two minutes")
	}
	if code != 0 {
		b, _ := os.ReadFile(out)
		return fmt.Errorf("gate3: warming the profile exited %d: %s", code, strings.TrimSpace(string(b)))
	}
	return nil
}
