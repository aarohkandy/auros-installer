//go:build windows

package gate3

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	procSetTokenInformation      = modadvapi32.NewProc("SetTokenInformation")
	procGetUserProfileDirectoryW = moduserenv.NewProc("GetUserProfileDirectoryW")
)

// LowIntegrityToken returns a primary copy of tok at Low mandatory integrity:
// DuplicateTokenEx, then SetTokenInformation(TokenIntegrityLevel) with a
// TOKEN_MANDATORY_LABEL naming S-1-16-4096 and SE_GROUP_INTEGRITY, as in
// "Designing Applications to Run at a Low Integrity Level"
// (learn.microsoft.com/previous-versions/dotnet/articles/bb625960(v=msdn.10)).
// tok must be open with TOKEN_DUPLICATE (DuplicateTokenEx); the copy is
// requested with TOKEN_ALL_ACCESS, which covers TOKEN_ADJUST_DEFAULT for
// SetTokenInformation(TokenIntegrityLevel) and the TOKEN_QUERY, TOKEN_DUPLICATE
// and TOKEN_ASSIGN_PRIMARY that CreateProcessWithTokenW requires of its token
// (learn.microsoft.com/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw;
// its caller needs SeImpersonatePrivilege, which the elevated runner account
// holds). The caller closes it.
func LowIntegrityToken(tok syscall.Handle) (syscall.Handle, error) {
	var dup syscall.Handle
	if r, _, e := procDuplicateTokenEx.Call(uintptr(tok), tokenAllAccess, 0, securityImpersonation,
		tokenPrimary, uintptr(unsafe.Pointer(&dup))); r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", e)
	}
	sid, err := syscall.StringToSid(LowIntegritySID)
	if err != nil {
		syscall.CloseHandle(dup)
		return 0, err
	}
	const tokenIntegrityLevel, seGroupIntegrity = 25, 0x20
	label := syscall.SIDAndAttributes{Sid: sid, Attributes: seGroupIntegrity}
	r, _, e := procSetTokenInformation.Call(uintptr(dup), tokenIntegrityLevel, uintptr(unsafe.Pointer(&label)),
		unsafe.Sizeof(label)+uintptr(sid.Len()))
	runtime.KeepAlive(sid)
	if r == 0 {
		syscall.CloseHandle(dup)
		return 0, fmt.Errorf("SetTokenInformation(TokenIntegrityLevel): %w", e)
	}
	return dup, nil
}

// LabelLow gives dir an inheritable Low mandatory label, so a Low process can
// write under it: `icacls <dir> /setintegritylevel (OI)(CI)L`
// (learn.microsoft.com/windows-server/administration/windows-commands/icacls).
// Only ever used on the harness's own volumes and directories, never on C:.
func LabelLow(dir string) error {
	if strings.EqualFold(filepath.VolumeName(dir), "C:") {
		return fmt.Errorf("refusing to label %s Low: that would open the system disk to the installer", dir)
	}
	out, err := exec.Command("icacls", dir, "/setintegritylevel", "(OI)(CI)L").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %s /setintegritylevel: %v: %s", dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ApplyEnforcement prepares the Low-integrity session the installer runs in and
// proves it: in that session, creating a directory must be refused at every
// probe on C: (a broad sample: folders whose DACL would let the account write,
// and folders with protected DACLs) and must succeed in each Low-labelled
// destination, and `whoami /groups` must report the Low label. Any miss fails
// closed. The caller closes the returned session's token.
//
// The declared exemption is the account's profile directory, where Windows
// keeps what a logon needs. At Low only its Low-labelled part (LocalLow) is
// writable at all; writes there are listed, not failed. The account's TEMP is
// inside the profile, and is probed: it must be refused too. The installer
// writes no TEMP or logs on Windows (its run log goes to the destination, its
// output to the harness's work directory).
func ApplyEnforcement(s *UserSession, workDir string, lowDirs []string) (*UserSession, *Enforcement) {
	e := &Enforcement{
		Mechanism: "mandatory integrity control: the installer tree runs at Low; only the harness's " +
			"destination volumes and work directory are labelled Low",
		Integrity: LowIntegritySID,
		Policy: "SYSTEM_MANDATORY_LABEL_NO_WRITE_UP, the default for every object; objects without a " +
			"label are Medium",
		ExemptWhy: "the account's own profile directory, which Windows needs for the logon (its TEMP is " +
			"inside it and is still refused at Low; only LocalLow is writable)",
	}
	prof, err := profileDir(s.Token)
	if err != nil {
		e.Error = "the migration account's profile directory is unknown: " + err.Error()
		return nil, e
	}
	e.Exemptions = []string{prof}
	for _, d := range append([]string{workDir}, lowDirs...) {
		if err := LabelLow(d); err != nil {
			e.Error = err.Error()
			return nil, e
		}
		e.LabeledLow = append(e.LabeledLow, d)
	}
	lowTok, err := LowIntegrityToken(s.Token)
	if err != nil {
		e.Error = err.Error()
		return nil, e
	}
	low := &UserSession{Token: lowTok, SID: s.SID, Elevated: s.Elevated, name: s.name, keepProfile: true}

	groups, _ := runAs(low, workDir, filepath.Join(os.Getenv("SystemRoot"), "System32", "whoami.exe"), "/groups")
	if !strings.Contains(groups, LowIntegritySID) {
		e.Error = "the installer's session does not report the Low mandatory label: " + tail(groups, 400)
		return low, e
	}
	e.Probes = append(e.Probes, "whoami /groups in the installer's session reports "+LowIntegritySID)

	type probe struct {
		dir   string
		allow bool
	}
	probes := []probe{
		{`C:\`, false}, {`C:\ProgramData`, false}, {`C:\Windows\Temp`, false}, {`C:\Program Files`, false},
		{`C:\Users\Public`, false}, {prof, false}, {filepath.Join(prof, `AppData\Local\Temp`), false},
	}
	for _, d := range lowDirs {
		probes = append(probes, probe{d, true})
	}
	for _, p := range probes {
		created, line := probeMkdir(low, filepath.Join(p.dir, "auros-gate3-enforcement-probe"), workDir)
		e.Probes = append(e.Probes, line)
		if created != p.allow {
			e.Error = "the enforcement did not do what it says: " + line
			return low, e
		}
	}
	e.Verified = true
	return low, e
}

// runAs runs one command in the session and returns what it printed.
func runAs(s *UserSession, workDir, exe string, args ...string) (string, int) {
	out := filepath.Join(workDir, "enforcement-probe.txt")
	os.Remove(out)
	p, err := StartInstaller(s, exe, args, out, workDir)
	if err != nil {
		return err.Error(), -1
	}
	code, timedOut := p.Wait(time.Minute)
	if timedOut {
		p.Kill()
	}
	p.Close()
	said, _ := os.ReadFile(out)
	return string(said), code
}

// probeMkdir runs `md dir` in the session and reports whether the directory
// came into existence. The harness removes it again.
func probeMkdir(s *UserSession, dir, workDir string) (bool, string) {
	os.Remove(dir)
	said, code := runAs(s, workDir, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "md", dir)
	_, serr := os.Stat(dir)
	os.Remove(dir)
	return serr == nil, fmt.Sprintf("md %s at Low: exit %d, created %v (%s)", dir, code, serr == nil,
		strings.TrimSpace(said))
}

var (
	procGetLogicalDriveStringsW = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modkernel32.NewProc("GetDriveTypeW")
)

// otherFixedVolumes adds every fixed volume root except C:\ to have.
func otherFixedVolumes(have []string) []string {
	buf := make([]uint16, 512)
	n, _, _ := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	seen := map[string]bool{}
	for _, h := range have {
		seen[strings.ToUpper(filepath.VolumeName(h))] = true
	}
	for i := 0; i < int(n); {
		j := i
		for j < int(n) && buf[j] != 0 {
			j++
		}
		root := syscall.UTF16ToString(buf[i:j])
		i = j + 1
		if root == "" {
			continue
		}
		p, _ := syscall.UTF16PtrFromString(root)
		const driveFixed = 3
		t, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(p)))
		v := strings.ToUpper(filepath.VolumeName(root))
		if t == driveFixed && v != "C:" && !seen[v] {
			seen[v] = true
			have = append(have, root)
		}
	}
	return have
}

func profileDir(tok syscall.Handle) (string, error) {
	n := uint32(1024)
	buf := make([]uint16, n)
	if r, _, e := procGetUserProfileDirectoryW.Call(uintptr(tok), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&n))); r == 0 {
		return "", e
	}
	return syscall.UTF16ToString(buf), nil
}
