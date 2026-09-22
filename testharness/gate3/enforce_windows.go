//go:build windows

package gate3

import (
	"errors"
	"fmt"
	"io/fs"
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
	return IntegrityToken(tok, LowIntegritySID)
}

// IntegrityToken is LowIntegrityToken for any mandatory level.
func IntegrityToken(tok syscall.Handle, level string) (syscall.Handle, error) {
	var dup syscall.Handle
	if r, _, e := procDuplicateTokenEx.Call(uintptr(tok), tokenAllAccess, 0, securityImpersonation,
		tokenPrimary, uintptr(unsafe.Pointer(&dup))); r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", e)
	}
	sid, err := syscall.StringToSid(level)
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

var (
	modntdll                                 = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryObject                        = modntdll.NewProc("NtQueryObject")
	procImpersonateLoggedOnUser              = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf                         = modadvapi32.NewProc("RevertToSelf")
	procAccessCheck                          = modadvapi32.NewProc("AccessCheck")
	procGetKernelObjectSecurity              = modadvapi32.NewProc("GetKernelObjectSecurity")
	procSetKernelObjectSecurity              = modadvapi32.NewProc("SetKernelObjectSecurity")
	procConvertSecurityDescriptorToStringSDW = modadvapi32.NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")
	procConvertStringSecurityDescriptorToSDW = modadvapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procLocalFree                            = modkernel32.NewProc("LocalFree")
)

const (
	maximumAllowed          = 0x02000000
	readControl             = 0x00020000
	writeDac                = 0x00040000
	daclSecurityInformation = 4
	sddlRevision1           = 1
)

// ApplyEnforcement checks that the installer's token is a standard user's,
// enumerates every directory on C: that token can write, denies it each one
// directly, and proves the result (see enforce.go). It always returns a
// restore function, which puts back every descriptor it changed and says how
// that went; the caller runs it after the run. Any miss fails closed.
//
// No exemptions: the installer writes no TEMP, logs or caches on Windows (no
// os.TempDir/CreateTemp outside internal/winenv's non-Windows stub; its run log
// goes to the destination and its output to the harness's work directory, off
// C:), so the account's profile and TEMP are denied like everything else.
func ApplyEnforcement(s *UserSession, workDir, sourceRoot string, destDirs []string) (*Enforcement, func() string) {
	e := &Enforcement{
		Mechanism: "standard-user token; an explicit deny ACE for the account on every directory of C: " +
			"that token could write, set on each directory alone",
		DenyMask:   fmt.Sprintf("0x%x (%s)", DenyMask, strings.Join(WriteRights(DenyMask), ",")),
		Exemptions: []string{},
		ExemptWhy: "the migration account's own AppData only: loading shell32.dll at Medium integrity " +
			"initialises per-user state under AppData\\Local, and with it denied the installer died at " +
			"startup (run 35671658363: 'Failed to load shell32.dll: A dynamic link library (DLL) " +
			"initialization routine failed'). AppData is operating-system and application state; the " +
			"profile's user folders — the migration SOURCE — stay denied and audited. Writes inside the " +
			"exemption are counted in C1's detail, never hidden.",
	}
	var denied []string
	saved := map[string][]byte{}
	restore := func() string {
		bad := 0
		var first string
		for _, d := range denied {
			if err := setDACL(d, saved[d]); err != nil {
				if bad++; first == "" {
					first = err.Error()
				}
			}
		}
		if bad > 0 {
			return fmt.Sprintf("%d of %d deny ACEs NOT removed, first: %s", bad, len(denied), first)
		}
		return fmt.Sprintf("all %d deny ACEs removed (each directory's saved descriptor put back)", len(denied))
	}

	desc, admin, err := tokenFacts(s.Token)
	e.Token = desc
	if err != nil {
		e.Error = "the installer's token could not be read: " + err.Error()
		return e, restore
	}
	if admin {
		e.Error = "the installer's token is an administrator's (" + desc + "): the enforcement assumes a " +
			"standard user"
		return e, restore
	}
	if s.SID == "" {
		e.Error = "the migration account's SID is unknown"
		return e, restore
	}
	prof, err := profileDir(s.Token)
	if err != nil {
		e.Error = "the migration account's profile directory is unknown: " + err.Error()
		return e, restore
	}
	// The destinations grant the account itself full control, so its writes
	// there do not hang on CREATOR OWNER or on what a fresh volume's root allows.
	for _, d := range destDirs {
		if out, err := exec.Command("icacls", d, "/grant", "*"+s.SID+":(OI)(CI)F").CombinedOutput(); err != nil {
			e.Error = fmt.Sprintf("icacls %s /grant: %v: %s", d, err, strings.TrimSpace(string(out)))
			return e, restore
		}
	}

	// ── enumerate: what can this token write on C:? ──
	_ = enablePrivilege("SeBackupPrivilege")  // list every directory
	_ = enablePrivilege("SeRestorePrivilege") // WRITE_DAC on every directory
	started := time.Now()
	writable, scanned, unlisted, unchecked, err := scanWritable(s.Token, `C:\`)
	e.ScanSeconds = time.Since(started).Seconds()
	e.Scanned, e.Unlisted = scanned, capList(unlisted, 50)
	for _, w := range writable {
		e.Writable = append(e.Writable, fmt.Sprintf("%s [%s]", w.path, strings.Join(WriteRights(w.granted), ",")))
	}
	paths := make([]string, len(writable))
	for i, w := range writable {
		paths[i] = w.path
	}
	e.WritableRoots = WritableRoots(paths)
	if err != nil {
		e.Error = "the scan of C: failed: " + err.Error()
		return e, restore
	}
	if len(unchecked) > 0 {
		e.Error = fmt.Sprintf("%d directories on C: could not be checked, so they may be writable: %s",
			len(unchecked), strings.Join(capList(unchecked, 10), "; "))
		return e, restore
	}

	// ── deny each one, directly — except inside the account's own AppData (see ExemptWhy) ──
	appData := filepath.Join(prof, "AppData")
	e.Exemptions = []string{appData}
	kept := paths[:0:0]
	for _, d := range paths {
		if !underFold(d, appData) {
			kept = append(kept, d)
		}
	}
	paths = kept
	for _, d := range paths {
		orig, err := denyDir(d, s.SID)
		if err != nil {
			e.Error = fmt.Sprintf("the deny ACE could not be set on %s: %v", d, err)
			return e, restore
		}
		saved[d] = orig
		denied = append(denied, d)
	}
	e.Probes = append(e.Probes, fmt.Sprintf("%d of %d directories on C: were writable by the account; each "+
		"now denies it %s (scan and deny took %.1fs)", len(paths), scanned, e.DenyMask, time.Since(started).Seconds()))

	// ── prove it: the granted mask again, then real creates ──
	var still []string
	runtime.LockOSThread()
	for _, d := range paths {
		g, err := grantedAs(s.Token, d)
		if err != nil {
			still = append(still, fmt.Sprintf("%s (%v)", d, err))
		} else if left := g & DenyMask &^ OwnerImplicit; left != 0 {
			still = append(still, fmt.Sprintf("%s [%s]", d, strings.Join(WriteRights(left), ",")))
		}
	}
	runtime.UnlockOSThread()
	if len(still) > 0 {
		e.Error = fmt.Sprintf("after the deny, the account still holds write-class rights on %d directories: %s",
			len(still), strings.Join(capList(still, 10), "; "))
		return e, restore
	}
	e.Probes = append(e.Probes, fmt.Sprintf("re-read as the account: no write-class right left on any of the %d "+
		"(an owner's implicit write-dac aside)", len(paths)))

	sample := []string{`C:\`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\Program Files`, `C:\Users\Public`,
		prof}
	if sourceRoot != "" {
		sample = append(sample, sourceRoot)
	}
	for i, w := range paths {
		if i >= 60 {
			break
		}
		sample = append(sample, w)
	}
	list := filepath.Join(workDir, "enforcement-deny-probe.txt")
	if err := os.WriteFile(list, []byte(strings.Join(sample, "\r\n")), 0o644); err != nil {
		e.Error = err.Error()
		return e, restore
	}
	self, err := os.Executable()
	if err != nil {
		e.Error = err.Error()
		return e, restore
	}
	said, code := runAs(s, workDir, self, "enforcement-probe", "-deny-list", list)
	line := fmt.Sprintf("a directory and a file created as the account in %d directories of C: (%d named, the "+
		"first writable ones after them): exit %d: %s", len(sample), len(sample)-min(len(paths), 60), code,
		tail(strings.TrimSpace(said), 3000))
	e.Probes = append(e.Probes, line)
	if code != 0 {
		e.Error = "the enforcement did not do what it says: " + line
		return e, restore
	}

	// Enforcement must not change what the installer can do legitimately: each
	// destination is probed with the installer's own write patterns and the
	// source by opening every file in it for read, as the account.
	for _, d := range destDirs {
		dir := filepath.Join(d, "auros-gate3-enforcement-probe")
		made := filepath.Join(d, "auros-gate3-harness-made")
		os.RemoveAll(dir)
		os.RemoveAll(made)
		os.MkdirAll(made, 0o755)
		said, code := runAs(s, workDir, self, "enforcement-probe", "-dest", dir, "-harness-dir", made)
		line := fmt.Sprintf("the installer's write patterns under %s as the account: exit %d: %s", d, code, strings.TrimSpace(said))
		if code != 0 {
			out, _ := exec.Command("icacls", dir, "/T").CombinedOutput()
			e.Diagnostics = append(e.Diagnostics, "icacls /T "+dir+": "+tail(strings.TrimSpace(string(out)), 3000))
		}
		os.RemoveAll(dir)
		os.RemoveAll(made)
		e.Probes = append(e.Probes, line)
		if code != 0 {
			e.Error = "the enforcement stops the installer writing to its own destination: " + line
			return e, restore
		}
	}
	if sourceRoot != "" {
		said, code := runAs(s, workDir, self, "enforcement-probe", "-source", sourceRoot)
		line := fmt.Sprintf("every file under %s opened for read as the account: exit %d: %s", sourceRoot, code, strings.TrimSpace(said))
		e.Probes = append(e.Probes, line)
		if code != 0 {
			e.Error = "the enforcement changes what the installer can READ: " + line
			return e, restore
		}
	}
	e.Verified = true
	return e, restore
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

type writableDir struct {
	path    string
	granted uint32
}

// errImpersonation is fatal to a scan: a thread left impersonating the account
// would run the rest of the harness as it.
type errImpersonation struct{ error }

// scanWritable walks every directory under root (listed as the harness, which
// holds SeBackupPrivilege; reparse points are not followed) and reads back what
// tok is granted on each. unlisted are directories the harness could not list;
// unchecked, ones whose check failed for a reason other than being refused or
// having vanished.
func scanWritable(tok syscall.Handle, root string) (w []writableDir, scanned int, unlisted, unchecked []string, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if d != nil && d.IsDir() && p != root {
				unlisted = append(unlisted, fmt.Sprintf("%s (%v)", p, werr))
				return nil
			}
			if p == root {
				return werr
			}
			return nil
		}
		if d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			// A link or junction: its target is scanned under its own name.
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		scanned++
		g, gerr := grantedAs(tok, p)
		if gerr == errSharingViolation {
			// Held open by another process with a share mode that excludes the data
			// rights MAXIMUM_ALLOWED asks for (run 35670743966: the Actions runner's
			// own bin directory). Sharing never governs READ_CONTROL, so compute the
			// same answer from the security descriptor with AccessCheck.
			g, gerr = grantedBySD(tok, p)
		}
		var imp errImpersonation
		switch {
		case errors.As(gerr, &imp):
			return gerr
		case gerr == syscall.ERROR_FILE_NOT_FOUND || gerr == syscall.ERROR_PATH_NOT_FOUND:
		case gerr != nil:
			unchecked = append(unchecked, fmt.Sprintf("%s (%v)", p, gerr))
		case g&DenyMask != 0:
			w = append(w, writableDir{p, g})
		}
		return nil
	})
	return
}

// grantedAs opens dir as tok for MAXIMUM_ALLOWED and returns the access the
// I/O manager granted, from NtQueryObject(ObjectBasicInformation) — the access
// check Windows itself performs, with nothing written. Refused is 0. The
// caller's thread must be locked to its OS thread.
func grantedAs(tok syscall.Handle, dir string) (uint32, error) {
	if r, _, e := procImpersonateLoggedOnUser.Call(uintptr(tok)); r == 0 {
		return 0, errImpersonation{fmt.Errorf("ImpersonateLoggedOnUser: %w", e)}
	}
	h, err := openDir(dir, maximumAllowed)
	if r, _, e := procRevertToSelf.Call(); r == 0 {
		if err == nil {
			syscall.CloseHandle(h)
		}
		return 0, errImpersonation{fmt.Errorf("RevertToSelf: %w", e)}
	}
	if err == syscall.ERROR_ACCESS_DENIED {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(h)
	// OBJECT_BASIC_INFORMATION: Attributes, GrantedAccess, then counts and
	// reserved words, 56 bytes (learn.microsoft.com/windows/win32/api/winternl/
	// nf-winternl-ntqueryobject).
	var info [14]uint32
	if st, _, _ := procNtQueryObject.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&info[0])),
		unsafe.Sizeof(info), 0); st != 0 {
		return 0, fmt.Errorf("NtQueryObject: NTSTATUS 0x%x", st)
	}
	return info[1], nil
}

func openDir(dir string, access uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(`\\?\` + dir)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(p, access, fileShareAll, nil, syscall.OPEN_EXISTING, backupSem, 0)
}

// denyDir prepends the deny ACE to dir's DACL on that directory alone:
// SetKernelObjectSecurity sets one object's descriptor and does not propagate
// to children, unlike SetNamedSecurityInfo and icacls. It returns the original
// descriptor, for setDACL to put back.
func denyDir(dir, sid string) ([]byte, error) {
	h, err := openDir(dir, readControl|writeDac)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)
	var need uint32
	procGetKernelObjectSecurity.Call(uintptr(h), daclSecurityInformation, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		return nil, fmt.Errorf("GetKernelObjectSecurity returned no size")
	}
	orig := make([]byte, need)
	if r, _, e := procGetKernelObjectSecurity.Call(uintptr(h), daclSecurityInformation, uintptr(unsafe.Pointer(&orig[0])),
		uintptr(need), uintptr(unsafe.Pointer(&need))); r == 0 {
		return nil, fmt.Errorf("GetKernelObjectSecurity: %w", e)
	}
	var str *uint16
	if r, _, e := procConvertSecurityDescriptorToStringSDW.Call(uintptr(unsafe.Pointer(&orig[0])), sddlRevision1,
		daclSecurityInformation, uintptr(unsafe.Pointer(&str)), 0); r == 0 {
		return nil, fmt.Errorf("ConvertSecurityDescriptorToStringSecurityDescriptor: %w", e)
	}
	sddl := utf16PtrToString(str)
	procLocalFree.Call(uintptr(unsafe.Pointer(str)))
	next, err := DenySDDL(sddl, sid)
	if err != nil {
		return nil, err
	}
	if err := setSDDL(h, next); err != nil {
		return nil, err
	}
	return orig, nil
}

func setSDDL(h syscall.Handle, sddl string) error {
	p, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var sd uintptr
	if r, _, e := procConvertStringSecurityDescriptorToSDW.Call(uintptr(unsafe.Pointer(p)), sddlRevision1,
		uintptr(unsafe.Pointer(&sd)), 0); r == 0 {
		return fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptor(%s): %w", sddl, e)
	}
	defer procLocalFree.Call(sd)
	if r, _, e := procSetKernelObjectSecurity.Call(uintptr(h), daclSecurityInformation, sd); r == 0 {
		return fmt.Errorf("SetKernelObjectSecurity: %w", e)
	}
	return nil
}

// setDACL puts back a descriptor denyDir saved.
func setDACL(dir string, sd []byte) error {
	if len(sd) == 0 {
		return fmt.Errorf("%s: no saved descriptor", dir)
	}
	h, err := openDir(dir, writeDac)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	defer syscall.CloseHandle(h)
	if r, _, e := procSetKernelObjectSecurity.Call(uintptr(h), daclSecurityInformation, uintptr(unsafe.Pointer(&sd[0]))); r == 0 {
		return fmt.Errorf("%s: SetKernelObjectSecurity: %w", dir, e)
	}
	return nil
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	n := 0
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; ptr = unsafe.Add(ptr, 2) {
		n++
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

// tokenFacts describes tok as the installer will run with it, and says whether
// it is an administrator's: elevated (TokenElevation), or holding the
// Administrators group (S-1-5-32-544) enabled rather than deny-only.
func tokenFacts(tok syscall.Handle) (string, bool, error) {
	t := syscall.Token(tok)
	elevated, err := tokenIsElevated(tok)
	if err != nil {
		return "", false, err
	}
	admins := "absent"
	adminEnabled := false
	buf := make([]byte, 8192)
	var n uint32
	const tokenGroupsClass, tokenIntegrityLevel = 2, 25
	if err := syscall.GetTokenInformation(t, tokenGroupsClass, &buf[0], uint32(len(buf)), &n); err != nil {
		return "", false, fmt.Errorf("GetTokenInformation(TokenGroups): %w", err)
	}
	tg := (*struct {
		GroupCount uint32
		Groups     [1]syscall.SIDAndAttributes
	})(unsafe.Pointer(&buf[0]))
	for _, g := range unsafe.Slice(&tg.Groups[0], tg.GroupCount) {
		if sid, _ := g.Sid.String(); sid == "S-1-5-32-544" {
			const enabled, denyOnly = 0x4, 0x10
			switch {
			case g.Attributes&denyOnly != 0:
				admins = "deny-only"
			case g.Attributes&enabled != 0:
				admins, adminEnabled = "ENABLED", true
			default:
				admins = "present, not enabled"
			}
		}
	}
	il := "unknown"
	ib := make([]byte, 256)
	if err := syscall.GetTokenInformation(t, tokenIntegrityLevel, &ib[0], uint32(len(ib)), &n); err == nil {
		il, _ = (*syscall.Tokenuser)(unsafe.Pointer(&ib[0])).User.Sid.String()
	}
	runtime.KeepAlive(buf)
	runtime.KeepAlive(ib)
	sid, _ := tokenSID(tok)
	return fmt.Sprintf("%s: elevated %v, Administrators %s, integrity %s", sid, elevated, admins, il),
		elevated || adminEnabled, nil
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

// errSharingViolation is ERROR_SHARING_VIOLATION (32).
const errSharingViolation = syscall.Errno(32)

// grantedBySD returns the access tok would be granted to dir, computed by
// AccessCheck against dir's owner, group and DACL — read by the harness with
// READ_CONTROL, which share modes do not govern — with the file generic mapping
// (learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck).
// It is the fallback for directories another process holds open; nothing is written.
func grantedBySD(tok syscall.Handle, dir string) (uint32, error) {
	h, err := openDir(dir, readControl)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(h)
	const info = 0x1 | 0x2 | 0x4 // OWNER | GROUP | DACL _SECURITY_INFORMATION
	var need uint32
	procGetKernelObjectSecurity.Call(uintptr(h), info, 0, 0, uintptr(unsafe.Pointer(&need)))
	if need == 0 {
		return 0, fmt.Errorf("GetKernelObjectSecurity reported a zero-length descriptor for %s", dir)
	}
	sd := make([]byte, need)
	if r, _, e := procGetKernelObjectSecurity.Call(uintptr(h), info, uintptr(unsafe.Pointer(&sd[0])),
		uintptr(need), uintptr(unsafe.Pointer(&need))); r == 0 {
		return 0, fmt.Errorf("GetKernelObjectSecurity %s: %w", dir, e)
	}
	// AccessCheck needs an impersonation token.
	const tokenQuery, tokenDuplicate, tokenImpersonate = 0x0008, 0x0002, 0x0004
	const securityIdentification, tokenImpersonation = 1, 2
	var imp syscall.Handle
	if r, _, e := procDuplicateTokenEx.Call(uintptr(tok), tokenQuery|tokenDuplicate|tokenImpersonate, 0,
		securityIdentification, tokenImpersonation, uintptr(unsafe.Pointer(&imp))); r == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx (impersonation) for AccessCheck: %w", e)
	}
	defer syscall.CloseHandle(imp)
	// GENERIC_MAPPING for files: FILE_GENERIC_READ, _WRITE, _EXECUTE, FILE_ALL_ACCESS.
	mapping := [4]uint32{0x120089, 0x120116, 0x1200A0, 0x1F01FF}
	var privs [256]byte
	privLen := uint32(len(privs))
	var granted, status uint32
	if r, _, e := procAccessCheck.Call(uintptr(unsafe.Pointer(&sd[0])), uintptr(imp), maximumAllowed,
		uintptr(unsafe.Pointer(&mapping[0])), uintptr(unsafe.Pointer(&privs[0])), uintptr(unsafe.Pointer(&privLen)),
		uintptr(unsafe.Pointer(&granted)), uintptr(unsafe.Pointer(&status))); r == 0 {
		return 0, fmt.Errorf("AccessCheck %s: %w", dir, e)
	}
	if status == 0 {
		return 0, nil // no access granted at all
	}
	return granted, nil
}

// underFold reports whether p is dir or below it, case-insensitively (NTFS
// names are case-insensitive for this purpose).
func underFold(p, dir string) bool {
	p, dir = strings.ToLower(filepath.Clean(p)), strings.ToLower(filepath.Clean(dir))
	return p == dir || strings.HasPrefix(p, dir+`\`)
}
