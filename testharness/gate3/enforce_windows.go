//go:build windows

package gate3

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// The deny ACE of enforce.go, applied with icacls. icacls sets the DACL through
// SetNamedSecurityInfo, which propagates inheritable ACEs to existing children
// (learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow),
// so applying and removing it each walk C:. Both are timed into the result.

var (
	procGetNamedSecurityInfoW    = modadvapi32.NewProc("GetNamedSecurityInfoW")
	procGetUserProfileDirectoryW = moduserenv.NewProc("GetUserProfileDirectoryW")
)

// ApplyEnforcement denies the migration account write-class rights on C:\,
// reads the ACE back, and proves it by making the account try: a directory at
// C:\ and one inherited under C:\ProgramData must be refused, and one in the
// account's profile (the exemption) must be allowed. It never returns nil; the
// caller defers Remove whatever happened.
//
// The one exemption is the profile directory, where Windows keeps what a logon
// needs. Its explicit grant to the account comes before the inherited deny in
// the DACL's canonical order, and the probe proves that rather than assuming it.
// TEMP needs no exemption of its own: the account's TEMP is under its profile.
// The installer does not write TEMP or logs on Windows (its run log goes to the
// destination, its output to the harness's work directory); if it ever did, the
// write would be listed under writes_inside_exemptions in every result.
func ApplyEnforcement(s *UserSession, user, workDir string) *Enforcement {
	e := &Enforcement{Path: `C:\`, Trustee: user, SID: s.SID, Mask: DenyMask, MaskNames: DenyMaskNames,
		Inheritance: "OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE",
		ExemptWhy: "the account's own profile directory, which Windows needs to log it on and run it " +
			"(its TEMP is inside it); its explicit grant precedes the inherited deny"}
	prof, err := profileDir(s.Token)
	if err != nil {
		e.Error = "the migration account's profile directory is unknown: " + err.Error()
		return e
	}
	e.Exemptions = []string{prof}
	if e.SID == "" {
		e.Error = "the migration account's SID is unknown"
		return e
	}
	aces, err := daclACEs(e.Path)
	if err != nil {
		e.Error = err.Error()
		return e
	}
	for _, a := range aces {
		if a.sid == e.SID {
			e.Error = fmt.Sprintf("%s already carries an ACE for %s (%s), so removing ours afterwards could "+
				"not restore it", e.Path, e.SID, a)
			return e
		}
	}
	e.Command = fmt.Sprintf(`icacls %s /deny *%s:%s`, e.Path, e.SID, DenyIcacls)
	t0 := time.Now()
	e.Applied = true // from here on Remove must run, even if icacls half-failed
	ace, err := ApplyDeny(e.Path, e.SID)
	e.ApplySec = time.Since(t0).Seconds()
	if err != nil {
		e.Error = err.Error()
		return e
	}
	e.ACE = ace
	for _, p := range []struct {
		dir   string
		allow bool
	}{
		{`C:\auros-gate3-ace-probe`, false},
		{`C:\ProgramData\auros-gate3-ace-probe`, false},
		{filepath.Join(prof, "auros-gate3-ace-probe"), true},
	} {
		created, line := probeMkdir(s, p.dir, workDir)
		e.Probes = append(e.Probes, line)
		if created != p.allow {
			e.Error = "the deny ACE did not do what it says: " + line
			return e
		}
	}
	e.Verified = true
	return e
}

// Remove takes the ACE off again and checks it is gone. Safe to call twice.
func (e *Enforcement) Remove() {
	if e == nil || !e.Applied || e.Removed {
		return
	}
	t0 := time.Now()
	err := RemoveDeny(e.Path, e.SID)
	e.RemoveSec = time.Since(t0).Seconds()
	if err != nil {
		e.RemoveError = err.Error()
		return
	}
	e.Removed, e.RemoveError = true, ""
}

// ApplyDeny adds the deny ACE for sid on path and returns it as read back.
func ApplyDeny(path, sid string) (string, error) {
	out, err := exec.Command("icacls", path, "/deny", "*"+sid+":"+DenyIcacls).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("icacls /deny on %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	aces, err := daclACEs(path)
	if err != nil {
		return "", err
	}
	for _, a := range aces {
		if a.sid == sid && a.typ == aceTypeDenied && a.flags&(DenyInherit|aceInherited) == DenyInherit &&
			a.mask&DenyMask == DenyMask {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("icacls reported success but %s carries no explicit OI|CI deny of 0x%08X for %s",
		path, DenyMask, sid)
}

// RemoveDeny removes every deny ACE for sid on path and checks none is left.
func RemoveDeny(path, sid string) error {
	out, err := exec.Command("icacls", path, "/remove:d", "*"+sid).CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls /remove:d on %s: %v: %s", path, err, strings.TrimSpace(string(out)))
	}
	aces, err := daclACEs(path)
	if err != nil {
		return err
	}
	for _, a := range aces {
		if a.sid == sid && a.typ == aceTypeDenied {
			return fmt.Errorf("%s still carries %s after icacls /remove:d", path, a)
		}
	}
	return nil
}

// probeMkdir runs `md dir` as the migration account and reports whether the
// directory came into existence. The harness removes it again.
func probeMkdir(s *UserSession, dir, workDir string) (bool, string) {
	os.Remove(dir)
	out := filepath.Join(workDir, "ace-probe.txt")
	p, err := StartInstaller(s, filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"),
		[]string{"/c", "md", dir}, out, workDir)
	if err != nil {
		return false, "md " + dir + ": " + err.Error()
	}
	code, timedOut := p.Wait(time.Minute)
	if timedOut {
		p.Kill()
	}
	p.Close()
	_, serr := os.Stat(dir)
	os.Remove(dir)
	said, _ := os.ReadFile(out)
	return serr == nil, fmt.Sprintf("md %s as the migration account: exit %d, created %v (%s)",
		dir, code, serr == nil, strings.TrimSpace(string(said)))
}

// ACE types and flags (winnt.h; learn.microsoft.com/windows/win32/api/winnt/ns-winnt-ace_header).
const (
	aceTypeAllowed = 0
	aceTypeDenied  = 1
	aceInherited   = 0x10 // INHERITED_ACE
)

type aceEntry struct {
	typ, flags byte
	mask       uint32
	sid        string
}

// String is the ACE in SDDL form, with the mask in hex.
func (a aceEntry) String() string {
	t := map[byte]string{aceTypeAllowed: "A", aceTypeDenied: "D"}[a.typ]
	var f string
	for _, x := range []struct {
		bit  byte
		name string
	}{{0x1, "OI"}, {0x2, "CI"}, {0x4, "NP"}, {0x8, "IO"}, {aceInherited, "ID"}} {
		if a.flags&x.bit != 0 {
			f += x.name
		}
	}
	return fmt.Sprintf("(%s;%s;0x%08X;;;%s)", t, f, a.mask, a.sid)
}

// daclACEs reads path's DACL and returns its allow and deny ACEs. The ACL is
// walked by hand — ACL header (8 bytes), then per ACE an ACE_HEADER (type,
// flags, size), the ACCESS_MASK and the SID — because this module takes no
// dependencies.
func daclACEs(path string) ([]aceEntry, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const seFileObject, daclSecurityInformation = 1, 4
	var dacl *byte
	var sd syscall.Handle
	if r, _, _ := procGetNamedSecurityInfoW.Call(uintptr(unsafe.Pointer(p)), seFileObject,
		daclSecurityInformation, 0, 0, uintptr(unsafe.Pointer(&dacl)), 0, uintptr(unsafe.Pointer(&sd))); r != 0 {
		return nil, fmt.Errorf("GetNamedSecurityInfo(%s): %w", path, syscall.Errno(r))
	}
	defer syscall.LocalFree(sd)
	if dacl == nil {
		return nil, fmt.Errorf("%s has a NULL DACL", path)
	}
	hdr := unsafe.Slice(dacl, 8)
	acl := unsafe.Slice(dacl, int(binary.LittleEndian.Uint16(hdr[2:4])))
	count := int(binary.LittleEndian.Uint16(hdr[4:6]))
	var out []aceEntry
	for i, off := 0, 8; i < count && off+8 <= len(acl); i++ {
		typ, flags := acl[off], acl[off+1]
		size := int(binary.LittleEndian.Uint16(acl[off+2 : off+4]))
		if size < 8 || off+size > len(acl) {
			return nil, fmt.Errorf("%s: malformed ACE %d", path, i)
		}
		if typ == aceTypeAllowed || typ == aceTypeDenied {
			sid, err := (*syscall.SID)(unsafe.Pointer(&acl[off+8])).String()
			if err != nil {
				return nil, err
			}
			out = append(out, aceEntry{typ: typ, flags: flags,
				mask: binary.LittleEndian.Uint32(acl[off+4 : off+8]), sid: sid})
		}
		off += size
	}
	return out, nil
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
