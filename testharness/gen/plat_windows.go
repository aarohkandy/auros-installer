//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

// Windows file attributes we set. Declared here rather than taken from the syscall package because not
// all of them are exported there, and a corpus property should not depend on which constants a given Go
// release happens to expose.
const (
	fileAttributeReadonly = 0x00000001
	fileAttributeOffline  = 0x00001000

	// FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS. We do NOT set this, and cannot: it is owned by the cloud
	// filter driver and is set by CfCreatePlaceholders under a registered sync root. See platSetOffline.
	fileAttributeRecallOnDataAccess = 0x00400000
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
	procGetVolumePathNameW    = kernel32.NewProc("GetVolumePathNameW")
	procLocalFree             = kernel32.NewProc("LocalFree")

	advapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procConvertStringSDToSD     = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetKernelObjectSecurity = advapi32.NewProc("SetKernelObjectSecurity")
)

func platFaithful() bool { return true }

// platVolumeSerial returns the volume serial in the DDDD-DDDD form `vol` prints, for the volume that
// contains path. This is the value the §4.7 guard compares against the harness token. A drive LETTER is
// not usable for this: a mount point or a subst'd letter can alias the system volume, which is exactly
// the mistake SAFETY.md phase 3 forbids in the installer itself.
func platVolumeSerial(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	p, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, syscall.MAX_PATH+1)
	r1, _, e := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("GetVolumePathNameW(%s): %w", abs, e)
	}
	var serial, maxComp, flags uint32
	r1, _, e = procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		0, 0,
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComp)),
		uintptr(unsafe.Pointer(&flags)),
		0, 0,
	)
	if r1 == 0 {
		return "", fmt.Errorf("GetVolumeInformationW: %w", e)
	}
	return fmt.Sprintf("%04X-%04X", serial>>16, serial&0xFFFF), nil
}

func platSetReadOnly(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(p, attrs|fileAttributeReadonly)
}

// platSetOffline sets FILE_ATTRIBUTE_OFFLINE, producing a file that LOOKS like a OneDrive Files-On-Demand
// placeholder to every attribute check the installer performs.
//
// It is not one, and the manifest says so: placeholder_fidelity is "attribute-only".
//
// A real placeholder is created by CfCreatePlaceholders under a sync root registered with
// CfRegisterSyncRoot, and reading it triggers hydration through the cloud filter driver. We can exercise
// the installer's DETECTION path faithfully — which is the path that decides whether to warn the user
// before starting a multi-hundred-gigabyte download over school Wi-Fi — but we cannot exercise the
// HYDRATION path without standing up a sync provider.
//
// Writing "placeholder" in the manifest without that qualifier would be a claim we have not earned, and
// §4.2's rule about not claiming capabilities we do not have is not limited to the marketing site.
func platSetOffline(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(p, attrs|fileAttributeOffline)
}

// platWriteStream writes an NTFS alternate data stream. CreateFileW is called directly on "path:stream"
// rather than going through os.Create, because Go's path fixing has no reason to expect a stream suffix
// and the failure mode if it ever starts normalising one is a silently missing stream.
func platWriteStream(path, stream string, data []byte) error {
	p, err := syscall.UTF16PtrFromString(path + ":" + stream)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p,
		syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ,
		nil,
		syscall.CREATE_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		return fmt.Errorf("CreateFile %s:%s: %w", path, stream, err)
	}
	defer syscall.CloseHandle(h)
	if len(data) == 0 {
		return nil
	}
	var done uint32
	return syscall.WriteFile(h, data, &done, nil)
}

// platHoldExclusive opens each file with dwShareMode = 0 — no sharing at all, not even read. This is
// what a live machine looks like: Word has a document open, Chrome has its profile locked, the antivirus
// has just grabbed something for a scan.
//
// A copy tool that quietly skips these files produces a "successful" migration that is missing the user's
// dissertation. SAFETY.md phase 4 requires them to be quarantined and REPORTED, never silently skipped,
// and this is how the harness proves that happens.
func platHoldExclusive(paths []string) (func(), error) {
	handles := make([]syscall.Handle, 0, len(paths))
	release := func() {
		for _, h := range handles {
			syscall.CloseHandle(h)
		}
	}
	for _, path := range paths {
		p, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			release()
			return nil, err
		}
		h, err := syscall.CreateFile(p,
			syscall.GENERIC_READ,
			0, // dwShareMode 0 — exclusive
			nil,
			syscall.OPEN_EXISTING,
			syscall.FILE_ATTRIBUTE_NORMAL,
			0)
		if err != nil {
			release()
			return nil, fmt.Errorf("cannot take an exclusive handle on %s: %w", path, err)
		}
		handles = append(handles, h)
	}
	return release, nil
}

// referenced so the constant is not dead weight a future reader deletes without reading the comment.
var _ = fileAttributeRecallOnDataAccess

// platMakeJunction makes a real NTFS junction (IO_REPARSE_TAG_MOUNT_POINT) with mklink /J, the
// built-in that makes the same object Windows setup made for "Application Data". A symbolic link would
// be a different reparse tag and would test a different code path.
func platMakeJunction(link, target string) error {
	out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink /J: %w: %s", err, out)
	}
	return nil
}

// denyListSDDL: Everyone is DENIED FILE_LIST_DIRECTORY (0x1) and allowed everything else, so the
// directory cannot be enumerated but can still be deleted. The legacy junctions carry the same deny
// (icacls shows "Everyone:(DENY)(S,RD)"). Protected (P), so nothing is inherited around it.
const denyListSDDL = "D:P(D;;0x1;;;WD)(A;;FA;;;WD)"

// platDenyList sets denyListSDDL on path ITSELF. The handle is opened with FILE_FLAG_OPEN_REPARSE_POINT,
// so on a junction it is the junction's ACL that changes and not its target's — denying the target
// here would make all of LocalAppData unlistable, which no real machine looks like.
func platDenyList(path string) error {
	sddl, err := syscall.UTF16PtrFromString(denyListSDDL)
	if err != nil {
		return err
	}
	var sd uintptr
	r1, _, e := procConvertStringSDToSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&sd)), 0)
	if r1 == 0 {
		return fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptorW: %w", e)
	}
	defer procLocalFree.Call(sd)

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	const writeDAC = 0x00040000
	const fileFlagOpenReparsePoint = 0x00200000
	h, err := syscall.CreateFile(p, writeDAC,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil,
		syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|fileFlagOpenReparsePoint, 0)
	if err != nil {
		return fmt.Errorf("CreateFile %s: %w", path, err)
	}
	defer syscall.CloseHandle(h)
	const daclSecurityInformation = 0x4
	r1, _, e = procSetKernelObjectSecurity.Call(uintptr(h), daclSecurityInformation, sd)
	if r1 == 0 {
		return fmt.Errorf("SetKernelObjectSecurity %s: %w", path, e)
	}
	return nil
}
