//go:build windows

package winenv

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// The real Win32 surface. Standard library only: no cgo, no external modules, so
// `go build` produces one static exe with no runtime dependency, which spec §6C
// requires. Every call goes through a lazily-resolved DLL so a missing export on
// an old build of Windows is a runtime error we can report, not a load failure
// that stops the program before it can say anything.

var (
	shell32  = syscall.NewLazyDLL("shell32.dll")
	ole32    = syscall.NewLazyDLL("ole32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procSHGetKnownFolderPath = shell32.NewProc("SHGetKnownFolderPath")
	procCoTaskMemFree        = ole32.NewProc("CoTaskMemFree")

	procGetLogicalDriveStringsW        = kernel32.NewProc("GetLogicalDriveStringsW")
	procGetVolumeNameForVolumeMountPtW = kernel32.NewProc("GetVolumeNameForVolumeMountPointW")
	procGetVolumeInformationW          = kernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW            = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetDriveTypeW                  = kernel32.NewProc("GetDriveTypeW")
	procGetWindowsDirectoryW           = kernel32.NewProc("GetWindowsDirectoryW")
	procGetVolumePathNameW             = kernel32.NewProc("GetVolumePathNameW")
	procGetFileAttributesW             = kernel32.NewProc("GetFileAttributesW")

	procRegOpenKeyExW    = advapi32.NewProc("RegOpenKeyExW")
	procRegEnumKeyExW    = advapi32.NewProc("RegEnumKeyExW")
	procRegQueryValueExW = advapi32.NewProc("RegQueryValueExW")
	procRegCloseKey      = advapi32.NewProc("RegCloseKey")
)

const (
	driveRemovable = 2

	// FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS and FILE_ATTRIBUTE_OFFLINE mark a
	// OneDrive Files On-Demand placeholder. SAFETY.md phase 1.
	attrRecallOnDataAccess = 0x00400000
	attrRecallOnOpen       = 0x00040000
	attrOffline            = 0x00001000
	attrReparsePoint       = 0x00000400
	invalidFileAttributes  = 0xFFFFFFFF

	hkeyLocalMachine = 0x80000002
	hkeyCurrentUser  = 0x80000001

	keyRead         = 0x20019
	keyWow64_64Key  = 0x0100
	keyWow64_32Key  = 0x0200
	errNoMoreItems  = 259
	regSZ           = 1
	regExpandSZ     = 2
	maxRegKeyNameCh = 256
)

type winEnv struct{}

// New returns the real Windows environment.
func New() Env { return &winEnv{} }

// Available reports whether the real Windows surface is present.
func Available() bool { return true }

func (w *winEnv) Platform() string { return "windows" }

func (w *winEnv) KnownFolders() ([]Folder, error) {
	out := make([]Folder, 0, len(knownFolderIDs))
	for _, kf := range knownFolderIDs {
		id := kf.ID
		// The out-parameter is typed *uint16 rather than uintptr so that the
		// CoTaskMem buffer never has to be converted back from an integer.
		// uintptr -> unsafe.Pointer is the one direction that is genuinely
		// unsound (the value is not a reference while it sits in an integer)
		// and `go vet` fails the build on it; this is the same shape
		// x/sys/windows uses for SHGetKnownFolderPath.
		var ptr *uint16
		r, _, _ := procSHGetKnownFolderPath.Call(
			uintptr(unsafe.Pointer(&id)),
			0, // no flags: do not create, do not verify
			0, // current user token
			uintptr(unsafe.Pointer(&ptr)),
		)
		if r != 0 || ptr == nil {
			out = append(out, Folder{ID: kf.Name, Present: false})
			continue
		}
		p := utf16PtrToString(ptr)
		procCoTaskMemFree.Call(uintptr(unsafe.Pointer(ptr)))
		st, err := os.Stat(p)
		out = append(out, Folder{ID: kf.Name, Path: p, Present: err == nil && st.IsDir()})
	}
	return out, nil
}

// uninstallKeys covers both registry views. A 32-bit installer on a 64-bit
// machine lands in the WOW6432Node view, and a tool that reads only one view
// tells the user a shorter list than the truth — which under §4.2 is the failure
// that costs a customer at month two.
var uninstallKeys = []struct {
	Root  uintptr
	Path  string
	Flags uintptr
}{
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, keyWow64_64Key},
	{hkeyLocalMachine, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, keyWow64_32Key},
	{hkeyCurrentUser, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, 0},
}

func (w *winEnv) InstalledPrograms() ([]Program, error) {
	seen := make(map[string]Program)
	for _, k := range uninstallKeys {
		h, err := regOpen(k.Root, k.Path, k.Flags)
		if err != nil {
			continue // a missing view is normal, not an error
		}
		for i := uint32(0); ; i++ {
			name, err := regEnumKey(h, i)
			if err != nil {
				break
			}
			sub, err := regOpen(uintptr(h), name, k.Flags)
			if err != nil {
				continue
			}
			display := regString(sub, "DisplayName")
			sysComp := regString(sub, "SystemComponent")
			parent := regString(sub, "ParentKeyName")
			// SystemComponent=1 and ParentKeyName mark updates and sub-entries.
			// They are noise in a list the user is asked to read and accept.
			if display != "" && sysComp != "1" && parent == "" {
				prog := Program{
					Name:      display,
					Publisher: regString(sub, "Publisher"),
					Version:   regString(sub, "DisplayVersion"),
					Source:    k.Path + `\` + name,
				}
				if _, dup := seen[prog.Name]; !dup {
					seen[prog.Name] = prog
				}
			}
			regClose(sub)
		}
		regClose(h)
	}
	out := make([]Program, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (w *winEnv) Volumes() ([]Volume, error) {
	buf := make([]uint16, 1024)
	n, _, err := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if n == 0 {
		return nil, fmt.Errorf("winenv: GetLogicalDriveStrings: %v", err)
	}
	sysVol, sysErr := w.SystemVolume()
	var out []Volume
	for _, root := range splitUTF16List(buf[:n]) {
		v, err := volumeAt(root)
		if err != nil {
			continue // a card reader with no card is not an error
		}
		if sysErr == nil && v.GUID != "" && v.GUID == sysVol.GUID {
			v.IsSystem = true
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out, nil
}

func volumeAt(root string) (Volume, error) {
	rp, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return Volume{}, err
	}
	v := Volume{Mount: root}

	nameBuf := make([]uint16, 64)
	if r, _, _ := procGetVolumeNameForVolumeMountPtW.Call(
		uintptr(unsafe.Pointer(rp)), uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf)),
	); r != 0 {
		v.GUID = utf16ToString(nameBuf)
	}

	label := make([]uint16, 261)
	fsName := make([]uint16, 261)
	procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rp)),
		uintptr(unsafe.Pointer(&label[0])), uintptr(len(label)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&fsName[0])), uintptr(len(fsName)),
	)
	v.Label = utf16ToString(label)
	v.FS = utf16ToString(fsName)

	var freeForCaller, total, totalFree uint64
	procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(rp)),
		uintptr(unsafe.Pointer(&freeForCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	// freeForCaller, not totalFree: a disk quota makes them differ, and the
	// number that decides whether the copy fits is the one we are allowed to use.
	v.FreeBytes, v.TotalBytes = freeForCaller, total

	dt, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(rp)))
	v.Removable = dt == driveRemovable

	if v.GUID == "" {
		return v, fmt.Errorf("winenv: no volume GUID for %s", root)
	}
	return v, nil
}

func (w *winEnv) SystemVolume() (Volume, error) {
	buf := make([]uint16, 512)
	n, _, err := procGetWindowsDirectoryW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return Volume{}, fmt.Errorf("winenv: GetWindowsDirectory: %v", err)
	}
	winDir := utf16ToString(buf[:n])
	root := filepath.VolumeName(winDir) + `\`
	v, verr := volumeAt(root)
	v.IsSystem = true
	return v, verr
}

// VolumeForPath asks Windows which volume holds this path.
//
// GetVolumePathNameW returns the mount point of the volume that the path is
// ACTUALLY on — it walks the path's real parentage, so a directory that lives on
// C: answers "C:\" even when the caller reached it through a junction on D:.
// GetVolumeNameForVolumeMountPointW then turns that mount point into the volume
// GUID, which is the only identity SAFETY.md phase 3 accepts.
//
// Deriving a volume from a string prefix against GetLogicalDriveStringsW — which
// is what this replaced — answers a different question: the identity of the
// DRIVE LETTER the user typed. That is exactly the answer a junction forges.
func (w *winEnv) VolumeForPath(path string) (Volume, error) {
	pp, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		return Volume{}, err
	}
	buf := make([]uint16, 32768)
	r, _, e := procGetVolumePathNameW.Call(
		uintptr(unsafe.Pointer(pp)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
	)
	if r == 0 {
		return Volume{}, fmt.Errorf("winenv: GetVolumePathName(%s): %v", path, e)
	}
	root := utf16ToString(buf)
	if root == "" {
		return Volume{}, fmt.Errorf("winenv: GetVolumePathName(%s) returned no mount point", path)
	}
	if !strings.HasSuffix(root, `\`) {
		root += `\`
	}
	v, verr := volumeAt(root)
	if verr != nil {
		return Volume{}, verr
	}
	if sys, serr := w.SystemVolume(); serr == nil && sys.GUID != "" && sys.GUID == v.GUID {
		v.IsSystem = true
	}
	return v, nil
}

// IsReparsePoint reports FILE_ATTRIBUTE_REPARSE_POINT on the path ITSELF.
// GetFileAttributesW reports the attributes of the link rather than of its
// target, which is what makes it the right call here: we are asking whether this
// name is a door to somewhere else, not what is behind the door.
func (w *winEnv) IsReparsePoint(path string) (bool, error) {
	attrs, err := fileAttributes(path)
	if err != nil {
		return false, err
	}
	return attrs&attrReparsePoint != 0, nil
}

// ReparseTag returns the reparse tag of path ITSELF, or 0 if it is not a
// reparse point.
//
// FindFirstFileW is asked about the name, which reads the PARENT directory's
// listing: a junction whose own ACL denies listing (LocalAppData\Application
// Data denies Everyone) still answers. WIN32_FIND_DATAW.dwReserved0 "specifies
// the reparse point tag" when FILE_ATTRIBUTE_REPARSE_POINT is set.
// https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-win32_find_dataw
func ReparseTag(path string) (uint32, error) {
	p, err := syscall.UTF16PtrFromString(longPath(path))
	if err != nil {
		return 0, err
	}
	var fd syscall.Win32finddata
	h, err := syscall.FindFirstFile(p, &fd)
	if err != nil {
		return 0, err
	}
	syscall.FindClose(h)
	if fd.FileAttributes&attrReparsePoint == 0 {
		return 0, nil
	}
	return fd.Reserved0, nil
}

func (w *winEnv) Firmware() (Firmware, error) {
	// Deliberately incomplete and deliberately honest.
	//
	// Secure Boot state, third-party UEFI CA trust, the TPM version and whether
	// this firmware honours BootNext cannot be established from the stdlib alone,
	// and every one of them is a fact we tell the user BEFORE they start. A
	// guess here becomes a promise the tool cannot keep, so this returns
	// Known=false until the detection is written and validated in a VM.
	//
	// Known=false is not a shrug any more: safety.Arm REFUSES to commit while it
	// is false, and the BitLocker fact in particular is probed separately by
	// internal/sysdisk (manage-bde -status), because asking that question means
	// running a command and this package is not allowed to.
	return Firmware{
		Known: false,
		Notes: []string{
			"Firmware detection is not implemented yet. Secure Boot, third-party UEFI CA trust, TPM version and BootNext support are UNKNOWN.",
			"SAFETY.md requires all three to be detected in phase 1 and stated before the run begins.",
		},
	}, nil
}

func (w *winEnv) CloudPlaceholders(root string) (PlaceholderStats, error) {
	var st PlaceholderStats
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable subtrees are the copy engine's problem, not this one's
		}
		if info.IsDir() {
			return nil
		}
		attrs, aerr := fileAttributes(p)
		if aerr != nil {
			return nil
		}
		if attrs&(attrRecallOnDataAccess|attrRecallOnOpen|attrOffline) != 0 {
			st.Count++
			st.LogicalSize += info.Size()
		}
		return nil
	})
	return st, err
}

func fileAttributes(p string) (uint32, error) {
	pp, err := syscall.UTF16PtrFromString(longPath(p))
	if err != nil {
		return 0, err
	}
	r, _, e := procGetFileAttributesW.Call(uintptr(unsafe.Pointer(pp)))
	if uint32(r) == invalidFileAttributes {
		return 0, e
	}
	return uint32(r), nil
}

// longPath adds the \\?\ prefix so paths over MAX_PATH work. Deep redirected
// Documents trees on school machines routinely exceed 260 characters.
func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) || !filepath.IsAbs(p) {
		return p
	}
	if strings.HasPrefix(p, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(p, `\\`)
	}
	return `\\?\` + p
}

// --- registry helpers (stdlib syscall only) ---

func regOpen(root uintptr, path string, flags uintptr) (syscall.Handle, error) {
	pp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var h syscall.Handle
	r, _, _ := procRegOpenKeyExW.Call(
		root, uintptr(unsafe.Pointer(pp)), 0, keyRead|flags, uintptr(unsafe.Pointer(&h)),
	)
	if r != 0 {
		return 0, fmt.Errorf("winenv: RegOpenKeyEx(%s): %d", path, r)
	}
	return h, nil
}

func regClose(h syscall.Handle) {
	if h != 0 {
		procRegCloseKey.Call(uintptr(h))
	}
}

func regEnumKey(h syscall.Handle, i uint32) (string, error) {
	buf := make([]uint16, maxRegKeyNameCh+1)
	n := uint32(len(buf))
	r, _, _ := procRegEnumKeyExW.Call(
		uintptr(h), uintptr(i), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)),
		0, 0, 0, 0,
	)
	if r != 0 {
		return "", fmt.Errorf("winenv: RegEnumKeyEx: %d", r)
	}
	return utf16ToString(buf[:n]), nil
}

func regString(h syscall.Handle, name string) string {
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var typ uint32
	var size uint32
	r, _, _ := procRegQueryValueExW.Call(
		uintptr(h), uintptr(unsafe.Pointer(np)), 0,
		uintptr(unsafe.Pointer(&typ)), 0, uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 || size == 0 || (typ != regSZ && typ != regExpandSZ) {
		return ""
	}
	buf := make([]uint16, size/2+1)
	r, _, _ = procRegQueryValueExW.Call(
		uintptr(h), uintptr(unsafe.Pointer(np)), 0,
		uintptr(unsafe.Pointer(&typ)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 {
		return ""
	}
	return utf16ToString(buf)
}

// --- UTF-16 helpers ---

func utf16ToString(s []uint16) string {
	for i, c := range s {
		if c == 0 {
			return syscall.UTF16ToString(s[:i])
		}
	}
	return syscall.UTF16ToString(s)
}

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	var n int
	for ptr := unsafe.Pointer(p); *(*uint16)(ptr) != 0; n++ {
		ptr = unsafe.Add(ptr, unsafe.Sizeof(uint16(0)))
	}
	return syscall.UTF16ToString(unsafe.Slice(p, n))
}

// splitUTF16List splits a NUL-separated, double-NUL-terminated UTF-16 list.
func splitUTF16List(b []uint16) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c != 0 {
			continue
		}
		if i > start {
			out = append(out, syscall.UTF16ToString(b[start:i]))
		}
		start = i + 1
	}
	return out
}
