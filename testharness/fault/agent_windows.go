//go:build windows

package fault

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// The guest half of the injector. Everything here runs inside the throwaway Windows VM, elevated,
// against a corpus that exists to be destroyed.
//
// Nothing in this file is safe to run anywhere else, which is why the fault agent refuses to start
// without the harness token — the same §4.7 guard gen/ uses, for the same reason.

const (
	fileAttributeReadonly = 0x00000001
	sePrivilegeEnabled    = 0x00000002
	tokenAdjustPrivileges = 0x0020
	tokenQuery            = 0x0008
)

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procGetVolumeInformationW = kernel32.NewProc("GetVolumeInformationW")
	procGetVolumePathNameW    = kernel32.NewProc("GetVolumePathNameW")
	advapi32                  = syscall.NewLazyDLL("advapi32.dll")

	procGetDiskFreeSpaceExW     = kernel32.NewProc("GetDiskFreeSpaceExW")
	procGetSystemTimeAsFileTime = kernel32.NewProc("GetSystemTimeAsFileTime")
	procFileTimeToSystemTime    = kernel32.NewProc("FileTimeToSystemTime")
	procSetSystemTime           = kernel32.NewProc("SetSystemTime")

	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

type winGuest struct {
	destVolumeRoot string // e.g. `E:\`
	balloonPath    string
}

// NewGuestControl builds the guest-side fault executor. destVolumeRoot is the destination volume, which
// by SAFETY.md phase 3 is never the system disk — and the agent checks that rather than trusting it.
func NewGuestControl(destVolumeRoot string) (GuestControl, error) {
	root := destVolumeRoot
	if !strings.HasSuffix(root, `\`) {
		root += `\`
	}
	sysRoot := os.Getenv("SystemDrive")
	if sysRoot != "" && strings.EqualFold(strings.TrimSuffix(root, `\`), strings.TrimSuffix(sysRoot, `\`)) {
		return nil, fmt.Errorf("REFUSING: destination volume %s is the system drive. Every fault in this "+
			"package damages its target on purpose", root)
	}
	return &winGuest{
		destVolumeRoot: root,
		balloonPath:    root + `auros-harness-balloon.bin`,
	}, nil
}

func freeBytes(root string) (int64, error) {
	p, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return 0, err
	}
	var freeToCaller, total, totalFree uint64
	r1, _, e := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeToCaller)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("GetDiskFreeSpaceExW(%s): %w", root, e)
	}
	return int64(freeToCaller), nil
}

// FillDestination writes a balloon file until the volume has leaveBytes free.
//
// It does NOT pre-size the destination disk to be too small. A disk that was always too small is caught
// by the free-space check in SAFETY.md phase 3 and the run never starts — which tests the check, not the
// failure. The interesting case is a destination that had room when we looked and does not any more,
// because that is what a Windows update, a second user, or an underestimated placeholder hydration does.
func (w *winGuest) FillDestination(leaveBytes int64) error {
	free, err := freeBytes(w.destVolumeRoot)
	if err != nil {
		return err
	}
	want := free - leaveBytes
	if want <= 0 {
		return nil
	}
	f, err := os.OpenFile(w.balloonPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	chunk := make([]byte, 4<<20)
	for i := range chunk {
		chunk[i] = byte(i) // not zeroes: a sparse or compressed volume would swallow zeroes
	}
	var written int64
	for written < want {
		n := int64(len(chunk))
		if want-written < n {
			n = want - written
		}
		k, werr := f.Write(chunk[:n])
		written += int64(k)
		if werr != nil {
			// ENOSPC here is success, not failure: the volume is full, which is the whole point.
			break
		}
	}
	return f.Sync()
}

func clearReadOnly(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := syscall.GetFileAttributes(p)
	if err != nil {
		return err
	}
	if attrs&fileAttributeReadonly == 0 {
		return nil
	}
	return syscall.SetFileAttributes(p, attrs&^fileAttributeReadonly)
}

// MutateSource rewrites a run of bytes one third of the way into the file — what a user saving an open
// document looks like to a copy loop that is partway through reading it.
//
// The replacement bytes are derived from the path, so a re-run mutates identically.
func (w *winGuest) MutateSource(path string) error {
	if err := clearReadOnly(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("refusing to mutate a zero-byte file: %s", path)
	}
	sum := sha256.Sum256([]byte("mutate\x00" + path))
	off := st.Size() / 3
	n := int64(len(sum))
	if off+n > st.Size() {
		off = 0
		if n > st.Size() {
			n = st.Size()
		}
	}
	_, err = f.WriteAt(sum[:n], off)
	return err
}

func (w *winGuest) DeleteSource(path string) error {
	if err := clearReadOnly(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(path)
}

func (w *winGuest) TruncateFile(path string, keepBytes int64) error {
	if keepBytes < 0 {
		keepBytes = 0
	}
	return os.Truncate(path, keepBytes)
}

// BitFlipFile flips one bit. The whole point of per-file SHA-256 is that this is detectable; if it is
// not detected, the hashing is decorative.
func (w *winGuest) BitFlipFile(path string, byteOffset int64, bit uint) error {
	if err := clearReadOnly(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.Size() == 0 {
		return fmt.Errorf("cannot flip a bit in a zero-byte file: %s", path)
	}
	if byteOffset >= st.Size() {
		byteOffset = byteOffset % st.Size()
	}
	var b [1]byte
	if _, err := f.ReadAt(b[:], byteOffset); err != nil {
		return err
	}
	b[0] ^= 1 << (bit % 8)
	if _, err := f.WriteAt(b[:], byteOffset); err != nil {
		return err
	}
	return f.Sync()
}

// enablePrivilege turns on a named privilege in this process's token. Without SeSystemtimePrivilege,
// SetSystemTime fails with ERROR_PRIVILEGE_NOT_HELD and the clock scenarios silently do nothing —
// which would look exactly like a pass.
func enablePrivilege(name string) error {
	var token syscall.Handle
	r1, _, e := procOpenProcessToken.Call(
		^uintptr(0), // GetCurrentProcess() is the pseudo-handle (HANDLE)-1
		uintptr(tokenAdjustPrivileges|tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return fmt.Errorf("OpenProcessToken: %w", e)
	}
	defer syscall.CloseHandle(token)

	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	type luid struct {
		LowPart  uint32
		HighPart int32
	}
	type luidAndAttributes struct {
		Luid       luid
		Attributes uint32
	}
	type tokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     [1]luidAndAttributes
	}
	var id luid
	r1, _, e = procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(np)), uintptr(unsafe.Pointer(&id)))
	if r1 == 0 {
		return fmt.Errorf("LookupPrivilegeValue(%s): %w", name, e)
	}
	tp := tokenPrivileges{PrivilegeCount: 1}
	tp.Privileges[0] = luidAndAttributes{Luid: id, Attributes: sePrivilegeEnabled}
	r1, _, e = procAdjustTokenPrivileges.Call(
		uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("AdjustTokenPrivileges(%s): %w", name, e)
	}
	// AdjustTokenPrivileges returns success even when it changed nothing. GetLastError is the only
	// place the truth lives, and e carries it.
	if errno, ok := e.(syscall.Errno); ok && errno != 0 {
		return fmt.Errorf("privilege %s was not actually enabled: %w", name, e)
	}
	return nil
}

// ClockBackwards moves the system clock back.
//
// This is in the catalogue because a dead CMOS battery on a 2013 laptop is the cohort, not an edge case:
// the clock resets to the firmware epoch at every boot and NTP yanks it back — or forward — seconds
// later. Any duration computed as end-minus-wall-clock-start goes negative, and any freshness decision
// made from mtime gets a wrong answer.
func (w *winGuest) ClockBackwards(seconds int64) error {
	if err := enablePrivilege("SeSystemtimePrivilege"); err != nil {
		return err
	}
	var ft syscall.Filetime
	procGetSystemTimeAsFileTime.Call(uintptr(unsafe.Pointer(&ft)))
	v := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	delta := uint64(seconds) * 10000000 // FILETIME ticks are 100 ns
	if delta >= v {
		return fmt.Errorf("moving the clock back %d seconds would go before the FILETIME epoch", seconds)
	}
	v -= delta
	back := syscall.Filetime{LowDateTime: uint32(v & 0xFFFFFFFF), HighDateTime: uint32(v >> 32)}
	var st syscall.Systemtime
	r1, _, e := procFileTimeToSystemTime.Call(uintptr(unsafe.Pointer(&back)), uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		return fmt.Errorf("FileTimeToSystemTime: %w", e)
	}
	r1, _, e = procSetSystemTime.Call(uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		return fmt.Errorf("SetSystemTime: %w", e)
	}
	return nil
}

// ExclusiveLock opens the file with dwShareMode 0 — no sharing at all — and holds it in the background,
// which is what real-time antivirus scanning looks like from the outside.
//
// Backup semantics (FILE_FLAG_BACKUP_SEMANTICS) do NOT get past this, and neither does FILE_SHARE_READ
// on the caller's side: sharing is decided by the first opener. VSS is the correct tool, and if VSS is
// unavailable SAFETY.md phase 4 requires the file to be quarantined and reported rather than skipped.
func (w *winGuest) ExclusiveLock(path string, holdMS int64) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil,
		syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("cannot take an exclusive handle on %s: %w", path, err)
	}
	go func() {
		time.Sleep(time.Duration(holdMS) * time.Millisecond)
		syscall.CloseHandle(h)
	}()
	return nil
}

// VolumeSerial returns the serial of the volume containing path, in the DDDD-DDDD form `vol` prints.
// Used by the §4.7 guard in guard.go. A drive LETTER would not do: a mount point or a subst'd letter can
// alias the system volume, which is the aliasing mistake SAFETY.md phase 3 forbids in the installer too.
func VolumeSerial(path string) (string, error) {
	p, err := syscall.UTF16PtrFromString(path)
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
		return "", fmt.Errorf("GetVolumePathNameW(%s): %w", path, e)
	}
	var serial, maxComp, flags uint32
	r1, _, e = procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(&buf[0])), 0, 0,
		uintptr(unsafe.Pointer(&serial)),
		uintptr(unsafe.Pointer(&maxComp)),
		uintptr(unsafe.Pointer(&flags)), 0, 0,
	)
	if r1 == 0 {
		return "", fmt.Errorf("GetVolumeInformationW: %w", e)
	}
	return fmt.Sprintf("%04X-%04X", serial>>16, serial&0xFFFF), nil
}
