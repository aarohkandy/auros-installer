//go:build windows

package gate3

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE INJECTOR
//
// Every action here damages something on purpose, and every one of them records
// the bytes it left behind at the moment it left them. That record — not the
// scenario table — is what the post-run comparison expects to find, so a fault
// that did not land the way it was meant to becomes a failure rather than an
// expectation that quietly absorbed it.
//
// The actions are deliberately NOT reused from testharness/fault: that package's
// guest control is shaped for a QEMU guest driven over a serial line, holds its
// locks for a fixed number of milliseconds, and fills a volume by writing four
// megabytes at a time. On a 40 GB destination with a pin measured in
// milliseconds, each of those is the difference between a scenario that fires
// where it says it does and one that does not.
// ─────────────────────────────────────────────────────────────────────────────

const (
	fsctlDismountVolume = 0x00090020
	fsctlLockVolume     = 0x00090018

	fileAttributeReadonly = 0x00000001
	sePrivilegeEnabled    = 0x00000002
	tokenAdjustPrivileges = 0x0020
	tokenQuery            = 0x0008
)

var (
	procGetDiskFreeSpaceExW     = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procSetSystemTime           = modkernel32.NewProc("SetSystemTime")
	procGetSystemTimeAsFileTime = modkernel32.NewProc("GetSystemTimeAsFileTime")
	procFileTimeToSystemTime    = modkernel32.NewProc("FileTimeToSystemTime")
	procOpenProcessToken        = modadvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW   = modadvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges   = modadvapi32.NewProc("AdjustTokenPrivileges")
)

// Injector performs one scenario's damage and remembers exactly what it did.
type Injector struct {
	mu         sync.Mutex
	held       []syscall.Handle // exclusive handles, released when the run ends
	clockDelta int64            // seconds the clock was moved back, for the restore
	CorpusRoot string
	DestDir    string
	DestVolume string // "E:\"
}

// Release undoes everything the injector is HOLDING (handles, the clock). It
// does not undo damage: damage is the point, and the post-run comparison is
// what accounts for it.
func (in *Injector) Release() {
	in.mu.Lock()
	defer in.mu.Unlock()
	for _, h := range in.held {
		syscall.CloseHandle(h)
	}
	in.held = nil
	if in.clockDelta != 0 {
		// Put the clock back. A runner whose clock is ten years out cannot
		// validate the TLS certificate it needs to report this result.
		if err := shiftClock(-in.clockDelta); err != nil {
			fmt.Fprintf(os.Stderr, "gate3: WARNING: could not restore the system clock: %v\n", err)
		}
		in.clockDelta = 0
		// Ask the time service for the truth as well, so a drift of a few
		// seconds introduced by the shift does not accumulate across runs.
		_ = exec.Command("w32tm", "/resync", "/force").Run()
	}
}

// FreeBytes is the destination's free space, which is how the harness measures
// that a copy is really happening without walking 18,000 files at the instant a
// power cut is due.
func FreeBytes(root string) (free, total int64, err error) {
	p, perr := syscall.UTF16PtrFromString(root)
	if perr != nil {
		return 0, 0, perr
	}
	var freeToCaller, totalBytes, totalFree uint64
	r1, _, e := procGetDiskFreeSpaceExW.Call(uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&freeToCaller)), uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&totalFree)))
	if r1 == 0 {
		return 0, 0, fmt.Errorf("gate3: GetDiskFreeSpaceEx(%s): %w", root, e)
	}
	return int64(freeToCaller), int64(totalBytes), nil
}

// DismountDestination is the USB being pulled out.
//
// FSCTL_DISMOUNT_VOLUME without taking the lock first is the faithful part: it
// forces the dismount while the installer holds open handles, and every one of
// those handles becomes invalid immediately, which is what the device
// disappearing looks like from inside a program. Detaching the backing disk
// afterwards stops NTFS quietly remounting it on the installer's next open.
func (in *Injector) DismountDestination() error {
	letter := trimVolume(in.DestVolume)
	v, err := openVolume(letter, true)
	if err != nil {
		return err
	}
	var ret uint32
	derr := syscall.DeviceIoControl(v.h, fsctlDismountVolume, nil, 0, nil, 0, &ret, nil)
	v.Close()
	if derr != nil {
		return fmt.Errorf("gate3: FSCTL_DISMOUNT_VOLUME on %s: %w", letter, derr)
	}
	return nil
}

// FillDestination consumes the destination's free space, leaving leaveBytes.
//
// SetEndOfFile rather than writing bytes: NTFS allocates the clusters
// immediately, so the volume is full within milliseconds of the pin instead of
// several seconds later, by which time the installer would be somewhere else
// entirely.
func (in *Injector) FillDestination(leaveBytes int64) (int64, error) {
	p := filepath.Join(in.DestVolume, "auros-harness-balloon.bin")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	// Grow until the volume really is full, re-measuring every time.
	//
	// The first version asked for all the free space at once and, when that was
	// refused, halved the request until it succeeded — which left a volume with
	// twenty gigabytes free and an installer that finished the copy perfectly.
	// The run reported that honestly ("the installer exited 0"), and the fault
	// was mine. Asking for the space that is left, and then asking again, is the
	// only form of this that ends with a full volume.
	var size int64
	for attempt := 0; attempt < 40; attempt++ {
		free, _, ferr := FreeBytes(in.DestVolume)
		if ferr != nil {
			return size, ferr
		}
		if free <= leaveBytes+(64<<10) {
			return size, f.Sync()
		}
		want := size + (free - leaveBytes)
		if terr := f.Truncate(want); terr != nil {
			// Refused: take half of what is left instead and go round again.
			want = size + (free-leaveBytes)/2
			if want <= size {
				return size, fmt.Errorf("gate3: could not consume the destination's free space: %d bytes "+
					"still free after %d attempts: %w", free, attempt+1, terr)
			}
			if terr2 := f.Truncate(want); terr2 != nil {
				return size, fmt.Errorf("gate3: could not consume the destination's free space (%d free): %w",
					free, terr2)
			}
		}
		size = want
	}
	free, _, _ := FreeBytes(in.DestVolume)
	if free > leaveBytes+(64<<10) {
		return size, fmt.Errorf("gate3: the destination still has %d bytes free after filling it: the "+
			"scenario did not happen", free)
	}
	return size, f.Sync()
}

// MutateFile rewrites two regions of a file with deterministic bytes.
//
// Two regions, near the start and near the end, because one region cannot
// produce the failure this is hunting. A copy loop that reads sequentially and
// is interrupted by a save has read the first region before the save and the
// second after it: the bytes it writes are a MIXTURE of two versions that never
// existed as a file. One region can only ever yield one version or the other,
// and would let a torn copy pass.
//
// The bytes are a function of the path, so a second call writes exactly what the
// first did: the file has two possible states, never three, which is what makes
// "the archive holds a version that really existed" a decidable question.
func MutateFile(path string) (Variant, error) {
	if err := clearReadOnly(path); err != nil {
		return Variant{}, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return Variant{}, err
	}
	st, serr := f.Stat()
	if serr != nil {
		f.Close()
		return Variant{}, serr
	}
	size := st.Size()
	if size < 64 {
		f.Close()
		return Variant{}, fmt.Errorf("gate3: %s is %d bytes: too small to tear", path, size)
	}
	head := sha256.Sum256([]byte("gate3-head\x00" + path))
	tail := sha256.Sum256([]byte("gate3-tail\x00" + path))
	if _, err := f.WriteAt(head[:], size/8); err != nil {
		f.Close()
		return Variant{}, err
	}
	if _, err := f.WriteAt(tail[:], size-32); err != nil {
		f.Close()
		return Variant{}, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return Variant{}, err
	}
	f.Close()
	v, err := HashOf(path)
	if err != nil {
		return Variant{}, err
	}
	v.Note = "rewritten by the harness"
	return v, nil
}

// HoldMutating keeps rewriting a file until stop is closed. Every iteration
// writes the same bytes, so the file still has only two possible states; what
// changes on every iteration is its modification time, which is what the
// installer has to notice.
func (in *Injector) HoldMutating(path string, stop <-chan struct{}, every time.Duration) (Variant, error) {
	v, err := MutateFile(path)
	if err != nil {
		return v, err
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				_, _ = MutateFile(path)
			}
		}
	}()
	return v, nil
}

// DeleteFile removes a source file.
func DeleteFile(path string) error {
	if err := clearReadOnly(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(path)
}

// BitFlip flips exactly one bit. Not one byte.
func BitFlip(path string, offset int64, bit uint) (Variant, error) {
	if err := clearReadOnly(path); err != nil {
		return Variant{}, err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return Variant{}, err
	}
	st, serr := f.Stat()
	if serr != nil {
		f.Close()
		return Variant{}, serr
	}
	if st.Size() == 0 {
		f.Close()
		return Variant{}, fmt.Errorf("gate3: cannot flip a bit in an empty file: %s", path)
	}
	off := offset % st.Size()
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		f.Close()
		return Variant{}, err
	}
	b[0] ^= 1 << (bit % 8)
	if _, err := f.WriteAt(b[:], off); err != nil {
		f.Close()
		return Variant{}, err
	}
	f.Sync()
	f.Close()
	v, err := HashOf(path)
	if err != nil {
		return Variant{}, err
	}
	v.Note = fmt.Sprintf("bit %d of byte %d flipped", bit%8, off)
	return v, nil
}

// TruncateTo shortens a file.
func TruncateTo(path string, keep int64) (Variant, error) {
	if err := os.Truncate(path, keep); err != nil {
		return Variant{}, err
	}
	v, err := HashOf(path)
	if err != nil {
		return Variant{}, err
	}
	v.Note = fmt.Sprintf("truncated to %d bytes", keep)
	return v, nil
}

// PlantFile writes a file the installer's manifest cannot know about.
func PlantFile(path string) (Variant, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return Variant{}, err
	}
	body := []byte("planted by the Auros Gate 3 harness: this file is not in the manifest, and an archive " +
		"that contains it is not the archive the manifest describes\n")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return Variant{}, err
	}
	sum := sha256.Sum256(body)
	return Variant{SHA256: fmt.Sprintf("%x", sum), Size: int64(len(body)), Note: "planted by the harness"}, nil
}

// LockExclusive opens a file with no sharing at all and holds it until Release.
// This is what real-time antivirus looks like from the outside, and neither
// backup semantics nor FILE_SHARE_READ on the other side gets past it: sharing
// is decided by the first opener.
func (in *Injector) LockExclusive(path string) error {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fmt.Errorf("gate3: exclusive handle on %s: %w", path, err)
	}
	in.mu.Lock()
	in.held = append(in.held, h)
	in.mu.Unlock()
	return nil
}

// MoveClockBack moves the system clock backwards and remembers by how much, so
// Release can put it back.
func (in *Injector) MoveClockBack(seconds int64) error {
	if err := shiftClock(-seconds); err != nil {
		return err
	}
	in.mu.Lock()
	in.clockDelta = -seconds
	in.mu.Unlock()
	return nil
}

func shiftClock(seconds int64) error {
	if err := enablePrivilege("SeSystemtimePrivilege"); err != nil {
		return err
	}
	var ft syscall.Filetime
	procGetSystemTimeAsFileTime.Call(uintptr(unsafe.Pointer(&ft)))
	v := int64(uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime))
	v += seconds * 10000000 // FILETIME ticks are 100ns
	if v <= 0 {
		return fmt.Errorf("gate3: that clock shift would go before the FILETIME epoch")
	}
	shifted := syscall.Filetime{LowDateTime: uint32(uint64(v) & 0xFFFFFFFF), HighDateTime: uint32(uint64(v) >> 32)}
	var st syscall.Systemtime
	r1, _, e := procFileTimeToSystemTime.Call(uintptr(unsafe.Pointer(&shifted)), uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		return fmt.Errorf("gate3: FileTimeToSystemTime: %w", e)
	}
	r1, _, e = procSetSystemTime.Call(uintptr(unsafe.Pointer(&st)))
	if r1 == 0 {
		return fmt.Errorf("gate3: SetSystemTime: %w", e)
	}
	return nil
}

func enablePrivilege(name string) error {
	var token syscall.Handle
	r1, _, e := procOpenProcessToken.Call(^uintptr(0),
		uintptr(tokenAdjustPrivileges|tokenQuery), uintptr(unsafe.Pointer(&token)))
	if r1 == 0 {
		return fmt.Errorf("gate3: OpenProcessToken: %w", e)
	}
	defer syscall.CloseHandle(token)
	np, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	type luid struct {
		Low  uint32
		High int32
	}
	type luidAndAttrs struct {
		Luid  luid
		Attrs uint32
	}
	type tokenPrivs struct {
		Count uint32
		Privs [1]luidAndAttrs
	}
	var id luid
	r1, _, e = procLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(np)), uintptr(unsafe.Pointer(&id)))
	if r1 == 0 {
		return fmt.Errorf("gate3: LookupPrivilegeValue(%s): %w", name, e)
	}
	tp := tokenPrivs{Count: 1}
	tp.Privs[0] = luidAndAttrs{Luid: id, Attrs: sePrivilegeEnabled}
	r1, _, e = procAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
	if r1 == 0 {
		return fmt.Errorf("gate3: AdjustTokenPrivileges(%s): %w", name, e)
	}
	if errno, ok := e.(syscall.Errno); ok && errno != 0 {
		return fmt.Errorf("gate3: privilege %s was not actually enabled: %w", name, e)
	}
	return nil
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

// PlantSymlink puts a link inside the corpus that points outside it.
func PlantSymlink(linkPath, target string) error {
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		return err
	}
	os.Remove(linkPath)
	// os.Symlink uses CreateSymbolicLinkW with the unprivileged-creation flag,
	// which an elevated process is allowed to use regardless.
	return os.Symlink(target, linkPath)
}

// MakeJunction creates an NTFS junction at linkPath pointing at target. mklink
// rather than DeviceIoControl: it is one line of a throwaway harness, and the
// reparse buffer is not the thing under test.
func MakeJunction(linkPath, target string) error {
	os.Remove(linkPath)
	out, err := exec.Command("cmd", "/c", "mklink", "/J", linkPath, target).CombinedOutput()
	if err != nil {
		return fmt.Errorf("gate3: mklink /J %s %s: %v: %s", linkPath, target, err, string(out))
	}
	return nil
}

func trimVolume(v string) string {
	v = filepath.Clean(v)
	if len(v) >= 2 && v[1] == ':' {
		return v[:2]
	}
	return v
}

// deterministicOffset picks the byte a bit flip lands on, from the scenario id
// and the path, so a failing run is one you can re-run rather than a story.
func deterministicOffset(scenarioID, path string, size int64) (int64, uint) {
	h := sha256.Sum256([]byte(scenarioID + "\x00" + path))
	a := binary.LittleEndian.Uint64(h[0:8])
	b := binary.LittleEndian.Uint64(h[8:16])
	if size <= 0 {
		return 0, 0
	}
	return int64(a % uint64(size)), uint(b % 8)
}

// denyListSDDL: Everyone is DENIED FILE_LIST_DIRECTORY and allowed everything
// else, so the directory cannot be enumerated but can still be removed. Protected
// (P), so nothing is inherited around it. The same ACE gen puts on its junctions.
const denyListSDDL = "D:P(D;;0x1;;;WD)(A;;FA;;;WD)"

var (
	procConvertStringSDToSD = syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procSetFileSecurityW    = syscall.NewLazyDLL("advapi32.dll").NewProc("SetFileSecurityW")
	procLocalFreeSD         = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

// DenyList makes dir a folder nobody can list.
func DenyList(dir string) error {
	sddl, err := syscall.UTF16PtrFromString(denyListSDDL)
	if err != nil {
		return err
	}
	var sd uintptr
	if r, _, e := procConvertStringSDToSD.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&sd)), 0); r == 0 {
		return fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptorW: %w", e)
	}
	defer procLocalFreeSD.Call(sd)
	p, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	const daclSecurityInformation = 0x4
	if r, _, e := procSetFileSecurityW.Call(uintptr(unsafe.Pointer(p)), daclSecurityInformation, sd); r == 0 {
		return fmt.Errorf("SetFileSecurityW %s: %w", dir, e)
	}
	return nil
}
