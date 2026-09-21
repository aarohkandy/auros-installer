//go:build windows

package gate3

import (
	"encoding/binary"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// MEASURING "NOTHING WAS WRITTEN TO THE SYSTEM DISK"
//
// The obvious implementation — list every file on C: before and after and diff
// the names and sizes — was measured on the runner this harness targets: 1.19
// million files, 276 seconds per pass. Two passes per run times 120 runs is a
// day and a half of enumeration, so it would have been quietly reduced to
// something cheaper and weaker.
//
// It is also the weaker check. A name-and-size diff cannot see a file that was
// created and deleted again, a file whose contents changed without changing
// length, an attribute or security change, or a new alternate data stream.
//
// The NTFS change journal sees all of them, and it is a read of a log the file
// system is already keeping. The harness records the journal's next USN before
// the installer starts and again after it exits, reads every record in between,
// resolves each to a full path, and requires the remainder — after the published
// noise list — to be empty.
//
// It fails closed in three ways: an error reading the journal is a failed check,
// a journal whose ID changed is a failed check, and a journal that discarded
// records we had not read (a wrap) is a failed check, because the window can no
// longer be accounted for.
// ─────────────────────────────────────────────────────────────────────────────

const (
	fsctlQueryUSNJournal  = 0x000900f4
	fsctlReadUSNJournal   = 0x000900bb
	fsctlCreateUSNJournal = 0x000900e7

	fileShareAll  = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
	backupSem     = 0x02000000 // FILE_FLAG_BACKUP_SEMANTICS
	fileReadAttrs = 0x0080     // FILE_READ_ATTRIBUTES
	volNameDOS    = 0x0        // VOLUME_NAME_DOS

	usnReasonMask = 0xFFFFFFFF
)

var (
	modkernel32              = syscall.NewLazyDLL("kernel32.dll")
	procOpenFileById         = modkernel32.NewProc("OpenFileById")
	procGetFinalPathNameByHW = modkernel32.NewProc("GetFinalPathNameByHandleW")
)

// USNMark is the journal position at one instant.
type USNMark struct {
	JournalID uint64
	NextUSN   int64
	FirstUSN  int64
	LowestUSN int64
	MaxSize   uint64
	Volume    string
}

type usnVolume struct {
	letter string // "C:"
	h      syscall.Handle
}

func openVolume(letter string, write bool) (*usnVolume, error) {
	letter = strings.TrimSuffix(strings.TrimSpace(letter), `\`)
	if len(letter) != 2 || letter[1] != ':' {
		return nil, fmt.Errorf("gate3: %q is not a drive letter", letter)
	}
	access := uint32(syscall.GENERIC_READ)
	if write {
		access |= syscall.GENERIC_WRITE
	}
	p, err := syscall.UTF16PtrFromString(`\\.\` + letter)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, access, fileShareAll, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("gate3: opening %s (this needs an elevated process): %w", letter, err)
	}
	return &usnVolume{letter: letter, h: h}, nil
}

func (v *usnVolume) Close() { syscall.CloseHandle(v.h) }

func (v *usnVolume) query() (USNMark, error) {
	var buf [80]byte
	var ret uint32
	err := syscall.DeviceIoControl(v.h, fsctlQueryUSNJournal, nil, 0, &buf[0], uint32(len(buf)), &ret, nil)
	if err != nil {
		return USNMark{}, fmt.Errorf("gate3: FSCTL_QUERY_USN_JOURNAL on %s: %w", v.letter, err)
	}
	if ret < 56 {
		return USNMark{}, fmt.Errorf("gate3: FSCTL_QUERY_USN_JOURNAL returned %d bytes", ret)
	}
	m := USNMark{
		Volume:    v.letter,
		JournalID: binary.LittleEndian.Uint64(buf[0:8]),
		FirstUSN:  int64(binary.LittleEndian.Uint64(buf[8:16])),
		NextUSN:   int64(binary.LittleEndian.Uint64(buf[16:24])),
		LowestUSN: int64(binary.LittleEndian.Uint64(buf[24:32])),
		MaxSize:   binary.LittleEndian.Uint64(buf[40:48]),
	}
	return m, nil
}

// EnlargeJournal grows the change journal so a busy run cannot wrap it.
//
// The runner's C: ships with a 32 MB journal, which is a few hundred thousand
// records. A wrap is not a silent loss here — MarkUSN's successor detects it and
// fails the check — but a check that fails for capacity reasons gets ignored,
// so the capacity is removed as a variable first.
func EnlargeJournal(letter string, maxSize, delta uint64) error {
	v, err := openVolume(letter, true)
	if err != nil {
		return err
	}
	defer v.Close()
	// A struct with uint64 fields, not a [16]byte: CREATE_USN_JOURNAL_DATA is two
	// DWORDLONGs and the file system rejects a buffer that is not aligned for
	// them with ERROR_INVALID_USER_BUFFER, which is what a byte array gets.
	var in struct{ MaximumSize, AllocationDelta uint64 }
	in.MaximumSize, in.AllocationDelta = maxSize, delta
	var ret uint32
	err = syscall.DeviceIoControl(v.h, fsctlCreateUSNJournal, (*byte)(unsafe.Pointer(&in)),
		uint32(unsafe.Sizeof(in)), nil, 0, &ret, nil)
	if err == nil {
		return nil
	}
	// Fall back to the tool Windows ships for this. The journal's SIZE is
	// plumbing, not evidence: a wrap is detected and fails the check either way,
	// and this only removes capacity as a reason for one.
	out, ferr := exec.Command("fsutil", "usn", "createjournal",
		fmt.Sprintf("m=%d", maxSize), fmt.Sprintf("a=%d", delta), letter).CombinedOutput()
	if ferr != nil {
		return fmt.Errorf("gate3: FSCTL_CREATE_USN_JOURNAL on %s: %v; fsutil also failed: %v: %s",
			letter, err, ferr, strings.TrimSpace(string(out)))
	}
	return nil
}

// MarkUSN reads the journal position on a volume.
func MarkUSN(letter string) (USNMark, error) {
	v, err := openVolume(letter, false)
	if err != nil {
		return USNMark{}, err
	}
	defer v.Close()
	return v.query()
}

// Change is one file the journal says changed.
type Change struct {
	Path    string
	Name    string
	Reasons uint32
	USN     int64
}

// DiffUSN reads every journal record between two marks and returns the changes,
// split into the ones the noise list excuses and the ones it does not.
func DiffUSN(start USNMark, extraExclusions []string) (*SystemDiskReport, error) {
	rep := &SystemDiskReport{
		Method:       "ntfs change journal (FSCTL_READ_USN_JOURNAL), every record between two USNs",
		JournalID:    start.JournalID,
		StartUSN:     start.NextUSN,
		Exclusions:   NoiseRules(),
		ExclusionSHA: NoiseSHA(),
	}
	for _, e := range extraExclusions {
		rep.Exclusions = append(rep.Exclusions, e+"  # damage this scenario did on purpose")
	}

	v, err := openVolume(start.Volume, false)
	if err != nil {
		rep.Error = err.Error()
		return rep, err
	}
	defer v.Close()

	end, err := v.query()
	if err != nil {
		rep.Error = err.Error()
		return rep, err
	}
	rep.EndUSN = end.NextUSN
	if end.JournalID != start.JournalID {
		rep.Wrapped = true
		rep.Error = fmt.Sprintf("the change journal was recreated during the run (%d -> %d): the window "+
			"cannot be accounted for", start.JournalID, end.JournalID)
		return rep, nil
	}
	if end.FirstUSN > start.NextUSN {
		rep.Wrapped = true
		rep.Error = fmt.Sprintf("the change journal discarded records we had not read (oldest kept USN %d, "+
			"our window starts at %d)", end.FirstUSN, start.NextUSN)
		return rep, nil
	}

	excl := make([]string, 0, len(extraExclusions))
	for _, e := range extraExclusions {
		excl = append(excl, strings.ToLower(e))
	}

	resolver := newPathResolver(v)
	next := start.NextUSN
	out := make([]byte, 1<<20)

	// Two passes. The first reads every record and remembers, for every file
	// reference the journal mentions, its name and its parent; the second turns
	// those into paths. A directory that was created and deleted inside the
	// window cannot be opened afterwards, so without the first pass those
	// changes resolve to nothing, land outside every noise rule, and every run
	// reports them — which is how a noise list grows until it covers the thing
	// it was supposed to catch.
	type rec struct {
		parent uint64
		name   string
		reason uint32
	}
	var records []rec
	for next < end.NextUSN {
		var in [40]byte
		binary.LittleEndian.PutUint64(in[0:8], uint64(next))
		binary.LittleEndian.PutUint32(in[8:12], usnReasonMask)
		binary.LittleEndian.PutUint32(in[12:16], 0) // ReturnOnlyOnClose
		binary.LittleEndian.PutUint64(in[16:24], 0) // Timeout
		binary.LittleEndian.PutUint64(in[24:32], 0) // BytesToWaitFor
		binary.LittleEndian.PutUint64(in[32:40], start.JournalID)

		var ret uint32
		if derr := syscall.DeviceIoControl(v.h, fsctlReadUSNJournal, &in[0], uint32(len(in)),
			&out[0], uint32(len(out)), &ret, nil); derr != nil {
			rep.Error = fmt.Sprintf("FSCTL_READ_USN_JOURNAL at USN %d: %v", next, derr)
			return rep, nil
		}
		if ret < 8 {
			break
		}
		newNext := int64(binary.LittleEndian.Uint64(out[0:8]))
		off := uint32(8)
		for off+60 <= ret {
			recLen := binary.LittleEndian.Uint32(out[off : off+4])
			if recLen < 60 || off+recLen > ret {
				break
			}
			r := out[off : off+recLen]
			fileRef := binary.LittleEndian.Uint64(r[8:16])
			parentRef := binary.LittleEndian.Uint64(r[16:24])
			usn := int64(binary.LittleEndian.Uint64(r[24:32]))
			reason := binary.LittleEndian.Uint32(r[40:44])
			attrs := binary.LittleEndian.Uint32(r[52:56])
			nameLen := binary.LittleEndian.Uint16(r[56:58])
			nameOff := binary.LittleEndian.Uint16(r[58:60])
			name := ""
			if uint32(nameOff)+uint32(nameLen) <= recLen {
				u16 := make([]uint16, nameLen/2)
				for i := range u16 {
					u16[i] = binary.LittleEndian.Uint16(r[int(nameOff)+i*2:])
				}
				name = string(utf16Decode(u16))
			}
			off += recLen
			if attrs&syscall.FILE_ATTRIBUTE_DIRECTORY != 0 {
				resolver.learn(fileRef, parentRef, name)
			}
			if usn >= end.NextUSN {
				continue
			}
			records = append(records, rec{parent: parentRef, name: name, reason: reason})
		}
		if newNext <= next {
			break
		}
		next = newNext
	}

	byDir := map[string]int{}
	unexplained := map[string]uint32{}
	for _, r := range records {
		rep.Records++
		full := resolver.resolve(r.parent, r.name)
		byDir[dirOf(full)]++
		if ok, _ := IsNoise(full); ok {
			rep.Excluded++
			continue
		}
		if matchesAny(full, excl) {
			rep.Excluded++
			continue
		}
		unexplained[full] |= r.reason
	}

	for p, reason := range unexplained {
		rep.Unexplained = append(rep.Unexplained, fmt.Sprintf("%s [%s]", p, reasonString(reason)))
	}
	sort.Strings(rep.Unexplained)
	if len(rep.Unexplained) > 200 {
		extra := len(rep.Unexplained) - 200
		rep.Unexplained = append(rep.Unexplained[:200:200], fmt.Sprintf("… and %d more", extra))
	}
	rep.topDirs = topDirs(byDir, 25)
	return rep, nil
}

func matchesAny(path string, lowered []string) bool {
	p := strings.ToLower(path)
	for _, e := range lowered {
		if p == e || strings.HasPrefix(p, e) {
			return true
		}
	}
	return false
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '\\'); i > 0 {
		return p[:i]
	}
	return p
}

func topDirs(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	all := make([]kv, 0, len(m))
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	out := make([]string, 0, n)
	for i, e := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%6d  %s", e.v, e.k))
	}
	return out
}

// pathResolver turns a parent file reference number into a path, with a cache.
//
// A directory that was itself created and deleted during the window cannot be
// opened any more. Rather than give up and call the change "unresolved", the
// resolver falls back to the reference number, which still lands OUTSIDE every
// noise rule and so is reported rather than excused — failing closed.
type pathResolver struct {
	v     *usnVolume
	cache map[uint64]string
	known map[uint64]struct {
		parent uint64
		name   string
	}
}

func newPathResolver(v *usnVolume) *pathResolver {
	// Opening a directory by its file id to read its name is a backup-style
	// read. Without the privilege the open fails on directories the harness
	// account cannot traverse, and the change resolves to nothing.
	_ = enablePrivilege("SeBackupPrivilege")
	return &pathResolver{v: v, cache: map[uint64]string{}, known: map[uint64]struct {
		parent uint64
		name   string
	}{}}
}

// learn records a directory the journal itself described, so a directory that
// no longer exists can still be named.
func (r *pathResolver) learn(ref, parent uint64, name string) {
	if name == "" || ref == 0 {
		return
	}
	if _, ok := r.known[ref]; !ok {
		r.known[ref] = struct {
			parent uint64
			name   string
		}{parent: parent, name: name}
	}
}

func (r *pathResolver) resolve(parentRef uint64, name string) string {
	dir := r.dirOf(parentRef, 0)
	if dir == "" {
		return fmt.Sprintf("<unresolved parent %d>\\%s", parentRef, name)
	}
	return strings.TrimRight(dir, `\`) + `\` + name
}

// dirOf names a directory by its file reference, from the file system if it is
// still there and from the journal's own records if it is not.
func (r *pathResolver) dirOf(ref uint64, depth int) string {
	if ref == 0 || depth > 64 {
		return ""
	}
	if p, ok := r.cache[ref]; ok {
		return p
	}
	p := r.lookup(ref)
	if p == "" {
		if k, ok := r.known[ref]; ok {
			if parent := r.dirOf(k.parent, depth+1); parent != "" {
				p = strings.TrimRight(parent, `\`) + `\` + k.name
			}
		}
	}
	r.cache[ref] = p
	return p
}

func (r *pathResolver) lookup(ref uint64) string {
	// FILE_ID_DESCRIPTOR: DWORD dwSize; FILE_ID_TYPE Type; union at offset 8.
	var desc [24]byte
	binary.LittleEndian.PutUint32(desc[0:4], 24)
	binary.LittleEndian.PutUint32(desc[4:8], 0) // FileIdType
	binary.LittleEndian.PutUint64(desc[8:16], ref)
	h, _, _ := procOpenFileById.Call(
		uintptr(r.v.h),
		uintptr(unsafe.Pointer(&desc[0])),
		uintptr(fileReadAttrs),
		uintptr(fileShareAll),
		0,
		uintptr(backupSem),
	)
	if h == 0 || h == uintptr(syscall.InvalidHandle) {
		return ""
	}
	defer syscall.CloseHandle(syscall.Handle(h))
	buf := make([]uint16, 32768)
	n, _, _ := procGetFinalPathNameByHW.Call(h, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), volNameDOS)
	if n == 0 || int(n) >= len(buf) {
		return ""
	}
	return strings.TrimPrefix(string(utf16Decode(buf[:n])), `\\?\`)
}

func utf16Decode(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		c := u[i]
		if c >= 0xD800 && c < 0xDC00 && i+1 < len(u) {
			c2 := u[i+1]
			if c2 >= 0xDC00 && c2 < 0xE000 {
				out = append(out, ((rune(c)-0xD800)<<10|(rune(c2)-0xDC00))+0x10000)
				i++
				continue
			}
		}
		out = append(out, rune(c))
	}
	return out
}

var usnReasonNames = []struct {
	bit  uint32
	name string
}{
	{0x00000001, "data-overwrite"}, {0x00000002, "data-extend"}, {0x00000004, "data-truncation"},
	{0x00000010, "named-data-overwrite"}, {0x00000020, "named-data-extend"}, {0x00000040, "named-data-truncation"},
	{0x00000100, "file-create"}, {0x00000200, "file-delete"}, {0x00000400, "ea-change"},
	{0x00000800, "security-change"}, {0x00001000, "rename-old-name"}, {0x00002000, "rename-new-name"},
	{0x00004000, "indexable-change"}, {0x00008000, "basic-info-change"}, {0x00010000, "hard-link-change"},
	{0x00020000, "compression-change"}, {0x00040000, "encryption-change"}, {0x00080000, "object-id-change"},
	{0x00100000, "reparse-point-change"}, {0x00200000, "stream-change"}, {0x00400000, "transacted-change"},
	{0x00800000, "integrity-change"}, {0x80000000, "close"},
}

func reasonString(r uint32) string {
	var parts []string
	for _, rn := range usnReasonNames {
		if r&rn.bit != 0 {
			parts = append(parts, rn.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%08x", r)
	}
	return strings.Join(parts, ",")
}
