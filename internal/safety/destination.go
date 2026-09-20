package safety

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// SAFETY.md phase 3. The destination must not be the system disk, and it must
// have room. If no qualifying destination exists we refuse to continue. We do
// not offer a smaller subset, we do not offer to skip verification, and we do
// not offer to use the system disk.
//
// # Why a Destination is a proof and not a pair of strings
//
// A path is not a place. `D:\backup` can be an NTFS junction onto
// `C:\AurosBackup`: the letter says D:, the bytes land on C:. Deriving the
// volume from the string the user typed answers a question nobody asked — the
// identity of the drive LETTER — and a run that does that writes the user's only
// copy onto the disk it is about to repoint, while printing the backup drive's
// GUID and the words "nothing was written to the system disk".
//
// So Destination's fields are unexported and there is no literal any caller can
// write. The only way to obtain one is Resolver.Resolve or Resolver.Choose,
// which resolve every link in the path FIRST, refuse a path that is itself a
// reparse point, and then ask the operating system which volume holds the
// RESOLVED directory. Everything downstream — the copy engine, the run log, the
// verifier, the arm plan — is handed that resolved path, because it is the only
// path in the program that has been proven to mean what it says.

var (
	// ErrNoDestination means nothing qualified. It is a refusal, not a prompt.
	ErrNoDestination = errors.New("safety: no destination volume qualifies; refusing to continue")

	// ErrDestinationIsSystemVolume means the candidate resolved to the very disk
	// we are protecting.
	ErrDestinationIsSystemVolume = errors.New("safety: destination is the system volume")

	// ErrDestinationTooSmall means the copy would not fit with headroom.
	ErrDestinationTooSmall = errors.New("safety: destination does not have room for the copy plus headroom")

	// ErrDestinationUnidentified means the volume has no GUID. We cannot PROVE
	// it is not the system volume, so we treat it as if it were. A destination
	// whose identity cannot be established is not a destination.
	ErrDestinationUnidentified = errors.New("safety: destination volume has no GUID; cannot prove it is not the system volume")

	// ErrDestinationIsLink means the path is still a reparse point after
	// resolution — a link we cannot pin to a real directory. A path we cannot
	// pin is a path whose volume we cannot name, and that is a refusal.
	ErrDestinationIsLink = errors.New("safety: the destination path is a link that cannot be resolved to a real directory")

	// ErrDestinationUnresolvable means the path could not be resolved to a real
	// directory at all. Unresolvable is unidentifiable is refused.
	ErrDestinationUnresolvable = errors.New("safety: the destination path cannot be resolved to a real directory")

	// ErrDestinationMoved means the destination's identity changed after it was
	// chosen: a link swapped in underneath a running copy. It is the TOCTOU case,
	// and it is checked again at the moment of the first write and again at the
	// moment the proof is minted.
	ErrDestinationMoved = errors.New("safety: the destination's identity changed during the run")

	// ErrDestinationNotResolved means a Destination that never came from a
	// Resolver reached code that requires a proven one.
	ErrDestinationNotResolved = errors.New("safety: destination was not resolved; it carries no proof of which volume it is on")
)

const (
	// headroomPercent is SAFETY.md phase 3's "inventory size × 1.1".
	headroomPercent = 110

	// MetadataReserveBytes covers the manifest, the run log and the quarantine
	// report, all of which live on the destination and all of which must fit
	// after the last file is written. A manifest that could not be written is a
	// copy that cannot be verified.
	MetadataReserveBytes int64 = 16 << 20
)

// RequiredBytes is how much free space a destination needs to hold an inventory
// of the given size.
func RequiredBytes(inventoryBytes int64) int64 {
	if inventoryBytes < 0 {
		inventoryBytes = 0
	}
	// Integer arithmetic, checked for overflow: a bogus inventory size must not
	// wrap around into a small requirement that then passes the check.
	const max = int64(1) << 62
	if inventoryBytes > max/headroomPercent {
		return max
	}
	return inventoryBytes*headroomPercent/100 + MetadataReserveBytes
}

// Destination is a directory that has been PROVEN to sit on a named volume that
// is not the system volume. Its fields are unexported: see the package comment
// above for why a caller must not be able to assert one into existence.
type Destination struct {
	vol      winenv.Volume
	dir      string // fully resolved: no component is a link
	res      *Resolver
	resolved bool
}

// Dir is the resolved directory. Every writer in the program uses this string
// and not the one the user typed.
func (d Destination) Dir() string { return d.dir }

// Volume is the volume that really holds Dir.
func (d Destination) Volume() winenv.Volume { return d.vol }

// Resolved reports whether this value came from a Resolver.
func (d Destination) Resolved() bool { return d.resolved && d.res != nil }

func (d Destination) String() string {
	if !d.resolved {
		return "(unresolved destination)"
	}
	return fmt.Sprintf("%s on %s", d.dir, d.vol.GUID)
}

// RunlogOptions builds the run log's options from the proof, so the run log's
// "is this the system volume?" flag is a measurement rather than something the
// caller passes in and can get wrong.
func (d Destination) RunlogOptions() runlog.Options {
	o := runlog.Options{}
	o.DestRoot = d.dir
	o.DestIsSystemVolume = !d.resolved || d.vol.IsSystem || SameVolume(d.vol, d.system())
	return o
}

func (d Destination) system() winenv.Volume {
	if d.res == nil {
		return winenv.Volume{}
	}
	return d.res.system
}

// Reassert re-establishes the destination's identity from scratch: it resolves
// the path again, refuses it if any component has become a link, and asks the
// operating system which volume holds it now.
//
// It exists because phase 3's answer has a shelf life. A junction swapped in
// after the destination was chosen would otherwise redirect every subsequent
// write without changing anything the program has already looked at. The copy
// engine calls this before its first write and safety.Verify calls it before
// minting the proof, so the window is closed at both ends.
func (d Destination) Reassert() error {
	if !d.Resolved() {
		return ErrDestinationNotResolved
	}
	real, _, err := d.res.assert(d.dir, d.vol)
	if err != nil {
		return err
	}
	// d.dir is already a resolved path. If it no longer resolves to itself,
	// something turned it, or a directory above it, into a link while the run was
	// in progress. That is the junction-swap, and it stops the run.
	if !samePath(real, d.dir) {
		return fmt.Errorf("%w: %s now resolves to %s", ErrDestinationMoved, d.dir, real)
	}
	return nil
}

// OnSystemVolume reports whether this destination is, right now, on the system
// volume. It is a measurement, taken on demand; nothing in this program prints
// "the system disk was not written to" from a literal.
func (d Destination) OnSystemVolume() bool {
	if !d.Resolved() {
		return true // unknown is not "no"
	}
	_, cur, err := d.res.assert(d.dir, d.vol)
	if err != nil {
		return true
	}
	return cur.IsSystem || SameVolume(cur, d.res.system)
}

// normalizeGUID makes volume-GUID comparison reliable. Windows hands the same
// volume back with different capitalisation and with or without the trailing
// separator depending on which API produced it, and an identity check that gets
// this wrong is an identity check that passes the system disk.
func normalizeGUID(g string) string {
	g = strings.TrimSpace(g)
	g = strings.TrimSuffix(g, `\`)
	g = strings.TrimSuffix(g, "/")
	return strings.ToLower(g)
}

// SameVolume reports whether two volumes are the same physical volume.
// Unidentified volumes are never equal to anything, including each other —
// "unknown" must never read as "different".
func SameVolume(a, b winenv.Volume) bool {
	ga, gb := normalizeGUID(a.GUID), normalizeGUID(b.GUID)
	if ga == "" || gb == "" {
		return false
	}
	return ga == gb
}

// CheckDestination is the phase 3 gate for one candidate volume and directory.
// It takes the volume rather than a Destination because a Destination is a
// proof, and this is one of the checks that produces it.
func CheckDestination(v winenv.Volume, dir string, system winenv.Volume, inventoryBytes int64) error {
	if normalizeGUID(v.GUID) == "" {
		return fmt.Errorf("%w: %s", ErrDestinationUnidentified, v.Mount)
	}
	if normalizeGUID(system.GUID) == "" {
		// If we do not know which volume is the system volume, we cannot check
		// anything. Refusing is the only safe answer.
		return fmt.Errorf("%w: the system volume has no GUID either, so nothing can be ruled out",
			ErrDestinationUnidentified)
	}
	if normalizeGUID(v.GUID) == normalizeGUID(system.GUID) {
		return fmt.Errorf("%w: %s (%s) is %s", ErrDestinationIsSystemVolume, v.Mount, v.GUID, system.Mount)
	}
	if v.IsSystem {
		// Belt and braces: the flag and the GUID must agree, and if either says
		// system disk, it is the system disk.
		return fmt.Errorf("%w: %s is flagged as the system volume", ErrDestinationIsSystemVolume, v.Mount)
	}
	if system.Mount != "" && dir != "" && winenv.PathUnderMount(dir, system.Mount) {
		// The resolved path lives inside the system volume's mount point even
		// though its volume GUID says otherwise. Two answers that disagree about
		// the system disk means we stop.
		return fmt.Errorf("%w: %s is inside %s", ErrDestinationIsSystemVolume, dir, system.Mount)
	}
	need := RequiredBytes(inventoryBytes)
	if v.FreeBytes < uint64(need) {
		return fmt.Errorf("%w: %s has %d bytes free, needs %d (%d bytes of data + 10%% headroom + %d metadata)",
			ErrDestinationTooSmall, v.Mount, v.FreeBytes, need, inventoryBytes, MetadataReserveBytes)
	}
	return nil
}

// Rejection records why one candidate was refused, so the user is told the real
// reason for every drive they can see rather than a blanket "no drive found".
type Rejection struct {
	Dir string
	Err error
}

// DescribeRejections renders the refusals for the user.
func DescribeRejections(rs []Rejection) string {
	if len(rs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("These drives were examined and cannot be used:\n")
	for _, r := range rs {
		fmt.Fprintf(&b, "  %-12s %s\n", r.Dir, r.Err)
	}
	return b.String()
}

// Resolver turns a path someone typed into a Destination, or refuses.
//
// It is the only producer of Destination values in the program.
type Resolver struct {
	env    winenv.Env
	system winenv.Volume

	// allowSynthetic permits a fabricated volume identity for a path that no
	// configured volume claims. It is set only for the non-Windows rehearsal
	// environment, and even then the identity is derived from the RESOLVED path,
	// so a link into the synthetic system tree is still refused.
	allowSynthetic bool
}

// NewResolver builds a resolver for this machine.
func NewResolver(env winenv.Env, system winenv.Volume) *Resolver {
	return &Resolver{env: env, system: system, allowSynthetic: env != nil && env.Platform() != "windows"}
}

// System is the volume this resolver is protecting.
func (r *Resolver) System() winenv.Volume { return r.system }

// assert resolves dir and returns the volume that really holds it. want, if it
// carries a GUID, is the identity the caller already established: a difference
// is ErrDestinationMoved rather than a silent re-identification.
func (r *Resolver) assert(dir string, want winenv.Volume) (string, winenv.Volume, error) {
	if r == nil || r.env == nil {
		return "", winenv.Volume{}, ErrDestinationNotResolved
	}
	// EvalSymlinks resolves EVERY component, so this covers a junction at the
	// leaf and a junction three directories up equally. The resolved path is what
	// the rest of the program will use; the path the user typed is never written
	// through again.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", winenv.Volume{}, fmt.Errorf("%w: %s: %v", ErrDestinationUnresolvable, dir, err)
	}
	if rp, rerr := r.env.IsReparsePoint(real); rerr != nil {
		return "", winenv.Volume{}, fmt.Errorf("%w: %s: %v", ErrDestinationUnresolvable, real, rerr)
	} else if rp {
		return "", winenv.Volume{}, fmt.Errorf("%w: %s", ErrDestinationIsLink, dir)
	}
	st, serr := os.Stat(real)
	if serr != nil || !st.IsDir() {
		return "", winenv.Volume{}, fmt.Errorf("%w: %s is not a directory", ErrDestinationUnresolvable, real)
	}
	v, verr := r.volumeFor(real)
	if verr != nil {
		return "", winenv.Volume{}, verr
	}
	if normalizeGUID(want.GUID) != "" && normalizeGUID(v.GUID) != normalizeGUID(want.GUID) {
		return "", winenv.Volume{}, fmt.Errorf("%w: %s was on %s and is now on %s",
			ErrDestinationMoved, dir, want.GUID, v.GUID)
	}
	return real, v, nil
}

// volumeFor asks the operating system which volume holds an already-resolved
// path. It never infers a volume from a string prefix.
func (r *Resolver) volumeFor(real string) (winenv.Volume, error) {
	v, err := r.env.VolumeForPath(real)
	if err == nil {
		return v, nil
	}
	if !r.allowSynthetic {
		return winenv.Volume{}, fmt.Errorf("%w: cannot identify the volume holding %s: %v",
			ErrDestinationUnidentified, real, err)
	}
	// Rehearsal only. The fabricated identity is derived from the RESOLVED path,
	// and a resolved path inside the system tree is refused before it is reached.
	if r.system.Mount != "" && winenv.PathUnderMount(real, r.system.Mount) {
		return winenv.Volume{}, fmt.Errorf("%w: %s is inside %s", ErrDestinationIsSystemVolume, real, r.system.Mount)
	}
	sv := winenv.Volume{}
	sv.GUID = "synthetic:" + filepath.ToSlash(real)
	sv.Mount = real
	sv.FS = "synthetic"
	sv.FreeBytes = 1 << 62
	sv.TotalBytes = sv.FreeBytes
	return sv, nil
}

// Resolve turns one path into a Destination, creating the directory if it does
// not exist, or refuses.
//
// The order is the point:
//
//  1. resolve the deepest EXISTING ancestor and identify its volume, so nothing
//     is created inside a link;
//  2. check that volume against the system volume and against the space needed;
//  3. create the directory under the resolved ancestor;
//  4. resolve the whole path again and re-identify the volume, so a link raced
//     in during step 3 is caught before a single file is written.
func (r *Resolver) Resolve(dir string, inventoryBytes int64) (Destination, error) {
	if r == nil || r.env == nil {
		return Destination{}, ErrDestinationNotResolved
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Destination{}, fmt.Errorf("%w: %s: %v", ErrDestinationUnresolvable, dir, err)
	}
	target, vol, err := r.inspect(abs, inventoryBytes)
	if err != nil {
		return Destination{}, err
	}
	_ = vol // the ancestor's identity gated the creation; the real one is taken below
	if err := os.MkdirAll(target, 0o755); err != nil {
		return Destination{}, fmt.Errorf("safety: creating the destination %s: %w", target, err)
	}
	// Re-resolve from scratch AFTER creation. If a link was raced in while the
	// directory was being made, this is where it is caught, before a byte is
	// written.
	real, final, err := r.assert(target, winenv.Volume{})
	if err != nil {
		return Destination{}, err
	}
	if err := CheckDestination(final, real, r.system, inventoryBytes); err != nil {
		return Destination{}, err
	}
	return Destination{vol: final, dir: real, res: r, resolved: true}, nil
}

// inspect resolves the deepest existing ancestor of abs, identifies its volume,
// gates it, and returns the real path the destination will occupy. Nothing is
// created here.
func (r *Resolver) inspect(abs string, inventoryBytes int64) (string, winenv.Volume, error) {
	anc := abs
	var rest []string
	for {
		if _, err := os.Lstat(anc); err == nil {
			break
		}
		parent := filepath.Dir(anc)
		if parent == anc {
			return "", winenv.Volume{}, fmt.Errorf("%w: nothing above %s exists", ErrDestinationUnresolvable, abs)
		}
		rest = append([]string{filepath.Base(anc)}, rest...)
		anc = parent
	}
	ancReal, vol, err := r.assert(anc, winenv.Volume{})
	if err != nil {
		return "", winenv.Volume{}, err
	}
	// Build the target under the RESOLVED ancestor, so MkdirAll never creates a
	// directory through a link.
	target := filepath.Join(append([]string{ancReal}, rest...)...)
	if err := CheckDestination(vol, target, r.system, inventoryBytes); err != nil {
		return "", winenv.Volume{}, err
	}
	return target, vol, nil
}

// Choose picks the best volume with room and puts subdir on it, or refuses.
//
// "Best" is the one with the most free space. There is no fallback to a smaller
// subset and no fallback to the system disk: if nothing qualifies, this returns
// ErrNoDestination and the run stops, having changed nothing. Each candidate is
// resolved and identified exactly as an explicit --dest would be, so the
// automatic path cannot be weaker than the manual one.
func (r *Resolver) Choose(subdir string, inventoryBytes int64) (Destination, []Rejection, error) {
	if r == nil || r.env == nil {
		return Destination{}, nil, ErrDestinationNotResolved
	}
	vols, err := r.env.Volumes()
	if err != nil {
		return Destination{}, nil, fmt.Errorf("safety: listing volumes: %w", err)
	}
	type cand struct {
		dir string
		vol winenv.Volume
	}
	var ok []cand
	var rejected []Rejection
	for _, v := range vols {
		if v.Mount == "" {
			continue
		}
		dir := filepath.Join(v.Mount, subdir)
		target, cv, cerr := r.inspect(dir, inventoryBytes)
		if cerr != nil {
			rejected = append(rejected, Rejection{Dir: dir, Err: cerr})
			continue
		}
		ok = append(ok, cand{dir: target, vol: cv})
	}
	if len(ok) == 0 {
		return Destination{}, rejected, fmt.Errorf("%w (%d candidate(s) examined, %d bytes needed)",
			ErrNoDestination, len(vols), RequiredBytes(inventoryBytes))
	}
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].vol.FreeBytes != ok[j].vol.FreeBytes {
			return ok[i].vol.FreeBytes > ok[j].vol.FreeBytes
		}
		return ok[i].vol.GUID < ok[j].vol.GUID // deterministic tie-break
	})
	d, derr := r.Resolve(ok[0].dir, inventoryBytes)
	if derr != nil {
		rejected = append(rejected, Rejection{Dir: ok[0].dir, Err: derr})
		return Destination{}, rejected, derr
	}
	return d, rejected, nil
}

// samePath compares two paths for equality after cleaning, case-insensitively on
// Windows, where the same directory has many spellings.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return false
}
