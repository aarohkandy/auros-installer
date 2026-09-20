package safety

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/internal/winenv"
)

// SAFETY.md phase 3. The destination must not be the system disk, and it must
// have room. If no qualifying destination exists we refuse to continue. We do
// not offer a smaller subset, we do not offer to skip verification, and we do
// not offer to use the system disk.

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

// Destination is a candidate place to put the second copy.
type Destination struct {
	Volume winenv.Volume
	// Dir is the directory on that volume that will hold the archive.
	Dir string
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

// CheckDestination is the phase 3 gate for one candidate.
func CheckDestination(d Destination, system winenv.Volume, inventoryBytes int64) error {
	if normalizeGUID(d.Volume.GUID) == "" {
		return fmt.Errorf("%w: %s", ErrDestinationUnidentified, d.Volume.Mount)
	}
	if normalizeGUID(system.GUID) == "" {
		// If we do not know which volume is the system volume, we cannot check
		// anything. Refusing is the only safe answer.
		return fmt.Errorf("%w: the system volume has no GUID either, so nothing can be ruled out",
			ErrDestinationUnidentified)
	}
	if normalizeGUID(d.Volume.GUID) == normalizeGUID(system.GUID) {
		return fmt.Errorf("%w: %s (%s) is %s", ErrDestinationIsSystemVolume,
			d.Volume.Mount, d.Volume.GUID, system.Mount)
	}
	if d.Volume.IsSystem {
		// Belt and braces: the flag and the GUID must agree, and if either says
		// system disk, it is the system disk.
		return fmt.Errorf("%w: %s is flagged as the system volume", ErrDestinationIsSystemVolume, d.Volume.Mount)
	}
	need := RequiredBytes(inventoryBytes)
	if d.Volume.FreeBytes < uint64(need) {
		return fmt.Errorf("%w: %s has %d bytes free, needs %d (%d bytes of data + 10%% headroom + %d metadata)",
			ErrDestinationTooSmall, d.Volume.Mount, d.Volume.FreeBytes, need, inventoryBytes, MetadataReserveBytes)
	}
	return nil
}

// Rejection records why one candidate was refused, so the user is told the real
// reason for every drive they can see rather than a blanket "no drive found".
type Rejection struct {
	Destination Destination
	Err         error
}

// ChooseDestination picks the best qualifying candidate, or refuses.
//
// "Best" is the one with the most free space. There is no fallback to a smaller
// subset and no fallback to the system disk: if the list of qualifying
// candidates is empty, this returns ErrNoDestination and the run stops, having
// changed nothing.
func ChooseDestination(candidates []Destination, system winenv.Volume, inventoryBytes int64) (Destination, []Rejection, error) {
	var ok []Destination
	var rejected []Rejection
	for _, c := range candidates {
		if err := CheckDestination(c, system, inventoryBytes); err != nil {
			rejected = append(rejected, Rejection{Destination: c, Err: err})
			continue
		}
		ok = append(ok, c)
	}
	if len(ok) == 0 {
		return Destination{}, rejected, fmt.Errorf("%w (%d candidate(s) examined, %d needed)",
			ErrNoDestination, len(candidates), RequiredBytes(inventoryBytes))
	}
	sort.Slice(ok, func(i, j int) bool {
		if ok[i].Volume.FreeBytes != ok[j].Volume.FreeBytes {
			return ok[i].Volume.FreeBytes > ok[j].Volume.FreeBytes
		}
		return ok[i].Volume.GUID < ok[j].Volume.GUID // deterministic tie-break
	})
	return ok[0], rejected, nil
}

// DescribeRejections renders the refusals for the user.
func DescribeRejections(rs []Rejection) string {
	if len(rs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("These drives were examined and cannot be used:\n")
	for _, r := range rs {
		fmt.Fprintf(&b, "  %-12s %s\n", r.Destination.Volume.Mount, r.Err)
	}
	return b.String()
}
