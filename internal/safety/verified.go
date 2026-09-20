package safety

import (
	"time"
)

// VerifiedArchive is proof that a second copy of the user's data exists and has
// been checked, file by file, by count and by SHA-256, reading from the
// destination.
//
// # Why it is a type and not a bool
//
// SAFETY.md: "not a check at the top of a function, which someone deletes in a
// year, but a value that cannot be constructed by any safe-Go path outside this
// package unless verification succeeded."
//
// That sentence is worded carefully, because the stronger one people reach for
// is false. Unexported fields are a compiler rule, not a memory boundary: two
// pointer writes through `unsafe` will set `valid` and `runID` on a zero value
// and forge this type. Reflection will not (it sets flagRO on unexported
// fields), embedding will not, encoding/json will not — but `unsafe` will.
//
// So the guarantee is enforced in two places, and both are mechanical:
//
//   - Go's own rules: no exported constructor, no literal a caller can write,
//     no setter, no Unmarshal, no exported field. Inside this package the only
//     code that populates one is Verify, at the end of a successful phase 5.
//   - TestWall_ForbiddenImports in wall_test.go: `unsafe` and `syscall` are
//     confined to the two packages that genuinely need Win32, and are forbidden
//     in internal/safety and in every phase 1-5 package. Forging this value is
//     therefore a red build, not a code review someone has to catch.
//
// A guarantee overstated by one word is the one people stop re-checking.
//
//	var v safety.VerifiedArchive       // legal, and useless: valid is false
//	safety.Arm(ctx, m, v, ...)         // returns ErrNotVerified
//
// Arm takes a VerifiedArchive by value. A caller who wants to cross the wall has
// exactly one way to obtain one, and that way is to have actually verified the
// data.
//
// It also carries runID, which binds it to one Machine. A VerifiedArchive from a
// previous run — deserialised, cached, or handed over from another goroutine's
// abandoned attempt — will not cross this run's wall.
type VerifiedArchive struct {
	valid bool // zero value is not a verified archive

	runID            string
	destRoot         string
	destVolumeGUID   string
	systemVolumeGUID string
	// systemMount is carried HERE rather than passed to Arm, so the volume the
	// privileged steps act on and the volume the verification looked at cannot
	// be two different things.
	systemMount    string
	manifestDigest string
	fileCount        int
	totalBytes       int64
	verifiedAt       time.Time
}

// ok reports whether this value came from a successful verification. Unexported
// on purpose: it is not a question callers get to answer for themselves.
func (v VerifiedArchive) ok() bool { return v.valid }

// IsVerified is the read-only public view, for display and logging. It can only
// ever be true for a value this package produced.
func (v VerifiedArchive) IsVerified() bool { return v.valid }

// FileCount is the number of files proven to exist in two places.
func (v VerifiedArchive) FileCount() int { return v.fileCount }

// TotalBytes is their total size.
func (v VerifiedArchive) TotalBytes() int64 { return v.totalBytes }

// Root is the destination root the archive was verified at.
func (v VerifiedArchive) Root() string { return v.destRoot }

// VolumeGUID is the destination volume's identity. Not its drive letter.
func (v VerifiedArchive) VolumeGUID() string { return v.destVolumeGUID }

// ManifestDigest identifies the exact archive that was verified.
func (v VerifiedArchive) ManifestDigest() string { return v.manifestDigest }

// VerifiedAt is the observable moment SAFETY.md requires: the point at which the
// data existed in two places and the system disk had not been touched.
func (v VerifiedArchive) VerifiedAt() time.Time { return v.verifiedAt }

// RunID is the run this proof belongs to.
func (v VerifiedArchive) RunID() string { return v.runID }

// SystemVolumeGUID is the volume the verification established was NOT written
// to, and therefore the only volume Arm is permitted to act on.
func (v VerifiedArchive) SystemVolumeGUID() string { return v.systemVolumeGUID }

// SystemMount is that volume's mount point, for display.
func (v VerifiedArchive) SystemMount() string { return v.systemMount }
