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
// year, but a value that CANNOT EXIST unless verification succeeded."
//
// Every field is unexported. There is no exported constructor, no literal a
// caller can write, no setter, no Unmarshal, no reflection path that is part of
// the API. Go permits a struct with unexported fields to be populated only
// inside its own package, and inside this package the only code that populates
// one is Verify, at the end of a successful phase 5.
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
	manifestDigest   string
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
