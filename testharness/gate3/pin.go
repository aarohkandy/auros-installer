package gate3

import (
	"errors"
	"fmt"
)

// ─────────────────────────────────────────────────────────────────────────────
// PINS
//
// "Kill at 43% of the copy" resolved, before anything runs, to an exact file and
// byte offset by integer arithmetic over the golden manifest. Same corpus, same
// scenario, same pin, on every machine, forever — which is what makes a failure
// something you can walk back into rather than a story about an afternoon.
//
// Basis points, not floats: 4300 = 43.00%. A pin computed as int64(0.43*total)
// depends on floating-point rounding and would move between machines by a few
// bytes for no reason anybody could explain later.
//
// The phase totals are both the corpus total, and that is not an approximation:
// COPY writes every byte to the destination once, VERIFY reads every byte back
// once. What the harness actually watches is the job object's I/O counters (see
// launch_windows.go), so a pin is a number of bytes the OPERATING SYSTEM has
// seen move, not a number the installer reported.
// ─────────────────────────────────────────────────────────────────────────────

// Phase names the installer phase a pin is measured in.
type Phase string

const (
	// PhaseCopy is SAFETY.md phase 4, measured by bytes written.
	PhaseCopy Phase = "COPY"
	// PhaseVerify is SAFETY.md phase 5, measured by bytes read after the copy
	// has ended.
	PhaseVerify Phase = "VERIFY"
)

// Pin is a trigger point made concrete.
type Pin struct {
	Phase            Phase  `json:"phase"`
	BP               int    `json:"bp"`
	CopyIndex        int    `json:"copy_index"`
	GoldenIndex      int    `json:"golden_index"`
	Path             string `json:"path"`
	Archive          string `json:"archive"`
	ByteOffsetInFile int64  `json:"byte_offset_in_file"`
	CumulativeBytes  int64  `json:"cumulative_bytes"`
	TotalBytes       int64  `json:"total_bytes"`
}

func (p Pin) String() string {
	return fmt.Sprintf("%s @%d.%02d%% → copy #%d (%s) +%d bytes, cumulative %d of %d",
		p.Phase, p.BP/100, p.BP%100, p.CopyIndex, p.Path, p.ByteOffsetInFile, p.CumulativeBytes, p.TotalBytes)
}

// ResolvePin converts a fraction of a phase's bytes into an exact file and
// offset. Zero-byte files are skipped: "stop in the middle of a zero-byte file"
// is not a place.
func ResolvePin(g *Golden, phase Phase, bp int) (Pin, error) {
	if g == nil || len(g.ByCopy) == 0 {
		return Pin{}, errors.New("gate3: no corpus to pin against")
	}
	if bp < 0 || bp > 10000 {
		return Pin{}, fmt.Errorf("gate3: trigger basis points out of range: %d", bp)
	}
	if g.TotalBytes <= 0 {
		return Pin{}, errors.New("gate3: the corpus has no bytes")
	}
	target := g.TotalBytes * int64(bp) / 10000
	var cum int64
	for i := range g.ByCopy {
		r := g.ByCopy[i]
		if r.Size == 0 {
			continue
		}
		if cum+r.Size > target {
			return Pin{
				Phase: phase, BP: bp,
				CopyIndex: r.CopyIndex, GoldenIndex: r.Index,
				Path: r.Path, Archive: r.Archive,
				ByteOffsetInFile: target - cum,
				CumulativeBytes:  target,
				TotalBytes:       g.TotalBytes,
			}, nil
		}
		cum += r.Size
	}
	for i := len(g.ByCopy) - 1; i >= 0; i-- {
		if r := g.ByCopy[i]; r.Size > 0 {
			return Pin{
				Phase: phase, BP: bp,
				CopyIndex: r.CopyIndex, GoldenIndex: r.Index,
				Path: r.Path, Archive: r.Archive,
				ByteOffsetInFile: r.Size,
				CumulativeBytes:  g.TotalBytes,
				TotalBytes:       g.TotalBytes,
			}, nil
		}
	}
	return Pin{}, errors.New("gate3: the corpus contains no non-empty file")
}

// TargetFromPin picks the file a scenario acts on, expressed as a distance in
// BYTES from the pin rather than in files.
//
// Bytes, not "the file 25 positions later", because the size distribution is a
// school laptop's: twenty-five files later can be eight hundred kilobytes or two
// hundred megabytes. A scenario that wants to lock a file the installer has not
// reached yet needs to know it has a second or two of copying left before it
// gets there, and that is a byte distance.
//
//	deltaBytes > 0  the first file that starts at least deltaBytes AFTER the pin
//	deltaBytes < 0  the last file that ends at least |deltaBytes| BEFORE the pin
//	deltaBytes == 0 the file in flight at the pin
//
// Zero-byte files are never chosen: corrupting or locking one proves nothing.
func TargetFromPin(g *Golden, pin Pin, deltaBytes int64) (Rec, error) {
	if g == nil || len(g.ByCopy) == 0 {
		return Rec{}, errors.New("gate3: no corpus")
	}
	switch {
	case deltaBytes == 0:
		for i := range g.ByCopy {
			if g.ByCopy[i].CopyIndex == pin.CopyIndex {
				return g.ByCopy[i], nil
			}
		}
		return Rec{}, fmt.Errorf("gate3: no file at copy index %d", pin.CopyIndex)
	case deltaBytes > 0:
		want := pin.CumulativeBytes + deltaBytes
		for i := range g.ByCopy {
			r := g.ByCopy[i]
			if r.Size > 0 && r.CumEnd-r.Size >= want {
				return r, nil
			}
		}
		return Rec{}, fmt.Errorf("gate3: no non-empty file starts %d bytes after the pin (the corpus "+
			"ends first); the scenario's trigger and its target are incompatible", deltaBytes)
	default:
		want := pin.CumulativeBytes + deltaBytes // deltaBytes is negative
		var best Rec
		found := false
		for i := range g.ByCopy {
			r := g.ByCopy[i]
			if r.Size > 0 && r.CumEnd <= want {
				best, found = r, true
			}
		}
		if !found {
			return Rec{}, fmt.Errorf("gate3: no non-empty file is complete %d bytes before the pin",
				-deltaBytes)
		}
		return best, nil
	}
}
