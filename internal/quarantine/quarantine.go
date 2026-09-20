// Package quarantine records files that could not be copied or could not be
// verified, together with the reason.
//
// The entire point of this package is that there is no code path anywhere in the
// repository that skips a file silently. A file is copied and verified, or it is
// in here with a reason attached and the user is shown it. SAFETY.md phase 4:
// "quarantined and reported, never silently skipped".
//
// A quarantined file is UNRESOLVED by default. The run does not cross the wall
// while any unresolved record exists (SAFETY.md phase 5). A record can be moved
// to resolved only by an explicit, recorded human waiver — SAFETY.md is clear
// that the user decides and that the default is to stop, so the mechanism exists,
// but it costs a separate flag and it is written to the run log with the reason.
package quarantine

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Reason is a closed set. A free-text reason would become a place to hide a
// category of failure nobody counted.
type Reason string

const (
	ReasonReadError         Reason = "read-error"
	ReasonWriteError        Reason = "write-error"
	ReasonSourceChanged     Reason = "source-changed-during-copy"
	ReasonSourceDisappeared Reason = "source-disappeared"
	ReasonHashMismatch      Reason = "hash-mismatch"
	ReasonSizeMismatch      Reason = "size-mismatch"
	ReasonMissingAtDest     Reason = "missing-at-destination"
	ReasonExtraAtDest       Reason = "unexpected-file-at-destination"
	ReasonDestinationFull   Reason = "destination-full"
	ReasonLocked            Reason = "locked-or-in-use"
	ReasonCloudPlaceholder  Reason = "cloud-placeholder-not-hydrated"
	ReasonPathEscape        Reason = "path-escapes-source-root"
	ReasonUnsupportedType   Reason = "not-a-regular-file"
	ReasonTooLarge          Reason = "exceeds-size-limit"
	ReasonNameCollision     Reason = "name-collision-unresolvable"
	ReasonCancelled         Reason = "cancelled-before-copy"
)

// Record is one quarantined file.
type Record struct {
	Path     string // original source path, as the user would recognise it
	Stored   string // intended destination path, if one was chosen
	Reason   Reason
	Detail   string // the underlying error text, for the post-mortem
	Attempts int    // how many times we tried before giving up
	At       time.Time

	// Waived is set only by an explicit human decision, recorded in WaivedBy.
	// A waived record no longer blocks the wall. Nothing in this package sets
	// it on its own.
	Waived   bool
	WaivedBy string
}

// Set is a concurrency-safe collection of records. The copy engine writes to it
// from multiple goroutines.
type Set struct {
	mu      sync.Mutex
	records map[string]Record // keyed by source path; last reason for a path wins
	now     func() time.Time
}

// NewSet returns an empty set. clock may be nil, in which case time.Now is used;
// tests pass a fixed clock so reports are deterministic.
func NewSet(clock func() time.Time) *Set {
	if clock == nil {
		clock = time.Now
	}
	return &Set{records: make(map[string]Record), now: clock}
}

// Add records a quarantined file. Re-quarantining the same path replaces the
// record and accumulates the attempt count, so the report shows the final reason
// and the real number of tries.
func (s *Set) Add(r Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.records == nil {
		s.records = make(map[string]Record)
	}
	if s.now == nil {
		s.now = time.Now
	}
	if r.At.IsZero() {
		r.At = s.now()
	}
	if prev, ok := s.records[r.Path]; ok {
		r.Attempts += prev.Attempts
		// A waiver survives a later re-quarantine only if the reason is the same;
		// a new failure mode has not been waived by anybody.
		if prev.Waived && prev.Reason == r.Reason {
			r.Waived, r.WaivedBy = prev.Waived, prev.WaivedBy
		}
	}
	s.records[r.Path] = r
}

// Waive marks a record resolved. who must be non-empty: an unattributed waiver is
// exactly the kind of thing that gets added "temporarily" and never removed.
func (s *Set) Waive(path, who string) error {
	if strings.TrimSpace(who) == "" {
		return fmt.Errorf("quarantine: refusing to waive %q with no attribution", path)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[path]
	if !ok {
		return fmt.Errorf("quarantine: no record for %q", path)
	}
	r.Waived, r.WaivedBy = true, who
	s.records[path] = r
	return nil
}

// Records returns every record sorted by source path.
func (s *Set) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Len is the total number of records, waived or not.
func (s *Set) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Unresolved is the number of records that still block the wall. This is the
// number SAFETY.md phase 5 requires to be zero before phase 6.
func (s *Set) Unresolved() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range s.records {
		if !r.Waived {
			n++
		}
	}
	return n
}

// Clear is used by the copy engine when a retry succeeds: a file that was
// quarantined on attempt 1 and copied cleanly on attempt 2 is not quarantined.
func (s *Set) Clear(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, path)
}

// WriteReport renders the human-facing list. This is what the user reads before
// deciding, so it names files rather than counting them.
func (s *Set) WriteReport(w io.Writer) error {
	recs := s.Records()
	if len(recs) == 0 {
		_, err := io.WriteString(w, "No files were quarantined. Every file was copied and verified.\n")
		return err
	}
	var b strings.Builder
	unresolved := 0
	for _, r := range recs {
		if !r.Waived {
			unresolved++
		}
	}
	fmt.Fprintf(&b, "%d file(s) could not be copied or verified (%d still unresolved).\n", len(recs), unresolved)
	b.WriteString("These files are NOT in the second copy. They are listed so you can decide.\n\n")
	byReason := make(map[Reason][]Record)
	order := make([]Reason, 0, 8)
	for _, r := range recs {
		if _, seen := byReason[r.Reason]; !seen {
			order = append(order, r.Reason)
		}
		byReason[r.Reason] = append(byReason[r.Reason], r)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	for _, reason := range order {
		fmt.Fprintf(&b, "%s (%d):\n", reason, len(byReason[reason]))
		for _, r := range byReason[reason] {
			mark := " "
			if r.Waived {
				mark = "~"
			}
			fmt.Fprintf(&b, "  %s %s\n", mark, r.Path)
			if r.Detail != "" {
				fmt.Fprintf(&b, "      %s\n", r.Detail)
			}
			if r.Waived {
				fmt.Fprintf(&b, "      waived by %s\n", r.WaivedBy)
			}
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
