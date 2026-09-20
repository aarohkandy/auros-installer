// Package fault is the induced-failure half of the Auros migration harness, and by SAFETY.md rule 2 it
// is the half that matters most: the abort path is tested more than the happy path.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// A FAULT IS A SCENARIO, NOT AN EVENT
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// "The power went out during a copy once and it seemed to recover" is a story. It is not evidence, it
// cannot be re-run, and nobody can tell whether a later change broke it.
//
// So every fault here is a named scenario with a trigger expressed as a fraction of the copy — "kill at
// 43% of bytes" — and that fraction is resolved, BEFORE any VM starts, into an exact pin:
//
//	Pin{FileIndex: 7742, Path: "Documents/…", ByteOffsetInFile: 118_243, CumulativeBytes: 3_612_004_182}
//
// The resolution is pure arithmetic over the golden manifest. Given the same seed and the same scenario
// id, the pin is the same number on every machine, forever. That is what makes `--scenario F02` a
// reproduction rather than an anecdote.
//
// This works ONLY because gen/ defines copy order canonically (sorted by the UTF-8 relative path, index
// assigned after the sort) and the installer is required to copy in that order. If the installer ever
// copies in directory-walk order instead, pins stop being reproducible and this package's central claim
// becomes false. The runner asserts the order from the progress log on every run for that reason.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// TRIGGERS ARE INTEGERS
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// Fractions are basis points (4300 = 43.00%), not float64. A pin computed as int64(0.43*totalBytes)
// depends on floating-point rounding; a pin computed as totalBytes*4300/10000 does not. It is a small
// thing that removes a whole category of "it fired one byte earlier on that machine".
package fault

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrStopped is returned by Watch when the caller's stop channel closed before the trigger fired.
var ErrStopped = errors.New("fault: watch stopped before the trigger fired")

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// SCENARIO MODEL
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// Site says who executes the action. Host faults are things the guest cannot do to itself — you cannot
// ask a VM to be power-cut and expect it to answer. Guest faults are things the host cannot reach into
// NTFS to do precisely.
type Site string

const (
	SiteHost  Site = "host"
	SiteGuest Site = "guest"
)

type Action string

const (
	ActionPowerCut          Action = "power_cut"
	ActionDetachDestination Action = "detach_destination"
	ActionFillDestination   Action = "fill_destination"
	ActionMutateSource      Action = "mutate_source"
	ActionDeleteSource      Action = "delete_source"
	ActionTruncateManifest  Action = "truncate_manifest"
	ActionBitFlip           Action = "bit_flip"
	ActionClockBackwards    Action = "clock_backwards"
	ActionExclusiveLock     Action = "exclusive_lock"
)

// Phase is the installer phase whose byte total the trigger fraction is measured against. SAFETY.md's
// phase diagram calls these 4 COPY and 5 VERIFY; a fault during VERIFY is a different test from the same
// fault during COPY, because VERIFY is the last thing standing between the user and the wall.
type Phase string

const (
	PhaseCopy   Phase = "COPY"
	PhaseVerify Phase = "VERIFY"
)

type Trigger struct {
	Phase Phase `json:"phase"`
	// BP is basis points of that phase's total bytes. 4300 = 43.00%.
	BP int `json:"bp"`
}

func (t Trigger) String() string {
	return fmt.Sprintf("%s@%d.%02d%%", t.Phase, t.BP/100, t.BP%100)
}

// Scenario is one induced failure. Every field exists because leaving it out produced a worse test.
type Scenario struct {
	ID     string `json:"id"`
	Family string `json:"family"`
	Name   string `json:"name"`
	Site   Site   `json:"site"`
	Action Action `json:"action"`

	Trigger Trigger `json:"trigger"`

	// TargetOffset selects the file the action applies to, RELATIVE TO THE PIN. Negative means a file
	// already fully copied (for corrupting the destination), zero means the file in flight at the pin,
	// positive means a file not yet reached (for mutating or removing the source out from under it).
	// Relative rather than absolute so the same scenario means the same thing at any corpus size.
	TargetOffset int `json:"target_offset"`

	Params map[string]string `json:"params,omitempty"`

	// Why this scenario exists. Not decoration: a scenario nobody can justify is a scenario that gets
	// quietly deleted the first time it is slow.
	Why string `json:"why"`

	// ExpectAbort is true for every scenario here. It is an explicit field anyway, because the day
	// somebody adds a fault the installer is supposed to SURVIVE rather than abort on, the difference
	// must be in the data and not in a reviewer's memory.
	ExpectAbort bool `json:"expect_abort"`

	// DeviatesCorpus is true when the scenario deliberately damages the SOURCE. Those runs are verified
	// against the golden manifest minus the file we damaged. Without this the harness would report its
	// own induced fault as data loss — and, far worse, a run that reported data loss for two files would
	// look the same as one that reported it for one.
	DeviatesCorpus bool `json:"deviates_corpus"`

	// WrongReason names the way this scenario could pass without proving anything. Every one of these is
	// checked mechanically by the runner (see postcondition P0), because "the fault fired" is the
	// assumption every green abort-test suite quietly stops satisfying.
	WrongReason string `json:"wrong_reason"`
}

func (s Scenario) paramInt(key string, def int64) int64 {
	if s.Params == nil {
		return def
	}
	v, ok := s.Params[key]
	if !ok {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return def
	}
	return n
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// MANIFEST — read-only view
//
// gen/generate.go owns golden-manifest.jsonl. These are the fields a pin depends on and nothing else.
// The duplication is deliberate and bounded: LoadManifest asserts that indices are contiguous and start
// at zero, so a format change that renumbers or reorders fails loudly here instead of silently moving
// every pin in the suite.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type Entry struct {
	Index   int    `json:"index"`
	Path    string `json:"path"`
	WinPath string `json:"win_path"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

func LoadManifest(path string) ([]Entry, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	h := sha256.New()
	sc := bufio.NewScanner(io.TeeReader(f, h))
	sc.Buffer(make([]byte, 0, 1<<20), 1<<22)
	var out []Entry
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, "", fmt.Errorf("manifest line %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, "", err
	}
	if len(out) == 0 {
		return nil, "", errors.New("empty manifest")
	}
	for i := range out {
		if out[i].Index != i {
			return nil, "", fmt.Errorf(
				"manifest index %d at line %d: copy order is not contiguous from zero, so every pin in "+
					"the suite would be wrong. Regenerate the corpus", out[i].Index, i+1)
		}
	}
	return out, fmt.Sprintf("%x", h.Sum(nil)), nil
}

func TotalBytes(entries []Entry) int64 {
	var t int64
	for i := range entries {
		t += entries[i].Size
	}
	return t
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// PIN
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// Pin is a trigger point made concrete. It is computed from the manifest alone — no VM, no run, no
// clock — which is what makes a scenario re-runnable.
type Pin struct {
	Phase            Phase  `json:"phase"`
	BP               int    `json:"bp"`
	FileIndex        int    `json:"file_index"`
	Path             string `json:"path"`
	WinPath          string `json:"win_path"`
	ByteOffsetInFile int64  `json:"byte_offset_in_file"`
	CumulativeBytes  int64  `json:"cumulative_bytes"`
	TotalBytes       int64  `json:"total_bytes"`
}

func (p Pin) String() string {
	return fmt.Sprintf("%s @%d bp → file #%d (%s) +%d bytes, cumulative %d of %d",
		p.Phase, p.BP, p.FileIndex, p.Path, p.ByteOffsetInFile, p.CumulativeBytes, p.TotalBytes)
}

// ResolvePin converts a fraction of the phase's bytes into an exact file and offset.
//
// Integer arithmetic throughout. Zero-byte files are skipped when landing the pin, because "stop in the
// middle of a zero-byte file" is not a place.
func ResolvePin(entries []Entry, t Trigger) (Pin, error) {
	if len(entries) == 0 {
		return Pin{}, errors.New("no manifest entries")
	}
	if t.BP < 0 || t.BP > 10000 {
		return Pin{}, fmt.Errorf("trigger basis points out of range: %d", t.BP)
	}
	total := TotalBytes(entries)
	if total <= 0 {
		return Pin{}, errors.New("manifest total byte count is zero")
	}
	target := total * int64(t.BP) / 10000

	var cum int64
	for i := range entries {
		sz := entries[i].Size
		if sz == 0 {
			continue
		}
		if cum+sz > target {
			return Pin{
				Phase:            t.Phase, BP: t.BP,
				FileIndex:        entries[i].Index,
				Path:             entries[i].Path,
				WinPath:          entries[i].WinPath,
				ByteOffsetInFile: target - cum,
				CumulativeBytes:  target,
				TotalBytes:       total,
			}, nil
		}
		cum += sz
	}
	// BP == 10000: the pin is the final byte of the last non-empty file.
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Size > 0 {
			return Pin{
				Phase:            t.Phase, BP: t.BP,
				FileIndex:        entries[i].Index,
				Path:             entries[i].Path,
				WinPath:          entries[i].WinPath,
				ByteOffsetInFile: entries[i].Size,
				CumulativeBytes:  total,
				TotalBytes:       total,
			}, nil
		}
	}
	return Pin{}, errors.New("manifest contains no non-empty files")
}

// TargetEntry resolves Scenario.TargetOffset against the pin, clamped into range. Deterministic.
func TargetEntry(entries []Entry, pin Pin, offset int) (Entry, error) {
	i := pin.FileIndex + offset
	if i < 0 {
		i = 0
	}
	if i >= len(entries) {
		i = len(entries) - 1
	}
	// Step towards a non-empty file: corrupting or deleting a zero-byte file proves nothing.
	step := 1
	if offset < 0 {
		step = -1
	}
	for j := i; j >= 0 && j < len(entries); j += step {
		if entries[j].Size > 0 {
			return entries[j], nil
		}
	}
	return Entry{}, errors.New("no non-empty target file near the pin")
}

// BitFlipSite picks the byte and bit to corrupt, deterministically from the scenario id and the target
// path. A randomly chosen bit would make a failing run un-re-runnable, which is the thing this whole
// package exists to prevent.
func BitFlipSite(scenarioID string, e Entry) (byteOffset int64, bit uint) {
	h := sha256.Sum256([]byte(scenarioID + "\x00" + e.Path))
	a := binary.LittleEndian.Uint64(h[0:8])
	b := binary.LittleEndian.Uint64(h[8:16])
	if e.Size <= 0 {
		return 0, 0
	}
	return int64(a % uint64(e.Size)), uint(b % 8)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// PROGRESS PROTOCOL
//
// This is the contract the installer (auros-installer task C5) must satisfy, and the harness ships
// first so that the contract exists before the code that has to meet it.
//
// The installer appends newline-delimited JSON to <destination>/auros-progress.ndjson and flushes each
// line. On the DESTINATION volume, never the system disk — SAFETY.md rule 5, and also because phases
// 1-5 are defined as read-only with respect to the system disk and a progress log would break that.
//
// Required reporting granularity: at least one line per 1 MiB of copied data, plus one at every file
// boundary. Trigger precision is bounded by that granularity plus the watcher's poll interval, and the
// runner records the OBSERVED bytes_done at fire time so a reviewer can see how close the pin landed
// rather than taking it on trust.
//
// No network. A school's uplink is not a safety-critical component (SAFETY.md rule 4), so the channel
// between the installer and the injector is a file on a volume they both already have open.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type Progress struct {
	Event      string `json:"event"` // phase | file_start | file_progress | file_done | abort
	Phase      string `json:"phase,omitempty"`
	Index      int    `json:"index"`
	Path       string `json:"path,omitempty"`
	Size       int64  `json:"size,omitempty"`
	BytesDone  int64  `json:"bytes_done"`  // cumulative within the phase
	BytesTotal int64  `json:"bytes_total"` // the phase's total, as the installer computed it
	SHA256     string `json:"sha256,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Watch tails the progress file and calls fn for every well-formed line. fn returns true to stop.
//
// Malformed lines are skipped rather than fatal: the file is being appended to by another process and
// the last line can legitimately be half-written when we read it.
func Watch(path string, stop <-chan struct{}, pollMS int, fn func(Progress) bool) error {
	if pollMS < 1 {
		pollMS = 5
	}
	pause := time.Duration(pollMS) * time.Millisecond

	var f *os.File
	for {
		select {
		case <-stop:
			return ErrStopped
		default:
		}
		var err error
		f, err = os.Open(path)
		if err == nil {
			break
		}
		if !os.IsNotExist(err) {
			return err
		}
		time.Sleep(pause)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	var partial []byte
	for {
		select {
		case <-stop:
			return ErrStopped
		default:
		}
		chunk, err := rd.ReadBytes('\n')
		if len(chunk) > 0 {
			partial = append(partial, chunk...)
		}
		if len(partial) > 0 && partial[len(partial)-1] == '\n' {
			var p Progress
			if json.Unmarshal(bytes.TrimSpace(partial), &p) == nil {
				if fn(p) {
					return nil
				}
			}
			partial = partial[:0]
			continue
		}
		if err == io.EOF {
			time.Sleep(pause)
			continue
		}
		if err != nil {
			return err
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// FIRE RECORD — the anti-vacuous-pass evidence
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// FireRecord is written for every fault run and is checked by the runner as postcondition P0.
//
// The failure mode it exists to catch: a scenario that never fired, because the installer finished
// early, or the progress file never appeared, or the trigger arithmetic was wrong. The run then shows a
// clean abort and a booting Windows and looks exactly like a pass. Twenty of those is a green suite
// that tests nothing, and it is the single most likely way this harness rots.
type FireRecord struct {
	ScenarioID string `json:"scenario_id"`
	Fired      bool   `json:"fired"`

	Pin Pin `json:"pin"`

	// Observed state at the moment the action was dispatched.
	ObservedBytesDone  int64  `json:"observed_bytes_done"`
	ObservedBytesTotal int64  `json:"observed_bytes_total"`
	ObservedIndex      int    `json:"observed_index"`
	ObservedPhase      string `json:"observed_phase"`

	// OvershootBytes is observed minus pinned. Small is good; large means the installer is reporting
	// progress too coarsely and the pin is nominal rather than real.
	OvershootBytes int64 `json:"overshoot_bytes"`

	TargetPath string `json:"target_path,omitempty"`
	ActionErr  string `json:"action_error,omitempty"`
	NotFired   string `json:"not_fired_reason,omitempty"`

	// OrderViolations counts progress lines whose index went backwards or skipped. Non-zero means the
	// installer is not copying in manifest order, which invalidates every pin in the suite.
	OrderViolations int `json:"order_violations"`
}

func (r FireRecord) Valid() error {
	if !r.Fired {
		reason := r.NotFired
		if reason == "" {
			reason = "unknown"
		}
		return fmt.Errorf("scenario %s never fired (%s): this run is not evidence", r.ScenarioID, reason)
	}
	if r.OrderViolations > 0 {
		return fmt.Errorf("scenario %s: %d copy-order violations — the installer is not copying in "+
			"manifest order, so the pin is meaningless", r.ScenarioID, r.OrderViolations)
	}
	return nil
}

// HarnessVersion is stamped into every FireRecord and every run result. It is bumped whenever a change
// makes older evidence non-comparable — the same discipline as matrix_version in auros-base, and for the
// same reason: a pass recorded under a weaker harness is not evidence of a pass under this one.
const HarnessVersion = "testharness/0.1.0"

// HarnessBuild is the value the guest agent puts on the wire.
func HarnessBuild() string { return HarnessVersion }
