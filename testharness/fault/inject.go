package fault

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHERE A FAULT IS EXECUTED, AND WHY IT IS SPLIT IN TWO
//
// The injector has to watch the copy to know when 43% of the bytes have gone past. The progress log
// lives on the DESTINATION volume inside the guest (SAFETY.md rule 5: the run log must survive a machine
// that will not boot, so it is not on the system disk). The host cannot read a live NTFS volume inside a
// running VM, so the WATCHER must be in the guest.
//
// But the guest cannot power-cut itself, and it cannot yank its own USB device — asking it to would be
// asking the thing under test to simulate its own destruction, which is both unfaithful and circular.
// So HOST faults are watched in the guest and executed on the host:
//
//	guest agent  ── virtio-serial ──▶  runner
//	 (watches)      "fire F02 …"       (kill -9 qemu / device_del)
//
// One channel, one line, no network. The guest end is fault.GuestExecute; the host end is
// fault.HostAwait + fault.HostDispatch.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type Logger func(format string, args ...any)

// GuestControl is everything the fault agent can do from inside Windows. Implemented in
// agent_windows.go; the non-Windows build refuses, loudly, rather than pretending.
type GuestControl interface {
	// FillDestination consumes free space on the destination volume until leaveBytes remain.
	FillDestination(leaveBytes int64) error
	// MutateSource rewrites bytes inside a source file that is currently being copied or about to be.
	MutateSource(path string) error
	// DeleteSource removes a source file.
	DeleteSource(path string) error
	// TruncateFile shortens a file to keepBytes. Used on the installer's own manifest.
	TruncateFile(path string, keepBytes int64) error
	// BitFlipFile flips exactly one bit. Not one byte. One bit.
	BitFlipFile(path string, byteOffset int64, bit uint) error
	// ClockBackwards moves the system clock back by seconds.
	ClockBackwards(seconds int64) error
	// ExclusiveLock opens a file with no sharing and holds it for holdMS, in the background.
	ExclusiveLock(path string, holdMS int64) error
}

// HostControl is what the runner can do to the VM from outside it.
type HostControl interface {
	// PowerCut must be indistinguishable from the mains being pulled: SIGKILL to the QEMU process, no
	// ACPI shutdown, no flush. See runner/vm.go for why cache.direct matters to this being honest.
	PowerCut() error
	// DetachDestination removes the USB storage device carrying the destination volume.
	DetachDestination() error
}

// GuestConfig is the guest half of a fault run.
type GuestConfig struct {
	Scenario Scenario
	Entries  []Entry

	// ProgressPath is the installer's NDJSON progress log on the destination volume.
	ProgressPath string
	// ManifestPath is the installer's own manifest on the destination volume (not the golden manifest,
	// which lives on the read-only marker volume and is never a fault target).
	ManifestPath string
	// DestDataRoot is where the archive's file tree is materialised, e.g. E:\auros-archive\data.
	// The installer contract is that a source file at relative path P appears at DestDataRoot\P.
	DestDataRoot string

	PollMS  int
	Log     Logger
	Stop    <-chan struct{}
	Control io.Writer // serial line to the host; required for SiteHost scenarios

	// PreFire is called with the completed FireRecord at the instant the trigger is reached and BEFORE
	// the action is dispatched.
	//
	// This exists because of the power-cut scenarios. If the record were written after the action, the
	// four runs that end with SIGKILL to QEMU would never produce one, and "no fire record" is exactly
	// how the runner detects a fault that never fired. The evidence for a power cut has to leave the
	// guest before the power does. In practice PreFire writes the record to the serial line, where the
	// host already has it by the time the VM stops existing.
	PreFire func(FireRecord) error
}

// GuestExecute watches the copy and fires the scenario at its pin.
//
// It returns a FireRecord even on failure, because "the fault never fired" is the most important thing
// this function can discover and it must reach the run result rather than an error string in a log.
func GuestExecute(cfg GuestConfig, guest GuestControl) (FireRecord, error) {
	if err := Validate(); err != nil {
		return FireRecord{}, err
	}
	sc := cfg.Scenario
	log := cfg.Log
	if log == nil {
		log = func(string, ...any) {}
	}

	pin, err := ResolvePin(cfg.Entries, sc.Trigger)
	if err != nil {
		return FireRecord{ScenarioID: sc.ID}, err
	}
	rec := FireRecord{ScenarioID: sc.ID, Pin: pin}
	log("scenario %s pinned: %s", sc.ID, pin.String())

	lastIndex := -1
	phaseSeen := false
	curPhase := ""

	werr := Watch(cfg.ProgressPath, cfg.Stop, cfg.PollMS, func(p Progress) bool {
		if p.Phase != "" {
			curPhase = p.Phase
		}
		if p.Event == "file_start" {
			// A repeated or backwards index means the installer is not copying in manifest order, which
			// makes every pin in the suite nominal. A FORWARD skip is not counted here — a quarantined
			// file legitimately produces one — and is caught instead by the final 18,000 count.
			if p.Index <= lastIndex {
				rec.OrderViolations++
			}
			lastIndex = p.Index
		}
		if Phase(curPhase) != sc.Trigger.Phase {
			return false
		}
		phaseSeen = true
		if p.BytesDone < pin.CumulativeBytes {
			return false
		}
		rec.Fired = true
		rec.ObservedBytesDone = p.BytesDone
		rec.ObservedBytesTotal = p.BytesTotal
		rec.ObservedIndex = p.Index
		rec.ObservedPhase = curPhase
		rec.OvershootBytes = p.BytesDone - pin.CumulativeBytes
		return true
	})

	if !rec.Fired {
		switch {
		case errors.Is(werr, ErrStopped):
			rec.NotFired = "the run ended before the trigger point was reached"
		case werr != nil:
			rec.NotFired = "watching progress failed: " + werr.Error()
		case !phaseSeen:
			rec.NotFired = "phase " + string(sc.Trigger.Phase) + " was never reported by the installer"
		default:
			rec.NotFired = fmt.Sprintf("phase %s ended having reported fewer than %d bytes",
				sc.Trigger.Phase, pin.CumulativeBytes)
		}
		log("scenario %s DID NOT FIRE: %s", sc.ID, rec.NotFired)
		return rec, nil
	}

	log("scenario %s fired at %d bytes (overshoot %d)", sc.ID, rec.ObservedBytesDone, rec.OvershootBytes)

	// ── the one measurement that is not the subject's own account of itself ───────────────────────
	//
	// Everything above came out of the installer's progress log. An installer that writes a
	// well-formed log and copies nothing produces exactly the record above. So before the action is
	// dispatched, walk the archive's data root and sum what is actually on the destination.
	//
	// Host-site scenarios do not do this: the walk costs hundreds of milliseconds and spending them
	// between the pin and a power cut would move the cut, which is the one thing those scenarios are
	// for. They are covered instead by the runner's archive verification on the verify boot (P8),
	// which re-hashes the whole destination tree and needs nothing from the guest at all.
	rec.DestBytesAtFire, rec.DestFilesAtFire, rec.DestScanMS, rec.DestScanNote =
		scanDestination(sc, cfg.DestDataRoot)
	log("scenario %s destination at fire: %d bytes in %d files (%dms) %s",
		sc.ID, rec.DestBytesAtFire, rec.DestFilesAtFire, rec.DestScanMS, rec.DestScanNote)

	// Evidence first, damage second. Always.
	if cfg.PreFire != nil {
		if err := cfg.PreFire(rec); err != nil {
			rec.ActionErr = "could not record the fire before dispatching it: " + err.Error()
			return rec, err
		}
	}

	switch sc.Site {
	case SiteHost:
		if cfg.Control == nil {
			rec.ActionErr = "no control channel to the host: a host-site fault cannot be executed"
			return rec, errors.New(rec.ActionErr)
		}
		// One line, tab-separated, so the host end needs no parser worth the name. After this the host
		// kills us; there is nothing after this line to do.
		line := fmt.Sprintf("fire\t%s\t%s\t%d\t%d\n", sc.ID, sc.Action, rec.ObservedBytesDone, rec.ObservedIndex)
		if _, err := io.WriteString(cfg.Control, line); err != nil {
			rec.ActionErr = "control channel write failed: " + err.Error()
			return rec, err
		}
	case SiteGuest:
		if guest == nil {
			rec.ActionErr = "no guest control implementation on this platform"
			return rec, errors.New(rec.ActionErr)
		}
		if err := dispatchGuest(cfg, pin, guest, &rec); err != nil {
			rec.ActionErr = err.Error()
			return rec, err
		}
	default:
		return rec, fmt.Errorf("scenario %s: unknown site %q", sc.ID, sc.Site)
	}
	return rec, nil
}

func dispatchGuest(cfg GuestConfig, pin Pin, g GuestControl, rec *FireRecord) error {
	sc := cfg.Scenario
	targetSel := ""
	if sc.Params != nil {
		targetSel = sc.Params["target"]
	}

	switch sc.Action {
	case ActionFillDestination:
		rec.TargetPath = "«destination volume»"
		return g.FillDestination(sc.paramInt("leave_bytes", 0))

	case ActionClockBackwards:
		rec.TargetPath = "«system clock»"
		return g.ClockBackwards(sc.paramInt("seconds", 86400))

	case ActionTruncateManifest:
		if cfg.ManifestPath == "" {
			return errors.New("no installer manifest path configured")
		}
		st, err := os.Stat(cfg.ManifestPath)
		if err != nil {
			return fmt.Errorf("installer manifest not found at %s: %w", cfg.ManifestPath, err)
		}
		keep := st.Size() * sc.paramInt("keep_fraction_bp", 5000) / 10000
		rec.TargetPath = "«installer manifest»"
		return g.TruncateFile(cfg.ManifestPath, keep)

	case ActionBitFlip:
		if targetSel == "manifest" {
			if cfg.ManifestPath == "" {
				return errors.New("no installer manifest path configured")
			}
			st, err := os.Stat(cfg.ManifestPath)
			if err != nil {
				return err
			}
			// Deterministic given a deterministic manifest, which is deterministic given a deterministic
			// corpus. If the installer ever writes a timestamp into its manifest this offset moves, and
			// the run result records the offset so that shows up as a diff rather than as a mystery.
			off, bit := BitFlipSite(sc.ID, Entry{Path: "«installer manifest»", Size: st.Size()})
			rec.TargetPath = fmt.Sprintf("«installer manifest» byte %d bit %d", off, bit)
			return g.BitFlipFile(cfg.ManifestPath, off, bit)
		}
		e, err := TargetEntry(cfg.Entries, pin, sc.TargetOffset)
		if err != nil {
			return err
		}
		off, bit := BitFlipSite(sc.ID, e)
		dst := destPath(cfg.DestDataRoot, e.Path)
		rec.TargetPath = fmt.Sprintf("%s byte %d bit %d", e.Path, off, bit)
		return g.BitFlipFile(dst, off, bit)

	case ActionMutateSource:
		e, err := TargetEntry(cfg.Entries, pin, sc.TargetOffset)
		if err != nil {
			return err
		}
		rec.TargetPath = e.Path // relative: this is what `gen verify -allow-missing` consumes
		return g.MutateSource(e.WinPath)

	case ActionDeleteSource:
		e, err := TargetEntry(cfg.Entries, pin, sc.TargetOffset)
		if err != nil {
			return err
		}
		rec.TargetPath = e.Path
		return g.DeleteSource(e.WinPath)

	case ActionExclusiveLock:
		e, err := TargetEntry(cfg.Entries, pin, sc.TargetOffset)
		if err != nil {
			return err
		}
		path := e.WinPath
		if targetSel == "destination" {
			path = destPath(cfg.DestDataRoot, e.Path)
		}
		rec.TargetPath = e.Path
		return g.ExclusiveLock(path, sc.paramInt("hold_ms", 120000))
	}
	return fmt.Errorf("scenario %s: action %q is not executable in the guest", sc.ID, sc.Action)
}

// destPath maps a manifest relative path to its place in the archive. The installer contract: a source
// file at relative path P is materialised at <DestDataRoot>\P.
func destPath(root, rel string) string {
	return strings.TrimRight(root, `\`) + `\` + strings.ReplaceAll(rel, "/", `\`)
}

// scanDestination sums the logical sizes of every file under the archive's data root.
//
// Returns (-1, 0, 0, reason) when the scan is deliberately not performed. "Deliberately" is the whole
// point of returning a reason rather than a zero: a zero here is a finding, and a finding must never be
// indistinguishable from a measurement that was skipped.
func scanDestination(sc Scenario, destDataRoot string) (bytes int64, files int, elapsedMS int64, note string) {
	if sc.Site == SiteHost {
		return -1, 0, 0, "not measured: host-site scenario, and the walk would delay the action past its pin"
	}
	if destDataRoot == "" {
		return -1, 0, 0, "not measured: no archive data root configured"
	}
	start := time.Now()
	err := filepath.WalkDir(destDataRoot, func(_ string, d fs.DirEntry, werr error) error {
		if werr != nil {
			// A file that vanished under the walk, or a directory we may not read. Neither is grounds
			// for abandoning the count; both are grounds for not pretending the count is exact.
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		files++
		bytes += info.Size()
		return nil
	})
	elapsedMS = time.Since(start).Milliseconds()
	if err != nil {
		if os.IsNotExist(err) {
			// The archive root does not exist at all. That is a measurement of zero, not a failure to
			// measure, and it is precisely the finding this scan exists to make.
			return 0, 0, elapsedMS, "archive data root does not exist"
		}
		return -1, 0, elapsedMS, "not measured: " + err.Error()
	}
	return bytes, files, elapsedMS, ""
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// HOST END
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// HostFire is the parsed "fire" line from the guest.
type HostFire struct {
	ScenarioID string
	Action     Action
	BytesDone  int64
	Index      int
}

// ControlKind is what a line on the control channel turned out to be.
type ControlKind string

const (
	CtlNone   ControlKind = ""
	CtlRecord ControlKind = "record" // a FireRecord, sent BEFORE the action is dispatched
	CtlFire   ControlKind = "fire"   // the guest asking the host to execute a host-site action
	CtlBeacon ControlKind = "beacon" // the guest reporting that it reached a state
	CtlExit   ControlKind = "exit"   // the installer's exit code, echoed by the guest's run script
	CtlLog    ControlKind = "log"    // free text
)

// ControlLine is one parsed line.
type ControlLine struct {
	Kind   ControlKind
	Raw    string
	Fire   HostFire
	Record FireRecord
	Exit   int
	Text   string
}

// ParseControlLine is a pure function so that the runner can multiplex ONE reader over the control
// channel — fire requests, fire records, beacons, the installer's exit code and free text all share the
// single serial line, and a helper that consumed the stream to wait for one of them would throw the
// others away.
//
// Lines from Go programs are tab-separated. `exit` and `beacon` also accept spaces, because they are
// emitted by a Windows batch file where producing a literal tab is a small adventure.
func ParseControlLine(line string) ControlLine {
	line = strings.TrimSpace(line)
	if line == "" {
		return ControlLine{Kind: CtlNone, Raw: line}
	}
	out := ControlLine{Raw: line}
	tabs := strings.Split(line, "\t")
	switch {
	case tabs[0] == "record" && len(tabs) >= 2:
		out.Kind = CtlRecord
		if err := json.Unmarshal([]byte(tabs[1]), &out.Record); err != nil {
			out.Kind = CtlLog
			out.Text = "unparseable fire record: " + err.Error()
		}
	case tabs[0] == "fire" && len(tabs) >= 5:
		out.Kind = CtlFire
		bytesDone, _ := strconv.ParseInt(tabs[3], 10, 64)
		idx, _ := strconv.Atoi(tabs[4])
		out.Fire = HostFire{ScenarioID: tabs[1], Action: Action(tabs[2]), BytesDone: bytesDone, Index: idx}
	default:
		f := strings.Fields(strings.ReplaceAll(line, "\t", " "))
		switch f[0] {
		case "exit":
			out.Kind = CtlExit
			if len(f) >= 2 {
				n, err := strconv.Atoi(f[1])
				if err != nil {
					out.Kind = CtlLog
					out.Text = line
				} else {
					out.Exit = n
				}
			}
		case "beacon":
			out.Kind = CtlBeacon
			out.Text = strings.Join(f[1:], " ")
		default:
			out.Kind = CtlLog
			out.Text = line
		}
	}
	return out
}

// HostDispatch executes a host-site action.
func HostDispatch(f HostFire, h HostControl) error {
	switch f.Action {
	case ActionPowerCut:
		return h.PowerCut()
	case ActionDetachDestination:
		return h.DetachDestination()
	}
	return fmt.Errorf("action %q is not a host-site action", f.Action)
}
