// Command auros-migrate copies a user's data off a Windows machine, verifies it,
// and only then points the next boot at install media.
//
// Dry run is the default. --commit is required to cross the wall, and the mode
// is printed at the top of every run, before every phase, and at the end.
//
// The phases are SAFETY.md's, in order, and they are enforced by
// internal/safety's state machine rather than by the order of the calls below.
// If this file were rewritten to call them in the wrong order, it would fail.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/safety"
	"github.com/aarohkandy/auros-installer/internal/winenv"
)

const usage = `auros-migrate — copy your files off, check them, then switch the machine over.

  DRY RUN IS THE DEFAULT. Nothing is written to this machine's system disk
  unless you pass --commit, and even then the privileged steps are compiled
  out of this binary unless it was built with -tags auros_arm_enabled.

Usage:
  auros-migrate --dest <folder on another drive> [flags]

Flags:
`

type config struct {
	dest         string
	sources      stringList
	commit       bool
	resume       bool
	acknowledged bool
	bootMedia    string
	restart      bool
	maxFileBytes int64
	bufSize      int
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nauros-migrate: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var cfg config
	fs := flag.NewFlagSet("auros-migrate", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.dest, "dest", "", "folder on a drive that is NOT the system disk")
	fs.Var(&cfg.sources, "source", "extra folder to copy, as label=path (repeatable)")
	fs.BoolVar(&cfg.commit, "commit", false, "cross the wall: actually change the boot settings (default: dry run)")
	fs.BoolVar(&cfg.resume, "resume", false, "reuse files already copied by an interrupted run")
	fs.BoolVar(&cfg.acknowledged, "i-understand-programs-do-not-migrate", false,
		"confirm you have read the list of programs that will NOT come across")
	fs.StringVar(&cfg.bootMedia, "boot-media", "", "firmware boot entry for install media you already made")
	fs.BoolVar(&cfg.restart, "restart", false, "restart at the end of a committed run")
	fs.Int64Var(&cfg.maxFileBytes, "max-file-bytes", 0, "quarantine files larger than this (0 = no limit)")
	fs.IntVar(&cfg.bufSize, "buffer-bytes", manifest.DefaultBufSize, "streaming buffer size")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return err
	}

	mode := safety.ModeDryRun
	if cfg.commit {
		mode = safety.ModeCommit
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	env := winenv.New()
	banner(mode, env)

	// ---- phase 1: INVENTORY (reads only) ----
	m := safety.NewMachine(mode, nil)
	if err := m.Advance(safety.PhaseInventory); err != nil {
		return err
	}
	section(mode, safety.PhaseInventory)

	folders, err := env.KnownFolders()
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	sources, err := buildSources(folders, cfg.sources)
	if err != nil {
		return err
	}
	for _, s := range sources {
		fmt.Printf("  %-16s %s\n", s.Label, s.Root)
	}
	if len(sources) == 0 {
		return errors.New("inventory: nothing to copy")
	}

	fw, err := env.Firmware()
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	printFirmware(fw)

	inventoryBytes, fileCount, err := measure(sources)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	fmt.Printf("\n  %d files, %s\n", fileCount, humanBytes(inventoryBytes))

	// ---- phase 2: DISCLOSE (reads only) ----
	if err := m.Advance(safety.PhaseDisclose); err != nil {
		return err
	}
	section(mode, safety.PhaseDisclose)
	programs, err := env.InstalledPrograms()
	if err != nil {
		return fmt.Errorf("disclose: %w", err)
	}
	printDisclosure(programs)
	if !cfg.acknowledged {
		return errors.New("you must read the list above and pass " +
			"--i-understand-programs-do-not-migrate to continue")
	}

	// ---- phase 3: DESTINATION (writes only to the destination) ----
	if err := m.Advance(safety.PhaseDestination); err != nil {
		return err
	}
	section(mode, safety.PhaseDestination)
	sysVol, err := env.SystemVolume()
	if err != nil {
		return fmt.Errorf("destination: cannot identify the system volume: %w", err)
	}
	dest, err := resolveDestination(env, sysVol, cfg.dest, inventoryBytes)
	if err != nil {
		return err
	}
	fmt.Printf("  destination : %s\n", dest.Dir)
	fmt.Printf("  volume      : %s\n", dest.Volume.GUID)
	fmt.Printf("  free        : %s (needs %s)\n",
		humanBytes(int64(dest.Volume.FreeBytes)), humanBytes(safety.RequiredBytes(inventoryBytes)))

	logOpts := runlog.Options{}
	logOpts.DestRoot = dest.Dir
	logOpts.DestIsSystemVolume = safety.SameVolume(dest.Volume, sysVol)
	log, err := runlog.Open(logOpts)
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	defer log.Close()
	fmt.Printf("  run log     : %s\n", log.Path())
	log.Event(safety.PhaseDestination.String(), "chosen", runlog.Fields{
		"dir":        dest.Dir,
		"free_bytes": dest.Volume.FreeBytes,
		"mode":       mode.String(),
		"platform":   env.Platform(),
		"volume":     dest.Volume.GUID,
	})

	// ---- phase 4: COPY (writes only to the destination) ----
	if err := m.Advance(safety.PhaseCopy); err != nil {
		return err
	}
	section(mode, safety.PhaseCopy)
	q := quarantine.NewSet(time.Now)

	copyOpts := copyengine.Options{}
	copyOpts.Sources = sources
	copyOpts.DestRoot = dest.Dir
	copyOpts.Quarantine = q
	copyOpts.Log = log
	copyOpts.BufSize = cfg.bufSize
	copyOpts.MaxFileBytes = cfg.maxFileBytes
	copyOpts.Resume = cfg.resume
	copyOpts.Progress = progressPrinter()

	cres, cerr := copyengine.Run(ctx, copyOpts)
	fmt.Print("\n" + cres.Describe())
	if cerr != nil {
		m.Abort("copy: " + cerr.Error())
		printQuarantine(q)
		return fmt.Errorf("copy: %w (nothing was written to the system disk)", cerr)
	}

	// ---- phase 5: VERIFY (reads only) ----
	section(mode, safety.PhaseVerify)
	vreq := safety.VerifyRequest{}
	vreq.DestRoot = dest.Dir
	vreq.DestVolumeGUID = dest.Volume.GUID
	vreq.SystemVolumeGUID = sysVol.GUID
	vreq.Manifest = cres.Manifest
	vreq.Quarantine = q
	vreq.Log = log
	vreq.BufSize = cfg.bufSize

	archive, report, verr := safety.Verify(ctx, m, vreq)
	if report != nil {
		fmt.Print(report.Describe())
	}
	if verr != nil {
		m.Abort("verify: " + verr.Error())
		printQuarantine(q)
		fmt.Printf("\nSTOPPED. The system disk was not touched: %v\n", m.SystemDiskUntouched())
		return fmt.Errorf("verify: %w", verr)
	}
	printQuarantine(q)
	fmt.Printf("\n  %d files now exist in two places. The system disk has not been written to.\n",
		archive.FileCount())
	fmt.Printf("  archive: %s\n  digest : %s\n", archive.Root(), archive.ManifestDigest())

	// ---- phase 6: ARM (the wall) ----
	section(mode, safety.PhaseArm)
	areq := safety.ArmRequest{}
	areq.SystemVolumeGUID = sysVol.GUID
	areq.SystemMount = sysVol.Mount
	areq.BitLockerProtected = fw.BitLockerOnSystemVolume == winenv.Yes
	areq.BootMediaGUID = cfg.bootMedia
	areq.Restart = cfg.restart && cfg.commit
	areq.Log = log

	ares, aerr := safety.Arm(ctx, m, archive, areq)
	if ares != nil {
		fmt.Print(ares.Describe())
	}
	if aerr != nil {
		return fmt.Errorf("arm: %w", aerr)
	}
	fmt.Printf("\nmode: %s — done.\n", mode)
	return nil
}

// ---- presentation ----

func banner(mode safety.Mode, env winenv.Env) {
	fmt.Printf("\nauros-migrate   mode: %s   platform: %s\n", mode, env.Platform())
	if env.Platform() != "windows" {
		fmt.Println("  NOTE: this is not a Windows machine. The environment is SYNTHETIC:")
		fmt.Println("        folder locations, the installed-programs list, volume identities and")
		fmt.Println("        firmware facts are all made up. This is a rehearsal, not a migration.")
	}
	if !mode.Commits() {
		fmt.Println("  DRY RUN: your files are copied and checked; nothing on this machine changes.")
	} else {
		fmt.Println("  COMMIT: after verification succeeds, boot settings WILL be changed.")
	}
	fmt.Println(strings.Repeat("-", 72))
}

func section(mode safety.Mode, p safety.Phase) {
	label := "reads and writes to the backup drive only"
	if p.TouchesSystemDisk() {
		label = "THE WALL — the only phase that touches this machine"
	}
	fmt.Printf("\n[%s] %s   (%s)\n", mode, p, label)
}

func printFirmware(fw winenv.Firmware) {
	fmt.Println("\n  before you start, three things can break \"one restart\":")
	if !fw.Known {
		fmt.Println("    ! firmware facts are UNKNOWN on this platform; none of the three were checked")
	} else {
		fmt.Printf("    BitLocker on the system volume : %s\n", fw.BitLockerOnSystemVolume)
		fmt.Printf("    Secure Boot                    : %s\n", fw.SecureBootEnabled)
		fmt.Printf("    third-party UEFI CA trusted    : %s\n", fw.ThirdPartyUEFICATrusted)
		fmt.Printf("    TPM version                    : %s\n", fw.TPMVersion)
		fmt.Printf("    BootNext honoured              : %s\n", fw.BootNextSupported)
	}
	for _, n := range fw.Notes {
		fmt.Printf("    - %s\n", n)
	}
}

// printDisclosure is prohibition §4.2 and SAFETY.md phase 2. It prints the
// actual installed-programs list by name. Not a generic warning: the literal
// list, because a school that finds out at month two that their attendance
// software is gone becomes a refund and a story.
func printDisclosure(programs []winenv.Program) {
	fmt.Printf("\n  WHAT DOES NOT COME ACROSS\n")
	fmt.Printf("  Windows programs do not migrate. Not any of them. These %d will be gone:\n\n", len(programs))
	names := make([]string, 0, len(programs))
	for _, p := range programs {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("    - %s\n", n)
	}
	fmt.Println("\n  Your files, browser bookmarks and history, Wi-Fi networks, printers and")
	fmt.Println("  account name do come across.")
	fmt.Println("  Saved passwords, cookies and payment details in Chrome and Edge DO NOT.")
	fmt.Println("  Export or sync them before you start.")
}

func printQuarantine(q *quarantine.Set) {
	if q.Len() == 0 {
		return
	}
	fmt.Println()
	if err := q.WriteReport(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "could not print the quarantine report: %v\n", err)
	}
}

func progressPrinter() func(copyengine.Progress) {
	var last time.Time
	return func(p copyengine.Progress) {
		now := time.Now()
		if p.Files < p.FilesTotal && now.Sub(last) < 200*time.Millisecond {
			return
		}
		last = now
		fmt.Printf("\r  %d/%d files  %s  quarantined %d          ",
			p.Files, p.FilesTotal, humanBytes(p.Bytes), p.Quarantined)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// ---- wiring ----

func buildSources(folders []winenv.Folder, extra stringList) ([]copyengine.Source, error) {
	var out []copyengine.Source
	for _, f := range folders {
		if !f.Present {
			continue
		}
		out = append(out, copyengine.Source{Root: f.Path, Label: f.ID})
	}
	for _, spec := range extra {
		label, path, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("--source %q: expected label=path", spec)
		}
		if _, err := manifest.CleanRel(label); err != nil {
			return nil, fmt.Errorf("--source %q: %w", spec, err)
		}
		out = append(out, copyengine.Source{Root: path, Label: label})
	}
	return out, nil
}

func measure(sources []copyengine.Source) (int64, int, error) {
	var total int64
	var count int
	for _, s := range sources {
		err := filepath.Walk(s.Root, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // unreadable subtrees are the copy engine's problem
			}
			if info.Mode().IsRegular() {
				total += info.Size()
				count++
			}
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	}
	return total, count, nil
}

// resolveDestination turns a --dest path into a Destination whose volume
// identity is known. It refuses rather than guessing: a destination whose volume
// cannot be identified cannot be proven not to be the system disk.
func resolveDestination(env winenv.Env, sysVol winenv.Volume, destFlag string, inventoryBytes int64) (safety.Destination, error) {
	vols, err := env.Volumes()
	if err != nil {
		return safety.Destination{}, fmt.Errorf("destination: %w", err)
	}

	if destFlag != "" {
		abs, aerr := filepath.Abs(destFlag)
		if aerr != nil {
			return safety.Destination{}, aerr
		}
		if v, ok := volumeFor(vols, abs); ok {
			d := safety.Destination{Volume: v, Dir: abs}
			return d, safety.CheckDestination(d, sysVol, inventoryBytes)
		}
		if env.Platform() == "windows" {
			return safety.Destination{}, fmt.Errorf(
				"destination: cannot identify the volume holding %s; refusing to continue", abs)
		}
		// Synthetic platform: fabricate an identity, and say so loudly. This
		// path exists so the whole pipeline can be rehearsed on Linux. It is
		// never reachable on Windows.
		v := winenv.Volume{}
		v.GUID = "synthetic:" + abs
		v.Mount = abs
		v.FS = "synthetic"
		v.FreeBytes = uint64(safety.RequiredBytes(inventoryBytes)) * 4
		v.TotalBytes = v.FreeBytes
		fmt.Printf("  NOTE: volume identity for %s is SYNTHETIC (%s)\n", abs, v.GUID)
		d := safety.Destination{Volume: v, Dir: abs}
		return d, safety.CheckDestination(d, sysVol, inventoryBytes)
	}

	var cands []safety.Destination
	for _, v := range vols {
		cands = append(cands, safety.Destination{Volume: v, Dir: filepath.Join(v.Mount, "auros-backup")})
	}
	chosen, rejected, cerr := safety.ChooseDestination(cands, sysVol, inventoryBytes)
	if s := safety.DescribeRejections(rejected); s != "" {
		fmt.Print("\n" + s)
	}
	if cerr != nil {
		return safety.Destination{}, cerr
	}
	if err := os.MkdirAll(chosen.Dir, 0o755); err != nil {
		return safety.Destination{}, err
	}
	return chosen, nil
}

func volumeFor(vols []winenv.Volume, path string) (winenv.Volume, bool) {
	var best winenv.Volume
	found := false
	for _, v := range vols {
		if v.Mount == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(path), strings.ToLower(v.Mount)) {
			continue
		}
		if !found || len(v.Mount) > len(best.Mount) {
			best, found = v, true
		}
	}
	return best, found
}
