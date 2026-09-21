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
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/quarantine"
	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/safety"
	"github.com/aarohkandy/auros-installer/internal/signals"
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
	placeholders string
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
	fs.StringVar(&cfg.placeholders, "cloud-files", "",
		"what to do about OneDrive Files On-Demand placeholders: hydrate (download them now); skip is not supported yet")
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

	ctx, stop := signal.NotifyContext(context.Background(), signals.Interrupting()...)
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

	// SAFETY.md phase 1: OneDrive Files On-Demand is a first-class case. The
	// placeholders are counted and the choice is the user's, made BEFORE the run
	// starts — not discovered forty minutes in, after a school uplink has been
	// saturated by a hydration nobody agreed to.
	ph, perr := countPlaceholders(env, sources)
	if perr != nil {
		return fmt.Errorf("inventory: counting cloud placeholders: %w", perr)
	}
	choice, cerr := placeholderChoice(ph, cfg.placeholders)
	if cerr != nil {
		return cerr
	}
	if ph.Count > 0 {
		inventoryBytes = adjustForPlaceholders(inventoryBytes, ph, choice)
		fmt.Printf("  after your choice (%s): %s to copy\n", choice, humanBytes(inventoryBytes))
	}

	// Wi-Fi networks and printers: read now, disclosed one by one below, and
	// written into the archive at the start of phase 4.
	x := gatherExtras(env)
	fmt.Printf("  %d saved Wi-Fi network(s), %d printer(s)\n", len(x.wifi), len(x.printers))

	// ---- phase 2: DISCLOSE (reads only) ----
	if err := m.Advance(safety.PhaseDisclose); err != nil {
		return err
	}
	section(mode, safety.PhaseDisclose)
	programs, err := env.InstalledPrograms()
	if err != nil {
		return fmt.Errorf("disclose: %w", err)
	}
	printDisclosure(os.Stdout, programs, x)
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
	resolver := safety.NewResolver(env, sysVol)
	dest, err := resolveDestination(resolver, cfg.dest, inventoryBytes)
	if err != nil {
		return err
	}
	if abs, aerr := filepath.Abs(cfg.dest); cfg.dest != "" && aerr == nil && abs != dest.Dir() {
		// The path the user typed was a link. Say so: they asked for one place
		// and the files are going to another.
		fmt.Printf("  NOTE: %s is a link; it resolves to %s, and that is where the files go.\n", abs, dest.Dir())
	}
	fmt.Printf("  destination : %s\n", dest.Dir())
	fmt.Printf("  volume      : %s\n", dest.Volume().GUID)
	fmt.Printf("  free        : %s (needs %s)\n",
		humanBytes(int64(dest.Volume().FreeBytes)), humanBytes(safety.RequiredBytes(inventoryBytes)))

	log, err := runlog.Open(dest.RunlogOptions())
	if err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	defer log.Close()
	fmt.Printf("  run log     : %s\n", log.Path())
	log.Event(safety.PhaseDestination.String(), "chosen", runlog.Fields{
		"dir":               dest.Dir(),
		"requested":         cfg.dest,
		"free_bytes":        dest.Volume().FreeBytes,
		"mode":              mode.String(),
		"platform":          env.Platform(),
		"volume":            dest.Volume().GUID,
		"on_system_volume":  dest.OnSystemVolume(),
		"cloud_placeholder": choice,
	})
	log.Event(safety.PhaseInventory.String(), "cloud-placeholders", runlog.Fields{
		"count":         ph.Count,
		"logical_bytes": ph.LogicalSize,
		"on_disk_bytes": ph.OnDiskSize,
		"choice":        choice,
	})

	// ---- phase 4: COPY (writes only to the destination) ----
	if err := m.Advance(safety.PhaseCopy); err != nil {
		return err
	}
	section(mode, safety.PhaseCopy)
	q := quarantine.NewSet(time.Now)

	// The Wi-Fi and printer exports are staged on the DESTINATION, under the
	// metadata directory verify does not count, and copied into the archive
	// from there like any other file — hashed, recorded, verified. The staging
	// copy is removed after the copy, so the plain-text keys are on the drive
	// once, inside the archive, and nowhere on this machine.
	if err := dest.Reassert(); err != nil {
		m.Abort("copy: " + err.Error())
		return fmt.Errorf("copy: %w", err)
	}
	exportDir := filepath.Join(dest.Dir(), manifest.MetaDir, exportDirName)
	extraSources, serr := x.stage(exportDir)
	removeExport := func() {
		if err := os.RemoveAll(exportDir); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not remove the staging copy of the Wi-Fi export at %s: %v\n", exportDir, err)
		}
	}
	if serr != nil {
		removeExport()
		m.Abort("copy: " + serr.Error())
		return fmt.Errorf("copy: %w", serr)
	}
	// Counts only. A profile's XML may hold its key in plain text and never
	// goes near the run log.
	log.Event(safety.PhaseCopy.String(), "extras-staged", runlog.Fields{
		"wifi_profiles": len(x.wifi),
		"printers":      len(x.printers),
	})

	copyOpts := copyengine.Options{}
	copyOpts.Sources = append(append([]copyengine.Source(nil), sources...), extraSources...)
	copyOpts.DestRoot = dest.Dir()
	copyOpts.AssertDestination = dest.Reassert
	copyOpts.ResumeIdentity = dest.Volume().GUID
	copyOpts.Quarantine = q
	copyOpts.Log = log
	copyOpts.BufSize = cfg.bufSize
	copyOpts.MaxFileBytes = cfg.maxFileBytes
	copyOpts.Resume = cfg.resume
	copyOpts.Progress = progressPrinter()

	cres, cerr := copyengine.Run(ctx, copyOpts)
	removeExport()
	fmt.Print("\n" + cres.Describe())
	if cerr != nil {
		m.Abort("copy: " + cerr.Error())
		printQuarantine(q)
		return fmt.Errorf("copy: %w (every byte went under %s; the system disk was not written to: %v)",
			cerr, dest.Dir(), !dest.OnSystemVolume())
	}

	// ---- phase 5: VERIFY (reads only) ----
	section(mode, safety.PhaseVerify)
	vreq := safety.VerifyRequest{}
	vreq.Dest = dest
	vreq.System = sysVol
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
	// Measured, not asserted: the destination's resolved path is re-identified
	// and its volume compared against the system volume, right now.
	if dest.OnSystemVolume() {
		return errors.New("verify: the archive is on the system volume; that is not a second copy")
	}
	fmt.Printf("\n  %d files now exist in two places, and the system disk has not been written to\n"+
		"  (checked just now: %s is on %s, the system volume is %s).\n",
		archive.FileCount(), dest.Dir(), dest.Volume().GUID, sysVol.GUID)
	fmt.Printf("  archive: %s\n  digest : %s\n", archive.Root(), archive.ManifestDigest())

	// ---- phase 6: ARM (the wall) ----
	section(mode, safety.PhaseArm)
	areq := safety.ArmRequest{}
	// Not "== Yes". Unknown must behave like Yes: the suspend step is planned
	// unless BitLocker is positively known to be off, and the volume and mount
	// the steps act on come from the VerifiedArchive rather than from here.
	areq.BitLocker = fw.BitLockerOnSystemVolume
	areq.FirmwareKnown = fw.Known
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
// identity has been PROVEN, or refuses.
//
// It does almost nothing itself, and that is the fix. The previous version
// lowercased the path, compared it against the drive roots with a string prefix
// test, and reported the GUID of the drive LETTER — so a junction at
// `D:\backup` pointing to `C:\AurosBackup` reported D:, passed every check, and
// put the user's only copy on the disk the tool was about to repoint. The volume
// of a directory is a question only the operating system can answer, and
// safety.Resolver is the one place that asks it.
func resolveDestination(r *safety.Resolver, destFlag string, inventoryBytes int64) (safety.Destination, error) {
	if destFlag != "" {
		d, err := r.Resolve(destFlag, inventoryBytes)
		if err != nil {
			return safety.Destination{}, fmt.Errorf("destination: %w", err)
		}
		return d, nil
	}
	d, rejected, err := r.Choose(manifest.ArchiveSubdir, inventoryBytes)
	if s := safety.DescribeRejections(rejected); s != "" {
		fmt.Print("\n" + s)
	}
	if err != nil {
		return safety.Destination{}, fmt.Errorf("destination: %w", err)
	}
	return d, nil
}

// ---- phase 1: OneDrive Files On-Demand ----

// countPlaceholders sums the cloud placeholders across every source root.
func countPlaceholders(env winenv.Env, sources []copyengine.Source) (winenv.PlaceholderStats, error) {
	var total winenv.PlaceholderStats
	for _, s := range sources {
		st, err := env.CloudPlaceholders(s.Root)
		if err != nil {
			return winenv.PlaceholderStats{}, err
		}
		total.Count += st.Count
		total.LogicalSize += st.LogicalSize
		total.OnDiskSize += st.OnDiskSize
	}
	return total, nil
}

// placeholderChoice prints what was found and requires the user to have made a
// choice. SAFETY.md phase 1: "their choice, stated in plain words, between
// hydrating (slow, may not fit) and leaving them in the cloud". A run that finds
// placeholders and was not told which to do stops here, before anything is
// copied and before a school's uplink is saturated.
func placeholderChoice(ph winenv.PlaceholderStats, flag string) (string, error) {
	flag = strings.ToLower(strings.TrimSpace(flag))
	// SYSTEM-REVIEW §2.21 / H10: copyengine.Options has no placeholder policy,
	// so "skip" would hydrate every placeholder anyway against a space estimate
	// that assumed it would not. Refused until the copy engine honours it.
	if flag == "skip" {
		return "", errors.New("inventory: --cloud-files=skip is not supported yet: the copy would still " +
			"download every OneDrive placeholder. Use --cloud-files=hydrate, or make those files " +
			"available offline (or move them out of the copied folders) before you start")
	}
	if ph.Count == 0 {
		fmt.Println("\n  no OneDrive Files On-Demand placeholders were found.")
		if flag == "" {
			return "none-found", nil
		}
		return flag, nil
	}
	fmt.Printf("\n  ONEDRIVE FILES ON-DEMAND\n")
	fmt.Printf("  %d of your files are placeholders: the name is on this laptop, the contents are not.\n", ph.Count)
	if ph.OnDiskSize > 0 {
		fmt.Printf("  They take %s here and would be %s once downloaded.\n",
			humanBytes(ph.OnDiskSize), humanBytes(ph.LogicalSize))
	} else {
		fmt.Printf("  They take almost nothing here and would be %s once downloaded.\n",
			humanBytes(ph.LogicalSize))
	}
	fmt.Println("  You choose, and you choose now rather than forty minutes into the copy:")
	fmt.Println("    --cloud-files=hydrate   download them all now. Slow on a school connection,")
	fmt.Println("                            and they have to fit on the backup drive.")
	fmt.Println("  Leaving them in the cloud (--cloud-files=skip) is not supported yet: the")
	fmt.Println("  copy would download them anyway.")
	switch flag {
	case "hydrate":
		return flag, nil
	case "":
		return "", errors.New("inventory: choose what happens to the cloud placeholders with --cloud-files=hydrate")
	default:
		return "", fmt.Errorf("inventory: --cloud-files=%q: expected hydrate", flag)
	}
}

// adjustForPlaceholders corrects the space estimate for the choice that was
// made. measure() sums logical sizes, which is the hydrated size; skipping means
// those bytes are not copied at all.
func adjustForPlaceholders(inventoryBytes int64, ph winenv.PlaceholderStats, choice string) int64 {
	if choice != "skip" {
		return inventoryBytes
	}
	adjusted := inventoryBytes - ph.LogicalSize
	if adjusted < 0 {
		return 0
	}
	return adjusted
}
