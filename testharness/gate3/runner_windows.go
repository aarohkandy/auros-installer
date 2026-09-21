//go:build windows

package gate3

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunConfig is everything one run needs.
type RunConfig struct {
	Scenario *Scenario // nil means a clean run
	RunID    string

	CorpusRoot string
	GoldenPath string
	Tool       string

	DestVolume  string // "E:\", freshly formatted before every run
	DestDirName string // the directory the installer is told to use, e.g. "auros-archive"
	SmallVolume string // a deliberately tiny volume, for the too-small scenario

	User     string
	Password string
	WorkDir  string
	Timeout  time.Duration

	Profile  string
	Seed     uint64
	Faithful bool
	Image    string

	// SettleQuiet and SettleMax bound the settle phase; zero means the default.
	SettleQuiet time.Duration
	SettleMax   time.Duration
}

// RunOnce performs one run end to end and returns its evidence.
//
// The order is the whole design:
//
//	mark the change journal → run the installer as the migration user →
//	fire the scenario at its pin, measured from outside the process →
//	read the journal back → re-hash the source → re-hash the archive →
//	read what the installer claimed → decide
//
// Every measurement after the run is made by this program from raw bytes. The
// installer's own account of itself is read last and only ever used to catch it
// claiming something the measurements contradict.
func RunOnce(cfg RunConfig) (*Result, error) {
	if err := Validate(); err != nil {
		return nil, err
	}
	sc := cfg.Scenario
	res := &Result{
		Harness: HarnessVersion, RunID: cfg.RunID, Kind: KindClean,
		CorpusRoot: cfg.CorpusRoot, ToolPath: cfg.Tool,
		Profile: cfg.Profile, CorpusSeed: cfg.Seed, Faithful: cfg.Faithful,
		Image: cfg.Image, Hosted: os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted",
	}
	res.Machine, _ = os.Hostname()
	if sc != nil {
		res.Kind = KindFault
		res.ScenarioID, res.Scenario, res.Expect = sc.ID, sc.Name, sc.Expect
	}
	if v, err := HashOf(cfg.Tool); err == nil {
		res.ToolSHA256 = v.SHA256
	}

	g, err := LoadGolden(cfg.GoldenPath)
	if err != nil {
		return nil, err
	}
	extras, err := g.AddBaselineExtras(cfg.CorpusRoot)
	if err != nil {
		return nil, err
	}
	for _, e := range extras {
		res.Findings = append(res.Findings, "a file that is not part of the generated corpus was in the "+
			"source tree before this run and is included in what the archive must contain: "+e)
	}
	res.CorpusFiles, res.CorpusBytes, res.CorpusDigest = len(g.ByGolden), g.TotalBytes, g.Digest
	res.attachGolden(g)

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return nil, err
	}
	if err := GrantFullControl(cfg.WorkDir, cfg.User); err != nil {
		return nil, err
	}

	// ── log the migration user on BEFORE settling ────────────────────────────
	// A logon and profile load wake Windows' own per-user machinery (the Entra
	// broker rewrites AppRepository\...\ActivationStore.dat). When this happened
	// after the "before" mark, every clean run showed those writes as unexplained
	// C: changes (runs 35632029937, 35596591968). The logon is harness setup, not
	// the installer, so its side effects belong in the settle window, and only the
	// installer runs between the marks.
	sess, err := LogonMigrationUser(cfg.User, cfg.Password)
	if err != nil {
		return nil, err
	}
	// Never unload: the profile must stay loaded for the whole job so the
	// account's registry hive stays out of the corpus. See KeepProfileLoaded.
	sess.KeepProfileLoaded()
	defer sess.Close()
	res.Elevated = sess.Elevated

	// ── settle: C: must go quiet before the "before" mark is taken ──────────
	// Done before the harness itself touches C: (destination prep, planted
	// links), so the only writers it waits out are the machine's own. A machine
	// that never settles is not measured: C1 fails with why, and nothing runs.
	quiet, maxWait := cfg.SettleQuiet, cfg.SettleMax
	if quiet <= 0 {
		quiet = DefaultSettleQuiet
	}
	if maxWait <= 0 {
		maxWait = DefaultSettleMax
	}
	poll, perr := journalPoller("C:")
	if perr != nil {
		res.Settle = &SettleReport{QuietSeconds: quiet.Seconds(), Error: perr.Error()}
	} else {
		res.Settle = Settle(poll, quiet, maxWait, SettleEvery, time.Now, time.Sleep)
	}
	if res.Settle.Why() != "" {
		res.Evaluate(sc, len(g.ByGolden))
		return res, nil
	}

	// ── the destination this scenario runs against ───────────────────────────
	destDir, destForCheck, prepErr := prepareDestination(cfg, sc)
	if prepErr != nil {
		return nil, prepErr
	}
	res.DestDir = destDir

	in := &Injector{CorpusRoot: cfg.CorpusRoot, DestDir: destForCheck, DestVolume: cfg.DestVolume}
	defer in.Release()

	var devs []Deviation

	// A link inside the source tree that points outside it. Planted before the
	// journal is marked, because the harness creating it is not the installer
	// writing to C:.
	if sc != nil && sc.PlantSymlinkEscape {
		link := filepath.Join(cfg.CorpusRoot, "Documents", "escape-hatch")
		target := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc")
		if err := PlantSymlink(link, target); err != nil {
			return nil, fmt.Errorf("gate3: planting the escaping link: %w", err)
		}
		defer os.Remove(link)
		devs = append(devs, Deviation{
			Tree: "source", Path: "Documents/escape-hatch", Kind: "link planted by the harness",
			Note: "points at " + target,
		})
	}

	// ── the pin ──────────────────────────────────────────────────────────────
	var pin Pin
	if sc != nil && sc.Trigger != TriggerNone {
		pin, err = ResolvePin(g, sc.Phase, sc.BP)
		if err != nil {
			return nil, err
		}
		res.Pin = &pin
	}

	// ── the invariant's opening mark, and the trace that attributes it ───────
	trace, terr := StartTrace(filepath.Join(cfg.WorkDir, "etw-"+cfg.RunID))
	if terr == nil {
		defer trace.Stop()
	}
	mark, merr := MarkUSN("C:")
	if merr != nil {
		res.SystemDisk = &SystemDiskReport{Error: merr.Error(), Exclusions: NoiseRules(), ExclusionSHA: NoiseSHA()}
	}

	// A run that tells the installer to leave the cloud placeholders alone
	// declares, in advance, that they must not be in the archive. If they are,
	// the archive check says so by name.
	if sc != nil && sc.CloudFiles == "skip" {
		for _, rec := range g.ByCopy {
			if rec.Placeholder {
				devs = append(devs, Deviation{
					Tree: "archive", Path: rec.Archive, Kind: "placeholder the user asked to leave alone",
					Absent: true,
					Note: "the run passed --cloud-files=skip, so this file must not have been copied; " +
						"the installer also reduced its free-space requirement by these bytes",
				})
			}
		}
	}

	// ── run the installer as the migration user ──────────────────────────────
	args := installerArgs(destDir, cloudFiles(sc))
	res.ToolArgs = args
	outPath := filepath.Join(cfg.WorkDir, "installer-"+cfg.RunID+".out")

	started := time.Now()
	proc, err := StartInstaller(sess, cfg.Tool, args, outPath, cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	defer proc.Close()

	fire := monitor(proc, in, g, sc, pin, destForCheck, cfg, &devs)
	if sc != nil && sc.Trigger != TriggerNone {
		res.Fire = fire
	}

	code, timedOut := proc.Wait(cfg.Timeout - time.Since(started))
	res.DurationSec = time.Since(started).Seconds()
	if timedOut {
		res.TimedOut = true
		_ = proc.Kill()
		code, _ = proc.Wait(30 * time.Second)
	}
	res.ExitCode = code
	res.KilledByUs = fire != nil && fire.Fired && sc != nil && sc.Action == ActionKill

	// Let anything the installer started on its way out land before the journal
	// is read back. Three seconds is not a fudge factor for flakiness: it is the
	// window in which a write issued just before exit reaches the file system,
	// and a write that lands in it is still a write to C:.
	time.Sleep(3 * time.Second)
	in.Release()

	if merr == nil {
		attr := &Attribution{Err: fmt.Sprintf("the trace did not start: %v", terr)}
		if terr == nil {
			attr = trace.Attribute([]uint32{proc.PID()})
		}
		rep, derr := DiffUSN(mark, injectedPaths(devs, cfg), attr)
		if derr != nil && rep == nil {
			rep = &SystemDiskReport{Error: derr.Error()}
		}
		res.SystemDisk = rep
	}

	// ── the measurements ─────────────────────────────────────────────────────
	out, _ := os.ReadFile(outPath)
	stdout := string(out)
	res.LogTail = tail(stdout, 6000)
	res.AttachOutput(stdout)
	res.Inventory = InventoryLines(stdout)
	if sc != nil && sc.Dest == DestAuto {
		if d := chosenDestination(stdout); d != "" {
			destForCheck = d
			res.DestDir = d
		}
	}

	src, serr := CheckSource(g, cfg.CorpusRoot, devs)
	if serr != nil && src == nil {
		return nil, serr
	}
	res.Source = src

	waitForVolume(destForCheck)
	arc, aerr := CheckArchive(g, destForCheck, devs, sc == nil || sc.Expect == ExpectSurvive)
	if aerr != nil && arc == nil {
		arc = &TreeReport{Tree: "archive", Root: destForCheck, Expected: len(g.ByCopy)}
	}
	res.Archive = arc
	res.Deviations = devs

	res.Claims, _ = ReadClaims(destForCheck)
	if res.Claims != nil {
		res.Claims.ArmPlanPrinted, res.Claims.ArmPerformed = ReadArmOutcome(stdout)
	}
	res.Manifest, _ = ReadInstallerManifest(destForCheck)
	res.Quarantine = ReadQuarantineReport(destForCheck)
	if res.Claims != nil {
		res.DestVolume = res.Claims.DestVolume
	}

	res.Findings = append(res.Findings, fidelityFindings(g, res)...)
	res.Evaluate(sc, len(g.ByGolden))
	return res, nil
}

// journalPoller returns a poll for Settle: each call reads the C: change
// journal since the previous call and returns the changes the noise list does
// not excuse. No attribution: while settling, every such change counts.
func journalPoller(letter string) (func() ([]string, error), error) {
	mark, err := MarkUSN(letter)
	if err != nil {
		return nil, err
	}
	return func() ([]string, error) {
		rep, err := DiffUSN(mark, nil, nil)
		if err != nil {
			return nil, err
		}
		if rep.Error != "" {
			return nil, fmt.Errorf("%s", rep.Error)
		}
		mark.NextUSN = rep.EndUSN
		return rep.Unexplained, nil
	}, nil
}

// installerArgs is the REAL command line, from cmd/auros-migrate/main.go.
//
//	--dest <folder>                              (not --destination)
//	--i-understand-programs-do-not-migrate       (without it every run stops in
//	                                              phase 2 and nothing is copied)
//	--cloud-files=hydrate                        (the corpus carries files marked
//	                                              FILE_ATTRIBUTE_OFFLINE, and the
//	                                              installer refuses to start
//	                                              until it is told what to do
//	                                              about them)
//
// No --commit: every run in this suite is a dry run and the wall is never
// crossed. There is no --json, no --runlog and no verify subcommand; the
// previous harness was written against all three.
func cloudFiles(sc *Scenario) string {
	if sc != nil && sc.CloudFiles != "" {
		return sc.CloudFiles
	}
	return "hydrate"
}

func installerArgs(destDir, cloud string) []string {
	args := []string{"--i-understand-programs-do-not-migrate", "--cloud-files=" + cloud}
	if destDir != "" {
		args = append(args, "--dest", destDir)
	}
	return args
}

func prepareDestination(cfg RunConfig, sc *Scenario) (destArg, destCheck string, err error) {
	name := cfg.DestDirName
	if name == "" {
		name = "auros-archive"
	}
	mode := DestNormal
	if sc != nil {
		mode = sc.Dest
	}
	switch mode {
	case DestNormal:
		d := filepath.Join(cfg.DestVolume, name)
		return d, d, nil
	case DestSystemVolume:
		// Named but never created: the installer must refuse before creating it,
		// and the change journal is watching for exactly that directory.
		d := `C:\auros-gate3-must-never-exist`
		os.RemoveAll(d)
		return d, filepath.Join(cfg.DestVolume, name), nil
	case DestTooSmall:
		if cfg.SmallVolume == "" {
			return "", "", fmt.Errorf("gate3: the too-small scenario needs a small volume")
		}
		d := filepath.Join(cfg.SmallVolume, name)
		return d, d, nil
	case DestJunctionToSystem:
		target := `C:\auros-gate3-junction-target`
		if err := os.MkdirAll(target, 0o755); err != nil {
			return "", "", err
		}
		link := filepath.Join(cfg.DestVolume, "looks-like-the-backup-drive")
		if err := MakeJunction(link, target); err != nil {
			return "", "", err
		}
		return filepath.Join(link, name), filepath.Join(cfg.DestVolume, name), nil
	case DestAuto:
		return "", filepath.Join(cfg.DestVolume, name), nil
	}
	return "", "", fmt.Errorf("gate3: unknown destination mode %q", mode)
}

// injectedPaths lists the C: paths the harness itself damaged, so the change
// journal check excuses them BY EXACT PATH and nothing else.
func injectedPaths(devs []Deviation, cfg RunConfig) []string {
	var out []string
	for _, d := range devs {
		if d.Tree != "source" {
			continue
		}
		out = append(out, filepath.Join(cfg.CorpusRoot, filepath.FromSlash(d.Path)))
	}
	// The junction scenario's target directory is created by the harness before
	// the run; the installer must not put anything in it, and anything it does
	// put there is a path UNDER this one, so the exclusion is the directory
	// itself and not its contents.
	if cfg.Scenario != nil && cfg.Scenario.Dest == DestJunctionToSystem {
		out = append(out, `C:\auros-gate3-junction-target`)
	}
	return out
}

// monitor watches the installer from outside and fires the scenario at its pin.
func monitor(p *Process, in *Injector, g *Golden, sc *Scenario, pin Pin, destDir string,
	cfg RunConfig, devs *[]Deviation) *FireRecord {
	if sc == nil || sc.Trigger == TriggerNone {
		return nil
	}
	rec := &FireRecord{ScenarioID: sc.ID, DestFilesAtFire: -1}
	freeAtStart, _, _ := FreeBytes(cfg.DestVolume)

	manifestPath := filepath.Join(destDir, MetaDirName, "manifest.tsv")
	target := pin.CumulativeBytes

	// A scenario that fires when the installer STARTS a particular file needs
	// that file to take long enough to notice. The byte pin usually lands in a
	// large one — large files dominate the byte count — but "usually" is how a
	// scenario ends up firing on a 3 KB file that was copied between two polls
	// and reporting that it never fired. So the watched file is the first one at
	// or after the pin that is big enough to be caught in the act, and the
	// record says which it was.
	watch := pin
	if sc.Trigger == TriggerPartial {
		for _, r := range g.ByCopy {
			if r.CopyIndex >= pin.CopyIndex && r.Size >= 4<<20 {
				watch.CopyIndex, watch.Archive, watch.Path = r.CopyIndex, r.Archive, r.Path
				break
			}
		}
		rec.TargetPath, rec.TargetArchive = watch.Path, watch.Archive
	}
	partialPath := filepath.Join(destDir, filepath.FromSlash(watch.Archive)+PartialSuffix)

	var readAtBoundary int64 = -1
	deadline := time.Now().Add(cfg.Timeout)
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()

	for {
		if time.Now().After(deadline) {
			rec.NotFired = "the run reached its timeout before the trigger point"
			return rec
		}
		if done, _ := p.Exited(); done {
			if rec.NotFired == "" {
				rec.NotFired = "the installer ended before the trigger point was reached"
			}
			return rec
		}
		io, err := p.IO()
		if err != nil {
			rec.NotFired = "the job's I/O counters could not be read: " + err.Error()
			return rec
		}

		switch {
		case sc.Trigger == TriggerPartial:
			if _, serr := os.Stat(partialPath); serr == nil {
				rec.ObservedBytes = io.Written
				rec.ObservedNote = "fired when the installer created the partial file for " + watch.Path +
					", which is the instant it started reading it"
				fireNow(p, in, g, sc, watch, destDir, cfg, rec, devs, freeAtStart)
				return rec
			}
		case sc.Phase == PhaseCopy:
			if io.Written >= target {
				rec.ObservedBytes = io.Written
				rec.OvershootBytes = io.Written - target
				fireNow(p, in, g, sc, pin, destDir, cfg, rec, devs, freeAtStart)
				return rec
			}
		case sc.Phase == PhaseVerify:
			if readAtBoundary < 0 {
				if _, serr := os.Stat(manifestPath); serr == nil {
					readAtBoundary = io.Read
				}
				break
			}
			if io.Read-readAtBoundary >= target {
				rec.ObservedBytes = io.Read - readAtBoundary
				rec.OvershootBytes = rec.ObservedBytes - target
				rec.ObservedNote = "verify progress measured as bytes read after the installer wrote its " +
					"manifest, which is the end of the copy"
				fireNow(p, in, g, sc, pin, destDir, cfg, rec, devs, freeAtStart)
				return rec
			}
		}
		<-tick.C
	}
}

// fireNow dispatches the scenario's action. Evidence first: the destination is
// measured before anything is damaged, because four of these scenarios end with
// the installer ceasing to exist.
func fireNow(p *Process, in *Injector, g *Golden, sc *Scenario, pin Pin, destDir string,
	cfg RunConfig, rec *FireRecord, devs *[]Deviation, freeAtStart int64) {
	rec.Fired = true
	if free, _, err := FreeBytes(cfg.DestVolume); err == nil {
		rec.DestBytesAtFire = freeAtStart - free
	}

	fail := func(err error) {
		if err != nil {
			rec.ActionError = err.Error()
		}
	}

	switch sc.Action {
	case ActionKill:
		fail(p.Kill())

	case ActionDismountDestination:
		fail(in.DismountDestination())

	case ActionFillDestination:
		n, err := in.FillDestination(0)
		fail(err)
		free, _, _ := FreeBytes(cfg.DestVolume)
		rec.TargetPath = fmt.Sprintf("«the destination volume»: %d bytes consumed, %d left free", n, free)

	case ActionMutateSource, ActionMutateSourceOnce:
		rec_, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath, rec.TargetArchive = rec_.Path, rec_.Archive
		full := filepath.Join(cfg.CorpusRoot, filepath.FromSlash(rec_.Path))
		var v Variant
		if sc.Action == ActionMutateSourceOnce {
			v, err = MutateFile(full)
		} else {
			stop := make(chan struct{})
			v, err = in.HoldMutating(full, stop, 15*time.Millisecond)
			go func() {
				// Keep rewriting until the installer is done with the file: one
				// save it can retry past is a different test (S01) from a file
				// that will not hold still (F09).
				defer close(stop)
				for i := 0; i < 2000; i++ {
					if done, _ := p.Exited(); done {
						return
					}
					time.Sleep(20 * time.Millisecond)
				}
			}()
		}
		if err != nil {
			fail(err)
			return
		}
		*devs = append(*devs, Deviation{
			Tree: "source", Path: rec_.Path, Kind: "rewritten by the harness",
			Allowed: []Variant{v},
			Note:    "the source's final state, measured by the harness at the moment it wrote it",
		})
		*devs = append(*devs, Deviation{
			Tree: "archive", Path: rec_.Archive, Kind: "copy of a file that changed under the copy",
			MayBeAbsent: true,
			Allowed: []Variant{
				{SHA256: rec_.SHA256, Size: rec_.Size, Note: "the version before the rewrite"},
				{SHA256: v.SHA256, Size: v.Size, Note: "the version after it"},
			},
			Note: "anything else is a torn file: a mixture of two versions that never existed on disk",
		})

	case ActionDeleteSource:
		rec_, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath, rec.TargetArchive = rec_.Path, rec_.Archive
		full := filepath.Join(cfg.CorpusRoot, filepath.FromSlash(rec_.Path))
		if _, serr := os.Stat(filepath.Join(destDir, filepath.FromSlash(rec_.Archive))); serr == nil {
			rec.Fired = false
			rec.NotFired = "the installer had already copied " + rec_.Path + " by the time the trigger fired"
			return
		}
		fail(DeleteFile(full))
		*devs = append(*devs, Deviation{
			Tree: "source", Path: rec_.Path, Kind: "deleted by the harness", Absent: true,
		})
		*devs = append(*devs, Deviation{
			Tree: "archive", Path: rec_.Archive, Kind: "source was deleted before it could be copied",
			Absent: true,
		})

	case ActionLockSource:
		rec_, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath, rec.TargetArchive = rec_.Path, rec_.Archive
		if _, serr := os.Stat(filepath.Join(destDir, filepath.FromSlash(rec_.Archive))); serr == nil {
			rec.Fired = false
			rec.NotFired = "the installer had already copied " + rec_.Path + " by the time the trigger fired"
			return
		}
		fail(in.LockExclusive(filepath.Join(cfg.CorpusRoot, filepath.FromSlash(rec_.Path))))
		*devs = append(*devs, Deviation{
			Tree: "archive", Path: rec_.Archive, Kind: "source was held open by another process",
			Absent: true, Note: "the installer must quarantine it and stop, not skip it",
		})

	case ActionLockArchive:
		rec_, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath, rec.TargetArchive = rec_.Path, rec_.Archive
		fail(in.LockExclusive(filepath.Join(destDir, filepath.FromSlash(rec_.Archive))))

	case ActionBitFlipArchive:
		rec_, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath, rec.TargetArchive = rec_.Path, rec_.Archive
		full := filepath.Join(destDir, filepath.FromSlash(rec_.Archive))
		off, bit := deterministicOffset(sc.ID, rec_.Path, rec_.Size)
		v, err := BitFlip(full, off, bit)
		if err != nil {
			fail(err)
			return
		}
		*devs = append(*devs, Deviation{
			Tree: "archive", Path: rec_.Archive, Kind: "one bit flipped by the harness",
			Allowed: []Variant{v},
		})

	case ActionCorruptArchiveMany:
		start, err := TargetFromPin(g, pin, sc.TargetDeltaBytes)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath = fmt.Sprintf("%d files from %s", sc.Count, start.Path)
		n := 0
		for i := start.CopyIndex; i < len(g.ByCopy) && n < sc.Count; i++ {
			r := g.ByCopy[i]
			if r.Size < 64 {
				continue
			}
			full := filepath.Join(destDir, filepath.FromSlash(r.Archive))
			if _, serr := os.Stat(full); serr != nil {
				continue
			}
			off, bit := deterministicOffset(sc.ID, r.Path, r.Size)
			v, ferr := BitFlip(full, off, bit)
			if ferr != nil {
				continue
			}
			*devs = append(*devs, Deviation{
				Tree: "archive", Path: r.Archive, Kind: "one bit flipped by the harness",
				Allowed: []Variant{v},
			})
			n++
		}
		if n < sc.Count {
			rec.ActionError = fmt.Sprintf("only %d of %d files could be corrupted", n, sc.Count)
		}

	case ActionTruncateManifest, ActionBitFlipManifest:
		man := filepath.Join(destDir, MetaDirName, "manifest.tsv")
		st, serr := os.Stat(man)
		if serr != nil {
			rec.Fired = false
			rec.NotFired = "the installer has not written its manifest yet: " + serr.Error()
			return
		}
		rec.TargetPath = man
		if sc.Action == ActionTruncateManifest {
			keep := st.Size() * int64(sc.KeepBP) / 10000
			_, err := TruncateTo(man, keep)
			fail(err)
		} else {
			off, bit := deterministicOffset(sc.ID, "manifest.tsv", st.Size())
			_, err := BitFlip(man, off, bit)
			fail(err)
		}

	case ActionPlantExtra:
		relative := "Documents/a-file-the-manifest-does-not-know-about.bin"
		full := filepath.Join(destDir, filepath.FromSlash(relative))
		v, err := PlantFile(full)
		if err != nil {
			fail(err)
			return
		}
		rec.TargetPath = relative
		*devs = append(*devs, Deviation{
			Tree: "archive", Path: relative, Kind: "planted by the harness", Allowed: []Variant{v},
		})

	case ActionClockBackwards:
		rec.TargetPath = "«the system clock»"
		fail(in.MoveClockBack(sc.Seconds))

	default:
		rec.ActionError = "no implementation for action " + string(sc.Action)
	}
}

// waitForVolume gives a dismounted volume a moment to come back so the archive
// can still be measured. NTFS remounts on the next open; if it does not, the
// archive check reports what it found, which is nothing, and that is a
// measurement too.
func waitForVolume(dir string) {
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(dir); err == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func chosenDestination(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.Index(line, "destination :"); i >= 0 {
			return strings.TrimSpace(line[i+len("destination :"):])
		}
	}
	return ""
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// fidelityFindings are measurements that are not part of the §6C exit condition
// and must not be lost in it either.
func fidelityFindings(g *Golden, res *Result) []string {
	var out []string
	if res.Claims != nil && res.Claims.Events > 0 && !res.Claims.SawPhaseEvents {
		out = append(out, "the run log on the destination carries no phase transitions, no abort reason "+
			"and no wall record: cmd/auros-migrate builds the state machine with a nil logger, so "+
			"SAFETY.md rule 5's post-mortem is missing the entries a post-mortem is for")
	}
	if n := g.Placeholders(); n > 0 {
		out = append(out, fmt.Sprintf("%d files carried FILE_ATTRIBUTE_OFFLINE (OneDrive placeholders, "+
			"attribute-only fidelity) and the run was given --cloud-files=hydrate", n))
	}
	if files, streams := g.StreamFiles(); files > 0 && res.Archive != nil && res.Archive.Present > 0 {
		out = append(out, fmt.Sprintf("%d source files carry %d alternate data streams; the installer "+
			"copies the main stream only, and does not report the streams it leaves behind",
			files, streams))
	}
	return out
}

// FormatDestination wipes the destination volume so every run starts with a
// genuinely empty one.
//
// Without it, run 7 is measured against whatever runs 1 to 6 left behind, and
// "100 consecutive runs" is decoration — the same argument the VM harness makes
// for its frozen base images.
func FormatDestination(volume string) error {
	letter := trimVolume(volume)
	if strings.EqualFold(letter, "C:") || strings.EqualFold(letter, strings.TrimSuffix(os.Getenv("SystemDrive"), `\`)) {
		return fmt.Errorf("gate3: refusing to format %s: that is the system volume", letter)
	}
	// Format-Volume rather than `format`: on a fixed disk, format.com asks the
	// operator to type the current volume label back as a confirmation, and a
	// process with no console input waits for that forever.
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
		fmt.Sprintf("Format-Volume -DriveLetter %s -FileSystem NTFS -NewFileSystemLabel AUROSDEST "+
			"-Force -Confirm:$false | Out-Null; exit $LASTEXITCODE", strings.TrimSuffix(letter, ":"))).CombinedOutput()
	if err != nil {
		return fmt.Errorf("gate3: formatting %s: %v: %s", letter, err, strings.TrimSpace(string(out)))
	}
	return nil
}
