// Command runner executes the §6C suite: 100 consecutive clean migrations and 20 induced-failure runs
// against a throwaway Windows VM, and produces the per-run evidence REPORT.md is assembled from.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// WHAT A RUN IS
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
//	 1. verify the immutable base images still hash to what base-image.json says   ← before AND after
//	 2. create a fresh qcow2 overlay for the system disk and for the destination
//	 3. build the marker volume: harness token, golden manifest, guest binaries, run script
//	 4. boot; the base image's startup task runs X:\run.cmd
//	 5. the guest holds the locked files open, starts the fault agent, runs the installer
//	 6. for a host-site fault the guest asks the runner over the serial line and the runner acts
//	 7. the guest reports the installer's exit code and powers off — or the runner kills it
//	 8. BOOT CHECK: boot the same overlay with NOTHING of ours attached and prove Windows comes back
//	 9. VERIFY BOOT: re-attach and re-hash all 18,000 source files against the golden manifest
//	10. write result.json, hash every artefact, delete the overlays
//
// Steps 8 and 9 are the slow ones and step 8 is the one spec §6C actually names. Neither can be turned
// off; see bootcheck.go for how that is enforced rather than requested.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────────
// BIG HOST / SMALL HOST
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// BLOCKED.md B1 is unresolved: there is no confirmed host with 100 GB free. So the runner does not
// assume one. `host.parallel` is the only difference between a machine that can hold several VMs and a
// machine that can hold one, and `host.reclaim_between_runs` deletes each run's overlays the moment its
// result is written rather than at the end of the suite. On the small path the working set is one
// overlay plus one destination at a time; on the big path it is `parallel` of each. The evidence is
// identical either way, and the run result records which path produced it.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

const runnerVersion = "testharness/0.1.0"

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type QemuCfg struct {
	Binary string `json:"binary"`
	Img    string `json:"img"`
	Accel  string `json:"accel"`
}

// BaseCfg describes the two images that are built ONCE and then never written to again, and the corpus
// that was baked into the first of them at build time.
//
// The corpus lives in the base image rather than being generated per run. Eighteen thousand files is
// eight gigabytes of writing, and doing it 120 times would add a day to the suite for no evidence: the
// corpus is deterministic, so every run would produce the same one. Baking it in also means the base
// image's SHA-256 covers the corpus, which is a stronger statement than "we generated it again and it
// hashed the same".
type BaseCfg struct {
	SystemImage        string `json:"system_image"`
	SystemSHA256       string `json:"system_sha256"`
	SystemVolumeSerial string `json:"system_volume_serial"`
	DestImage          string `json:"dest_image"`
	DestSHA256         string `json:"dest_sha256"`
	DestVolumeSerial   string `json:"dest_volume_serial"`

	CorpusSeed    uint64 `json:"corpus_seed"`
	CorpusProfile string `json:"corpus_profile"`
	CorpusCount   int    `json:"corpus_count"`
	CorpusDigest  string `json:"corpus_digest"`
	CorpusFaithful bool  `json:"corpus_faithful"`

	// SystemStateSHA256 is the pristine value of the boot-critical region, captured at base build time.
	// Every aborted run must still report this exact value.
	SystemStateSHA256 string `json:"system_state_sha256"`

	WindowsEdition string `json:"windows_edition"`
	ISOSource      string `json:"iso_source"`
}

type MachineCfg struct {
	MemoryMB int `json:"memory_mb"`
	CPUs     int `json:"cpus"`
	Headless bool `json:"headless"`
}

type HostCfg struct {
	WorkDir            string `json:"work_dir"`
	ArtifactDir        string `json:"artifact_dir"`
	Parallel           int    `json:"parallel"`
	MinFreeGB          int    `json:"min_free_gb"`
	ReclaimBetweenRuns bool   `json:"reclaim_between_runs"`
	KeepOverlayOnFail  bool   `json:"keep_overlay_on_fail"`
}

type GuestCfg struct {
	CorpusRoot        string `json:"corpus_root"`
	DestVolume        string `json:"dest_volume"`
	DestDataRoot      string `json:"dest_data_root"`
	ProgressPath      string `json:"progress_path"`
	InstallerManifest string `json:"installer_manifest"`
	MarkerDrive       string `json:"marker_drive"`
}

type BinariesCfg struct {
	Installer      string `json:"installer_exe"`
	FaultAgent     string `json:"faultagent_exe"`
	Gen            string `json:"gen_exe"`
	GoldenManifest string `json:"golden_manifest"`
	GoldenMeta     string `json:"golden_meta"`
	CorpusPlan     string `json:"corpus_plan"`
}

type TimeoutsCfg struct {
	RunSec            int     `json:"run_sec"`
	BootCheckSec      int     `json:"boot_check_sec"`
	VerifySec         int     `json:"verify_sec"`
	NormalBootSeconds float64 `json:"normal_boot_seconds"`
}

type MtoolsCfg struct {
	MkfsVfat string `json:"mkfs_vfat"`
	Mcopy    string `json:"mcopy"`
	SizeMB   int    `json:"marker_size_mb"`
}

type Config struct {
	Comment  string      `json:"$comment"`
	Qemu     QemuCfg     `json:"qemu"`
	Base     BaseCfg     `json:"base"`
	Machine  MachineCfg  `json:"machine"`
	Host     HostCfg     `json:"host"`
	Guest    GuestCfg    `json:"guest"`
	Binaries BinariesCfg `json:"binaries"`
	Timeouts TimeoutsCfg `json:"timeouts"`
	Mtools   MtoolsCfg   `json:"mtools"`

	// InstallerArgs is the command line the guest runs. %DEST% and %PROGRESS% are substituted.
	InstallerArgs []string `json:"installer_args"`

	// InstallerScope states, in words that end up in REPORT.md, which of SAFETY.md's seven phases the
	// clean suite actually exercises. It is a required field because the alternative is a report that
	// says "100 successful migrations" while the runs stopped at phase 5.
	InstallerScope string `json:"installer_scope"`
}

func loadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.InstallerScope == "" {
		return nil, errors.New("installer_scope is required: a report that does not say which phases " +
			"were exercised is a report that implies all of them")
	}
	if c.Host.Parallel < 1 {
		c.Host.Parallel = 1
	}
	if c.Timeouts.NormalBootSeconds <= 0 {
		c.Timeouts.NormalBootSeconds = 180
	}
	return &c, nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// RESULT
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type Check struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail. There is no "skip": see result.schema.json.
	Detail string `json:"detail,omitempty"`
}

type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type InstallerOutcome struct {
	ExitCode     int    `json:"exit_code"`
	ExitReported bool   `json:"exit_reported"`
	Killed       bool   `json:"killed_by_harness"`
	PhaseReached string `json:"phase_reached,omitempty"`
}

type CorpusVerify struct {
	Expected     int      `json:"expected_files"`
	Present      int      `json:"present_files"`
	HashMatches  int      `json:"hash_matches"`
	Missing      []string `json:"missing,omitempty"`
	Corrupt      []string `json:"corrupt,omitempty"`
	AllowedDev   []string `json:"allowed_deviations,omitempty"`
	Clean        bool     `json:"clean"`
	Reported     bool     `json:"reported"`
}

type RunResult struct {
	Harness  string `json:"harness"`
	SuiteID  string `json:"suite_id"`
	RunID    string `json:"run_id"`
	Kind     string `json:"kind"` // clean | fault
	Ordinal  int    `json:"ordinal"`
	Scenario string `json:"scenario_id,omitempty"`

	HostProfile string `json:"host_profile"` // "parallel=N reclaim=…" — the B1 path this ran on

	BaseSystemSHA string `json:"base_system_sha256"`
	BaseDestSHA   string `json:"base_dest_sha256"`
	CorpusDigest  string `json:"corpus_digest"`
	CorpusProfile string `json:"corpus_profile"`
	CorpusSeed    uint64 `json:"corpus_seed"`
	CorpusFiles   int    `json:"corpus_files"`

	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	DurationMS int64  `json:"duration_ms"`

	Pin  *fault.Pin        `json:"pin,omitempty"`
	Fire *fault.FireRecord `json:"fire,omitempty"`

	Installer InstallerOutcome `json:"installer"`
	Corpus    CorpusVerify     `json:"corpus_verify"`
	BootCheck *BootCheck       `json:"boot_check"`

	Checks    []Check    `json:"checks"`
	Artifacts []Artifact `json:"artifacts"`

	// Verdict is a convenience for humans. `runner report` RECOMPUTES it from Checks and ignores this
	// field, because a field that says "pass" is exactly what a broken harness would write.
	Verdict string `json:"verdict"`

	Notes []string `json:"notes,omitempty"`
}

func (r *RunResult) check(id, name string, ok bool, detail string) {
	st := "fail"
	if ok {
		st = "pass"
	}
	r.Checks = append(r.Checks, Check{ID: id, Name: name, Status: st, Detail: detail})
}

// Recompute derives the verdict from the checks. Every check must pass.
func (r *RunResult) Recompute() string {
	if len(r.Checks) == 0 {
		return "fail"
	}
	for _, c := range r.Checks {
		if c.Status != "pass" {
			return "fail"
		}
	}
	return "pass"
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// CONTROL CHANNEL
//
// One serial line carries five kinds of traffic. The runner multiplexes a single reader over it rather
// than having each consumer wait for its own message, because a helper that blocks until it sees a
// "fire" line throws away the fire RECORD that arrived immediately before it — and the record is the
// only evidence that survives a power cut.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

type control struct {
	mu       sync.Mutex
	log      *os.File
	fire     chan fault.HostFire
	fireOnce sync.Once

	record   *fault.FireRecord
	exitCode int
	exitSeen bool
	beacons  []string
}

func newControl(logPath string) (*control, error) {
	f, err := os.Create(logPath)
	if err != nil {
		return nil, err
	}
	return &control{log: f, fire: make(chan fault.HostFire, 1)}, nil
}

func (c *control) pump(conn net.Conn) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		line := sc.Text()
		fmt.Fprintln(c.log, line)
		cl := fault.ParseControlLine(line)
		c.mu.Lock()
		switch cl.Kind {
		case fault.CtlRecord:
			rec := cl.Record
			c.record = &rec
		case fault.CtlExit:
			c.exitCode, c.exitSeen = cl.Exit, true
		case fault.CtlBeacon:
			c.beacons = append(c.beacons, cl.Text)
		case fault.CtlFire:
			f := cl.Fire
			c.fireOnce.Do(func() { c.fire <- f })
		}
		c.mu.Unlock()
	}
}

func (c *control) snapshot() (*fault.FireRecord, int, bool, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.record, c.exitCode, c.exitSeen, append([]string(nil), c.beacons...)
}

func (c *control) Close() { c.log.Close() }

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "doctor":
		err = cmdDoctor(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "report":
		err = cmdReport(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "runner: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `runner — the §6C suite

  runner plan   -config F [-manifest F]   resolve every scenario's pin. No VM, no QEMU, no Windows:
                                          this is the part you can run on a laptop, and it is how you
                                          check a trigger point before spending an hour on a VM.
  runner doctor -config F                 check the host can actually run the suite before it starts.
  runner run    -config F -suite clean|faults|all [-n 100] [-scenario F02] [-from N] [-to N]
  runner report -config F -results DIR -template REPORT.md -out REPORT.filled.md
`)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// plan — the part that needs nothing
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	cfgPath := fs.String("config", "runner.config.json", "")
	manOverride := fs.String("manifest", "", "golden-manifest.jsonl (default: from config)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := fault.Validate(); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	manPath := cfg.Binaries.GoldenManifest
	if *manOverride != "" {
		manPath = *manOverride
	}
	entries, digest, err := fault.LoadManifest(manPath)
	if err != nil {
		return err
	}
	if cfg.Base.CorpusDigest != "" && cfg.Base.CorpusDigest != digest {
		return fmt.Errorf("the golden manifest hashes to %s but base-image says the corpus baked into the "+
			"base image is %s. Every pin below would be computed against a corpus the VM does not have",
			digest, cfg.Base.CorpusDigest)
	}
	total := fault.TotalBytes(entries)
	fmt.Printf("corpus: %d files, %d bytes, digest %s\n", len(entries), total, digest)
	fmt.Printf("scope:  %s\n\n", cfg.InstallerScope)
	fmt.Println(fault.Describe())
	fmt.Println("resolved pins (pure arithmetic over the manifest — identical on every machine, forever):")
	for _, sc := range fault.StandardSuite() {
		pin, err := fault.ResolvePin(entries, sc.Trigger)
		if err != nil {
			return fmt.Errorf("%s: %w", sc.ID, err)
		}
		fmt.Printf("  %-4s %-14s %s\n", sc.ID, sc.Trigger.String(), pin.String())
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// doctor — refuse to start a suite that cannot finish
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgPath := fs.String("config", "runner.config.json", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	var problems []string
	note := func(ok bool, msg string) {
		mark := "ok  "
		if !ok {
			mark = "FAIL"
			problems = append(problems, msg)
		}
		fmt.Printf("  [%s] %s\n", mark, msg)
	}

	fmt.Println("catalogue")
	note(fault.Validate() == nil, "the 20-scenario catalogue validates")

	fmt.Println("binaries")
	for _, p := range []string{cfg.Qemu.Binary, cfg.Qemu.Img, cfg.Mtools.MkfsVfat, cfg.Mtools.Mcopy} {
		_, err := os.Stat(p)
		note(err == nil, "present: "+p)
	}
	for _, p := range []string{cfg.Binaries.Installer, cfg.Binaries.FaultAgent, cfg.Binaries.Gen} {
		_, err := os.Stat(p)
		note(err == nil, "guest binary present: "+p)
	}

	fmt.Println("base images (built once, never written to again)")
	note(AssertBaseUnchanged(cfg.Base.SystemImage, cfg.Base.SystemSHA256) == nil,
		"windows base image hashes to "+cfg.Base.SystemSHA256)
	note(AssertBaseUnchanged(cfg.Base.DestImage, cfg.Base.DestSHA256) == nil,
		"destination base image hashes to "+cfg.Base.DestSHA256)
	note(cfg.Base.CorpusFaithful,
		"the corpus baked into the base image was generated on Windows (faithful=true). An unfaithful "+
			"corpus has no read-only bits, no alternate data streams and no offline attributes, and a "+
			"100/100 against it would be a number that does not mean what the heading says")

	fmt.Println("golden manifest")
	entries, digest, merr := fault.LoadManifest(cfg.Binaries.GoldenManifest)
	note(merr == nil, "golden manifest parses and its copy order is contiguous from zero")
	if merr == nil {
		note(digest == cfg.Base.CorpusDigest,
			fmt.Sprintf("golden manifest digest %s matches the corpus in the base image", digest))
		note(len(entries) == cfg.Base.CorpusCount,
			fmt.Sprintf("golden manifest has %d files (config says %d)", len(entries), cfg.Base.CorpusCount))
	}

	fmt.Println("host")
	note(ReclaimDiskGuard(cfg.Host.WorkDir, cfg.Host.MinFreeGB) == nil,
		fmt.Sprintf("at least %d GB free on %s", cfg.Host.MinFreeGB, cfg.Host.WorkDir))
	fmt.Printf("  [note] host profile: parallel=%d reclaim_between_runs=%v (BLOCKED.md B1)\n",
		cfg.Host.Parallel, cfg.Host.ReclaimBetweenRuns)
	fmt.Printf("  [note] %s\n", PowerCutNote)
	fmt.Printf("  [note] installer scope: %s\n", cfg.InstallerScope)

	if len(problems) > 0 {
		return fmt.Errorf("%d problem(s); the suite will not start", len(problems))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "runner.config.json", "")
	suite := fs.String("suite", "all", "clean | faults | all")
	n := fs.Int("n", 100, "clean runs (spec §6C says 100)")
	scenario := fs.String("scenario", "", "run one scenario, e.g. F02, and nothing else")
	suiteID := fs.String("suite-id", "", "identifier for this suite; defaults to a timestamp")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := fault.Validate(); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if err := cmdDoctorQuiet(cfg); err != nil {
		return err
	}
	sid := *suiteID
	if sid == "" {
		// The only clock reading in the harness that reaches an artefact, and it is a RUN property, not
		// a corpus property. gen/ has none for exactly this reason.
		sid = time.Now().UTC().Format("20060102T150405Z")
	}
	entries, digest, err := fault.LoadManifest(cfg.Binaries.GoldenManifest)
	if err != nil {
		return err
	}

	type job struct {
		kind     string
		ordinal  int
		scenario string
	}
	var jobs []job
	if *scenario != "" {
		sc, err := fault.Lookup(*scenario)
		if err != nil {
			return err
		}
		jobs = append(jobs, job{"fault", 1, sc.ID})
	} else {
		if *suite == "clean" || *suite == "all" {
			for i := 1; i <= *n; i++ {
				jobs = append(jobs, job{"clean", i, ""})
			}
		}
		if *suite == "faults" || *suite == "all" {
			for i, sc := range fault.StandardSuite() {
				jobs = append(jobs, job{"fault", i + 1, sc.ID})
			}
		}
	}

	outDir := filepath.Join(cfg.Host.ArtifactDir, sid)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	fmt.Printf("suite %s: %d runs, host profile parallel=%d reclaim=%v\n",
		sid, len(jobs), cfg.Host.Parallel, cfg.Host.ReclaimBetweenRuns)

	sem := make(chan struct{}, cfg.Host.Parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	passed, failed := 0, 0

	for _, j := range jobs {
		j := j
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := executeRun(cfg, sid, outDir, j.kind, j.ordinal, j.scenario, entries, digest)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				fmt.Printf("  %-18s ERROR %v\n", runLabel(j.kind, j.ordinal, j.scenario), err)
				return
			}
			if res.Recompute() == "pass" {
				passed++
			} else {
				failed++
			}
			fmt.Printf("  %-18s %-4s  %s\n", res.RunID, res.Recompute(), failureSummary(res))
		}()
	}
	wg.Wait()

	fmt.Printf("\nsuite %s: %d passed, %d failed, of %d\n", sid, passed, failed, len(jobs))
	if failed > 0 {
		return fmt.Errorf("%d run(s) failed", failed)
	}
	return nil
}

func cmdDoctorQuiet(cfg *Config) error {
	if err := AssertBaseUnchanged(cfg.Base.SystemImage, cfg.Base.SystemSHA256); err != nil {
		return err
	}
	if err := AssertBaseUnchanged(cfg.Base.DestImage, cfg.Base.DestSHA256); err != nil {
		return err
	}
	if !cfg.Base.CorpusFaithful {
		return errors.New("base.corpus_faithful is false: the corpus in the base image was generated on a " +
			"non-Windows host and has no read-only bits, alternate data streams or offline attributes. " +
			"A suite against it is not the §6C exit condition and must not be published as one")
	}
	return ReclaimDiskGuard(cfg.Host.WorkDir, cfg.Host.MinFreeGB)
}

func runLabel(kind string, ordinal int, scenario string) string {
	if scenario != "" {
		return fmt.Sprintf("%s-%s", kind, scenario)
	}
	return fmt.Sprintf("%s-%04d", kind, ordinal)
}

func failureSummary(r *RunResult) string {
	var bad []string
	for _, c := range r.Checks {
		if c.Status != "pass" {
			bad = append(bad, c.ID)
		}
	}
	if len(bad) == 0 {
		return fmt.Sprintf("%.0fs", float64(r.DurationMS)/1000)
	}
	return "failed: " + strings.Join(bad, ",")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// report — recomputes every verdict rather than trusting one
// ─────────────────────────────────────────────────────────────────────────────────────────────────

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("config", "runner.config.json", "")
	resultsDir := fs.String("results", "", "directory of run result JSON files")
	template := fs.String("template", "REPORT.md", "")
	out := fs.String("out", "REPORT.filled.md", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if *resultsDir == "" {
		return errors.New("-results is required")
	}
	tmpl, err := os.ReadFile(*template)
	if err != nil {
		return err
	}
	var results []*RunResult
	err = filepath.Walk(*resultsDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(p) != "result.json" {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		var r RunResult
		if jerr := json.Unmarshal(b, &r); jerr != nil {
			// A result that does not parse is a FAILED run, never an absent one.
			results = append(results, &RunResult{
				RunID: p, Verdict: "fail",
				Checks: []Check{{ID: "SCHEMA", Name: "result parses", Status: "fail", Detail: jerr.Error()}},
			})
			return nil
		}
		results = append(results, &r)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(results, func(i, j int) bool { return results[i].RunID < results[j].RunID })

	cleanPass, cleanTotal, faultPass, faultTotal := 0, 0, 0, 0
	var cleanRows, faultRows strings.Builder
	for _, r := range results {
		v := r.Recompute() // NOT r.Verdict
		if r.Kind == "fault" {
			faultTotal++
			if v == "pass" {
				faultPass++
			}
			boot := "—"
			if r.BootCheck != nil {
				boot = r.BootCheck.Verdict
			}
			pin := "—"
			if r.Pin != nil {
				pin = fmt.Sprintf("#%d+%d", r.Pin.FileIndex, r.Pin.ByteOffsetInFile)
			}
			over := "—"
			if r.Fire != nil && r.Fire.Fired {
				over = fmt.Sprintf("%d", r.Fire.OvershootBytes)
			}
			fmt.Fprintf(&faultRows, "| %s | %s | %s | %s | %s | %d/%d | %s | %s |\n",
				r.RunID, r.Scenario, pin, over, boot,
				r.Corpus.HashMatches, r.Corpus.Expected, resultDigestShort(r), v)
		} else {
			cleanTotal++
			if v == "pass" {
				cleanPass++
			}
			fmt.Fprintf(&cleanRows, "| %s | %d/%d | %d | %.0fs | %s | %s |\n",
				r.RunID, r.Corpus.HashMatches, r.Corpus.Expected,
				len(r.Corpus.Corrupt), float64(r.DurationMS)/1000, resultDigestShort(r), v)
		}
	}

	s := string(tmpl)
	repl := map[string]string{
		"{{SUITE_ID}}":         firstNonEmpty(results, func(r *RunResult) string { return r.SuiteID }),
		"{{HARNESS_VERSION}}":  runnerVersion,
		"{{CORPUS_DIGEST}}":    cfg.Base.CorpusDigest,
		"{{CORPUS_PROFILE}}":   cfg.Base.CorpusProfile,
		"{{CORPUS_SEED}}":      fmt.Sprintf("%d", cfg.Base.CorpusSeed),
		"{{CORPUS_COUNT}}":     fmt.Sprintf("%d", cfg.Base.CorpusCount),
		"{{BASE_SYSTEM_SHA}}":  cfg.Base.SystemSHA256,
		"{{BASE_DEST_SHA}}":    cfg.Base.DestSHA256,
		"{{WINDOWS_EDITION}}":  cfg.Base.WindowsEdition,
		"{{ISO_SOURCE}}":       cfg.Base.ISOSource,
		"{{INSTALLER_SCOPE}}":  cfg.InstallerScope,
		"{{HOST_PROFILE}}":     fmt.Sprintf("parallel=%d reclaim_between_runs=%v", cfg.Host.Parallel, cfg.Host.ReclaimBetweenRuns),
		"{{POWER_CUT_NOTE}}":   PowerCutNote,
		"{{CLEAN_PASS}}":       fmt.Sprintf("%d", cleanPass),
		"{{CLEAN_TOTAL}}":      fmt.Sprintf("%d", cleanTotal),
		"{{FAULT_PASS}}":       fmt.Sprintf("%d", faultPass),
		"{{FAULT_TOTAL}}":      fmt.Sprintf("%d", faultTotal),
		"{{CLEAN_RUN_ROWS}}":   strings.TrimRight(cleanRows.String(), "\n"),
		"{{FAULT_RUN_ROWS}}":   strings.TrimRight(faultRows.String(), "\n"),
		"{{SCENARIO_TABLE}}":   fault.Describe(),
	}
	for k, v := range repl {
		s = strings.ReplaceAll(s, k, v)
	}
	if strings.Contains(s, "{{") {
		// A published report with an unfilled placeholder is a report with a hole in it where a number
		// should be, and prohibition §4.4 is about exactly that kind of gap being read as a claim.
		return fmt.Errorf("the filled report still contains a {{placeholder}}: refusing to write %s", *out)
	}
	return os.WriteFile(*out, []byte(s), 0o644)
}

func firstNonEmpty(rs []*RunResult, f func(*RunResult) string) string {
	for _, r := range rs {
		if v := f(r); v != "" {
			return v
		}
	}
	return "(none)"
}

func resultDigestShort(r *RunResult) string {
	b, err := json.Marshal(r)
	if err != nil {
		return "(unhashable)"
	}
	sum, err := sha256Bytes(b)
	if err != nil {
		return "(unhashable)"
	}
	return sum[:16]
}
