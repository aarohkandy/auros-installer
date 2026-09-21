//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aarohkandy/auros-installer/testharness/fault"
	"github.com/aarohkandy/auros-installer/testharness/gate3"
)

// ─────────────────────────────────────────────────────────────────────────────
// SPEC §4.7 ON A HOSTED RUNNER
//
// "Never tested against the operator's own machine." The VM harness enforces
// that with a token naming the volume serial of a disk the runner created. The
// same guard applies here and has to, because this program creates a local
// account, redirects its known folders, formats a volume, moves the system clock
// and writes a corpus into C:\. On a laptop that is a bad afternoon.
//
// So it refuses twice: the machine must say it is an ephemeral GitHub-hosted
// runner, AND a token minted on THIS machine must vouch for the exact volume
// serials in play. Minting the token is itself refused off a hosted runner, so
// there is no path that starts on somebody's desk.
// ─────────────────────────────────────────────────────────────────────────────

func assertDisposable() error {
	if os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return fmt.Errorf("REFUSING: this machine does not identify itself as an ephemeral GitHub-hosted " +
			"runner (RUNNER_ENVIRONMENT is not \"github-hosted\"). This harness creates accounts, formats " +
			"volumes and moves the system clock; spec §4.7 says it is never pointed at a machine anybody " +
			"cares about")
	}
	if os.Getenv("GITHUB_RUN_ID") == "" {
		return fmt.Errorf("REFUSING: no GITHUB_RUN_ID: this is not a workflow run")
	}
	return nil
}

func cmdMintToken(args []string) error {
	fs := flag.NewFlagSet("mint-token", flag.ExitOnError)
	corpus := fs.String("corpus", "", "the corpus root, e.g. C:\\gate3\\corpus")
	dest := fs.String("dest-volume", "", "the destination volume root, e.g. E:\\")
	out := fs.String("out", "", "where to write the token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpus == "" || *dest == "" || *out == "" {
		return fmt.Errorf("-corpus, -dest-volume and -out are required")
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	if err := os.MkdirAll(*corpus, 0o755); err != nil {
		return err
	}
	corpusSerial, err := fault.VolumeSerial(*corpus)
	if err != nil {
		return err
	}
	destSerial, err := fault.VolumeSerial(*dest)
	if err != nil {
		return err
	}
	if strings.EqualFold(corpusSerial, destSerial) {
		return fmt.Errorf("REFUSING: the corpus and the destination are the same volume; a harness that "+
			"blurs those two cannot show that the installer keeps them apart (%s)", corpusSerial)
	}
	tok := fault.Token{
		Harness:                gate3.HarnessVersion,
		SuiteID:                os.Getenv("GITHUB_RUN_ID") + "-" + os.Getenv("GITHUB_RUN_ATTEMPT"),
		RunID:                  os.Getenv("GITHUB_JOB"),
		TargetVolSerial:        corpusSerial,
		DestVolSerial:          destSerial,
		DestroysEverythingHere: true,
		Note: "minted on an ephemeral GitHub-hosted Windows runner, which is destroyed when the job " +
			"ends. RUNNER_ENVIRONMENT=" + os.Getenv("RUNNER_ENVIRONMENT") + " image=" + os.Getenv("ImageVersion"),
	}
	b, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("token vouches for corpus volume %s and destination volume %s\n", corpusSerial, destSerial)
	return nil
}

func cmdPrepare(args []string) error {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	corpus := fs.String("corpus", "", "the corpus root")
	work := fs.String("work", "", "the harness's own working directory (NOT on the system disk)")
	pwFile := fs.String("password-file", "", "where to keep the migration account's password for this job")
	user := fs.String("user", gate3.MigrationUser, "the migration account")
	journalMB := fs.Int("journal-mb", 512, "grow C:'s change journal to this many megabytes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpus == "" || *work == "" || *pwFile == "" {
		return fmt.Errorf("-corpus, -work and -password-file are required")
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	if err := gate3.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(*work, 0o755); err != nil {
		return err
	}

	// Quiet the machine before anything is measured: every background writer
	// stopped here is one the change-journal noise list does not have to
	// forgive. What it did is printed in full.
	fmt.Println("quiescing the machine's own background software:")
	for _, line := range gate3.Quiesce() {
		fmt.Println("  " + line)
	}

	// A bigger change journal so that a busy run cannot wrap it. A wrap is
	// detected and fails the check; it is removed as a variable anyway, because
	// a check that fails for capacity reasons is a check people learn to ignore.
	if err := gate3.EnlargeJournal("C:", uint64(*journalMB)<<20, 64<<20); err != nil {
		return fmt.Errorf("growing the change journal: %w", err)
	}

	pw, err := gate3.NewPassword()
	if err != nil {
		return err
	}
	if err := gate3.CreateMigrationUser(*user, pw); err != nil {
		return err
	}
	if err := os.WriteFile(*pwFile, []byte(pw), 0o600); err != nil {
		return err
	}
	if err := gate3.GrantFullControl(*work, *user); err != nil {
		return err
	}

	sess, err := gate3.LogonMigrationUser(*user, pw)
	if err != nil {
		return err
	}
	// The profile stays loaded for the whole job, on purpose: see
	// UserSession.KeepProfileLoaded. It is what keeps the account's registry
	// hive out of the folders the installer is about to inventory.
	sess.KeepProfileLoaded()
	defer sess.Close()
	folders, err := gate3.RedirectKnownFolders(sess, *corpus)
	if err != nil {
		return err
	}
	env, werr := gate3.WarmProfile(sess, *work, *corpus)
	fmt.Printf("migration account %s ready (elevated token: %v, SID %s)\n", *user, sess.Elevated, sess.SID)
	fmt.Println("known folders redirected to the corpus:")
	keys := make([]string, 0, len(folders))
	for k := range folders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-40s %s\n", k, folders[k])
	}
	if env != nil {
		fmt.Println("what that account's own environment says:")
		for _, k := range []string{"USERPROFILE", "APPDATA", "LOCALAPPDATA", "TEMP"} {
			fmt.Printf("  %-40s %s\n", "%"+k+"%", env[k])
		}
	}
	if werr != nil {
		return werr
	}
	fmt.Println("\nthe installer will inventory THESE folders, because it asks Windows where they are " +
		"(SHGetKnownFolderPath) rather than assuming the user profile directory. If it ever stopped " +
		"doing that, every run would come up empty and check C9 would say so.")
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	scenario := fs.String("scenario", "", "scenario id, or empty for a clean run")
	runID := fs.String("run-id", "", "an id for this run")
	golden := fs.String("golden", "", "golden-manifest.jsonl")
	corpus := fs.String("corpus", "", "the corpus root")
	tool := fs.String("tool", "", "auros-migrate.exe")
	destVol := fs.String("dest-volume", "", `the destination volume root, e.g. E:\`)
	destName := fs.String("dest-name", "auros-archive", "the directory on it the installer is told to use")
	smallVol := fs.String("small-volume", "", `a deliberately tiny volume, e.g. F:\`)
	work := fs.String("work", "", "the harness's working directory")
	pwFile := fs.String("password-file", "", "the migration account's password for this job")
	user := fs.String("user", gate3.MigrationUser, "the migration account")
	out := fs.String("out", "", "where to write this run's result JSON")
	timeout := fs.Duration("timeout", 45*time.Minute, "how long the installer gets before it is killed")
	profile := fs.String("profile", "realistic", "the corpus profile, for the record")
	seed := fs.Uint64("seed", 0, "the corpus seed, for the record")
	noFormat := fs.Bool("no-format", false, "do not wipe the destination volume first (for debugging only)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{"-golden": *golden, "-corpus": *corpus, "-tool": *tool,
		"-dest-volume": *destVol, "-work": *work, "-password-file": *pwFile, "-out": *out} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	pw, err := os.ReadFile(*pwFile)
	if err != nil {
		return err
	}
	var sc *gate3.Scenario
	if *scenario != "" {
		s, lerr := gate3.Lookup(*scenario)
		if lerr != nil {
			return lerr
		}
		sc = &s
	}
	id := *runID
	if id == "" {
		id = "clean"
		if sc != nil {
			id = sc.ID
		}
	}
	if hive := gate3.HiveInCorpus(*corpus); len(hive) > 0 {
		return fmt.Errorf("REFUSING TO RUN: the migration account's registry hive is inside the corpus "+
			"(%s). The installer would quarantine it and stop, and this run would be filed under a "+
			"scenario it never reached", strings.Join(hive, ", "))
	}
	if !*noFormat {
		if err := gate3.FormatDestination(*destVol); err != nil {
			return err
		}
	}
	cfg := gate3.RunConfig{
		Scenario: sc, RunID: id,
		CorpusRoot: *corpus, GoldenPath: *golden, Tool: *tool,
		DestVolume: *destVol, DestDirName: *destName, SmallVolume: *smallVol,
		User: *user, Password: strings.TrimSpace(string(pw)),
		WorkDir: filepath.Join(*work, id), Timeout: *timeout,
		Profile: *profile, Seed: *seed, Faithful: true,
		Image: os.Getenv("ImageOS") + " " + os.Getenv("ImageVersion"),
	}
	res, err := gate3.RunOnce(cfg)
	if err != nil {
		return err
	}
	required := gate3.RequiredChecks(res.Kind, sc)
	fmt.Print(res.Summary(required))
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		return err
	}
	if err := res.Write(*out); err != nil {
		return err
	}
	verdict, reasons := res.Recompute(required)
	if verdict != gate3.Pass {
		return fmt.Errorf("run %s FAILED: %s", id, strings.Join(reasons, "; "))
	}
	return nil
}

// errSuffix makes a report's own error visible. Without it, a window that
// failed closed — a journal recreated underneath it, a read that errored —
// prints as "0 records" and reads like a quiet machine.
func errSuffix(r *gate3.SystemDiskReport) string {
	if r == nil || r.Error == "" {
		return ""
	}
	return "\n   the window could not be accounted for: " + r.Error
}

func cmdFormatDestination(args []string) error {
	fs := flag.NewFlagSet("format-destination", flag.ExitOnError)
	vol := fs.String("volume", "", `the volume to wipe, e.g. E:\`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *vol == "" {
		return fmt.Errorf("-volume is required")
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	return gate3.FormatDestination(*vol)
}

// cmdProveRed is DECISIONS.md D34 applied to the one check that cannot be
// exercised anywhere but here: the change-journal measurement of the system
// disk.
//
// It writes one small file to C:, inside a marked window, and requires the check
// to report it. A check nobody has watched fail is a check nobody knows works,
// and this one is the whole of D27.
func cmdProveRed(args []string) error {
	fs := flag.NewFlagSet("prove-red", flag.ExitOnError)
	work := fs.String("work", "", "a working directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	_ = work

	// The journal is resized here rather than by the workflow, because resizing
	// recreates it and the harness has to wait for that to settle before it
	// marks anything.
	if err := gate3.EnlargeJournal("C:", 512<<20, 64<<20); err != nil {
		return err
	}

	// 1. A window in which nothing of ours touches C: must come back clean.
	quiet, err := gate3.MarkUSN("C:")
	if err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	quietRep, err := gate3.DiffUSN(quiet, nil)
	if err != nil {
		return err
	}
	fmt.Printf("idle window: %d records, %d excused as noise, %d unexplained (journal %d, USN %d..%d)%s\n",
		quietRep.Records, quietRep.Excluded, len(quietRep.Unexplained),
		quietRep.JournalID, quietRep.StartUSN, quietRep.EndUSN, errSuffix(quietRep))
	for _, u := range quietRep.Unexplained {
		fmt.Printf("   ! %s\n", u)
	}

	// 2. A window in which something DOES touch C: must come back red. The file
	//    is written where a migration tool would plausibly put scratch state,
	//    and it is deleted again immediately — a name-and-size snapshot would
	//    not have seen it at all.
	mark, err := gate3.MarkUSN("C:")
	if err != nil {
		return err
	}
	probe := `C:\auros-gate3-prove-red.tmp`
	if err := os.WriteFile(probe, []byte("a tool wrote this to the system disk\n"), 0o644); err != nil {
		return err
	}
	if err := os.Remove(probe); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)
	rep, err := gate3.DiffUSN(mark, nil)
	if err != nil {
		return err
	}
	found := false
	for _, u := range rep.Unexplained {
		if strings.Contains(strings.ToLower(u), "auros-gate3-prove-red.tmp") {
			found = true
			fmt.Printf("the system-disk check reported it: %s\n", u)
		}
	}
	if !found {
		return fmt.Errorf("THE SYSTEM-DISK CHECK DID NOT NOTICE a file created and deleted on C: "+
			"during its window. It is decoration, not a check. (%d records, %d unexplained, "+
			"journal %d, USN %d..%d)%s",
			rep.Records, len(rep.Unexplained), rep.JournalID, rep.StartUSN, rep.EndUSN, errSuffix(rep))
	}
	if quietRep.Records == 0 {
		return fmt.Errorf("the idle window saw no change-journal records at all, which means the journal " +
			"is not being read: a check that sees nothing passes everything")
	}
	fmt.Println("the system-disk check goes red when the system disk is written to, and green when it is not")
	return nil
}
