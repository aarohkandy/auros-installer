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
	"syscall"
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

// cmdProveRed is DECISIONS.md D34 applied to C1, the one check that cannot be
// exercised anywhere but here.
//
// This process stands in for the installer's tree. Under the same ETW trace a
// run uses, it opens a C: file read-only, writes a file to C: outside any
// exemption, tries to write into a directory carrying the same deny ACE a run
// puts on C:\ (applied by the same code, to a directory rather than the whole
// volume), and writes into a directory declared exempt. Each must land in its
// own bucket, and C1 must go red. A check nobody has watched fail is a check
// nobody knows works.
func cmdProveRed(args []string) error {
	fs := flag.NewFlagSet("prove-red", flag.ExitOnError)
	work := fs.String("work", "", "a working directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	if *work == "" {
		*work = os.TempDir()
	}
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	u, err := tok.GetTokenUser()
	tok.Close()
	if err != nil {
		return err
	}
	sid, err := u.User.Sid.String()
	if err != nil {
		return err
	}

	root := `C:\auros-gate3-prove-red`
	denied, exempt := filepath.Join(root, "denied"), filepath.Join(root, "exempt")
	os.RemoveAll(root)
	for _, d := range []string{denied, exempt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	defer os.RemoveAll(root)
	ace, err := gate3.ApplyDeny(denied, sid)
	if err != nil {
		return err
	}
	defer func() {
		if err := gate3.RemoveDeny(denied, sid); err != nil {
			fmt.Printf("gate3: %v\n", err)
		}
	}()
	fmt.Printf("deny ACE on %s: %s\n", denied, ace)

	trace, err := gate3.StartTrace(filepath.Join(*work, "gate3-prove-red-etw"))
	if err != nil {
		return err
	}
	defer trace.Stop()

	hosts := filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")
	if _, err := os.ReadFile(hosts); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "written.tmp"), []byte("a tool wrote this to C:\n"), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(denied, "blocked.tmp"), []byte("x"), 0o644); err == nil {
		return fmt.Errorf("the deny ACE %s did not stop a write into %s", ace, denied)
	} else {
		fmt.Printf("the deny ACE refused the write, as it must: %v\n", err)
	}
	if err := os.WriteFile(filepath.Join(exempt, "allowed.tmp"), []byte("x"), 0o644); err != nil {
		return err
	}
	time.Sleep(2 * time.Second)

	attr := trace.Attribute([]uint32{uint32(os.Getpid())})
	fmt.Printf("trace events: %v\n", attr.Events)
	for id, fields := range attr.Schema {
		fmt.Printf("schema Kernel-File/%s: %s\n", id, fields)
	}
	w := attr.AuditWrites([]string{exempt})
	for _, l := range w.Writes {
		fmt.Printf("   WROTE  %s\n", l)
	}
	for _, l := range w.Denied {
		fmt.Printf("   DENIED %s\n", l)
	}
	for _, l := range w.Exempt {
		fmt.Printf("   exempt %s\n", l)
	}
	if w.Error != "" {
		return fmt.Errorf("the trace could not vouch for the window, so every run would fail closed: %s", w.Error)
	}
	in := func(bucket []string, name string) bool {
		for _, l := range bucket {
			if strings.Contains(strings.ToLower(l), name) {
				return true
			}
		}
		return false
	}
	for _, c := range []struct {
		ok   bool
		what string
	}{
		{in(w.Writes, `prove-red\written.tmp`), "the write to C: outside the exemptions is not under writes"},
		{in(w.Denied, `denied\blocked.tmp`), "the write the deny ACE refused is not under denied attempts"},
		{in(w.Exempt, `exempt\allowed.tmp`), "the write into the exemption is not under exempt writes"},
		{!in(w.Writes, `exempt\`) && !in(w.Denied, `exempt\`), "a write into the exemption was counted against the run"},
		{!in(w.Writes, `blocked.tmp`) && !in(w.Exempt, `blocked.tmp`), "the refused write landed in the wrong bucket"},
		{!in(append(append(w.Writes, w.Denied...), w.Exempt...), `\hosts`), "a read-only open of " + hosts + " was counted as a write"},
	} {
		if !c.ok {
			return fmt.Errorf("C1's classification is wrong on a real trace: %s", c.what)
		}
	}
	enf := &gate3.Enforcement{Path: denied, SID: sid, ACE: ace, Applied: true, Verified: true, Exemptions: []string{exempt}}
	ok, detail := gate3.SystemDiskVerdict(enf, w)
	fmt.Printf("C1 on this window: ok=%v: %s\n", ok, detail)
	if ok {
		return fmt.Errorf("C1 PASSED a window in which C: was written to: it is decoration, not a check")
	}
	fmt.Println("C1 goes red on a write to C: and on a refused attempt, and does not count reads or the exemption")
	return nil
}
