//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
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
// It starts a copy of itself the way a run starts the installer — at Low
// integrity, through the same launcher, under the same ETW trace — and that
// child reads a C: file, writes into a directory labelled Low that is NOT
// exempt (standing in for something like LocalLow), tries to write into an
// ordinary (Medium) directory, which Windows must refuse, and writes into a
// Low directory declared exempt. Each must land in its own bucket, and C1 must
// go red. A check nobody has watched fail is a check nobody knows works.
func cmdProveRed(args []string) error {
	fs := flag.NewFlagSet("prove-red", flag.ExitOnError)
	work := fs.String("work", "", "a working directory, not on C:")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := assertDisposable(); err != nil {
		return err
	}
	if *work == "" {
		return fmt.Errorf("-work is required")
	}
	root := `C:\auros-gate3-prove-red`
	os.RemoveAll(root)
	defer os.RemoveAll(root)
	for _, d := range []string{"denied", "lowspot", "exempt"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return err
		}
	}
	// Labelled here directly: gate3.LabelLow refuses C:, which is the point of it.
	for _, d := range []string{"lowspot", "exempt"} {
		if out, err := exec.Command("icacls", filepath.Join(root, d), "/setintegritylevel", "(OI)(CI)L").CombinedOutput(); err != nil {
			return fmt.Errorf("labelling %s Low: %v: %s", d, err, out)
		}
	}
	outDir := filepath.Join(*work, "gate3-prove-red-out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := gate3.LabelLow(outDir); err != nil {
		return err
	}
	// syscall.OpenCurrentProcessToken opens with TOKEN_QUERY only, and
	// DuplicateTokenEx needs a source handle opened with TOKEN_DUPLICATE
	// (learn.microsoft.com/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex).
	// Run 35665472869 failed exactly there. The run path duplicates the
	// TOKEN_ALL_ACCESS token launch_windows.go already holds, and works.
	me, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(me, syscall.TOKEN_DUPLICATE|syscall.TOKEN_QUERY, &tok); err != nil {
		return fmt.Errorf("OpenProcessToken(TOKEN_DUPLICATE|TOKEN_QUERY): %w", err)
	}
	low, err := gate3.LowIntegrityToken(syscall.Handle(tok))
	tok.Close()
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(low)
	self, err := os.Executable()
	if err != nil {
		return err
	}

	trace, err := gate3.StartTrace(filepath.Join(*work, "gate3-prove-red-etw"))
	if err != nil {
		return err
	}
	defer trace.Stop()
	outFile := filepath.Join(outDir, "child.txt")
	proc, err := gate3.StartInstaller(&gate3.UserSession{Token: low}, self, []string{"prove-red-child", root},
		outFile, outDir)
	if err != nil {
		return err
	}
	code, timedOut := proc.Wait(2 * time.Minute)
	pid := proc.PID()
	proc.Close()
	time.Sleep(2 * time.Second)
	said, _ := os.ReadFile(outFile)
	fmt.Printf("the Low child said (exit %d):\n%s\n", code, said)
	if timedOut || code != 0 {
		return fmt.Errorf("the Low-integrity child did not behave as a Low process must (exit %d, timed out %v)", code, timedOut)
	}

	exempt := filepath.Join(root, "exempt")
	attr := trace.Attribute([]uint32{pid})
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
	all := append(append(append([]string{}, w.Writes...), w.Denied...), w.Exempt...)
	for _, c := range []struct {
		ok   bool
		what string
	}{
		{in(w.Writes, `lowspot\written.tmp`), "the write to C: outside the exemptions is not under writes"},
		{in(w.Denied, `denied\blocked.tmp`), "the write Windows refused is not under denied attempts"},
		{in(w.Exempt, `exempt\allowed.tmp`), "the write into the exemption is not under exempt writes"},
		{!in(w.Writes, `exempt\`) && !in(w.Denied, `exempt\`), "a write into the exemption was counted against the run"},
		{!in(w.Writes, `blocked.tmp`) && !in(w.Exempt, `blocked.tmp`), "the refused write landed in the wrong bucket"},
		{!in(all, `\hosts`), "a read-only open of the hosts file was counted as a write"},
	} {
		if !c.ok {
			return fmt.Errorf("C1's classification is wrong on a real trace: %s", c.what)
		}
	}
	enf := &gate3.Enforcement{Mechanism: "prove-red", Integrity: gate3.LowIntegritySID, Verified: true,
		Exemptions: []string{exempt}}
	ok, detail := gate3.SystemDiskVerdict(enf, w)
	fmt.Printf("C1 on this window: ok=%v: %s\n", ok, detail)
	if ok {
		return fmt.Errorf("C1 PASSED a window in which C: was written to: it is decoration, not a check")
	}
	fmt.Println("C1 goes red on a write to C: and on a refused attempt, and does not count reads or the exemption")
	return nil
}

// cmdProveRedChild is prove-red's stand-in for the installer, run at Low.
func cmdProveRedChild(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: prove-red-child ROOT")
	}
	root := args[0]
	if _, err := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts")); err != nil {
		return fmt.Errorf("a Low process could not READ from C:, and the installer must: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "lowspot", "written.tmp"), []byte("x"), 0o644); err != nil {
		return fmt.Errorf("writing into a Low-labelled directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(root, "denied", "blocked.tmp"), []byte("x"), 0o644); err == nil {
		return fmt.Errorf("a Low process WROTE into an unlabelled (Medium) directory on C:: no-write-up did not hold")
	} else {
		fmt.Printf("refused, as it must be: %v\n", err)
	}
	if err := os.WriteFile(filepath.Join(root, "exempt", "allowed.tmp"), []byte("x"), 0o644); err != nil {
		return fmt.Errorf("writing into the exempt Low directory: %w", err)
	}
	return nil
}

// cmdEnforcementProbe runs inside the installer's Low-integrity session (see
// gate3.ApplyEnforcement). -dest does what the installer does on a destination:
// creates its directories itself, creates a run log for append inside them and
// writes a file below. -source opens every file of the source for read. It
// prints what it did and exits non-zero on the first thing refused.
func cmdEnforcementProbe(args []string) error {
	fs := flag.NewFlagSet("enforcement-probe", flag.ExitOnError)
	dest := fs.String("dest", "", "a directory to create on a destination, as the installer would")
	source := fs.String("source", "", "a tree whose every file must open for read")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dest != "" {
		// Each variant is tried and reported, so a refusal says WHICH access
		// pattern Low cannot use: run 35666421442 refused the run log's
		// O_APPEND create with full control and an inherited (OI)(CI)(NW) Low
		// label on both directories. syscall.Open (Go 1.25) asks O_APPEND for
		// FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|READ_CONTROL|
		// SYNCHRONIZE with OPEN_ALWAYS; O_TRUNC asks GENERIC_WRITE.
		meta := filepath.Join(*dest, "_auros")
		deeper := filepath.Join(*dest, "Documents", "Term 2")
		for _, d := range []string{meta, deeper} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				return err
			}
		}
		appendTo := func(p string, flag int) error {
			f, err := os.OpenFile(p, flag, 0o644)
			if err != nil {
				return err
			}
			_, werr := f.WriteString("{}\n")
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			return werr
		}
		failed := 0
		for _, v := range []struct {
			what string
			do   func() error
		}{
			{"create+truncate write (GENERIC_WRITE) in _auros", func() error {
				return os.WriteFile(filepath.Join(meta, "truncated.bin"), []byte("x"), 0o644)
			}},
			{"append to an existing file in _auros", func() error {
				return appendTo(filepath.Join(meta, "truncated.bin"), os.O_WRONLY|os.O_APPEND)
			}},
			{"create for append, as the run log does, in _auros", func() error {
				return appendTo(filepath.Join(meta, "run-probe.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND)
			}},
			{"create+truncate write, as a copy does, two levels down", func() error {
				return os.WriteFile(filepath.Join(deeper, "notes.docx.auros-partial"), []byte("x"), 0o644)
			}},
		} {
			if err := v.do(); err != nil {
				failed++
				fmt.Printf("REFUSED %s: %v\n", v.what, err)
			} else {
				fmt.Printf("ok      %s\n", v.what)
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d of the installer's write patterns were refused", failed)
		}
	}
	if *source != "" {
		n := 0
		err := filepath.WalkDir(*source, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.Type().IsRegular() {
				return err
			}
			f, oerr := os.Open(p)
			if oerr != nil {
				return oerr
			}
			n++
			return f.Close()
		})
		if err != nil {
			return fmt.Errorf("after %d files: %w", n, err)
		}
		fmt.Printf("%d files opened for read\n", n)
	}
	return nil
}
