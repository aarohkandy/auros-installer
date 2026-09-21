// Command auros-restore puts a school's files back on the new machine.
//
// It is SAFETY.md phase 7 and it runs at the single most dangerous moment in
// the whole product: the archive on the USB stick is the ONLY copy of the
// user's data, because the Windows disk it was copied from has already been
// overwritten. Everything here is arranged around that.
//
//	auros-restore                 find the archive, check it, restore it
//	auros-restore --dry-run       do everything except write the files
//	auros-restore --list          say what would be found and stop
//	auros-restore --archive DIR   use this archive and do not search
//
// It is safe to run more than once. A restore stopped by a power cut is
// finished by running it again: every file already on disk is checked by hash
// and skipped, and nothing that is already correct is written twice.
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

	"github.com/aarohkandy/auros-installer/internal/deskbus"
	"github.com/aarohkandy/auros-installer/internal/manifest"
	"github.com/aarohkandy/auros-installer/internal/restore"
	"github.com/aarohkandy/auros-installer/internal/runlog"
	"github.com/aarohkandy/auros-installer/internal/signals"
)

// Exit codes. Distinct, because the systemd unit and a person debugging a
// laptop in a school corridor both need to tell these apart.
const (
	exitOK           = 0
	exitUsage        = 1
	exitArchiveBad   = 2 // the archive did not verify; NOTHING was written
	exitIncomplete   = 3 // files were restored, and something needs attention
	exitAmbiguous    = 4 // several archives attached; the user must choose
	exitNoArchive    = 5 // --require-archive was set and none was found
	exitCannotReport = 6 // the restore ran but the user could not be told
	// exitNoArchiveOnMedia: a removable drive IS attached and none of them
	// holds a backup. Not a quiet no-op: on a machine running this program the
	// most likely reason somebody plugged in a drive is that it is the backup,
	// and the first version of this command answered "nothing to do", exit 0,
	// for an archive it had simply failed to look inside.
	exitNoArchiveOnMedia = 7
)

const usage = `auros-restore — put your files back on this computer.

  Finds the backup by the list of files inside it, not by which drive letter
  it happens to get. Checks every file on the backup BEFORE writing anything.
  Checks every file again afterwards. Tells you the count on your desktop.

  Safe to run twice: files already here are checked and left alone.

Usage:
  auros-restore [flags]

Flags:
`

type config struct {
	archive        string
	home           string
	dryRun         bool
	list           bool
	requireArchive bool
	noNotify       bool
	stamp          string
	force          bool
	bufSize        int
	quiet          bool
}

func main() {
	code, err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nauros-restore: %v\n", err)
	}
	os.Exit(code)
}

func run() (int, error) {
	var cfg config
	fs := flag.NewFlagSet("auros-restore", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	fs.StringVar(&cfg.archive, "archive", "", "use this folder as the backup instead of searching for one")
	fs.StringVar(&cfg.home, "home", "", "restore into this home directory (default: the current user's)")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "check everything, write nothing")
	fs.BoolVar(&cfg.list, "list", false, "say which backups are attached and stop")
	fs.BoolVar(&cfg.requireArchive, "require-archive", false, "fail if no backup is attached (default: exit quietly)")
	fs.BoolVar(&cfg.noNotify, "no-notify", false, "do not put a pop-up on the desktop")
	fs.StringVar(&cfg.stamp, "stamp", "", "write this file when the restore finishes cleanly")
	fs.BoolVar(&cfg.force, "force", false, "run even though the stamp file says it already finished")
	fs.IntVar(&cfg.bufSize, "buffer-bytes", manifest.DefaultBufSize, "streaming buffer size")
	fs.BoolVar(&cfg.quiet, "quiet", false, "print nothing to the terminal (the desktop report is still written)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return exitUsage, nil
	}

	out := os.Stdout
	say := func(format string, args ...any) {
		if !cfg.quiet {
			fmt.Fprintf(out, format+"\n", args...)
		}
	}

	home := cfg.home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return exitUsage, fmt.Errorf("cannot find your home directory: %w", err)
		}
		home = h
	}
	layout, err := restore.NewLayout(home, "", os.Getenv)
	if err != nil {
		return exitUsage, err
	}
	// Under a root run (an administrator with --home), everything this
	// command creates in the home directory — the state directory, the log,
	// the stamp, the report — is handed to whoever owns that home. Decided
	// before anything is created, and a root run that cannot tell who that is
	// stops here rather than leaving root-owned files the user cannot touch.
	own, err := restore.OwnershipFor(layout.Home)
	if err != nil {
		return exitUsage, err
	}

	stateDir := filepath.Join(layout.Home, ".local", "state", "auros-restore")
	stamp := cfg.stamp
	if stamp == "" {
		stamp = filepath.Join(stateDir, "done")
	}
	if !cfg.force && !cfg.list && !cfg.dryRun {
		if _, err := os.Stat(stamp); err == nil {
			say("The restore already finished on this computer (%s).", stamp)
			say("Run it again with --force if you really want to.")
			return exitOK, nil
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), signals.Interrupting()...)
	defer stop()

	log, logPath := openLog(stateDir, own)
	if log != nil {
		defer log.Close()
	}
	logEvent := func(kind string, f runlog.Fields) {
		if log != nil {
			log.Event("7-restore", kind, f)
		}
	}
	logEvent("start", runlog.Fields{"home": layout.Home, "dry_run": cfg.dryRun})

	// ---- FIND ----
	finder := &restore.Finder{Explicit: cfg.archive}
	archives, err := finder.Find()
	if err != nil {
		code, msg := findRefusal(err, cfg.requireArchive)
		say("%s", msg)
		logEvent("find-refused", runlog.Fields{
			"exit": code, "error": err.Error(),
			"searched":  strings.Join(finder.Searched, " "),
			"removable": strings.Join(finder.SearchedRemovable, " "),
			"count":     len(archives),
		})
		if code == exitOK || !cfg.quiet {
			// Already said on the terminal. Under --quiet — which is how the
			// login unit runs it — the returned error is the only thing that
			// reaches the journal, so it is returned.
			return code, nil
		}
		return code, err
	}
	a := archives[0]
	say("Backup found: %s", a.Root)
	say("  %d files listed, %s", a.FileCount, humanBytes(a.TotalBytes))
	logEvent("archive", runlog.Fields{
		"root": a.Root, "digest": a.Digest, "files": a.FileCount, "bytes": a.TotalBytes,
		"mount": a.MountPoint, "fstype": a.FSType,
	})

	if cfg.list {
		for _, arc := range archives {
			say("%s", arc.String())
		}
		return exitOK, nil
	}

	// ---- PLAN ----
	plan, err := restore.BuildPlan(a, layout)
	if err != nil {
		say("Refusing to restore this backup:\n%v", err)
		logEvent("plan-refused", runlog.Fields{"error": err.Error()})
		return exitArchiveBad, err
	}
	say("  %d files to place, %d Wi-Fi item(s), %d printer item(s), %d not migrated by design",
		len(plan.Files), len(plan.WiFi), len(plan.Printers), len(plan.Withheld))

	// ---- RUN ----
	opts := restore.Options{
		DryRun:  cfg.dryRun,
		BufSize: cfg.bufSize,
		WiFiSink: &restore.WiFiHandler{
			StagingDir: filepath.Join(layout.Home, ".local", "share", "auros-restore", "network"),
			AsRoot:     os.Geteuid() == 0,
		},
		PrinterSink: &restore.PrinterHandler{
			PlanPath: filepath.Join(stateDir, "printers.plan"),
		},
		Progress: progressPrinter(say, cfg.quiet),
	}
	summary, runErr := restore.Execute(ctx, plan, opts)

	// The report is written whatever happened, INCLUDING when the archive did
	// not verify. A user whose backup is damaged is the user who most needs a
	// file on their desktop explaining it.
	if !cfg.noNotify {
		sum, body, urgent := restore.NotifyBody(summary)
		urgency := byte(1)
		if urgent {
			urgency = 2
		}
		okNotify, detail := deskbus.Send(deskbus.Notification{
			AppName:  "Auros",
			Summary:  sum,
			Body:     body,
			Icon:     "document-save",
			Urgency:  urgency,
			ExpireMS: -1,
		}, os.Getenv, os.Getuid(), 5*time.Second)
		summary.NotifyAttempt = detail
		logEvent("notify", runlog.Fields{"ok": okNotify, "detail": detail})
	} else {
		summary.NotifyAttempt = "not attempted (--no-notify)"
	}

	// Written ONCE, after the notification result is known; WriteReport
	// records its own path before rendering. There is deliberately no second
	// write "to fix it up": the first version had one, with O_TRUNC and its
	// error discarded, and the run it was most likely to empty was the one that
	// stopped because the disk was full.
	reportPath, reportErr := restore.WriteReport(summary, layout)

	say("")
	say("%s", restore.RenderReport(summary, layout))
	if logPath != "" {
		say("A detailed log is at %s", logPath)
	}
	logEvent("finish", runlog.Fields{
		"clean":     summary.Clean(),
		"restored":  summary.FilesRestored(),
		"failed":    summary.Counts[restore.OutFailed],
		"withheld":  summary.Counts[restore.OutWithheld],
		"stopped":   summary.StoppedEarly,
		"report":    reportPath,
		"reverify":  summary.ReVerify != nil && summary.ReVerify.Clean(),
		"preverify": summary.PreVerify != nil && summary.PreVerify.Clean(),
	})

	if reportErr != nil {
		fmt.Fprintf(os.Stderr, "auros-restore: could not write the report the user is supposed to read: %v\n", reportErr)
		return exitCannotReport, reportErr
	}
	if runErr != nil && summary.PreVerify != nil && !summary.PreVerify.Clean() {
		return exitArchiveBad, runErr
	}
	if !summary.Clean() {
		return exitIncomplete, runErr
	}
	if !cfg.dryRun {
		if err := writeStamp(stamp, summary, own); err != nil {
			fmt.Fprintf(os.Stderr, "auros-restore: could not write the stamp file: %v\n", err)
		}
	}
	return exitOK, nil
}

// writeStamp records that the restore finished cleanly, so the login unit does
// not run it again. It is written ONLY on a clean run: a run that had a problem
// deserves another attempt at the next login, because the usual cause is a USB
// stick that was not plugged in yet.
func writeStamp(path string, s *restore.Summary, own *restore.Ownership) error {
	if err := restore.MkdirAllOwned(filepath.Dir(path), 0o700, own); err != nil {
		return err
	}
	body := fmt.Sprintf("auros-restore finished cleanly\nfiles: %d\narchive: %s\nat: %s\n",
		s.FilesRestored(), s.Archive.Digest, s.FinishedAt.Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return err
	}
	return own.Apply(path)
}

func openLog(stateDir string, own *restore.Ownership) (*runlog.Logger, string) {
	if err := restore.MkdirAllOwned(stateDir, 0o700, own); err != nil {
		return nil, ""
	}
	p := filepath.Join(stateDir, "restore.log")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, ""
	}
	if err := own.Apply(p); err != nil {
		f.Close()
		return nil, ""
	}
	return runlog.NewWriter(f, nil), p
}

// findRefusal decides what the command does when the finder did not hand back
// exactly one archive: the exit code, and the sentence the operator reads.
//
// It is a pure function so every branch can be driven from a test. The first
// version was an inline switch that sent three different situations — nothing
// attached; a drive attached with the archive one folder down, where the
// finder never looked; and an --archive path the user typed wrong — to the
// same "Nothing to do", exit 0. Only the first of those is a no-op.
//
// Each sentinel is matched by name and none wraps another, so an error this
// function does not recognise falls through to the last branch and fails
// closed.
func findRefusal(err error, requireArchive bool) (int, string) {
	switch {
	case errors.Is(err, restore.ErrAmbiguous):
		return exitAmbiguous, err.Error()
	case errors.Is(err, restore.ErrExplicitArchiveMissing):
		return exitUsage, fmt.Sprintf("There is no backup in the folder you gave with --archive.\n%v", err)
	case errors.Is(err, restore.ErrNoArchiveOnAttachedMedia):
		return exitNoArchiveOnMedia, fmt.Sprintf(
			"A drive is plugged in, but no backup was found on it.\n"+
				"If that drive IS your backup, do not wipe it — tell whoever set this computer up, "+
				"and show them this:\n%v", err)
	case errors.Is(err, restore.ErrNoArchive):
		if requireArchive {
			return exitNoArchive, err.Error()
		}
		// No backup attached is the ordinary state of a machine that was not
		// migrated. It is not an error and it does not get a scary note on the
		// desktop: a fresh Auros laptop has no archive and its owner should
		// never see a warning about one.
		return exitOK, "No backup drive with files to restore is attached. Nothing to do."
	default:
		return exitArchiveBad, fmt.Sprintf("The backup is there but cannot be read: %v", err)
	}
}

func progressPrinter(say func(string, ...any), quiet bool) func(done, total int, path string) {
	if quiet {
		return nil
	}
	last := -1
	return func(done, total int, _ string) {
		if total == 0 {
			return
		}
		pct := done * 100 / total
		if pct/5 == last/5 {
			return
		}
		last = pct
		say("  %3d%%  %d of %d", pct, done, total)
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
