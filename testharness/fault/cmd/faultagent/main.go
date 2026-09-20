// Command faultagent is the guest half of the fault injector. It runs inside the throwaway Windows VM,
// elevated, alongside the installer under test.
//
// It does three things and nothing else:
//
//  1. Refuses to start unless the §4.7 harness token vouches for the volumes it is about to damage.
//  2. Tails the installer's progress log and fires its scenario at the pinned byte.
//  3. Reports what it did over the serial line BEFORE it does it, because four of the twenty scenarios
//     end with the VM ceasing to exist and evidence that leaves afterwards does not leave.
//
// It is also the guest end for clean runs, where it fires nothing and exists only to emit the beacon
// the runner's boot check waits for.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/aarohkandy/auros-installer/testharness/fault"
)

func main() {
	var (
		tokenPath   = flag.String("token", "", "harness token on the AUROS-HARNESS marker volume")
		corpusRoot  = flag.String("corpus-root", "", `the corpus root, e.g. C:\Users\student`)
		destVolume  = flag.String("dest-volume", "", `destination volume root, e.g. E:\`)
		destData    = flag.String("dest-data-root", "", `archive data root, e.g. E:\auros-archive\data`)
		goldenMan   = flag.String("golden-manifest", "", "golden-manifest.jsonl on the marker volume")
		expectDig   = flag.String("expect-corpus-digest", "", "refuse if the golden manifest does not hash to this")
		progress    = flag.String("progress", "", "the installer's auros-progress.ndjson on the destination")
		instManifest = flag.String("installer-manifest", "", "the installer's own manifest on the destination")
		scenarioID  = flag.String("scenario", "", "F01..F20, or empty for a clean run")
		control     = flag.String("control", `\\.\COM2`, "serial line to the runner")
		out         = flag.String("out", "", "also write the FireRecord JSON here")
		timeoutSec  = flag.Int("timeout-sec", 5400, "give up waiting for the trigger after this long")
		pollMS      = flag.Int("poll-ms", 5, "progress poll interval")
	)
	flag.Parse()

	if err := fault.Validate(); err != nil {
		die("the fault catalogue is invalid: %v", err)
	}
	if *tokenPath == "" || *corpusRoot == "" {
		die("-token and -corpus-root are required")
	}

	// §4.7 first, before anything is opened for writing.
	if _, err := fault.AssertScratch(*tokenPath, *corpusRoot, *destVolume); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctl, err := os.OpenFile(*control, os.O_RDWR, 0)
	if err != nil {
		die("cannot open the control line %s: %v", *control, err)
	}
	defer ctl.Close()
	logf := func(format string, args ...any) {
		fmt.Fprintf(ctl, "log\t"+format+"\n", args...)
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}

	// The beacon tells the runner the guest reached a usable state. The boot check waits for exactly
	// this line, and its ABSENCE within the timeout is a failed boot — never a skip.
	fmt.Fprintf(ctl, "beacon\tagent-up\t%s\n", fault.HarnessBuild())

	if *scenarioID == "" {
		logf("clean run: no scenario, holding the line open for the duration")
		time.Sleep(time.Duration(*timeoutSec) * time.Second)
		return
	}

	sc, err := fault.Lookup(*scenarioID)
	if err != nil {
		die("%v", err)
	}
	if *goldenMan == "" || *progress == "" {
		die("-golden-manifest and -progress are required for a fault run")
	}
	entries, digest, err := fault.LoadManifest(*goldenMan)
	if err != nil {
		die("golden manifest: %v", err)
	}
	if *expectDig != "" && digest != *expectDig {
		die("REFUSING: golden manifest hashes to %s, expected %s. Every pin in this scenario was computed "+
			"against a different corpus", digest, *expectDig)
	}

	guest, gerr := fault.NewGuestControl(*destVolume)
	if sc.Site == fault.SiteGuest && gerr != nil {
		die("%v", gerr)
	}

	stop := make(chan struct{})
	timer := time.AfterFunc(time.Duration(*timeoutSec)*time.Second, func() { close(stop) })
	defer timer.Stop()

	cfg := fault.GuestConfig{
		Scenario:     sc,
		Entries:      entries,
		ProgressPath: *progress,
		ManifestPath: *instManifest,
		DestDataRoot: *destData,
		PollMS:       *pollMS,
		Log:          logf,
		Stop:         stop,
		Control:      ctl,
		PreFire: func(rec fault.FireRecord) error {
			// Serial line first. On a power-cut scenario this is the only copy that survives.
			b, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(ctl, "record\t%s\n", string(b)); err != nil {
				return err
			}
			if *out != "" {
				_ = os.WriteFile(*out, append(b, '\n'), 0o644)
			}
			return nil
		},
	}

	rec, execErr := fault.GuestExecute(cfg, guest)

	// Emit the final record too: for guest-site scenarios it carries the action's outcome, which PreFire
	// could not know yet.
	if b, err := json.Marshal(rec); err == nil {
		fmt.Fprintf(ctl, "record\t%s\n", string(b))
		if *out != "" {
			_ = os.WriteFile(*out, append(b, '\n'), 0o644)
		}
	}
	fmt.Fprintf(ctl, "beacon\tagent-done\t%s\t%v\n", sc.ID, rec.Fired)

	if execErr != nil {
		die("scenario %s: %v", sc.ID, execErr)
	}
	if err := rec.Valid(); err != nil {
		// Exit 4 is "the fault did not fire". The runner treats it as a FAILED run, not a skipped one:
		// a scenario that did not happen is not a scenario that passed.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(4)
	}
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "faultagent: "+format+"\n", args...)
	os.Exit(1)
}
