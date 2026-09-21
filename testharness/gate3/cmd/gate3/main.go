// Command gate3 drives the REAL auros-migrate CLI against a real, throwaway
// Windows machine and measures what happened.
//
// It is the runner-side counterpart to testharness/runner, which drives QEMU.
// DECISIONS.md D27 moved Gate 3 onto ephemeral `windows-latest` runners, and
// this program is what runs there: it creates the migration account, points its
// known folders at the synthetic corpus, runs the installer as that account,
// fires one induced failure at an exact pin, and then re-hashes both trees and
// reads the NTFS change journal to say whether the invariant held.
//
//	gate3 suite                 print the induced-failure catalogue
//	gate3 plan                  resolve every pin against a golden manifest (no Windows needed)
//	gate3 mint-token            the §4.7 guard: vouch for THIS disposable machine
//	gate3 prepare               create the migration account and redirect its known folders
//	gate3 run                   one run, clean or induced
//	gate3 aggregate             recompute every result's verdict and decide Gate 3
//	gate3 prove-red             drive each check into failure, and fail if any stays green
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aarohkandy/auros-installer/testharness/gate3"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "suite":
		fmt.Print(gate3.Describe())
		err = gate3.Validate()
	case "plan":
		err = cmdPlan(os.Args[2:])
	case "aggregate":
		err = cmdAggregate(os.Args[2:])
	case "mint-token":
		err = cmdMintToken(os.Args[2:])
	case "prepare":
		err = cmdPrepare(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "prove-red":
		err = cmdProveRed(os.Args[2:])
	case "prove-red-child": // prove-red's stand-in for the installer, started at Low integrity
		err = cmdProveRedChild(os.Args[2:])
	case "enforcement-probe": // run by the harness inside the installer's Low-integrity session
		err = cmdEnforcementProbe(os.Args[2:])
	case "format-destination":
		err = cmdFormatDestination(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate3: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `gate3 — the Gate 3 harness for ephemeral Windows runners (DECISIONS.md D27)

  gate3 suite
  gate3 plan        -golden FILE
  gate3 mint-token  -corpus DIR -dest-volume E:\ -out FILE
  gate3 prepare     -corpus DIR -work DIR -password-file FILE
  gate3 run         -golden FILE -corpus DIR -tool EXE -dest-volume E:\ -work DIR
                    -password-file FILE -out FILE [-scenario F02] [-run-id ID]
  gate3 aggregate   -results DIR -expect-clean 100 -expect-faults F01,F02,…
  gate3 prove-red   -work DIR
`)
}

// cmdPlan resolves every scenario's pin without a VM, a runner or Windows. It is
// how a trigger point is checked before an hour of machine time is spent on it.
func cmdPlan(args []string) error {
	fs := flag.NewFlagSet("plan", flag.ExitOnError)
	golden := fs.String("golden", "", "golden-manifest.jsonl")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *golden == "" {
		return fmt.Errorf("-golden is required")
	}
	if err := gate3.Validate(); err != nil {
		return err
	}
	g, err := gate3.LoadGolden(*golden)
	if err != nil {
		return err
	}
	fmt.Printf("corpus: %d files, %d bytes, digest %s\n", len(g.ByGolden), g.TotalBytes, g.Digest)
	fmt.Printf("placeholders: %d\n", g.Placeholders())
	files, streams := g.StreamFiles()
	fmt.Printf("alternate data streams: %d streams on %d files\n", streams, files)
	for _, sc := range gate3.Suite() {
		if sc.Trigger == gate3.TriggerNone {
			fmt.Printf("%-4s %-22s (no trigger: %s)\n", sc.ID, sc.Action, sc.Dest)
			continue
		}
		pin, err := gate3.ResolvePin(g, sc.Phase, sc.BP)
		if err != nil {
			return fmt.Errorf("%s: %w", sc.ID, err)
		}
		line := fmt.Sprintf("%-4s %-22s %s", sc.ID, sc.Action, pin.String())
		if sc.TargetDeltaBytes != 0 || sc.Action == gate3.ActionMutateSource {
			t, terr := gate3.TargetFromPin(g, pin, sc.TargetDeltaBytes)
			if terr != nil {
				return fmt.Errorf("%s: %w", sc.ID, terr)
			}
			line += fmt.Sprintf("\n        target: %s (%d bytes)", t.Path, t.Size)
		}
		fmt.Println(line)
	}
	return nil
}

// row is one run's recomputed verdict.
type row struct {
	id      string
	verdict gate3.Status
	reasons []string
	res     *gate3.Result
}

// cmdAggregate is the verdict. It recomputes every result's verdict from its
// checks and requires the SHAPE the suite owed: a run that produced no result
// file is a missing run and a failure, never an absent row.
func cmdAggregate(args []string) error {
	fs := flag.NewFlagSet("aggregate", flag.ExitOnError)
	dir := fs.String("results", "", "directory of result JSON files")
	expectClean := fs.Int("expect-clean", 100, "how many clean runs the suite owed")
	expectFaults := fs.String("expect-faults", "", "comma-separated scenario ids the suite owed")
	summary := fs.String("summary", "", "write a markdown summary here as well")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("-results is required")
	}
	if err := gate3.Validate(); err != nil {
		return err
	}

	var files []string
	err := filepath.Walk(*dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		files = append(files, p)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)

	var clean []row
	faults := map[string]row{}
	for _, f := range files {
		res, rerr := gate3.ReadResult(f)
		if rerr != nil {
			return rerr
		}
		var sc *gate3.Scenario
		if res.ScenarioID != "" {
			s, lerr := gate3.Lookup(res.ScenarioID)
			if lerr != nil {
				return fmt.Errorf("%s: %w", f, lerr)
			}
			sc = &s
		}
		v, why := res.Recompute(gate3.RequiredChecks(res.Kind, sc))
		r := row{id: res.RunID, verdict: v, reasons: why, res: res}
		if res.Kind == gate3.KindClean {
			clean = append(clean, r)
		} else {
			faults[strings.ToUpper(res.ScenarioID)] = r
		}
	}

	var b strings.Builder
	cleanPass := 0
	for _, r := range clean {
		if r.verdict == gate3.Pass {
			cleanPass++
		}
	}
	fmt.Fprintf(&b, "## Gate 3\n\n")
	fmt.Fprintf(&b, "Harness `%s`. Every verdict below is recomputed from that run's measurements; the "+
		"verdict stored in a result file is ignored.\n\n", gate3.HarnessVersion)
	fmt.Fprintf(&b, "| | required | measured |\n|---|---|---|\n")
	fmt.Fprintf(&b, "| clean runs | %d, zero lost, zero corrupted | **%d of %d passed** |\n",
		*expectClean, cleanPass, len(clean))

	wanted := []string{}
	for _, id := range strings.Split(*expectFaults, ",") {
		if id = strings.TrimSpace(strings.ToUpper(id)); id != "" {
			wanted = append(wanted, id)
		}
	}
	faultPass := 0
	for _, id := range wanted {
		if r, ok := faults[id]; ok && r.verdict == gate3.Pass {
			faultPass++
		}
	}
	fmt.Fprintf(&b, "| induced failures | %d behaving as required | **%d of %d passed** |\n\n",
		len(wanted), faultPass, len(wanted))

	fmt.Fprintf(&b, "### Induced failures\n\n| id | scenario | expected | verdict | why |\n|---|---|---|---|---|\n")
	for _, id := range wanted {
		r, ok := faults[id]
		if !ok {
			fmt.Fprintf(&b, "| %s | — | — | **MISSING** | the run produced no result file |\n", id)
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | %s | **%s** | %s |\n", id, r.res.Scenario, r.res.Expect,
			strings.ToUpper(string(r.verdict)), truncate(strings.Join(r.reasons, "; "), 240))
	}
	fmt.Fprintf(&b, "\n### Clean runs\n\n")
	failed := 0
	for _, r := range clean {
		if r.verdict != gate3.Pass {
			failed++
			fmt.Fprintf(&b, "- **%s FAILED**: %s\n", r.id, truncate(strings.Join(r.reasons, "; "), 400))
		}
	}
	if failed == 0 && len(clean) > 0 {
		fmt.Fprintf(&b, "All %d clean runs passed every check.\n", len(clean))
	}

	// Findings are not verdicts. They are printed because a suite that only
	// prints its verdicts loses everything it measured on the way there.
	seen := map[string]bool{}
	var findings []string
	for _, r := range append(append([]row{}, clean...), valuesOf(faults)...) {
		for _, f := range r.res.Findings {
			if !seen[f] {
				seen[f] = true
				findings = append(findings, f)
			}
		}
	}
	if len(findings) > 0 {
		fmt.Fprintf(&b, "\n### Measured, and not part of the exit condition\n\n")
		sort.Strings(findings)
		for _, f := range findings {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}

	var profiles []string
	for _, r := range append(append([]row{}, clean...), valuesOf(faults)...) {
		profiles = append(profiles, r.res.Profile)
	}
	missing := len(wanted) - countPresent(wanted, faults)
	var verdict error
	if cleanPass != *expectClean || faultPass != len(wanted) || missing > 0 || len(clean) != *expectClean {
		verdict = fmt.Errorf("GATE 3 NOT PASSED: %d/%d clean, %d/%d induced failures, %d runs missing",
			cleanPass, *expectClean, faultPass, len(wanted), missing+*expectClean-len(clean))
	} else {
		var claim string
		if claim, verdict = gateClaim(*expectClean, wanted, profiles); verdict == nil {
			fmt.Fprintf(&b, "\n**%s**\n", claim)
		}
	}

	fmt.Print(b.String())
	if *summary != "" {
		if err := os.WriteFile(*summary, []byte(b.String()), 0o644); err != nil {
			return err
		}
	}
	return verdict
}

// gateClaim is what a run in which every owed run passed may say about Gate 3.
// "GATE 3 PASSED" is reserved for the §6C shape: at least 100 clean runs, every
// scenario in the catalogue, and every corpus the realistic profile. A smaller
// shape — the push run is two compact runs and three faults — says what it was.
// A shape that owed nothing measured nothing, and is an error rather than a pass.
func gateClaim(expectClean int, wanted, profiles []string) (string, error) {
	if expectClean == 0 && len(wanted) == 0 {
		return "", fmt.Errorf("GATE 3 NOT PASSED: the run owed zero clean runs and zero induced failures, " +
			"so nothing was measured")
	}
	var short []string
	if expectClean < 100 {
		short = append(short, fmt.Sprintf("%d clean runs of the 100 §6C requires", expectClean))
	}
	owed := map[string]bool{}
	for _, id := range wanted {
		owed[id] = true
	}
	var notRun []string
	for _, sc := range gate3.Suite() {
		if !owed[strings.ToUpper(sc.ID)] {
			notRun = append(notRun, sc.ID)
		}
	}
	if len(notRun) > 0 {
		short = append(short, fmt.Sprintf("%d catalogue scenarios not run (%s)", len(notRun), strings.Join(notRun, ",")))
	}
	for _, p := range profiles {
		if p != "realistic" {
			short = append(short, fmt.Sprintf("corpus profile %q, which gen says is not the exit condition", p))
			break
		}
	}
	if len(short) == 0 {
		return "GATE 3 PASSED", nil
	}
	return "every run owed passed. This was NOT the Gate 3 suite: " + strings.Join(short, "; "), nil
}

func valuesOf(m map[string]row) []row {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]row, 0, len(m))
	for _, k := range keys {
		out = append(out, m[k])
	}
	return out
}

func countPresent(want []string, have map[string]row) int {
	n := 0
	for _, w := range want {
		if _, ok := have[w]; ok {
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "|", "/")
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
