// Command bootbeacon is installed ONCE into the Windows base image as a service that starts at boot.
//
// It exists so that "Windows still boots normally" can be a machine check rather than a person looking
// at a screenshot. Spec §6C names that condition; bootcheck.go explains why it is the one most likely to
// be quietly dropped. This is the half that runs inside the guest.
//
// It writes one line to COM1 on every boot:
//
//	auros-boot-beacon {"boot_id":41,"seconds_since_boot":38.2,"bugcheck":false, …}
//
// COM1 rather than a file, because the point is to be readable by the host from a machine that may not
// be in a state to hand anything over afterwards. Because it is baked into the BASE image, every overlay
// has it, and the boot check needs nothing attached to the VM to collect its evidence — which is what
// makes that boot a NORMAL boot rather than a harness-assisted one.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const beaconVersion = "bootbeacon/0.1.0"

// BootReport must stay field-for-field identical to runner.BootReport. It is duplicated rather than
// shared because this binary is cross-compiled for Windows and lives inside an image that is rebuilt
// far less often than the runner; a shared type would silently couple the two lifetimes.
type BootReport struct {
	Version             string   `json:"version"`
	BootID              int      `json:"boot_id"`
	SecondsSinceBoot    float64  `json:"seconds_since_boot"`
	Bugcheck            bool     `json:"bugcheck"`
	BugcheckDetail      string   `json:"bugcheck_detail,omitempty"`
	DirtyShutdown       bool     `json:"dirty_shutdown"`
	ChkdskBlockedBoot   bool     `json:"chkdsk_blocked_boot"`
	RecoveryEnvironment bool     `json:"recovery_environment"`
	SystemStateSHA      string   `json:"system_state_sha256"`
	BootEntriesAdded    []string `json:"boot_entries_added,omitempty"`
	BootNextSet         bool     `json:"boot_next_set"`
}

func main() {
	port := flag.String("port", `\\.\COM1`, "where to write the beacon")
	stateDir := flag.String("state", `C:\ProgramData\auros-harness`, "where the boot counter lives")
	baseline := flag.String("baseline", "", "comma-separated boot entry identifiers present in the base image")
	flag.Parse()

	r := BootReport{Version: beaconVersion}
	r.BootID = bumpBootID(*stateDir)
	r.SecondsSinceBoot = secondsSinceBoot()

	ev := collectEventEvidence()
	r.Bugcheck = ev.bugcheck
	r.BugcheckDetail = ev.bugcheckDetail
	r.DirtyShutdown = ev.dirtyShutdown
	r.ChkdskBlockedBoot = ev.chkdsk
	r.RecoveryEnvironment = ev.recoveryEnv

	// The boot-critical region. SAFETY.md phase 6 is the only code in the product permitted to change
	// any of this, and on an aborted run phase 6 never ran — so this value must be byte-identical to the
	// one captured when the base image was built.
	sha, entries, bootNext, err := systemState()
	if err != nil {
		r.SystemStateSHA = ""
	} else {
		r.SystemStateSHA = sha
	}
	r.BootNextSet = bootNext
	r.BootEntriesAdded = diffEntries(entries, strings.Split(*baseline, ","))

	b, _ := json.Marshal(r)
	line := "auros-boot-beacon " + string(b) + "\r\n"

	f, err := os.OpenFile(*port, os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bootbeacon: cannot open %s: %v\n", *port, err)
		os.Exit(1)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		fmt.Fprintf(os.Stderr, "bootbeacon: %v\n", err)
		os.Exit(1)
	}
}

// bumpBootID increments a counter that survives reboots, so the host can tell this boot's beacon from
// one left in a log by the boot before it.
func bumpBootID(dir string) int {
	_ = os.MkdirAll(dir, 0o755)
	p := filepath.Join(dir, "boot-id")
	n := 0
	if b, err := os.ReadFile(p); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	n++
	_ = os.WriteFile(p, []byte(strconv.Itoa(n)), 0o644)
	return n
}

func diffEntries(now, baseline []string) []string {
	base := map[string]bool{}
	for _, b := range baseline {
		b = strings.TrimSpace(b)
		if b != "" {
			base[strings.ToLower(b)] = true
		}
	}
	// No baseline configured means we do not know which entries the base image shipped with. Reporting
	// every entry as "added" would fail every run on a machine nothing had touched — a check that cries
	// wolf gets switched off, and then it is not a check. The system-state hash already covers any
	// change to the BCD, so silence here is not a gap.
	if len(base) == 0 {
		return nil
	}
	var added []string
	for _, e := range now {
		e = strings.TrimSpace(e)
		if e != "" && !base[strings.ToLower(e)] {
			added = append(added, e)
		}
	}
	return added
}
