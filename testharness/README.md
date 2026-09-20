# `testharness` — the synthetic-file test harness for the migration installer

This is the evidence-producing half of the most dangerous thing Auros builds. Read
[`../SAFETY.md`](../SAFETY.md) first; everything here exists to make one sentence in it checkable:

> **Nothing is written to the system disk until the user's data exists in two places and the second copy
> has been verified by file count and per-file hash.**

Spec §6C is the binary exit condition for Gate 3:

> 100 consecutive runs against a Windows VM with 18,000 synthetic files — 100 successes, zero files lost,
> zero corrupted. 20 runs with induced failure (power cut mid-copy, USB pulled, disk full, hash
> mismatch) — 20 clean aborts, Windows still boots normally every time, zero data loss.
> **The abort path is tested more than the happy path.**

**No suite has been run.** There are no results in this repository and `REPORT.md` is an unfilled
template. BLOCKED.md B1 — a VM host with room — is open.

---

## 1. Why you cannot point this at your own laptop

Spec §4.7: *never test the migration installer against the operator's own machine.* A rule in a document
is obeyed until the evening somebody is in a hurry, so it is also a thing that does not work.

The runner mints a **harness token** once per suite and writes it to a small FAT image labelled
`AUROS-HARNESS`, attached read-only to the test VM and to nothing else. The token names the **volume
serial** of the disk the harness is allowed to destroy — which the runner knows because the base image
was built once and its volume serial was recorded then. `gen generate` and `faultagent` both read the
volume serial of the path they are about to write to, compare, and exit without touching anything if it
does not match. Drive letters are not used for this: a mount point or a `subst`'d letter can alias the
system volume, which is the same aliasing mistake `SAFETY.md` phase 3 forbids in the installer itself.

There is **no `--force`**. To run any of this against a real machine you would have to mint a token
naming that machine's volume serial, put it on a volume labelled `AUROS-HARNESS`, and attach it. That is
not impossible — ten minutes for a determined person. It is meant to be *awkward*, and to leave behind an
artefact that says, in the operator's own handwriting, that they declared this disk disposable.

The fault agent additionally refuses if the destination volume is the system drive, and refuses if the
destination and the corpus are the same volume — a harness that blurs those two cannot demonstrate that
the installer keeps them apart.

## 2. Getting a Windows test image, legally

**Microsoft's free pre-built developer VMs are gone.** The "Windows 10/11 development environment"
images (VMware / Hyper-V / VirtualBox / Parallels) were retired in 2024 and have not been replaced. Any
guide that tells you to download one is out of date.

**The current legitimate path is the Microsoft Evaluation Center**, `microsoft.com/en-us/evalcenter` —
an ISO you install yourself, time-limited to **90 days**. Register, download, install into QEMU.

What to be accurate about, because getting it wrong is a licensing problem and not a technical one:

- **Evaluation editions are evaluation software.** They are not licensed for production use, and an
  evaluation install cannot be upgraded in place to a licensed one — you reinstall. The binding terms are
  the licence terms shipped *inside the ISO*; read those rather than a blog post, including anything
  about rearming, which differs between client and server editions and has changed over time.
- **Check what is actually offered before planning around it.** Windows 11 Enterprise evaluation is the
  edition to expect. Windows 10 reached end of support in October 2025 and its evaluation availability
  has changed accordingly; confirm on the Evaluation Center page rather than assuming, and record what
  you actually downloaded in `base.iso_source` so `REPORT.md` can state the provenance.
- **The 90 days are an operational constraint, not a footnote.** An expired evaluation starts shutting
  itself down on a timer, which will end a long run mid-copy and produce a "failure" that is ours, not
  the installer's. Rebuild the base image well before expiry, and never let a suite straddle it. Record
  the expiry alongside the image.

**Not acceptable, in any circumstance:** KMS emulators, activation-bypass scripts, "loader" tools,
re-hosted or repacked ISOs from third-party mirrors, a key belonging to anyone else, or a customer's
own licence. A migration tool for schools cannot have a piracy story attached to its safety evidence.
If we ever need a longer-lived Windows than an evaluation allows, the honest options are a Visual Studio
subscription or a cloud Windows VM with the licence included — both of which **spend money and are
therefore a §9 decision for the human**, not something this harness decides.

## 3. Building the base image — once

Everything about the suite depends on this being done once and then left alone.

1. **Install Windows** from the evaluation ISO into a fresh qcow2. Create the local account the corpus
   root belongs to (`corpus_root` in `runner.config.json`, e.g. `C:\Users\student`).
2. **Assign the volumes.** Fix the destination volume's drive letter (`E:`) with `diskpart`, so the run
   script and the fault agent agree with the guest about where the archive goes. The marker volume is
   located by the run script from its own path, so its letter is not load-bearing.
3. **Install the boot beacon.** Cross-compile `runner/cmd/bootbeacon` for Windows, copy it in, and
   register it to run at every boot as SYSTEM (a scheduled task with an *At startup* trigger is enough).
   It writes one JSON line to `COM1` per boot. This is what makes the boot check need nothing attached
   to the VM — see §6.
4. **Register the run hook.** A second SYSTEM scheduled task, at startup: if `run.cmd` exists on the
   marker volume, run it. That is the only entry point the harness needs inside Windows: no per-run
   agent install, no WinRM, no network.
5. **Generate the corpus, in the guest.** Read the C: volume serial (`vol C:`), write a harness token
   naming it onto a *temporarily writable* marker volume, then:

   ```
   gen generate -seed 20260920 -profile realistic -count 18000 ^
       -root C:\Users\student -token X:\token.json -manifest-dir X:\
   ```

   This prints `corpus_digest=…`. Copy `golden-manifest.jsonl`, `golden-manifest.meta.json` and
   `corpus-plan.json` off the image; they go into `binaries.*` in the config.

   The corpus is baked into the base image rather than generated per run. Eighteen thousand files is
   gigabytes of writing and doing it 120 times would add a day to the suite for no evidence — the corpus
   is deterministic, so every run would produce the same one. Baking it in also means the base image's
   SHA-256 **covers the corpus**, which is a stronger statement than "we generated it again and it hashed
   the same".
6. **Capture the pristine system state.** Run `bootbeacon` once and record its `system_state_sha256` into
   `base.system_state_sha256`. Every aborted run must reproduce that exact value.
7. **Freeze it.** `chmod 0444` both base images, record their SHA-256 and volume serials in
   `runner.config.json`, set `base.corpus_faithful` true (it is only true if the corpus was generated
   *on Windows* — see §7).
8. **Build the empty destination base**: a second qcow2, NTFS-formatted, empty, also frozen. Every run
   overlays it, so every run starts with a genuinely empty destination.

From then on: **one base image, one throwaway overlay per run.** `qemu-img create -f qcow2 -F qcow2 -b
<base> <overlay>`, deleted when the run ends. The base's hash is checked *before and after every single
run* — "before" catches an edited base, "after" catches a run that somehow wrote through its overlay,
which should be impossible and is therefore exactly the thing worth checking. Without that, run 74 is
being tested against whatever runs 1–73 left behind and "100 consecutive" is decoration.

## 4. Running the suite

```
runner plan   -config runner.config.json          # resolve every pin. No VM, no QEMU, no Windows.
runner doctor -config runner.config.json          # refuse to start a suite that cannot finish
runner run    -config runner.config.json -suite all -n 100
runner report -config runner.config.json -results artifacts/<suite> -template REPORT.md -out REPORT.filled.md
```

`plan` is the part that runs on a laptop. It reads the golden manifest and resolves all twenty triggers
to exact `(file index, byte offset)` pins by integer arithmetic — no VM involved, identical on every
machine. Use it to check a trigger point before spending an hour of VM time on it.

Host dependencies: `qemu-system-x86_64`, `qemu-img`, and `mtools` (`mkfs.vfat`, `mcopy`) for building the
marker volume. mtools rather than a loop mount so that preparing a test needs no root — a harness that
needs `sudo` is a harness that gets run less often.

### Big host and small host — BLOCKED.md B1

B1 is open: there is no confirmed host with ~100 GB free. The runner does not assume one.

- **Small host (the default).** `host.parallel = 1`, `host.reclaim_between_runs = true`. The working set
  is one system overlay plus one destination overlay at a time, deleted the moment the run's result is
  written. `host.min_free_gb` is a floor the runner checks *before every run* and refuses to start below
  — because discovering it at run 61 means ENOSPC in somebody else's job on a shared box.
- **Big host.** Raise `host.parallel`. Nothing else changes.

The evidence is identical either way; which path produced it is recorded in every result and printed in
`REPORT.md`, because that is a fact about the run and not a detail worth losing.

`host.keep_overlay_on_fail` keeps a failing run's overlay so it can be booted and poked at rather than
only re-run.

## 5. What the installer has to do for this harness to work

The harness ships before the installer (tasks C5/C6), so it defines the interface rather than discovering
it. `auros-migrate.exe` must:

1. **Copy in manifest index order** — the order `gen` defines: sorted by the UTF-8 forward-slash relative
   path, index assigned after that sort. This is what makes "kill at 43% of bytes" resolvable to an exact
   offset in advance. Every run asserts it from the progress log (`order_violations`); if it is ever
   violated, every pin in the suite is nominal and the runs stop being evidence.
2. **Emit progress** as newline-delimited JSON, appended and flushed per line, to
   `<dest>\auros-progress.ndjson` — on the **destination** volume, never the system disk. At least one
   line per 1 MiB copied, plus one at every file boundary. Fields are in `fault/fault.go` (`Progress`).
   Trigger precision is bounded by this granularity, and each run publishes its actual overshoot so a
   reader can judge whether a pin was real.
3. **Materialise the archive** at `<dest>\auros-archive\data\<relative path>`, with its own manifest at
   `<dest>\auros-archive\manifest.jsonl`.
4. **Write `<dest>\auros-archive\COMPLETE` only after VERIFY succeeds** with zero unresolved files. On an
   aborted run it must not exist — that is postcondition P5, and it is the Wubi failure in one line.
5. **Exit 0 on success, non-zero on abort**, and accept `--no-arm` to stop at the wall.

No network in any of this. A school's uplink is not a safety-critical component (SAFETY.md rule 4), so
the channel between the installer and the injector is a file on a volume they both already have open.

## 6. The boot check, and why it is shaped the way it is

Spec §6C's clause about Windows still booting normally is the slowest check in the suite and the one
whose absence nobody notices, because every other number still looks green without it. So it is not a
flag. There is no `--skip-boot-check` and no `--fast`. Four things make skipping it hard:

1. `boot_check` is a **required** property in `runner/result.schema.json`. A result without it does not
   validate, and `runner report` counts anything that does not validate as a **failed** run, never as
   unknown.
2. `performed` defaults to false and false is a fail. Absence is not neutral.
3. The verdict is recomputed by the reporter from the checks; a harness that wrote `pass` without doing
   the work would be caught by the thing reading it.
4. "Boots" is not "the process started". The evidence is a beacon the guest emits from a logged-on
   session, and its *absence* within the timeout is a failure rather than an inconclusive.

The boot-check boot attaches **nothing of ours** — no marker volume, no destination, no installer. A
machine that only boots when the harness's disks are present has not demonstrated the thing a school's
IT person cares about. That is why `bootbeacon` lives in the base image rather than on the marker.

It checks: beacon seen, no bugcheck, no *blocking* chkdsk (NTFS self-healing is silent and fine; a
file-system check that holds the boot is not), not the Recovery Environment, no boot entries added, no
one-time boot set, boot time under the normal ceiling, and the boot-critical region of the system disk
byte-identical to the base image's. A dirty-shutdown event is *recorded but not a failure* — after an
induced power cut the machine was switched off mid-write and Windows is right to say so.

## 7. Honest limits

- **OneDrive placeholders are attribute-only.** We set `FILE_ATTRIBUTE_OFFLINE`, which exercises the
  installer's *detection* path faithfully. We cannot create a real placeholder without `CfCreatePlaceholders`
  under a registered cloud-filter sync root, so the *hydration* path is not exercised. Every affected
  manifest entry carries `placeholder_fidelity: "attribute-only"` and `REPORT.md` repeats it.
- **A corpus generated off Windows is not a corpus.** `gen` runs on macOS and Linux in `-manifest-only`
  mode so the layout can be reviewed, and it marks the manifest `faithful: false`. `runner doctor` and
  every suite start refuse to run against one: a 100/100 against a corpus with no read-only bits, no
  alternate data streams and no offline attributes is a number that does not mean what the heading says.
- **`compact` is not the exit condition.** Both profiles have 18,000 files and every structural case;
  `compact` shrinks the long tail from ~8.4 GB to ~1.5 GB for a small host. The profile is recorded in
  every result and printed in the report.
- **Power cuts are only as honest as the cache setting.** The guest's disks are opened `cache.direct=on`
  so that a write the guest believes reached the platter is the only kind that survives a SIGKILL. With
  host writeback caching the host would flush the guest's unflushed writes after the process died, which
  is strictly more forgiving than the failure we claim to be testing.
- **None of this is hardware.** No real USB controller, no firmware, no failing ten-year-old spinning
  disk, no BitLocker TPM 1.2 recovery prompt. `hardware/compat.tsv` is where physical evidence goes, and
  it has a `source` column so a VM row can never be mistaken for one.

## 8. Layout

```
gen/       generate.go       deterministic corpus generator: 18,000 files, golden manifest.
           plat_windows.go   read-only bits, alternate data streams, offline attributes, exclusive holds.
           plat_other.go     refuses, loudly, rather than pretending.
fault/     catalogue.go      the 20 scenarios across 9 families. Go, not YAML, so it compiles or it doesn't.
           fault.go          pin arithmetic, the progress protocol, the FireRecord.
           inject.go         guest watcher, host dispatcher, control-line parser.
           guard.go          the §4.7 token check.
           agent_windows.go  the nine actions, inside the guest.
           cmd/faultagent/   the guest binary.
runner/    runner.go         config, suite orchestration, report generation.
           execute.go        one run: overlays, marker volume, the three boots, the postconditions.
           vm.go             QEMU, qcow2 overlays, QMP, base-image immutability.
           bootcheck.go      "Windows still boots normally", made unskippable.
           cmd/bootbeacon/   the beacon baked into the base image.
           result.schema.json  the shape of one run's evidence. Fails closed.
           runner.config.json  host and base-image configuration.
REPORT.md  the template the published evidence is filled into.
```

Build: `go build ./gen`, `GOOS=windows GOARCH=amd64 go build -o dist/faultagent.exe ./fault/cmd/faultagent`,
`GOOS=windows GOARCH=amd64 go build -o dist/bootbeacon.exe ./runner/cmd/bootbeacon`,
`go build ./runner`. No third-party dependencies, deliberately: every dependency is something that can
change between the run that produced `REPORT.md` and the run an auditor re-executes.
