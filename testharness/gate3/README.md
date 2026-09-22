# `gate3` — Gate 3 against a real, throwaway Windows machine

This is the half of the harness that runs the **real `auros-migrate` CLI**, exactly as it ships, on an
ephemeral `windows-latest` runner, and then measures what happened without taking anything from the
program under test.

It is not a replacement for [`../runner`](../runner), which drives QEMU and can boot the machine
afterwards. It is the half that DECISIONS.md **D27** made possible: a hosted Windows runner is a
throwaway Windows machine, destroyed after every job by construction, and there are twenty of them at
once.

Read [`../../SAFETY.md`](../../SAFETY.md) first. Everything here exists to make one sentence checkable:

> **Nothing is written to the system disk until the user's data exists in two places and the second copy
> has been verified by file count and per-file hash.**

---

## 1. What the previous harness got wrong, and why it matters

`.github/workflows/gate3.yml` used to be written against a CLI that does not exist:

| it called | the installer actually has |
|---|---|
| `--destination <dir>` | `--dest <dir>` |
| `--json`, `--runlog <file>` | neither |
| `auros-migrate verify --archive … --against …` | no subcommands at all |
| *(nothing)* | `--i-understand-programs-do-not-migrate`, **required** |
| `go build ./testharness/gen` from the repo root | `testharness/` is a separate module |

The missing acknowledgement flag is the one worth dwelling on: without it every run stops in **phase 2**,
having copied nothing. A hundred runs of that would have produced a hundred identical early exits, and
the workflow would have scored them however its exit-code test happened to read — the most expensive
possible way to test nothing at all.

## 2. How a run is measured

Nothing in a verdict comes from the installer's account of itself.

**The invariant — nothing written to C:, by enforcement.** The installer runs on the migration account's
**standard-user token**: the account is not an administrator, and the run refuses a token that is elevated
or holds Administrators enabled. What a standard user may still write on C: is **enumerated on the
runner, not remembered**: every directory of C: is opened as the account for `MAXIMUM_ALLOWED` and the
granted mask read back (nothing is written), and each directory where it holds any write-class right
(`0xd0156`: add-file, add-subdirectory, write-EA, delete-child, write-attributes, delete, write-DAC,
write-owner) gets an explicit deny ACE for the account on that directory alone —
`SetKernelObjectSecurity`, no propagation. The list, its roots with counts and the scan time are in the
result (`enforcement.writable_dirs`, `writable_roots`, `scan_seconds`). Before the run the deny is proved:
the granted mask is re-read on every denied directory, a directory and a file are created as the account
in a sample (`C:\`, `C:\ProgramData`, `C:\Windows\Temp`, `C:\Program Files`, `C:\Users\Public`, its
profile and TEMP, the corpus, the first writable directories) and every one must be refused, and the
installer's own write patterns on each destination must succeed. After the run every directory's saved
descriptor is put back (`enforcement.restored`). There are no exemptions: the installer writes no TEMP,
logs or caches on Windows. C1 then reads the ETW trace for the installer's tree and fails on any
write-class operation on C:, any open Windows refused (`STATUS_ACCESS_DENIED`: it tried), or an
enforcement that was not verified. Measured history: a deny ACE on `C:\` took 282 s and never reached
`C:\ProgramData`; Low integrity blocked C: but also every file create on the NTFS destination.

Known ceilings, stated: a directory's owner keeps WRITE_DAC whatever its DACL says, and an existing file
whose own ACL grants the account write is not denied (only directories are); both are left to the ETW
audit, which fails the write itself.

One consequence, stated: as a standard user the installer's `manage-bde -status` probe cannot answer, so
BitLocker is reported unknown and the suspend step is planned anyway — the path the installer already
takes on a machine where the probe fails.

The whole-disk change-journal diff this replaced never converged on a shared runner: Windows' own
servicing writes C: whatever the installer does. It is still recorded, as a report line that never gates.

**Progress — where "43% of the copy" is.** From the Windows **job object's I/O accounting**: the bytes
the operating system saw this process tree read and write. The installer has no progress protocol and
this harness does not ask it to grow one; a pin is therefore a number the OS produced, and an installer
that reported a copy it was not performing could not move it. Every fire record also carries how much
the destination volume's free space had actually fallen at that instant.

**Both trees, re-hashed.** After the run the harness re-reads every source file and every archive file
and compares them against the golden manifest `gen` wrote — a different module, a different hash loop,
a different path implementation. "Zero corrupted" is a comparison between two independent accounts of
the same bytes; if one program produced both sides it would only prove that program is self-consistent.

**What the installer says** is read last, and only ever to catch it claiming something the measurements
contradict — a run log that records a verified archive on a run that aborted is a far worse finding than
the abort. Its manifest on the destination is parsed by a second implementation of the format, because
that file is what the Linux-side restore will re-check every hash against.

**An abort has to be for its own reason.** Each scenario names the reason the installer must give —
one of `internal/quarantine`'s closed set, or the text of a phase-3 refusal — and an abort that does not
name it fails. Twenty scenarios all aborting for one unrelated reason is a green suite that proves
nothing, and this is not hypothetical: see §4.

## 3. The known-folders problem

`auros-migrate` inventories the known folders of whoever runs it, always, through
`SHGetKnownFolderPath`. That is not incidental and must not become a flag: SAFETY.md phase 1 exists
because a tool that can be told to skip the user's real folders is a tool that will one day skip them.

On a hosted runner that would mean copying the CI account's own Documents, Desktop, Pictures and
AppData alongside the corpus — and a comparison against a golden manifest would either fail for reasons
that have nothing to do with the installer or, worse, pass while measuring files nobody generated.

**What this harness does:** it creates a local account, **redirects that account's known folders into
the synthetic corpus**, and runs the installer as that account.

Folder redirection is not a trick invented for the test. It is the configuration SAFETY.md phase 1 is
written about — *"Documents is redirected far more often than people expect, and a school laptop is
exactly where that happens"* — so the arrangement is more faithful than a stock profile, not less. It
also buys a check the harness could not otherwise make: an installer that built its paths from
`%USERPROFILE%` instead of asking Windows would inventory empty folders, and the run would go red on
check **C9** rather than quietly copying nothing.

Two alternatives were rejected. A dedicated account whose **profile directory** is the corpus puts the
account's own registry hive inside the inventoried folders — see §4, which is what happens. And a
**build-tagged switch** in the installer that restricted the inventory to `--source` would have put a
code path that skips the user's real folders into the repository, where the next person in a hurry
finds it.

**Nothing in `internal/` or `cmd/` was changed to make this harness work.**

## 4. What the first real run found

The first configuration redirected Local AppData into the corpus, and Windows put the account's classes
hive — `%LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat` — there with it, because that path is decided
when a profile is first loaded. The kernel holds that file open with no sharing. The installer could not
read it, quarantined it, and then refused to issue a `VerifiedArchive` because SAFETY.md phase 5 does
not proceed while the unresolved count is non-zero. Every run ended that way.

Two consequences, and they are different:

- **A finding about the product**, reported in full at the end of this file. Every logged-on Windows
  account has that file in that folder.
- **A problem for this suite**, because twenty scenarios that all abort for the same unrelated reason
  are twenty runs that prove nothing. So the harness loads the profile once, before the redirection is
  written, and never unloads it: the hive stays at the account's default location, outside the corpus.
  `prepare` and every `run` refuse to start if it is there anyway.

## 5. Spec §4.7 on a hosted runner

*"Never tested against the operator's own machine."* This program creates a local account, redirects its
known folders, formats a volume, moves the system clock and writes a corpus into `C:\`. On a laptop that
is a bad afternoon.

So it refuses twice. The machine must identify itself as an ephemeral GitHub-hosted runner
(`RUNNER_ENVIRONMENT`, `GITHUB_RUN_ID`), **and** a token minted on that machine must vouch for the exact
volume serials in play — the same `fault.Token` the VM harness uses, and the same fail-closed check.
Minting is itself refused off a hosted runner, so there is no path that starts on somebody's desk.

## 6. Honest limits

- **A process kill is not a power cut.** `TerminateJobObject` takes the installer's own buffers and
  deferred cleanup with it, which is the half that matters for "did it write a completion marker
  optimistically". It does not take the operating system's cache with it. A real power cut is Gate 5,
  or the QEMU harness with `cache.direct=on`.
- **No firmware.** BitLocker suspension, `BootNext` and ARM itself are compiled out of the binary under
  test and are deferred to Gate 5's physical machines, which is the only place they could ever be
  honestly tested (D27).
- **Redirecting Local AppData is synthetic.** Group Policy cannot redirect it, precisely because of the
  hive. The other seven folders are redirected exactly as a school's fileserver setup would.
- **Real-time antivirus is off on these runners.** The scenario that takes an exclusive handle on a file
  reproduces what a scanner does to one file; it does not reproduce a scanner's load.
- **`compact` is not the exit condition.** Both profiles have 18,000 files and every structural case,
  but `compact` shrinks the byte volume. The profile is recorded in every result and printed in the
  summary.
- **Alternate data streams are measured, not gated.** The corpus carries them; the installer copies the
  main stream only and does not report the streams it leaves behind. That is reported as a finding on
  every run rather than folded into "zero files lost", which is a statement about files.

## 7. Running it

```
gate3 suite                      # the catalogue this suite owes
gate3 plan   -golden …           # resolve every pin by integer arithmetic. No Windows needed.
gate3 aggregate -results … -expect-clean 100 -expect-faults F01,…
```

Those three work anywhere. Everything that touches a machine — `mint-token`, `prepare`, `run`,
`prove-red` — is Windows-only and refuses to exist elsewhere.

`prove-red` is DECISIONS.md **D34** applied to the one check that cannot be exercised off a real
machine: it starts a copy of itself at Low integrity through the run's own launcher and trace; the copy
reads a C: file, writes into a Low-labelled C: directory that is not exempt, is refused writing into an
ordinary one, and writes into a declared exemption. Each must be classified correctly and C1 must go red.
A check nobody has watched fail is a check nobody knows works. It runs as its own job in the workflow,
and the verdict refuses to pass if it did not.
