# auros-installer

Both halves of the migration: the Windows tool that copies a school's files off, and the Linux
tool that puts them back. **Read [SAFETY.md](SAFETY.md) before touching any code here.**
It is the ordering contract and it is binding.

| Command | Runs on | Phases |
|---|---|---|
| `cmd/auros-migrate` | the old Windows machine | 1–6 |
| `cmd/auros-restore` | the new Auros machine, at first login | 7 |

## The one thing to understand

```
   ┌──────────────── NON-DESTRUCTIVE ────────────────┐ ╎ ┌─── DESTRUCTIVE ───┐
   1 INVENTORY → 2 DISCLOSE → 3 DESTINATION → 4 COPY → 5 VERIFY →╎ 6 ARM → 7 RESTORE
                                                            THE WALL
```

Nothing is written to the system disk until the user's data exists in two places and the
second copy has been **verified** by file count and per-file SHA-256.

That is not enforced by a check at the top of a function, because somebody deletes those.
It is enforced by a type:

```go
// internal/safety/verified.go — every field unexported, no exported constructor
type VerifiedArchive struct { valid bool; /* ... */ }

// internal/safety/arm.go — the only function permitted to touch the system disk
func Arm(ctx context.Context, m *Machine, va VerifiedArchive, req ArmRequest) (*ArmResult, error)
```

`safety.Verify` is the only code in the program that constructs a `VerifiedArchive`, and it
does so only after re-reading every file from the destination. Go's visibility rules do the
rest: no other package can build one, and the zero value is inert.

`internal/safety/wall_test.go` is the second half. It parses every `.go` file in the repo and
fails if any package other than `internal/safety` imports `internal/sysdisk`, or if any package
other than `internal/sysdisk` imports `os/exec`. **That test is the wall.**

`internal/safety/wall_restore_test.go` extends it to phase 7, because the wall does not stop at
the wall. The restore packages may not import `internal/sysdisk`, `internal/safety`, `os/exec`
or `unsafe`; only `internal/deskbus` may open a socket; and the only network string it may
pass to `net.Dial` is the `unix` constant, asserted by reading its AST.

That last rule is why there is a hand-written D-Bus client in this repository instead of a call
to `notify-send`. Running a subprocess is confined to one package by a test, and that
confinement is worth more than the convenience of a toast.

## Two gates before anything can touch a disk

1. **`--commit`.** Dry run is the default and the mode is printed at every phase.
2. **The `auros_arm_enabled` build tag.** The privileged steps are *compiled out* of every
   binary CI publishes and every binary you get from `go build`. Enabling them is a decision
   recorded in a build command. They stay off until SPEC §10 gate 3 — 100 clean migrations and
   20 clean aborts against a Windows VM, never the operator's own machine (SPEC §4.7).

## Layout

| Path | Phase | Writes to |
|---|---|---|
| `internal/winenv` | — | nothing (Win32 behind an interface + a synthetic impl) |
| `internal/manifest` | — | nothing (per-file SHA-256, stable serialization) |
| `internal/copyengine` | 4 | destination only |
| `internal/verify` | 5 | nothing |
| `internal/quarantine` | 4, 5 | nothing |
| `internal/runlog` | all | destination only |
| `internal/safety` | 5, 6 | **the wall**; the only importer of `sysdisk` |
| `internal/sysdisk` | 6 | the system disk — and only when built with `auros_arm_enabled` |
| `internal/restore` | 7 | the user's home directory only |
| `internal/netprofile` | 7 | NetworkManager keyfiles, mode 0600, read back off the disk |
| `internal/printers` | 7 | nothing (it decides; it creates no queue) |
| `internal/deskbus` | 7 | the session bus socket, and nothing else |

## Phase 7 — the Linux side

```
FIND      the archive, by its MANIFEST, on any attached volume. Never a
          remembered path, never a drive letter. Several found means ASK.
VERIFY    every file and the total count, read FROM THE ARCHIVE, BEFORE
          anything is written. A mismatch STOPS: the user still has the
          archive, and a half-written restore on top of a damaged one makes
          a bad day worse.
PLAN      every destination, validated together. One path that would land
          outside the home directory refuses the whole run.
WRITE     atomically, per file. Never over a file we cannot prove is ours.
RE-VERIFY every restored file, read back off the home directory. Third check.
REPORT    on the desktop — a note they can open, and a pop-up. Any
          discrepancy is SHOWN.
```

**It is safe to run twice.** A restore stopped by a power cut is finished by running it again:
every file already on disk is checked by hash and skipped. That property comes from re-hashing
what is on the disk, never from a state file — because the disk is the thing that survives the
power cut.

**Nothing writes to the archive.** Not a lock file, not a stamp, not a log. It is the only copy
of the data, at the moment the Windows disk it came from has already been overwritten.

See [packaging/systemd/README.md](packaging/systemd/README.md) for what goes into the image, and for the
two privileged steps that are deliberately **not** in this repository yet.

## What this tool does not do

- **It does not write boot media** (DECISIONS.md D13). That would mean an elevated raw handle
  on `\\.\PhysicalDriveN`, a hand-rolled GPT and sector-aligned writes — irreversibly
  destructive on a machine we do not own. Install media is made elsewhere. SAFETY.md §6 step 2
  still describes writing it; **D13 supersedes that and the divergence is deliberate.**
- **It does not migrate programs.** No Windows program migrates. The tool prints the actual
  installed-programs list by name and refuses to continue without acknowledgement.
- **It does not migrate saved passwords, cookies or payment data** from Chrome or Edge
  (D15). Bookmarks and history do. The restore enforces this with an ALLOW-list, not a
  deny-list: a file Google adds to a profile next year does not migrate until somebody
  decides it should.
- **It does not switch the Wi-Fi networks on, and it does not add printer queues.** Both need
  root. It writes the Wi-Fi keyfiles at mode 0600 and the printer plan as data, and the note
  on the desktop says in plain words that they are saved and not yet live. Nothing anywhere
  reports either as migrated. See `packaging/systemd/README.md` and BLOCKED.md B19.
- **It does not create a queue for a printer it would have to invent an address for.** A USB
  port name is alphanumeric and sails through a host-shaped test; `ipp://USB001/ipp/print` was
  a real bug in this code for about ten minutes. A queue that exists and cannot print is worse
  than no queue, because the user believes the problem is their document.

## Tests

The abort path is tested more than the happy path (SPEC §6C, SAFETY.md rule 2), and CI fails
if that ratio ever inverts. Every abort test fingerprints a stand-in system disk before the
run and asserts it is byte-identical afterwards — the invariant is *asserted*, not assumed.

```
go test ./... -race -count=1
```

**And the suite is watched failing.** `tools/prove-red.sh` reintroduces fourteen specific
defects, one at a time, into a scratch copy — the pre-verification stops being a gate, the
re-check stops comparing, Chrome's password database joins the allow-list, the aggregate gate
ignores failed files — and requires the suite that owns each one to go red *for the stated
reason*. A green suite cannot tell you that its assertions would disagree with wrong code
(DECISIONS.md D34, D37).

```
tools/prove-red.sh          # all of them
tools/prove-red.sh M05      # one
tools/dbus-e2e/run.sh       # the notification, through a real dbus-daemon
```

Two of the fourteen were found by writing it: the plan's home-directory assertion was
**unreachable** behind an earlier check and could never have failed, and the report counted
damaged files instead of naming them.
