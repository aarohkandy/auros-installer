# auros-installer

The Windows-side migration tool. **Read [SAFETY.md](SAFETY.md) before touching any code here.**
It is the ordering contract and it is binding.

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

## What this tool does not do

- **It does not write boot media** (DECISIONS.md D13). That would mean an elevated raw handle
  on `\\.\PhysicalDriveN`, a hand-rolled GPT and sector-aligned writes — irreversibly
  destructive on a machine we do not own. Install media is made elsewhere. SAFETY.md §6 step 2
  still describes writing it; **D13 supersedes that and the divergence is deliberate.**
- **It does not migrate programs.** No Windows program migrates. The tool prints the actual
  installed-programs list by name and refuses to continue without acknowledgement.
- **It does not migrate saved passwords, cookies or payment data** from Chrome or Edge
  (D15). Bookmarks and history do.

## Tests

The abort path is tested more than the happy path (SPEC §6C, SAFETY.md rule 2), and CI fails
if that ratio ever inverts. Every abort test fingerprints a stand-in system disk before the
run and asserts it is byte-identical afterwards — the invariant is *asserted*, not assumed.

```
go test ./... -race -count=1
```
