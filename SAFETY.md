# The ordering contract

This is the most dangerous thing Auros builds. It runs on a stranger's ten-year-old laptop, on a disk
with no backup, containing the only copy of somebody's work. Everything in this document exists because
**Wubi destroyed people's data by getting one ordering wrong**, and we are building the same product.

Read this before touching any code in this repo.

---

## The invariant

> **Nothing is written to the system disk until the user's data exists in two places and the second copy
> has been verified by file count and per-file hash.**

Not "until the copy finishes". Until it is **verified**. There must be a moment — and it must be an
observable, logged moment — where the data exists twice and the original disk has not been touched.

Every other rule in this document is downstream of that one. If a proposed change makes the invariant
harder to state, the change is wrong.

## The phases, and the wall

```
   ┌──────────────────── NON-DESTRUCTIVE ────────────────────┐ ╎ ┌──── DESTRUCTIVE ────┐
   │                                                         │ ╎ │                     │
   1 INVENTORY  →  2 DISCLOSE  →  3 DESTINATION  →  4 COPY  →  5 VERIFY  →╎  6 ARM  →  7 WRITE
   │                                                         │ ╎ │                     │
   │  reads only. aborting here changes nothing, always.     │ ╎ │ aborting here must  │
   └─────────────────────────────────────────────────────────┘ ╎ │ still leave Windows │
                                                          THE WALL │ bootable.        │
```

**Phases 1–5 are read-only with respect to the system disk.** They may write only to the destination
volume, which is by construction not the system disk. An abort anywhere in 1–5 is not a special case
needing cleanup logic; it is a process exit. That property is worth more than any amount of careful
rollback code, and it is why the wall is placed after VERIFY rather than after COPY.

**Phase 6 (ARM) is the only place we cross.** It is one function. It is the only code in the repository
permitted to write to the system disk or to firmware variables, and it refuses to run unless it is handed
a `VerifiedArchive` value — a type that cannot be constructed except by a successful phase 5.

That is the enforcement mechanism: not a check at the top of a function, which someone deletes in a year,
but a value that **cannot be constructed by any safe-Go path** unless verification succeeded. `Arm()`
takes a `VerifiedArchive`. There is no other way to call it.

The wording is exact, because the stronger sentence this file used to carry — "a value that cannot
exist" — is false, and a guarantee overstated by one word is the one people stop re-checking. Go's
unexported fields are a compiler rule, not a memory boundary: two pointer writes through `unsafe` forge
the type. Reflection does not (it sets `flagRO` and panics on `SetBool`), embedding does not,
`encoding/json` does not. So the guarantee has two halves, and both are mechanical:

- **the type**, which closes every safe path; and
- **`TestWall_ForbiddenImports` and `TestWall_SyscallIsConstantsOnly`**, which confine `unsafe` to
  `internal/winenv` and allow `syscall` outside `internal/winenv`/`internal/sysdisk` only for errno and
  signal constants. Forging the proof, or reaching Win32 from a package the wall does not watch, is a
  red build rather than something a reviewer has to catch.

## What each phase must do

### 1 — INVENTORY (read-only)
Resolve the real locations via `SHGetKnownFolderPath`, never by string-concatenating `%USERPROFILE%` —
Documents is redirected far more often than people expect, and a school laptop is exactly where that
happens.

**OneDrive Files On-Demand is a first-class case, not an edge case.** Files with
`FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x00400000) or `FILE_ATTRIBUTE_OFFLINE` are cloud placeholders.
Reading them naively either triggers a multi-hundred-gigabyte hydration over school Wi-Fi or fails
outright. We detect them, count them, and **tell the user before we start** — their choice, stated in
plain words, between hydrating (slow, may not fit) and leaving them in the cloud (fine, since they are
already in two places, which is the whole point of the invariant).

### 2 — DISCLOSE (read-only)
Enumerate the **actual installed-programs list** from the registry and show it by name. Not a generic
warning. The literal list: *"these 34 programs will not come across: Adobe Acrobat, Sage 50, PowerSchool
Installer, …"*

This is prohibition §4.2 and it is also the commercial argument. A school that discovers at month two
that their attendance software is gone becomes a refund and a story. A school that sees the list before
they start either accepts it or walks away, and both of those outcomes are fine. **Hiding it loses them
at month two; showing it loses only the ones we were always going to lose.**

Acknowledgement is required and recorded in the run log.

### 3 — DESTINATION (writes only to the destination)
Must not be the system disk. Verified by volume GUID, **not by drive letter** — a mount point or a
subst'd letter can alias the system volume. Requires free space ≥ (inventory size × 1.1) + manifest.

**The path is resolved before it is trusted, and the volume is derived from the resolved path.**
`D:\backup` can be an NTFS junction onto `C:\AurosBackup`: the letter says D:, the bytes land on C:. So
the destination is resolved through every link first, the operating system is asked which volume holds
the *resolved* directory (`GetVolumePathNameW`, then `GetVolumeNameForVolumeMountPointW`), and the
resolved path — never the one the user typed — is what the copy engine, the run log and the verifier are
given. The identity is re-established once more before the first write and again before the proof is
minted, so a junction swapped in mid-run stops the run instead of redirecting it.

A `Destination` is therefore a proof, not a pair of strings: its fields are unexported and the only
producer is `safety.Resolver`. No caller can assert one into existence.
If no qualifying destination exists, we **refuse to continue**. We do not offer a smaller subset, we do
not offer to skip verification, and we do not offer to use the system disk.

### 4 — COPY (writes only to the destination)
Streaming SHA-256 computed **during** the copy, so the read that produced the bytes we wrote is the read
we hashed. Hashing afterwards from the source is a second read of a file that may have changed in between.

Locked and in-use files are normal on a live machine. Open with backup semantics and shared read/write/
delete; where that is not enough, a VSS snapshot is the correct tool, and if a VSS snapshot cannot be
taken, that file is **quarantined and reported, never silently skipped.**

### 5 — VERIFY (read-only)
Re-read every file **from the destination** and re-hash. Compare count and hash against the manifest.

**A per-file mismatch is retried once, then quarantined and surfaced. The run does not proceed to phase 6
unless the unresolved count is zero.** A literal reading of "any mismatch aborts everything" fails on most
real machines — OneDrive hydrates, antivirus touches files, a browser writes its profile, the user leaves
a document open — and a tool that aborts constantly gets worked around, which is far more dangerous than
one that reports precisely. The safety property is untouched by retrying a file: the invariant is about
**what is true before we cross the wall**, not about how many reads it took to get there.

If the unresolved count is not zero, the user sees the exact list and decides. We do not decide for them,
and the default is to stop.

### 6 — ARM (first system-disk write)
Takes a `VerifiedArchive`. In order:
1. **Suspend BitLocker for exactly one boot** (`manage-bde -protectors -disable C: -RebootCount 1`).
   On TPM 1.2 — common across 2012–2015 — changing firmware boot order triggers a recovery-key prompt.
   Stranding a user at a recovery prompt **on the abort path** is the worst outcome this tool can produce,
   so this is unconditional, not an option.

   "Unconditional" means the step is planned unless BitLocker is **positively known to be off**. The
   finding is a tri-state and its zero value is Unknown, which is treated as protected: suspending
   protectors on a machine that is not using BitLocker is a no-op, and not suspending them on a machine
   that is costs a school its laptop. Where phase 1 could not tell, `internal/sysdisk` probes
   `manage-bde -status` — a read — before the plan is built. **And a commit-mode run refuses to arm at
   all while the firmware facts are not established**, because arming on facts the tool admits it never
   checked is arming blind.
2. Set one-time boot, preferring `BootNext`, falling back to `shutdown /r /fw` (send the user to the
   firmware menu with instructions) because `BootNext` is not honoured reliably across vendors.
3. Restart.

**We do not write the boot medium. D13.** An earlier version of this section had "write the boot medium"
as step 2, carried over from SPEC §6C.5. D13 removed it from the product: writing boot media means an
elevated raw handle to a physical drive, a dismount of every child volume, a hand-rolled GPT and ESP, and
sector-aligned raw writes — irreversibly destructive, on a machine we do not own, with no undo. The media
is produced elsewhere by a machine with the tools for it, and this tool at most points the firmware at a
stick the user already made.

That deletion is why this file exists as a separate contract rather than as a restatement of the spec.
`auros-web/src/content/migration/20-files.md` tells the customer, in as many words, that *the Windows
program does not write your USB stick*. A safety contract that still listed the write as a step would
mean the code was written against one promise and the customer bought a different one, and the one the
customer read is the one that matters.

**Every step is individually reversible, and the reversal is tested more than the action.**

**The reversals run on a context the cancellation cannot reach.** If the user presses Ctrl-C between
step 1 and step 2, the run's context is already dead, and reversals built from it refuse to start a
process — leaving BitLocker suspended and the boot order changed, which is the half-armed machine the
unwind exists to prevent, produced by the abort path itself. So the unwind derives its context with
`context.WithoutCancel` and its own deadline, and a panic inside a step unwinds before it propagates.
The step loop and the unwind live in an untagged file so that the abort path is testable on every
platform; only the part that starts a process is behind `auros_arm_enabled`.

### 7 — RESTORE (Linux side, first boot)
Restore from the archive, **re-verify count and hash a third time**, and report the count on the desktop
where the user can see it. A discrepancy is shown, never swallowed.

## Rules that are not negotiable

1. **`Arm()` takes a `VerifiedArchive` and there is no other constructor.** Enforcement by type, not by
   convention.
2. **The abort path is tested more than the happy path.** Spec §6C. 100 clean runs and 20 induced-failure
   runs, and if the ratio of abort tests to happy tests ever drops below 1:1, the suite has regressed.
3. **Never tested against the operator's own machine.** Windows in a VM, synthetic files, destroyed
   repeatedly. Spec §4.7.
4. **No network dependency in phases 1–6.** A school's uplink is not a safety-critical component.
5. **The run log is written to the destination volume, not the system disk,** so a post-mortem survives
   a machine that will not boot.
6. **Dry-run is the default.** `--commit` is required to cross the wall, and the UI says which mode it is
   in at all times.
7. **No claim about the system disk is a literal.** "Nothing was written to the system disk" is printed
   only where it has been measured — the resolved destination's volume GUID compared against the system
   volume's, at the moment of logging. A sentence that is printed whether or not it is true is worse than
   no sentence, and three of them were.
8. **No refusal has an exported off switch.** `VerifyRequest.AllowEmpty` was one: an exported bool that
   disabled the empty-archive refusal whose own doc comment names that as the failure it catches. Options
   that weaken a check are unexported and in-package, the way `copyengine`'s test hooks are.

## What "one restart" actually means, and what we may say

We may not say "one restart" without qualification. Three things break it on this exact cohort, and all
three need the user to touch firmware:

- **BitLocker on TPM 1.2** — mitigated unconditionally in phase 6, above.
- **Secure Boot** — Fedora's shim is signed by Microsoft's *third-party* UEFI CA, which some Lenovo and
  Dell business firmware ships disabled. That is a firmware toggle we cannot automate.
- **`BootNext` is not reliably honoured** — Fast Boot can skip USB enumeration, and some OEM firmware
  rewrites `BootOrder` at POST.

So the tool **detects all three during phase 1 and tells the user before they start**, and the firmware-
menu fallback is a first-class path rather than an error case. The website wording is a §9 decision
reserved for the human; the honest form is *"one restart on most machines — some need one firmware
setting changed, and the tool tells you which before you begin."*
