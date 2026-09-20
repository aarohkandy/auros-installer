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
but a value that **cannot exist** unless verification succeeded. `Arm()` takes a `VerifiedArchive`. There
is no other way to call it.

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
2. Write the boot medium.
3. Set one-time boot, preferring `BootNext`, falling back to `shutdown /r /fw` (send the user to the
   firmware menu with instructions) because `BootNext` is not honoured reliably across vendors.
4. Restart.

**Every step is individually reversible, and the reversal is tested more than the action.**

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
