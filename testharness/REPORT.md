# Migration harness — evidence

> **This file is the TEMPLATE.** `runner report` replaces every placeholder token — the ones written in
> double braces — with values read from the run results, and writes `REPORT.filled.md`. A file that still
> contains a placeholder token has not been filled, contains no results, and is not evidence of anything.
> `runner report` refuses to write an output that still has one, because a gap where a number should be
> gets read as a claim.
>
> **No suite has been run yet.** There are no numbers in this repository, and there will be none until
> BLOCKED.md B1 is resolved and a base image exists. Spec §4.4 forbids inventing figures for the website;
> it applies with at least as much force to the document the website would cite.

---

## Claim

Spec §6C, the binary exit condition for Gate 3:

> 100 consecutive runs against a Windows VM with 18,000 synthetic files — 100 successes, zero files lost,
> zero corrupted. 20 runs with induced failure — 20 clean aborts, Windows still boots normally every
> time, zero data loss.

**Result: {{CLEAN_PASS}}/{{CLEAN_TOTAL}} clean · {{FAULT_PASS}}/{{FAULT_TOTAL}} induced-failure.**

Every verdict below is recomputed from each run's `checks` array by `runner report`. The `verdict` field
stored inside a result file is ignored, because a field that says `pass` is exactly what a broken harness
would write.

## Scope — what these runs did and did not exercise

{{INSTALLER_SCOPE}}

This section is not boilerplate and is not moved below the table. "100 successful migrations" read
without it would imply phases this suite did not run.

## What was under test

| | |
|---|---|
| Harness | `{{HARNESS_VERSION}}` |
| Suite | `{{SUITE_ID}}` |
| Windows edition | {{WINDOWS_EDITION}} |
| Image provenance | {{ISO_SOURCE}} |
| Base system image | `{{BASE_SYSTEM_SHA}}` |
| Base destination image | `{{BASE_DEST_SHA}}` |
| Corpus | {{CORPUS_COUNT}} files, profile `{{CORPUS_PROFILE}}`, seed `{{CORPUS_SEED}}` |
| Corpus digest | `{{CORPUS_DIGEST}}` |
| Host profile | `{{HOST_PROFILE}}` |

The base image is built once and never written to again. Its SHA-256 is verified **before and after every
single run**; if it ever changed, every result recorded afterwards would be measured against a different
operating system than the ones before it, and "100 consecutive runs" would be 100 runs of different
things. The corpus is baked into that base image, so the digest above is covered by the image hash rather
than asserted separately.

A corpus regenerated from seed `{{CORPUS_SEED}}` on any machine, on any day, hashes to
`{{CORPUS_DIGEST}}`. That is the whole reason a failure in this suite is reproducible.

## Postconditions checked on every run

| | Check |
|---|---|
| **P0** | The induced fault actually fired at its pin, proven by the progress log. *A suite where nothing was ever induced looks exactly like a suite that passed; this is the check that tells them apart.* |
| **P1** | The installer aborted (or, for F10/F17/F18, correctly continued). |
| **P2** | The system disk's boot-critical region is byte-identical: first 1 MiB of PhysicalDrive0, the full BCD enumeration, and the firmware boot entry. *SAFETY.md phase 6 is the only code permitted to change any of it. This is "the wall was not crossed" as a measurement rather than as the installer's own opinion.* |
| **P3** | Windows still boots normally — beacon from a logged-on session, no bugcheck, no blocking chkdsk, no Recovery Environment, within the normal-boot ceiling. |
| **P4** | Zero files lost, zero corrupted: all {{CORPUS_COUNT}} source files re-hashed against the golden manifest after the run, aborted or not. |
| **P5** | No archive claims to be complete after an abort. |
| **P6** | The immutable base image is unchanged after the run. |
| **P7** | The corpus tested is the one this report names. |

There is no `skip` status. A check that did not run is a check that failed.

## Clean runs — {{CLEAN_PASS}} of {{CLEAN_TOTAL}}

| Run | Verified / expected | Corrupt | Duration | Result digest | Verdict |
|---|---|---|---|---|---|
{{CLEAN_RUN_ROWS}}

`Result digest` is the first 16 hex characters of the SHA-256 of that run's `result.json`. The full file,
its serial log, its control log and its screenshots live under `artifacts/{{SUITE_ID}}/<run>/`, each with
its own recorded hash. A row here is a pointer to a file anyone can reopen, not a summary of one.

## Induced-failure runs — {{FAULT_PASS}} of {{FAULT_TOTAL}}

| Run | Scenario | Pin | Overshoot (bytes) | Boot check | Verified / expected | Result digest | Verdict |
|---|---|---|---|---|---|---|---|
{{FAULT_RUN_ROWS}}

**Pin** is the exact file index and byte offset the fault was scheduled to fire at, computed from the
golden manifest by integer arithmetic before the VM started. **Overshoot** is how far past it the fault
actually fired — bounded by the installer's progress-reporting granularity. It is published per run so a
reader can judge whether the pin was real or nominal, rather than taking it on trust.

### The scenarios

```
{{SCENARIO_TABLE}}
```

Three of the twenty expect the installer to **continue** rather than abort — F10 (source rewritten after
copy, before verify), F17 and F18 (the clock jumps backwards). A tool that aborts on a clock jump is a
tool a school works around by month two, and a tool that gets worked around protects nobody. Those runs
fail if the installer aborts.

## Fidelity notes

{{POWER_CUT_NOTE}}

**OneDrive placeholders are attribute-only.** The corpus contains files carrying
`FILE_ATTRIBUTE_OFFLINE`, which exercises the installer's *detection* path faithfully — the path that
decides whether to warn a user before starting a multi-hundred-gigabyte download over school Wi-Fi. It
does not exercise *hydration*, which needs a registered cloud-filter sync root. Every affected entry in
the golden manifest carries `placeholder_fidelity: "attribute-only"`, and this paragraph exists so the
qualifier does not get lost between the manifest and the claim.

**A `compact` corpus is not the exit condition.** Both profiles have 18,000 files and every structural
case — zero-byte files, near-MAX_PATH paths, alternate data streams, read-only files, files held open —
but `compact` shrinks the long tail from roughly 8.4 GB to roughly 1.5 GB for a disk-constrained host.
The profile is named in the table above. If it says `compact`, this document does not report the §6C
exit condition and must not be cited as though it does.

## What this does not prove

- Nothing about real hardware. Every run is QEMU: no real USB controller, no firmware, no failing
  ten-year-old spinning disk, no BitLocker TPM 1.2 recovery prompt. `hardware/compat.tsv` is where
  physical evidence goes, and it is a different document with a `source` column for exactly this reason.
- Nothing about a real user's data. The corpus is synthetic and its shape is our best model of a school
  laptop, not a measurement of one.
- Nothing about phases outside the scope stated at the top.
- Nothing about an installer build other than the one whose SHA-256 appears in each run's artefact list.

## Reproducing any row

```
runner plan -config runner.config.json          # resolve every pin; needs no VM and no Windows
runner run  -config runner.config.json -scenario F02
```

A single scenario re-runs against a fresh overlay on the same base image and lands at the same pin.
That is the property this harness exists to have: a failure here is a thing you can walk back into, not
a story about an afternoon.
