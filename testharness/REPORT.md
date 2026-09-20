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

Every value in this table is read out of the **run results**, not out of a configuration file, and every
run in the suite had to agree on it. `runner report` refuses to write this document if two runs disagree,
or if any of them disagrees with `runner.config.json` as it reads now. A header assembled at report time
from a file that can be edited afterwards is a claim about that file, not about the runs.

Both base images are built once and never written to again. Their SHA-256 **and their file modes** are
verified **before and after every single run**; if either ever changed, every result recorded afterwards
would be measured against a different machine than the ones before it, and "100 consecutive runs" would
be 100 runs of different things. It is both images because a destination base that is no longer empty
makes a broken copy look complete. The corpus is baked into the system base image, so the digest above is
covered by the image hash rather than asserted separately.

A corpus regenerated from seed `{{CORPUS_SEED}}` on any machine, on any day, hashes to
`{{CORPUS_DIGEST}}`. That is the whole reason a failure in this suite is reproducible.

## Postconditions checked on every run

| | Check |
|---|---|
| **P0** | The induced fault actually fired at its pin, proven by the progress log. *A suite where nothing was ever induced looks exactly like a suite that passed; this is the check that tells them apart.* |
| **P1** | The installer aborted (or, for F10/F17/F18, correctly continued). |
| **P2** | The system disk's boot-critical region is byte-identical: first 1 MiB of PhysicalDrive0, the full BCD enumeration, and the firmware boot entry. *SAFETY.md phase 6 is the only code permitted to change any of it. This is "the wall was not crossed" as a measurement rather than as the installer's own opinion.* |
| **P3** | Windows still boots normally — beacon from a logged-on session, no bugcheck, no blocking chkdsk, no Recovery Environment, within the normal-boot ceiling. |
| **P4** | Zero files lost, zero corrupted: all {{CORPUS_COUNT}} **source** files re-hashed against the golden manifest after the run, aborted or not. The count is pinned to this report's figure and the manifest the guest verified against is pinned to the digest above, so "12 of 12, clean" cannot present itself as eighteen thousand. |
| **P5** | The installer's `COMPLETE` marker tells the truth: absent after an abort, and present *and corroborated by P8* after a run that claims success. *The marker is written by the thing under test. It is checked against the measurement, never instead of it.* |
| **P6** | **Both** immutable base images are unchanged, by hash and by file mode, after the run. |
| **P7** | The corpus tested is the one this report names. |
| **P8** | The archive the installer materialised on the destination matches the golden manifest by count and per-file hash, re-read from raw bytes by the harness. *Spec §4.1 requires the data to exist in two places with the second copy verified. P4 measures place one; this measures place two, and it takes nothing from the installer. On an aborted run the archive is legitimately partial, so what P8 requires there is that it was measured at all.* |
| **P9** | The guest finished the run on its own. *A run the harness had to kill on its timeout is not an abort — it is an installer that never reached one.* |

There is no `skip` status. A check that did not run is a check that failed, and `runner report`
additionally fails any run whose result does not **contain** every postcondition its kind owes.

Every run the suite owed is in the tables below. A run that produced no result file appears as
`MISSING` and counts against the denominator; the denominators are the shape the suite owed (100 clean,
20 induced), never a count of the files that happened to be written.

## Clean runs — {{CLEAN_PASS}} of {{CLEAN_TOTAL}}

| Run | Source verified | Archive verified | Corrupt | Duration | Result digest | Verdict |
|---|---|---|---|---|---|---|
{{CLEAN_RUN_ROWS}}

`Result digest` is the first 16 hex characters of the SHA-256 of that run's `result.json` **as written
to disk** — `sha256sum` that file and the first 16 characters are this column. The full file,
its serial log, its control log and its screenshots live under `artifacts/{{SUITE_ID}}/<run>/`, each with
its own recorded hash. A row here is a pointer to a file anyone can reopen, not a summary of one.

## Induced-failure runs — {{FAULT_PASS}} of {{FAULT_TOTAL}}

| Run | Scenario | Pin | Overshoot (bytes) | Boot check | Source verified | Archive verified | Result digest | Verdict |
|---|---|---|---|---|---|---|---|---|
{{FAULT_RUN_ROWS}}

**Pin** is the exact file index and byte offset the fault was scheduled to fire at, computed from the
golden manifest by integer arithmetic before the VM started. **Overshoot** is how far past it the fault
actually fired. It is published per run so a reader can judge whether the pin was real or nominal — and
it is also *bounded*: a fire further past its pin than `max_overshoot_bytes` fails P0, because a fault
pinned at 43% that actually fired at 99.9% is a different test wearing this one's name.

Guest-site scenarios additionally record how many bytes were on the destination at the instant the
trigger fired, measured by walking the archive tree rather than by reading the installer's log. Host-site
scenarios do not: the walk would take hundreds of milliseconds and spending them between the pin and a
power cut would move the cut. Those runs are covered instead by P8.

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
