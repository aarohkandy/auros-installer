#!/usr/bin/env bash
# prove-red.sh — break the Linux restore on purpose, one defect at a time, and
# require the suite that owns each defect to go RED for the stated reason.
#
# Why this exists, in one sentence: a green test suite cannot tell you that its
# assertions would disagree with wrong code.
#
# DECISIONS.md D34 turned "a step that cannot fail is not a check" into a
# mechanism after the rule alone had been broken three times in reviewed files.
# D37 sharpened it: the aggregate gate itself had the bug it was written to
# catch, and nobody found it until something broke the gate on purpose. This is
# that mechanism for `cmd/auros-restore`.
#
# Each mutation below reintroduces a SPECIFIC defect — several of them defects
# that were really in this code during the afternoon it was written — and names
# the test that must catch it and a phrase that must appear in the failure. A
# mutation that turns the suite red for an unrelated reason is NOT scored as a
# catch: that is how a suite gets credit for noticing a compile error.
#
# Usage:  tools/prove-red.sh            all mutations
#         tools/prove-red.sh M03        one of them
set -o errexit -o nounset -o pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
SKIPPED_FILTER="${1:-}"

# mutate FILE OLD NEW — exact string replacement, in the scratch copy only.
# An OLD that is absent, or present more than once, is a FAILURE of this
# script rather than something to work around: it means the code moved and
# this mutation is no longer reintroducing the defect it claims to.
mutate() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding='utf-8').read()
n = s.count(old)
if n != 1:
    sys.stderr.write(
        "prove-red: the text this mutation replaces appears %d times in %s (want exactly 1).\n"
        "prove-red: the code moved; fix the mutation rather than deleting it.\n"
        "prove-red: looking for:\n---\n%s\n---\n" % (n, path, old))
    sys.exit(2)
open(path, 'w', encoding='utf-8').write(s.replace(old, new))
PY
}

# run_case ID DESCRIPTION PKG TESTPATTERN EXPECTED_PHRASE MUTATOR_FN
run_case() {
  local id="$1" desc="$2" pkg="$3" pattern="$4" phrase="$5" fn="$6"
  if [ -n "$SKIPPED_FILTER" ] && [ "$SKIPPED_FILTER" != "$id" ]; then return 0; fi

  local dir="$WORK/$id"
  mkdir -p "$dir"
  # cp -a, not git: the working tree is what is being proved, including
  # uncommitted work.
  tar -C "$REPO" --exclude=.git --exclude=testharness --exclude=packaging -cf - . | tar -C "$dir" -xf -

  echo "── $id  $desc"
  if ! "$fn" "$dir"; then
    echo "   MUTATION FAILED TO APPLY — this script is out of date, which is itself a red."
    FAIL=$((FAIL + 1))
    return 0
  fi

  local out="$dir/.out"
  set +o errexit
  (cd "$dir" && go test "$pkg" -run "$pattern" -count=1 2>&1) >"$out"
  local rc=$?
  set -o errexit

  if [ "$rc" -eq 0 ]; then
    echo "   NOT CAUGHT: $pattern still passes with the defect reintroduced."
    echo "   ────────────────────────────────────────────────────────────"
    sed 's/^/   | /' "$out" | head -20
    FAIL=$((FAIL + 1))
    return 0
  fi
  if ! grep -qF -- "$phrase" "$out"; then
    echo "   RED FOR THE WRONG REASON: expected the failure to mention:"
    echo "     $phrase"
    echo "   ────────────────────────────────────────────────────────────"
    sed 's/^/   | /' "$out" | head -30
    FAIL=$((FAIL + 1))
    return 0
  fi
  echo "   caught."
  PASS=$((PASS + 1))
}

# ── M01 ───────────────────────────────────────────────────────────────────
# The pre-verification stops being a gate. This is the defect the whole
# program is arranged to prevent: writing onto the new machine from an archive
# that did not check out, while the user's only copy is that archive.
m01() {
  mutate "$1/internal/restore/run.go" \
    '	if !pre.Clean() {
		s.FinishedAt = now()
		s.StoppedEarly = "the archive did not verify; nothing was written"' \
    '	if false {
		s.FinishedAt = now()
		s.StoppedEarly = "the archive did not verify; nothing was written"'
}

# ── M02 ───────────────────────────────────────────────────────────────────
# A pre-existing file is overwritten instead of being left alone. On a machine
# a user has already started working on, this destroys work that was never
# backed up anywhere.
m02() {
  mutate "$1/internal/restore/run.go" \
    '			target = aside(it.Route.Target, n)
			continue
		default:' \
    '			break
		default:'
}

# ── M03 ───────────────────────────────────────────────────────────────────
# The third check stops comparing. "We checked again afterwards" becomes a
# sentence rather than a fact.
m03() {
  mutate "$1/internal/restore/run.go" \
    '		if sum != it.Entry.SHA256 {' \
    '		if false && sum != it.Entry.SHA256 {'
}

# ── M04 ───────────────────────────────────────────────────────────────────
# The plan stops asserting that the destination is inside the home directory.
# CleanRel already refuses "..", so this is the SECOND of two independent
# checks — and a check that only ever runs behind another one is exactly the
# check nobody notices has stopped working.
m04() {
  mutate "$1/internal/restore/plan.go" \
    '			if !underPath(target, l.Home) {' \
    '			if false && !underPath(target, l.Home) {'
}

# ── M04b ──────────────────────────────────────────────────────────────────
# The plan stops re-validating the paths the manifest hands it. The manifest's
# digest says the bytes are the bytes that were written; it does not say the
# program that wrote them had no bugs.
#
# Note what this one proved when it was first written: disabling THIS check
# left the suite green, because the home-directory assertion below caught the
# same case. The two checks really are independent, which is the good news,
# and it meant the CleanRel arm had no case of its own — one that lands
# somewhere perfectly ordinary inside the home directory and is still wrong.
m04b() {
  mutate "$1/internal/restore/plan.go" \
    '		clean, err := manifest.CleanRel(e.Path)' \
    '		clean, err := e.Path, error(nil)'
}

# ── M05 ───────────────────────────────────────────────────────────────────
# D15 breach: Chrome's password database joins the allow-list. This is the
# mutation that matters most commercially — it is the difference between a
# product that tells the truth about what migrates and one that ships a
# password blob to a machine that cannot decrypt it.
m05() {
  mutate "$1/internal/restore/route.go" \
    '	"Favicons":  "the site icons your history displays",' \
    '	"Favicons":   "the site icons your history displays",
	"Login Data": "your saved passwords",'
}

# ── M06 ───────────────────────────────────────────────────────────────────
# The Wi-Fi keyfile permission check stops being a check. A world-readable
# file holding a school's Wi-Fi password is a real disclosure AND a silent
# failure, because NetworkManager refuses to load it.
m06() {
  mutate "$1/internal/netprofile/netprofile.go" \
    '		if got != Mode {' \
    '		if false && got != Mode {'
}

# ── M07 ───────────────────────────────────────────────────────────────────
# An 802.1X network gets a connection file anyway. The credentials are not in
# the archive and cannot be, so the file is a promise that fails in front of a
# classroom for no visible reason.
m07() {
  mutate "$1/internal/netprofile/netprofile.go" \
    '		if v != VerdictWrite {
			out = append(out, rec)
			continue
		}' \
    '		if false {
			out = append(out, rec)
			continue
		}'
}

# ── M08 ───────────────────────────────────────────────────────────────────
# The real defect this code had: a USB port name is alphanumeric, so a
# host-shaped test accepts "USB001" and invents ipp://USB001/ipp/print. Put
# the ordering back the wrong way round.
m08() {
  mutate "$1/internal/printers/printers.go" \
    '	if isLocalPort(strings.ToLower(h)) {
		return "", false
	}' \
    '	if false {
		return "", false
	}'
  mutate "$1/internal/printers/printers.go" \
    '	if isLocalPort(lowPort) {
		d.Disp = DispLocal' \
    '	if false {
		d.Disp = DispLocal'
}

# ── M09 ───────────────────────────────────────────────────────────────────
# D37, exactly: the aggregate gate reports PASS whatever the suites under it
# did. `verify` had this bug; so could this.
m09() {
  mutate "$1/internal/restore/run.go" \
    '	if s.Counts[OutFailed] > 0 {
		return false
	}' \
    '	if false {
		return false
	}'
}

# ── M10 ───────────────────────────────────────────────────────────────────
# Several archives attached, and the program picks one. Restoring the wrong
# archive onto a fresh machine is not something the user can undo.
m10() {
  mutate "$1/internal/restore/archive.go" \
    '	if len(found) > 1 && !allSame {' \
    '	if false && len(found) > 1 && !allSame {'
}

# ── M11 ───────────────────────────────────────────────────────────────────
# The notification path acquires the ability to open a real network socket.
m11() {
  mutate "$1/internal/deskbus/conn.go" \
    '	c, err := net.DialTimeout(unixNetwork, addr, timeout)' \
    '	c, err := net.DialTimeout("tcp", addr, timeout)'
}

# ── M12 ───────────────────────────────────────────────────────────────────
# The restore shells out. This is the wall, and the wall is the reason the
# Windows side can say "one function touches the system disk" and mean it.
m12() {
  mutate "$1/internal/restore/handlers.go" \
    'import (
	"context"' \
    'import (
	"context"
	"os/exec"'
  mutate "$1/internal/restore/handlers.go" \
    'const defaultProfileMaxBytes = 1 << 20 // 1 MiB: a wireless profile is ~2 KB' \
    'const defaultProfileMaxBytes = 1 << 20 // 1 MiB: a wireless profile is ~2 KB

var _ = exec.Command'
}

# ── M13 ───────────────────────────────────────────────────────────────────
# The report counts damaged files instead of naming them. "1 of 1 files
# disagreed" is a swallowed discrepancy wearing a number: the user cannot act
# on it and cannot tell anyone else what happened. This was a real bug in this
# file, found by the test that now guards it.
m13() {
  mutate "$1/internal/restore/report.go" \
    '		for i, d := range s.PreVerify.Disagreements {' \
    '		for i, d := range s.PreVerify.Disagreements[:0] {'
  mutate "$1/internal/restore/report.go" \
    '	if s.PreVerify != nil && len(s.PreVerify.Disagreements) > 0 {
		w("%s", preVerifyHeading)' \
    '	if false {
		w("%s", preVerifyHeading)'
}

# ── M14 ───────────────────────────────────────────────────────────────────
# FATAL, and real: the finder stops looking one level down. The Windows half
# writes <mount>/auros-backup/_auros/manifest.tsv; the first version of the
# finder only ever stat'ed <mount>/_auros, so an intact archive was reported
# as "no backup drive is attached", exit 0, after the Windows disk was gone.
m14() {
  mutate "$1/internal/restore/archive.go" \
    '	out := []string{root, filepath.Join(root, manifest.ArchiveSubdir)}
	ents, err := os.ReadDir(root)' \
    '	out := []string{root}
	ents, err := os.ReadDir(root)
	ents = nil'
}

# ── M14b ──────────────────────────────────────────────────────────────────
# The agreed name moves. Every stick made before the change carries the old
# one, so this is pinned as a literal where the constant is defined...
m14b() {
  mutate "$1/internal/manifest/manifest.go" \
    '	ArchiveSubdir = "auros-backup"' \
    '	ArchiveSubdir = "auros-archive"'
}

# ── M14c ──────────────────────────────────────────────────────────────────
# ...and where the Windows half uses it, which is where the halves drifted
# apart the first time: its own literal instead of the shared constant.
m14c() {
  mutate "$1/cmd/auros-migrate/main.go" \
    '	d, rejected, err := r.Choose(manifest.ArchiveSubdir, inventoryBytes)' \
    '	d, rejected, err := r.Choose("auros-archive", inventoryBytes)'
}

# ── M15 ───────────────────────────────────────────────────────────────────
# FATAL, and real: Summary.Clean stops reading the Wi-Fi and printer reports.
# A refused keyfile became "Your files are here", a calm popup and a stamp
# that stopped the unit ever running again.
m15() {
  mutate "$1/internal/restore/run.go" \
    '		if h != nil && len(h.Problems) > 0 {
			return false
		}' \
    '		if false && h != nil && len(h.Problems) > 0 {
			return false
		}'
}

# ── M16 ───────────────────────────────────────────────────────────────────
# The layout's check goes back to being lexical: a user directory that is a
# link out of the home passes because its NAME is inside the home.
m16() {
  mutate "$1/internal/restore/layout.go" \
    '		if !underPath(rp, realHome) {
			bad = append(bad, fmt.Sprintf("%s=%s (from %s) is a link' \
    '		if false && !underPath(rp, realHome) {
			bad = append(bad, fmt.Sprintf("%s=%s (from %s) is a link'
}

# ── M16b ──────────────────────────────────────────────────────────────────
# The plan's check goes back to being lexical: a link one level INSIDE a user
# directory — which the layout never looks at — carries the file out.
m16b() {
  mutate "$1/internal/restore/plan.go" \
    '			if !underPath(rd, l.realHome) {' \
    '			if false && !underPath(rd, l.realHome) {'
}

# ── M16c ──────────────────────────────────────────────────────────────────
# The write path stops re-checking, so a directory swapped for a link AFTER
# the plan was checked is followed. Both of its checks are removed; either one
# alone is enough to refuse.
m16c() {
  mutate "$1/internal/restore/run.go" \
    '	if err := insideHome(dir, l); err != nil {
		base.Outcome, base.Final, base.Detail = OutFailed, target, err.Error()
		return base
	}
	if err := mkdirAllOwned(' \
    '	if err := mkdirAllOwned('
  mutate "$1/internal/restore/run.go" \
    '	if err := insideHome(dir, l); err != nil {
		base.Outcome, base.Final, base.Detail = OutFailed, target, err.Error()
		return base
	}
	if err := writeAtomic(' \
    '	if err := writeAtomic('
}

# ── M17 ───────────────────────────────────────────────────────────────────
# MAJOR, and real: a root run stops handing its files over. Every 0600 file
# lands owned by root in a home owned by the user, and the re-check passes
# because root can read it all back.
m17() {
  mutate "$1/internal/restore/owner.go" \
    '	if o == nil {
		return nil
	}
	fn := o.chown' \
    '	if o == nil || true {
		return nil
	}
	fn := o.chown'
}

# ── M18 ───────────────────────────────────────────────────────────────────
# MAJOR, and real: "was this renamed" is derived from the outcome again, so
# the second run — which finds its own earlier copy and says already-there —
# stops telling the user that the file under its own name is not theirs.
m18() {
  mutate "$1/internal/restore/report.go" \
    '		if !r.Renamed {
			continue
		}' \
    '		if r.Outcome != OutPlacedAside {
			continue
		}'
}

# ── M19 ───────────────────────────────────────────────────────────────────
# MAJOR, and real: a Thumbs.db beside the archive is counted as a stranger's
# file again, and the restore tells a school its only copy is damaged.
m19() {
  mutate "$1/internal/verify/verify.go" \
    '		if isLitter(stored) {' \
    '		if false && isLitter(stored) {'
}

# ── M20 ───────────────────────────────────────────────────────────────────
# The re-check stops asking whether two entries claim one file. Every hash
# matches, because it is the same file hashed twice.
m20() {
  mutate "$1/internal/restore/run.go" \
    '		if prev, dup := claimed[key]; dup {' \
    '		if prev, dup := claimed[key]; false && dup {'
}

# ── M20b ──────────────────────────────────────────────────────────────────
# The write path stops treating another entry's name as taken, so an aside
# name lands on it and one of the user's files ends up existing nowhere.
m20b() {
  mutate "$1/internal/restore/run.go" \
    '		if target != it.Route.Target && reserved[filepath.Clean(target)] {' \
    '		if false && target != it.Route.Target && reserved[filepath.Clean(target)] {'
}

# ── M21 ───────────────────────────────────────────────────────────────────
# An --archive path that holds nothing is reported as "no backup attached"
# again, which the command answers with exit 0.
m21() {
  mutate "$1/internal/restore/archive.go" \
    '		case f.Explicit != "":
			return nil, fmt.Errorf("%w: %s' \
    '		case false:
			return nil, fmt.Errorf("%w: %s'
}

# ── M22 ───────────────────────────────────────────────────────────────────
# The finder stops distinguishing an attached-and-empty drive from nothing
# attached.
m22() {
  mutate "$1/internal/restore/archive.go" \
    '		case len(f.SearchedRemovable) > 0:' \
    '		case false:'
}

# ── M22b ──────────────────────────────────────────────────────────────────
# The command collapses "a drive is attached and held no backup" back into
# the quiet exit 0.
m22b() {
  mutate "$1/cmd/auros-restore/main.go" \
    '		return exitNoArchiveOnMedia, fmt.Sprintf(' \
    '		return exitOK, fmt.Sprintf('
}

# ── M23 ───────────────────────────────────────────────────────────────────
# WriteReport stops recording where it wrote, which is what made the caller
# write the report a second time with O_TRUNC.
m23() {
  mutate "$1/internal/restore/report.go" \
    '		prev := s.ReportFilePath
		s.ReportFilePath = p' \
    '		prev := s.ReportFilePath'
}

# ── M24 ───────────────────────────────────────────────────────────────────
# The sweep is removed: one stale .part per interruption, forever.
m24() {
  mutate "$1/internal/restore/run.go" \
    '		s.PartialsSwept = sweepPartials(p)' \
    '		s.PartialsSwept = nil'
}

# ── M24b ──────────────────────────────────────────────────────────────────
# The sweep gets greedy and deletes a user's own file that happens to end
# in .part.
m24b() {
  mutate "$1/internal/restore/run.go" \
    '	return strings.HasPrefix(name, partialPrefix) && strings.HasSuffix(name, partialSuffix) &&' \
    '	return strings.HasSuffix(name, partialSuffix) || strings.HasPrefix(name, partialPrefix) &&'
}

run_case M01 "the archive check stops being a gate" \
  ./internal/restore 'TestExecute_AWrongHashInTheArchiveAbortsBeforeAnythingIsWritten' \
  'file(s) were written despite a damaged archive' m01
run_case M02 "a file already on the machine is overwritten" \
  ./internal/restore 'TestExecute_AFileAlreadyThereIsNeverOverwritten' \
  "the user's own file was overwritten" m02
run_case M03 "the re-check after writing stops comparing" \
  ./internal/restore 'TestReVerify_AFileChangedAfterTheWriteIsCaught' \
  'the re-check passed over a file that was changed' m03
run_case M04 "the plan stops checking that ROUTED targets are inside home" \
  ./internal/restore 'TestPlan_ARoutingRuleThatLandsOutsideHomeIsRefused' \
  'want ErrPathEscape' m04
run_case M04b "the plan stops re-validating the manifest's own paths" \
  ./internal/restore 'TestPlan_APathThatIsNotWhatItClaimsIsRefused' \
  'want ErrPathEscape' m04b
run_case M05 "Chrome's password database joins the allow-list (D15)" \
  ./internal/restore 'TestPlan_ChromeSecretsAreWithheldAndNamed' \
  'D15 BREACH' m05
run_case M06 "the Wi-Fi keyfile permission check stops checking" \
  ./internal/netprofile 'TestWrite_AWorldReadableKeyfileIsRefusedAndDeleted' \
  'wrong permissions was left in place' m06
run_case M07 "an 802.1X network is given a connection that cannot work" \
  ./internal/netprofile 'TestWrite_EnterpriseAndSealedProfilesProduceNoFile' \
  'could never have worked' m07
run_case M08 "a USB port is turned into an invented network address" \
  ./internal/printers 'TestDecide_OnlyARealNetworkPrinterGetsAQueue|TestNetworkHost_RefusesAnythingItWouldHaveToInvent' \
  'want "plugged in with a cable"' m08
run_case M09 "the aggregate gate ignores failed files (D37)" \
  ./internal/restore 'TestClean_TheGateGoesRedForEveryReasonSeparately' \
  'Clean() is still true after: a file failed' m09
run_case M10 "two different archives, and it picks one" \
  ./internal/restore 'TestFind_TwoDifferentArchivesRefuseToBeGuessedBetween' \
  'want ErrAmbiguous' m10
run_case M11 "the notification path opens a real network socket" \
  ./internal/safety 'TestWall_DeskbusDialsUnixAndNothingElse' \
  'WALL BREACH' m11
run_case M12 "the restore shells out" \
  ./internal/safety 'TestWall_TheRestoreCannotReachTheSystemDisk' \
  'WALL BREACH' m12
run_case M13 "damaged files are counted instead of named" \
  ./internal/restore 'TestExecute_AWrongHashInTheArchiveAbortsBeforeAnythingIsWritten' \
  'does not name the damaged file' m13

run_case M14 "the finder stops looking one folder down (FATAL)" \
  ./internal/restore 'TestFinder_FindsTheArchiveWhereTheWindowsHalfActuallyPutsIt' \
  'the finder did not see it' m14
run_case M14b "the archive folder's agreed name moves" \
  ./internal/manifest 'TestArchiveSubdir_IsTheNameOnSticksInTheField' \
  'Sticks made by every earlier build' m14b
run_case M14c "the Windows half stops using the agreed name" \
  ./cmd/auros-migrate 'TestResolveDestination_TheAutomaticChoiceIsTheFolderTheRestoreLooksIn' \
  'the restore on the new machine looks for' m14c
run_case M15 "Clean() stops reading the Wi-Fi and printer reports (FATAL)" \
  ./internal/restore 'TestSummary_AWiFiProblemMakesTheRunUnclean' \
  'the run is CLEAN with a Wi-Fi problem in it' m15
run_case M16 "the layout's link check goes back to lexical" \
  ./internal/restore 'TestNewLayout_AUserDirectoryThatIsALinkOutOfHomeIsRefused' \
  'want ErrDirOutsideHome' m16
run_case M16b "the plan's link check goes back to lexical" \
  ./internal/restore 'TestPlan_ALinkInsideAUserDirectoryIsRefusedBeforeAnyWrite' \
  'a link inside ~/Documents was planned' m16b
run_case M16c "the write path stops re-checking for a swapped-in link" \
  ./internal/restore 'TestExecute_ADirectorySwappedForALinkAfterPlanningIsNotFollowed' \
  'followed a link swapped in after planning' m16c
run_case M17 "a root run stops handing files to the home's owner" \
  ./internal/restore 'TestExecute_HandsEveryCreatedPathToTheHomeOwner' \
  'was not handed over' m17
run_case M18 "the second run forgets the file was renamed" \
  ./internal/restore 'TestExecute_TheSecondRunStillSaysTheFileWasRenamed' \
  'second run: 0 renamed files' m18
run_case M19 "a Thumbs.db is a damaged archive again" \
  ./internal/verify 'TestVerify_LitterBesideAPerfectArchiveIsNamedNotCounted' \
  'litter made a perfect archive fail' m19
run_case M20 "the re-check stops catching two entries claiming one file" \
  ./internal/restore 'TestReVerify_TwoEntriesClaimingOneFileIsADisagreement' \
  'the re-check called it clean' m20
run_case M20b "an aside name can land on another entry's real name" \
  ./internal/restore 'TestExecute_TwoEntriesWithTheSameBytesCannotCollapseIntoOneFile' \
  'are both reported as the file at' m20b
run_case M21 "a wrong --archive path reads as no backup attached" \
  ./internal/restore 'TestFinder_AnExplicitArchiveThatIsNotThereIsNotAnAbsenceOfBackups' \
  'The user typed a path' m21
run_case M22 "an attached, empty drive reads as nothing attached" \
  ./internal/restore 'TestFinder_ADriveThatIsAttachedButEmptyIsNotNothingAttached' \
  'want ErrNoArchiveOnAttachedMedia' m22
run_case M22b "the command answers an attached, empty drive with exit 0" \
  ./cmd/auros-restore 'TestFindRefusal_OnlyNothingAttachedIsAQuietNoOp' \
  'became a quiet exit 0' m22b
run_case M23 "the report forgets its own path, inviting a second O_TRUNC write" \
  ./internal/restore 'TestWriteReport_WritesOnceAndRecordsThePathItWroteTo' \
  'left Summary.ReportFilePath as' m23
run_case M24 "stale .part files are never swept" \
  ./internal/restore 'TestExecute_SweepsAStalePartialFromAnInterruptedRun' \
  'survived a full clean run' m24
run_case M24b "the sweep deletes a user's own .part file" \
  ./internal/restore 'TestSweepPartials_TouchesOnlyItsOwnPatternInItsOwnDirectories' \
  'was not its to remove' m24b

echo
echo "prove-red: $PASS caught, $FAIL not caught."
if [ "$FAIL" -ne 0 ]; then
  echo
  echo "A mutation that is not caught means the suite would agree with wrong code."
  echo "Fix the assertion. Do not delete the mutation."
  exit 1
fi
