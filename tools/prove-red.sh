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

echo
echo "prove-red: $PASS caught, $FAIL not caught."
if [ "$FAIL" -ne 0 ]; then
  echo
  echo "A mutation that is not caught means the suite would agree with wrong code."
  echo "Fix the assertion. Do not delete the mutation."
  exit 1
fi
