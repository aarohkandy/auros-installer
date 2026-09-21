package gate3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// THE NOISE LIST
//
// D27 replaced "Windows still boots" with the invariant it depends on: nothing
// was written to the system disk. The harness measures that through the NTFS
// change journal, which records every create, delete, rename, data write,
// attribute change and stream change on C: between two exact USNs.
//
// Windows itself writes to C: constantly and would do so whether the installer
// ran or not: event logs, registry hives, the profile service loading a user
// hive so the installer can run AS that user, the CI runner's own logs. The
// change journal cannot say which process made a change, so those have to be
// excluded by path.
//
// Every exclusion below is therefore a hole in the check, and the rules for
// adding one are strict:
//
//   - It must name a path WINDOWS OWNS and the installer has no business in.
//     `C:\Windows\System32\config` is the registry; `C:\Users\<the migration
//     user>\NTUSER.DAT` is that user's hive. The installer contains no registry
//     write path at all — internal/winenv opens keys with KEY_READ and nothing
//     in the repository imports anything that could write one.
//   - It must be as narrow as the churn it covers. `C:\Windows\Temp\` is
//     excluded; `C:\Windows\` is not. `%LOCALAPPDATA%\Temp` of the CI account is
//     excluded; the MIGRATION user's profile is not, because that is exactly
//     where a tool that wrote scratch files to the system disk would put them.
//   - It is printed in the job log and its SHA-256 is recorded in every result,
//     so a reader can tell whether the list grew between one run and the next.
//
// Nothing under the corpus is excluded. Nothing under the destination is
// excluded (the destination is not on C: — and if it ever were, the run would
// already have failed on the check that says so).
// ─────────────────────────────────────────────────────────────────────────────

// NoiseRule is one exclusion and the reason it exists.
type NoiseRule struct {
	Pattern string
	Why     string
	re      *regexp.Regexp
}

// noiseRules are matched against the lowercased full path of a changed file.
var noiseRules = []NoiseRule{
	{`^[a-z]:\\\$extend\\`, "NTFS's own metadata files, including the change journal this check reads"},
	{`^[a-z]:\\\$mft`, "the master file table"},
	{`^[a-z]:\\(pagefile|swapfile|hiberfil)\.sys$`, "the kernel's own files; their size changes with load"},
	{`^[a-z]:\\\$recycle\.bin\\`, "the recycle bin"},
	{`^[a-z]:\\system volume information\\`, "volume shadow / indexing metadata owned by the OS"},

	{`^c:\\windows\\system32\\config\\`, "the registry hives and their transaction logs"},
	{`^c:\\windows\\system32\\winevt\\logs\\`, "the Windows event logs"},
	{`^c:\\windows\\system32\\logfiles\\`, "Windows service log files"},
	{`^c:\\windows\\system32\\(sru|wdi)\\`, "system resource usage and diagnostics databases"},
	{`^c:\\windows\\system32\\spool\\`, "the print spooler's working directory"},
	{`^c:\\windows\\system32\\catroot2\\`, "the catalogue database, rewritten by signature checks"},
	{`^c:\\windows\\(temp|logs|debug|tracing|inf|appcompat|serviceprofiles|softwaredistribution|prefetch|servicing|winsxs|panther|bootstat\.dat)`,
		"directories Windows uses as scratch, log or servicing space"},
	{`^c:\\windows\\security\\`, "local security policy databases, rewritten on logon"},
	{`^c:\\programdata\\microsoft\\(windows defender|windows\\wer|network|crypto|diagnosis|windows\\appreplocations|windows\\caches|clipsvc)\\`,
		"Defender, error reporting, and the licensing and crypto stores"},
	{`^c:\\programdata\\microsoft\\windows\\start menu\\`, "start-menu bookkeeping"},
	{`^c:\\programdata\\usoshared\\`, "the update orchestrator"},

	{`^c:\\actions-runner\\`, "the CI runner's own installation and diagnostic logs"},
	{`^c:\\actionarchivecache\\`, "the CI runner's action cache"},

	{`^c:\\users\\runneradmin\\appdata\\local\\temp\\`, "the CI account's temp directory"},
	{`^c:\\users\\runneradmin\\appdata\\local\\microsoft\\`, "the CI account's own Windows bookkeeping"},
	{`^c:\\users\\runneradmin\\appdata\\roaming\\microsoft\\`, "the CI account's own Windows bookkeeping"},
	{`^c:\\users\\runneradmin\\\.dotnet\\`, "the .NET CLI's first-run sentinel, written by the runner's own tooling"},
	{`^c:\\users\\runneradmin\\ntuser\.`, "the CI account's registry hive and its logs"},

	// The migration account's hive. Loading a user's profile is what makes
	// SHGetKnownFolderPath answer for that user at all, and the profile service
	// writes these files at every load and unload. Named exactly — the rest of
	// that profile, and all of the corpus, stay inside the check.
	{`^c:\\users\\auros-gate3\\(ntuser\.dat|ntuser\.ini|ntuser\.dat\.log[0-9]*|ntuser\.dat\{[0-9a-f-]+\}\.tm\.blf|ntuser\.dat\{[0-9a-f-]+\}\.tmcontainer[0-9]+\.regtrans-ms)$`,
		"the migration account's registry hive, written by the profile service at logon and logoff"},
	{`^c:\\users\\auros-gate3\\appdata\\local\\microsoft\\windows\\usrclass\.dat`,
		"the migration account's classes hive, loaded and flushed with the profile"},
	{`^c:\\users\\auros-gate3\\appdata\\local\\(temp|microsoft\\windows\\(inetcache|history|ie|explorer|caches))\\`,
		"the migration account's own temp and shell caches. NOTE: this account's known folders are " +
			"REDIRECTED to the corpus, so nothing the installer reads or writes for the migration " +
			"passes through here"},
}

var compiledNoise = func() []NoiseRule {
	out := make([]NoiseRule, len(noiseRules))
	for i, r := range noiseRules {
		r.re = regexp.MustCompile(r.Pattern)
		out[i] = r
	}
	return out
}()

// IsNoise reports whether a changed path is one of the excluded ones, and which
// rule excused it.
func IsNoise(path string) (bool, string) {
	p := strings.ToLower(path)
	p = strings.TrimPrefix(p, `\\?\`)
	for _, r := range compiledNoise {
		if r.re.MatchString(p) {
			return true, r.Pattern
		}
	}
	return false, ""
}

// NoiseRules renders the list for the job log and the result file.
func NoiseRules() []string {
	out := make([]string, 0, len(noiseRules))
	for _, r := range noiseRules {
		out = append(out, fmt.Sprintf("%s  # %s", r.Pattern, r.Why))
	}
	return out
}

// NoiseSHA identifies the exact list a run was measured against, so a reader can
// see at a glance whether it changed between runs.
func NoiseSHA() string {
	h := sha256.New()
	for _, r := range noiseRules {
		h.Write([]byte(r.Pattern))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
