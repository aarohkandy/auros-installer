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
	{Pattern: `^[a-z]:\\\$extend\\`, Why: "NTFS's own metadata files, including the change journal this check reads"},
	{Pattern: `^[a-z]:\\\$mft`, Why: "the master file table"},
	{Pattern: `^[a-z]:\\(pagefile|swapfile|hiberfil)\.sys$`, Why: "the kernel's own files; their size changes with load"},
	{Pattern: `^[a-z]:\\\$recycle\.bin\\`, Why: "the recycle bin"},
	{Pattern: `^[a-z]:\\system volume information\\`, Why: "volume shadow / indexing metadata owned by the OS"},

	{Pattern: `^c:\\windows\\system32\\config\\`, Why: "the registry hives and their transaction logs"},
	{Pattern: `^c:\\windows\\system32\\winevt\\logs\\`, Why: "the Windows event logs"},
	{Pattern: `^c:\\windows\\system32\\logfiles\\`, Why: "Windows service log files"},
	{Pattern: `^c:\\windows\\system32\\(sru|wdi)\\`, Why: "system resource usage and diagnostics databases"},
	{Pattern: `^c:\\windows\\system32\\spool\\`, Why: "the print spooler's working directory"},
	{Pattern: `^c:\\windows\\system32\\catroot2\\`, Why: "the catalogue database, rewritten by signature checks"},
	{Pattern: `^c:\\windows\\(temp|logs|debug|tracing|inf|appcompat|serviceprofiles|softwaredistribution|prefetch|servicing|winsxs|panther|bootstat\.dat)`, Why: "directories Windows uses as scratch, log or servicing space"},
	{Pattern: `^c:\\windows\\security\\`, Why: "local security policy databases, rewritten on logon"},
	{Pattern: `^c:\\windows\\servicestate\\`, Why: "service heartbeat files, e.g. the event log's lastalive"},
	{Pattern: `^c:\\windows\\system32\\microsoft\\protect\\`, Why: "DPAPI's own machine key store and its diagnostic log"},
	{Pattern: `^c:\\windows\\system32\\(perfstringbackup\.(ini|tmp)|perftmp\.dat|perf[a-z][0-9]+\.dat)$`,
		Why: "the performance-counter registry, rebuilt whenever anything queries WMI. `manage-bde -status` " +
			"— the installer's own BitLocker READ — is one of the things that triggers it"},
	{Pattern: `^c:\\windows\\system32\\wbem\\performance\\`, Why: "the WMI performance-counter cache, rebuilt by any WMI query"},
	{Pattern: `^c:\\programdata\\microsoft\\(windows defender|windows\\wer|network|crypto|diagnosis|windows\\appreplocations|windows\\caches|clipsvc)\\`, Why: "Defender, error reporting, and the licensing and crypto stores"},
	{Pattern: `^c:\\programdata\\microsoft\\windows\\start menu\\`, Why: "start-menu bookkeeping"},
	{Pattern: `^c:\\programdata\\(usoshared|usoprivate)\\`, Why: "the update orchestrator's stores"},
	{Pattern: `^c:\\programdata\\microsoft\\windows\\onesettings\\`, Why: "Windows' own settings cache"},
	{Pattern: `^c:\\users\\[^\\]+\\appdata\\locallow\\microsoft\\cryptneturlcache\\`,
		Why: "the certificate-revocation cache, written by whichever process last validated a certificate"},
	{Pattern: `^c:\\windows\\system32\\smi\\store\\`, Why: "the component store's database, written by servicing"},
	{Pattern: `^c:\\windows\\apppatch\\`, Why: "the application-compatibility database"},
	{Pattern: `^c:\\windows\\systemtemp\\`, Why: "the temp directory Windows' own services use"},
	// Measured on windows-2025, run 35562498238 clean-0-1, with wuauserv and
	// UsoSvc already stopped: 86 records, all from one servicing-stack scan.
	// Each rule is the exact shape measured, not the directory.
	{Pattern: `^c:\\windows\\cbstemp\\([0-9]+_[0-9]+(\\localfodenum(\\(actionlist|deviceinventory|servertargetcompdb_[a-z0-9_-]+)\.xml)?)?|\{[0-9a-f-]{36}\})$`,
		Why: "Component-Based Servicing (TiWorker.exe, the TrustedInstaller service) enumerating Features " +
			"on Demand into a session folder and deleting it again. Only the session folder, its " +
			"LocalFoDEnum subfolder, the XML files CBS names there and CBS's {GUID} rename target match"},
	// Run 35569388666 clean-0-0: MAPPING2.MAP [data-overwrite,data-extend] with
	// no open and no handle write in the trace. The WMI repository is written
	// through a mapped view (flushed by the memory manager, not a Write IRP), so
	// attribution cannot see it; the installer's own manage-bde status read is a
	// WMI client. Exactly the CIM repository's files, nothing else in wbem.
	{Pattern: `^c:\\windows\\system32\\wbem\\repository\\(mapping[1-3]\.map|objects\.data|index\.btr)$`,
		Why: "the WMI CIM repository (winmgmt), written through a memory-mapped view"},
	{Pattern: `^c:\\windows\\windowsupdate\.log$`,
		Why: "the Windows Update agent's legacy log file, written by the same scan"},
	{Pattern: `^c:\\windows\\system32\\tasks\\microsoft\\windows\\`,
		Why: "the last-run bookkeeping of WINDOWS' OWN scheduled tasks. Narrowed to Microsoft\\Windows: a " +
			"task installed anywhere else — which is what a tool that wanted to survive a reboot would " +
			"do — is still reported"},
	{Pattern: `^c:\\programdata\\microsoft\\(diagnosticlogcsp|provisioning|windows\\clipsvc)\\`,
		Why: "the diagnostic-log collector and the provisioning sequence, both of which Windows runs on " +
			"its own schedule"},

	{Pattern: `^c:\\actions-runner\\`, Why: "the CI runner's own installation and diagnostic logs"},
	{Pattern: `^c:\\windowsazure\\`,
		Why: "the Azure guest agent's status logs. This runner is a VM and its HOST writes here; it is " +
			"the one entry on this list that exists because of where the test runs rather than because " +
			"of what Windows does"},
	{Pattern: `^c:\\actionarchivecache\\`, Why: "the CI runner's action cache"},

	{Pattern: `^c:\\users\\runneradmin\\appdata\\local\\temp\\`, Why: "the CI account's temp directory"},
	{Pattern: `^c:\\users\\runneradmin\\appdata\\local\\microsoft\\`, Why: "the CI account's own Windows bookkeeping"},
	{Pattern: `^c:\\users\\runneradmin\\appdata\\roaming\\microsoft\\`, Why: "the CI account's own Windows bookkeeping"},
	{Pattern: `^c:\\users\\runneradmin\\\.dotnet\\`, Why: "the .NET CLI's first-run sentinel, written by the runner's own tooling"},
	{Pattern: `^c:\\users\\runneradmin\\ntuser\.`, Why: "the CI account's registry hive and its logs"},

	// The migration account's hive. Loading a user's profile is what makes
	// SHGetKnownFolderPath answer for that user at all, and the profile service
	// writes these files at every load and unload. Named exactly — the rest of
	// that profile, and all of the corpus, stay inside the check.
	{Pattern: `^c:\\users\\auros-gate3\\(ntuser\.dat|ntuser\.ini|ntuser\.dat\.log[0-9]*|ntuser\.dat\{[0-9a-f-]+\}\.tm\.blf|ntuser\.dat\{[0-9a-f-]+\}\.tmcontainer[0-9]+\.regtrans-ms)$`, Why: "the migration account's registry hive, written by the profile service at logon and logoff"},
	{Pattern: `^c:\\users\\auros-gate3\\appdata\\local\\microsoft\\windows\\usrclass\.dat`, Why: "the migration account's classes hive, loaded and flushed with the profile"},
	{Pattern: `^c:\\users\\auros-gate3\\appdata\\(roaming|local)\\microsoft\\`,
		Why: "Windows' own per-user state for the migration account — DPAPI master keys, CloudStore, " +
			"shell bookkeeping — created by the LOGON, in the account's default profile. Its known " +
			"folders are redirected into the corpus, so nothing the installer copies passes through here"},
	// This account's known folders are REDIRECTED to the corpus, so nothing the
	// installer reads or writes for the migration passes through here.
	{Pattern: `^c:\\users\\auros-gate3\\appdata\\local\\(temp|microsoft\\windows\\(inetcache|history|ie|explorer|caches))\\`, Why: "the migration account's own temp and shell caches"},
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
