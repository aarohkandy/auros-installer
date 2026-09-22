//go:build windows

package gate3

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ─────────────────────────────────────────────────────────────────────────────
// RUNNING THE INSTALLER AS THE MIGRATION USER
//
// The installer inventories the known folders of WHOEVER IS RUNNING IT, through
// SHGetKnownFolderPath. That is not incidental — SAFETY.md phase 1 is emphatic
// that the folders must come from Windows and never from string-concatenating
// %USERPROFILE%, because a school laptop is exactly where Documents is
// redirected somewhere else.
//
// So the harness does not try to talk the installer out of looking at the
// current user's folders. It creates a user whose folders ARE the corpus (see
// prepare_windows.go) and runs the installer as that user, with that user's
// profile loaded so the redirection in its hive is the answer Windows gives.
//
// The process is launched inside a JOB OBJECT, which buys three things at once:
//
//   - progress, measured by the operating system: the job's I/O accounting says
//     how many bytes this process tree has read and written, so "kill at 43% of
//     the copy" needs nothing from the installer and cannot be fooled by an
//     installer that reports progress it is not making;
//   - a power cut that is really a power cut: TerminateJobObject, no signal, no
//     deferred cleanup, no flush of the installer's own buffers;
//   - no orphans: whatever the installer spawned dies with it.
// ─────────────────────────────────────────────────────────────────────────────

const (
	logon32LogonBatch       = 4
	logon32LogonInteractive = 2
	logon32ProviderDefault  = 0

	securityImpersonation = 2
	tokenPrimary          = 1
	tokenAllAccess        = 0xF01FF

	createUnicodeEnvironment = 0x00000400
	createSuspended          = 0x00000004
	createNoWindow           = 0x08000000

	startfUseStdHandles = 0x00000100

	jobObjectBasicAndIoAccounting = 8
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	moduserenv  = syscall.NewLazyDLL("userenv.dll")

	procLogonUserW               = modadvapi32.NewProc("LogonUserW")
	procCreateProcessWithTokenW  = modadvapi32.NewProc("CreateProcessWithTokenW")
	procDuplicateTokenEx         = modadvapi32.NewProc("DuplicateTokenEx")
	procLoadUserProfileW         = moduserenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile        = moduserenv.NewProc("UnloadUserProfile")
	procCreateEnvironmentBlock   = moduserenv.NewProc("CreateEnvironmentBlock")
	procDestroyEnvironmentBlock  = moduserenv.NewProc("DestroyEnvironmentBlock")
	procCreateJobObjectW         = modkernel32.NewProc("CreateJobObjectW")
	procAssignProcessToJobObject = modkernel32.NewProc("AssignProcessToJobObject")
	procQueryInformationJobObj   = modkernel32.NewProc("QueryInformationJobObject")
	procTerminateJobObject       = modkernel32.NewProc("TerminateJobObject")
	procResumeThread             = modkernel32.NewProc("ResumeThread")
)

// profileInfo mirrors PROFILEINFOW.
type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     syscall.Handle
}

// UserSession is a logged-on migration user with its profile loaded.
type UserSession struct {
	Token       syscall.Handle
	Profile     syscall.Handle
	Elevated    bool
	SID         string
	name        string
	keepProfile bool
}

// LogonMigrationUser logs the migration user on and loads its profile.
//
// The profile matters twice over: it is what makes HKEY_CURRENT_USER — and
// therefore SHGetKnownFolderPath — answer for this user at all, and it is where
// prepare_windows.go wrote the redirection that points the known folders at the
// corpus.
//
// The token is the one the logon returns, a STANDARD user's: the account is
// not an administrator (see CreateMigrationUser), and ApplyEnforcement refuses
// to run the installer on a token that is elevated or holds Administrators. A
// split UAC token is never swapped for its linked full one. The consequence,
// stated: the installer's `manage-bde -status` needs administrative rights, so
// BitLocker is reported unknown and the suspend step is planned anyway, which
// is what the installer does wherever that probe cannot answer
// (internal/sysdisk/probe_windows.go). Batch logon needs SeBatchLogonRight,
// which a standard account lacks by default, so the interactive fallback below
// is the path taken.
func LogonMigrationUser(name, password string) (*UserSession, error) {
	u, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	d, _ := syscall.UTF16PtrFromString(".")
	p, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		return nil, err
	}
	var tok syscall.Handle
	r1, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(p)), logon32LogonBatch, logon32ProviderDefault, uintptr(unsafe.Pointer(&tok)))
	if r1 == 0 {
		r1, _, e = procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)),
			uintptr(unsafe.Pointer(p)), logon32LogonInteractive, logon32ProviderDefault,
			uintptr(unsafe.Pointer(&tok)))
		if r1 == 0 {
			return nil, fmt.Errorf("gate3: LogonUser(%s): %w", name, e)
		}
	}
	s := &UserSession{Token: tok, name: name}
	if s.Elevated, err = tokenIsElevated(tok); err != nil {
		syscall.CloseHandle(tok)
		return nil, fmt.Errorf("gate3: reading %s's token: %w", name, err)
	}
	pi := profileInfo{UserName: u}
	pi.Size = uint32(unsafe.Sizeof(pi))
	r1, _, e = procLoadUserProfileW.Call(uintptr(s.Token), uintptr(unsafe.Pointer(&pi)))
	if r1 == 0 {
		syscall.CloseHandle(s.Token)
		return nil, fmt.Errorf("gate3: LoadUserProfile(%s): %w", name, e)
	}
	s.Profile = pi.Profile
	sid, serr := tokenSID(s.Token)
	if serr == nil {
		s.SID = sid
	}
	return s, nil
}

// KeepProfileLoaded stops Close from unloading the profile.
//
// THIS IS WHERE THE USER'S REGISTRY HIVE LIVES, AND IT MATTERS.
//
// The classes hive — %LOCALAPPDATA%\Microsoft\Windows\UsrClass.dat — is
// created, and its location decided, when the profile is FIRST loaded. The
// harness loads the profile once (hive at the account's default location), then
// writes the known-folder redirection, and then never unloads it for the rest of
// the job: every later logon attaches to the profile that is already loaded and
// the hive stays where it was.
//
// Without that, the next logon reads the redirected Local AppData and puts the
// hive INSIDE THE CORPUS — where the installer inventories it, cannot read it
// (the kernel holds it open with no sharing), quarantines it, and then refuses
// to issue a VerifiedArchive. That is not a hypothetical: it is what the first
// run of this harness did, and it is the blocking product finding this gate
// reports. It is reproduced deliberately by the locked-file scenario; it must
// not also be the reason every other run fails, because then every scenario
// would abort for the same unrelated reason and the suite would prove nothing.
func (s *UserSession) KeepProfileLoaded() { s.keepProfile = true }

// Close unloads the profile and drops the token.
func (s *UserSession) Close() {
	if s == nil {
		return
	}
	if s.Profile != 0 && !s.keepProfile {
		procUnloadUserProfile.Call(uintptr(s.Token), uintptr(s.Profile))
	}
	if s.Token != 0 {
		syscall.CloseHandle(s.Token)
	}
}

// tokenIsElevated is TOKEN_ELEVATION.TokenIsElevated (TokenElevation, 20).
func tokenIsElevated(tok syscall.Handle) (bool, error) {
	var el, n uint32
	const tokenElevation = 20
	if err := syscall.GetTokenInformation(syscall.Token(tok), tokenElevation,
		(*byte)(unsafe.Pointer(&el)), 4, &n); err != nil {
		return false, err
	}
	return el != 0, nil
}

func tokenSID(tok syscall.Handle) (string, error) {
	// GetTokenUser rather than a hand-built TOKEN_USER: the structure's first
	// field is a POINTER into the buffer, and reading it back through a uintptr
	// is the one unsafe.Pointer conversion that is genuinely unsound — `go vet`
	// rejects it, and internal/winenv had the same bug (D35).
	u, err := syscall.Token(tok).GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String()
}

// Process is a running installer under harness control.
type Process struct {
	job     syscall.Handle
	process syscall.Handle
	thread  syscall.Handle
	pid     uint32
	started time.Time
}

// IO is what the operating system has seen this process tree move.
type IO struct {
	Read      int64
	Written   int64
	Processes int
}

// StartInstaller launches the installer as the migration user, suspended, inside
// a job object, then resumes it.
//
// It runs through cmd.exe so that the installer's own output is redirected by
// the shell into a file the harness can read afterwards. That is deliberate
// rather than lazy: handle inheritance across a CreateProcessWithTokenW boundary
// is the kind of thing that works on one Windows build and returns an empty file
// on another, and an empty output file would silently disable the check that the
// installer looked at the right folders.
func StartInstaller(s *UserSession, exe string, args []string, outPath, workDir string) (*Process, error) {
	quoted := make([]string, 0, len(args)+1)
	quoted = append(quoted, `"`+exe+`"`)
	for _, a := range args {
		if strings.ContainsAny(a, ` "`) {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		quoted = append(quoted, a)
	}
	// cmd /c "<command> > "out" 2>&1" — the outer quotes are stripped by cmd.
	cmdline := fmt.Sprintf(`cmd.exe /c "%s > "%s" 2>&1"`, strings.Join(quoted, " "), outPath)

	comspec := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	app, err := syscall.UTF16PtrFromString(comspec)
	if err != nil {
		return nil, err
	}
	cl, err := syscall.UTF16PtrFromString(cmdline)
	if err != nil {
		return nil, err
	}
	wd, err := syscall.UTF16PtrFromString(workDir)
	if err != nil {
		return nil, err
	}

	var envBlock uintptr
	if r1, _, _ := procCreateEnvironmentBlock.Call(uintptr(unsafe.Pointer(&envBlock)), uintptr(s.Token), 0); r1 == 0 {
		envBlock = 0
	}
	defer func() {
		if envBlock != 0 {
			procDestroyEnvironmentBlock.Call(envBlock)
		}
	}()

	job, _, jerr := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return nil, fmt.Errorf("gate3: CreateJobObject: %w", jerr)
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation
	flags := uintptr(createUnicodeEnvironment | createSuspended | createNoWindow)

	r1, _, e := procCreateProcessWithTokenW.Call(
		uintptr(s.Token), 0,
		uintptr(unsafe.Pointer(app)),
		uintptr(unsafe.Pointer(cl)),
		flags,
		envBlock,
		uintptr(unsafe.Pointer(wd)),
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
	)
	if r1 == 0 {
		syscall.CloseHandle(syscall.Handle(job))
		return nil, fmt.Errorf("gate3: CreateProcessWithTokenW: %w", e)
	}
	if r2, _, aerr := procAssignProcessToJobObject.Call(job, uintptr(pi.Process)); r2 == 0 {
		syscall.TerminateProcess(pi.Process, 1)
		syscall.CloseHandle(pi.Process)
		syscall.CloseHandle(pi.Thread)
		syscall.CloseHandle(syscall.Handle(job))
		return nil, fmt.Errorf("gate3: AssignProcessToJobObject: %w", aerr)
	}
	if r3, _, rerr := procResumeThread.Call(uintptr(pi.Thread)); uint32(r3) == 0xFFFFFFFF {
		return nil, fmt.Errorf("gate3: ResumeThread: %w", rerr)
	}
	return &Process{
		job: syscall.Handle(job), process: pi.Process, thread: pi.Thread,
		pid: pi.ProcessId, started: time.Now(),
	}, nil
}

// IO reads the job's accounting counters.
func (p *Process) IO() (IO, error) {
	var buf [96]byte
	var ret uint32
	r1, _, e := procQueryInformationJobObj.Call(uintptr(p.job), jobObjectBasicAndIoAccounting,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
	if r1 == 0 {
		return IO{}, fmt.Errorf("gate3: QueryInformationJobObject: %w", e)
	}
	return IO{
		Processes: int(binary.LittleEndian.Uint32(buf[40:44])),
		Read:      int64(binary.LittleEndian.Uint64(buf[72:80])),
		Written:   int64(binary.LittleEndian.Uint64(buf[80:88])),
	}, nil
}

// Kill is the power cut: every process in the job stops existing at once.
func (p *Process) Kill() error {
	r1, _, e := procTerminateJobObject.Call(uintptr(p.job), 0x101)
	if r1 == 0 {
		return fmt.Errorf("gate3: TerminateJobObject: %w", e)
	}
	return nil
}

// Exited reports whether the installer has finished, without blocking.
func (p *Process) Exited() (bool, int) {
	ev, err := syscall.WaitForSingleObject(p.process, 0)
	if err != nil || ev != 0 /* WAIT_OBJECT_0 */ {
		return false, 0
	}
	var code uint32
	if err := syscall.GetExitCodeProcess(p.process, &code); err != nil {
		return true, -1
	}
	return true, int(int32(code))
}

// Wait blocks until the installer exits or the timeout expires.
func (p *Process) Wait(timeout time.Duration) (code int, timedOut bool) {
	ms := uint32(timeout / time.Millisecond)
	ev, err := syscall.WaitForSingleObject(p.process, ms)
	if err != nil || ev == 0x00000102 /* WAIT_TIMEOUT */ {
		return 0, true
	}
	var c uint32
	if err := syscall.GetExitCodeProcess(p.process, &c); err != nil {
		return -1, false
	}
	return int(int32(c)), false
}

// Close releases the handles.
func (p *Process) Close() {
	syscall.CloseHandle(p.thread)
	syscall.CloseHandle(p.process)
	syscall.CloseHandle(p.job)
}

// Elapsed is how long the installer has been running.
func (p *Process) Elapsed() time.Duration { return time.Since(p.started) }

// PID is the cmd.exe wrapper's process id, for the log.
func (p *Process) PID() uint32 { return p.pid }
