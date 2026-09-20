// Package winenv is the Windows surface, behind an interface, with a synthetic
// implementation that exists on every platform.
//
// The split is the reason the safety core is testable at all. Everything that
// needs Win32 — known folders, the installed-programs list, volume identity,
// firmware facts, OneDrive placeholder detection — lives behind Env. Linux CI
// runs the whole of safety, manifest, copyengine, verify, quarantine and runlog
// against NewSynthetic, and none of those packages contains a build tag.
//
// NewSynthetic is NOT test-only scaffolding hidden in a _test.go file: the
// dry-run demonstration mode uses it too, so the code path CI exercises is a
// code path that ships.
package winenv

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// TriState exists because "we do not know" is a real and common answer for
// firmware facts, and collapsing it into false is how a tool ends up telling a
// user Secure Boot is off when it never checked.
type TriState int

const (
	Unknown TriState = iota
	Yes
	No
)

func (t TriState) String() string {
	switch t {
	case Yes:
		return "yes"
	case No:
		return "no"
	default:
		return "unknown"
	}
}

// Folder is one resolved known folder. Path is resolved via
// SHGetKnownFolderPath, never by concatenating %USERPROFILE% — SAFETY.md phase 1.
type Folder struct {
	ID      string // e.g. "Documents"
	Path    string
	Present bool
}

// Program is one row of the installed-programs list. This list is shown to the
// user by name under prohibition §4.2: Windows programs do not migrate.
type Program struct {
	Name      string
	Publisher string
	Version   string
	Source    string // registry key it came from, for the post-mortem
}

// Volume identifies a volume by GUID. SAFETY.md phase 3 is explicit that the
// destination check is by GUID and not by drive letter, because a mount point or
// a subst'd letter can alias the system volume.
type Volume struct {
	GUID       string // \\?\Volume{........-....-....-....-............}\
	Mount      string // "C:\" on Windows, a directory on the synthetic env
	Label      string
	FS         string
	TotalBytes uint64
	FreeBytes  uint64
	Removable  bool
	IsSystem   bool
}

func (v Volume) String() string {
	return fmt.Sprintf("%s (%s, %s, %d bytes free)", v.Mount, v.GUID, v.FS, v.FreeBytes)
}

// Firmware carries the three facts that break "one restart", per SAFETY.md's
// closing section. All three are detected in phase 1 and told to the user before
// anything starts.
type Firmware struct {
	Known                   bool
	SecureBootEnabled       TriState
	ThirdPartyUEFICATrusted TriState
	TPMVersion              string
	BitLockerOnSystemVolume TriState
	BootNextSupported       TriState
	Notes                   []string
}

// PlaceholderStats counts OneDrive Files On-Demand placeholders. SAFETY.md phase
// 1 treats these as a first-class case: reading them naively either hydrates
// hundreds of gigabytes over a school's uplink or fails outright.
type PlaceholderStats struct {
	Count       int
	LogicalSize int64 // what they would occupy if hydrated
	OnDiskSize  int64 // what they occupy now
}

// Env is the whole Windows surface. Nothing outside this package calls Win32.
type Env interface {
	Platform() string
	KnownFolders() ([]Folder, error)
	InstalledPrograms() ([]Program, error)
	Volumes() ([]Volume, error)
	SystemVolume() (Volume, error)
	Firmware() (Firmware, error)
	CloudPlaceholders(root string) (PlaceholderStats, error)

	// VolumeForPath names the volume that ACTUALLY holds path, by asking the
	// operating system rather than by comparing the path against a list of
	// drive roots.
	//
	// This distinction is the whole reason the method exists. `D:\backup` can be
	// an NTFS junction onto `C:\AurosBackup`; its drive letter says D: and every
	// byte written through it lands on C:. A string prefix test reports the
	// volume of the LETTER. GetVolumePathNameW reports the volume of the
	// DIRECTORY. Only the second one is an identity.
	//
	// The caller must pass an already-resolved path (see IsReparsePoint): this
	// answers "which volume holds this path", not "is this path a link".
	VolumeForPath(path string) (Volume, error)

	// IsReparsePoint reports whether path is itself a reparse point — an NTFS
	// junction, a directory symlink, a mount point — without following it.
	IsReparsePoint(path string) (bool, error)
}

// PathUnderMount reports whether path lies within mount, comparing whole path
// segments so that "C:\Users2" is not treated as being inside "C:\Users". It is
// used by the synthetic environment and by refusal messages; the real Windows
// answer comes from VolumeForPath, never from this.
func PathUnderMount(path, mount string) bool {
	p, m := normPathForCompare(path), normPathForCompare(mount)
	if p == "" || m == "" {
		return false
	}
	if p == m {
		return true
	}
	if m == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, m+"/")
}

func normPathForCompare(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	p = strings.ToLower(p)
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = p[:len(p)-1]
	}
	return p
}

// SyntheticConfig describes a fake machine.
type SyntheticConfig struct {
	Folders      []Folder
	Programs     []Program
	Vols         []Volume
	FW           Firmware
	Placeholders PlaceholderStats
	Err          error // if set, every method returns it
}

type syntheticEnv struct{ cfg SyntheticConfig }

// NewSynthetic returns an Env backed by the supplied description. It is available
// on every platform.
func NewSynthetic(cfg SyntheticConfig) Env { return &syntheticEnv{cfg: cfg} }

func (e *syntheticEnv) Platform() string { return "synthetic" }

func (e *syntheticEnv) KnownFolders() ([]Folder, error) {
	if e.cfg.Err != nil {
		return nil, e.cfg.Err
	}
	out := append([]Folder(nil), e.cfg.Folders...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (e *syntheticEnv) InstalledPrograms() ([]Program, error) {
	if e.cfg.Err != nil {
		return nil, e.cfg.Err
	}
	out := append([]Program(nil), e.cfg.Programs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (e *syntheticEnv) Volumes() ([]Volume, error) {
	if e.cfg.Err != nil {
		return nil, e.cfg.Err
	}
	out := append([]Volume(nil), e.cfg.Vols...)
	sort.Slice(out, func(i, j int) bool { return out[i].GUID < out[j].GUID })
	return out, nil
}

func (e *syntheticEnv) SystemVolume() (Volume, error) {
	if e.cfg.Err != nil {
		return Volume{}, e.cfg.Err
	}
	for _, v := range e.cfg.Vols {
		if v.IsSystem {
			return v, nil
		}
	}
	return Volume{}, fmt.Errorf("winenv: synthetic config has no system volume")
}

func (e *syntheticEnv) Firmware() (Firmware, error) {
	if e.cfg.Err != nil {
		return Firmware{}, e.cfg.Err
	}
	return e.cfg.FW, nil
}

// VolumeForPath resolves a path to one of the configured volumes by longest
// matching mount point, compared segment-wise. The synthetic environment is the
// one that runs on Linux CI and in the rehearsal mode, so it has to answer this
// question the same SHAPE as Windows does: a path under the system mount must
// come back as the system volume even when the caller reached it through a link.
func (e *syntheticEnv) VolumeForPath(path string) (Volume, error) {
	if e.cfg.Err != nil {
		return Volume{}, e.cfg.Err
	}
	var best Volume
	found := false
	for _, v := range e.cfg.Vols {
		if v.Mount == "" || !PathUnderMount(path, v.Mount) {
			continue
		}
		if !found || len(normPathForCompare(v.Mount)) > len(normPathForCompare(best.Mount)) {
			best, found = v, true
		}
	}
	if !found {
		return Volume{}, fmt.Errorf("winenv: no configured volume holds %s", path)
	}
	return best, nil
}

// IsReparsePoint reports whether path is a link, without following it. On the
// synthetic environment that is an lstat; ModeIrregular is included because that
// is how some reparse points surface.
func (e *syntheticEnv) IsReparsePoint(path string) (bool, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	return st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0, nil
}

func (e *syntheticEnv) CloudPlaceholders(string) (PlaceholderStats, error) {
	if e.cfg.Err != nil {
		return PlaceholderStats{}, e.cfg.Err
	}
	return e.cfg.Placeholders, nil
}

// DefaultSynthetic is a plausible 2014 school laptop: BitLocker on, TPM 1.2,
// Secure Boot on with the third-party CA state unknown, and a USB stick that is
// big enough. Every one of those is a condition the tool must handle rather than
// an inconvenience.
func DefaultSynthetic(sysMount, destMount string) SyntheticConfig {
	return SyntheticConfig{
		Folders: []Folder{
			{ID: "Desktop", Path: sysMount + "Users/synthetic/Desktop", Present: true},
			{ID: "Documents", Path: sysMount + "Users/synthetic/Documents", Present: true},
			{ID: "Downloads", Path: sysMount + "Users/synthetic/Downloads", Present: true},
			{ID: "Pictures", Path: sysMount + "Users/synthetic/Pictures", Present: true},
		},
		Programs: []Program{
			{Name: "Adobe Acrobat Reader DC", Publisher: "Adobe", Version: "23.1", Source: "synthetic"},
			{Name: "Microsoft Office Professional Plus 2016", Publisher: "Microsoft", Version: "16.0", Source: "synthetic"},
			{Name: "PowerSchool Installer", Publisher: "PowerSchool", Version: "4.2", Source: "synthetic"},
			{Name: "Sage 50 Accounts", Publisher: "Sage", Version: "27.1", Source: "synthetic"},
		},
		Vols: []Volume{
			{
				GUID:       `\\?\Volume{11111111-1111-1111-1111-111111111111}\`,
				Mount:      sysMount,
				Label:      "OS",
				FS:         "NTFS",
				TotalBytes: 250 << 30,
				FreeBytes:  40 << 30,
				IsSystem:   true,
			},
			{
				GUID:       `\\?\Volume{22222222-2222-2222-2222-222222222222}\`,
				Mount:      destMount,
				Label:      "BACKUP",
				FS:         "exFAT",
				TotalBytes: 128 << 30,
				FreeBytes:  120 << 30,
				Removable:  true,
			},
		},
		FW: Firmware{
			Known:                   true,
			SecureBootEnabled:       Yes,
			ThirdPartyUEFICATrusted: Unknown,
			TPMVersion:              "1.2",
			BitLockerOnSystemVolume: Yes,
			BootNextSupported:       Unknown,
			Notes: []string{
				"TPM 1.2: changing firmware boot order can trigger a BitLocker recovery prompt.",
				"Third-party UEFI CA trust is unknown; some Lenovo and Dell business firmware ships it disabled.",
				"BootNext is not reliably honoured; the firmware-menu fallback may be needed.",
			},
		},
	}
}
