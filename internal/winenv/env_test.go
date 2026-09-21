package winenv

import (
	"errors"
	"testing"
)

// PathUnderMount is small and it decides whether a directory is on the system
// disk. A prefix test that got it wrong by one character would call
// "C:\Users2" part of "C:\Users" and refuse a perfectly good destination, or —
// far worse — compare the wrong way round and accept one.
//
// So this is the whole truth table, including the spellings Windows hands back
// for the same place.

func TestPathUnderMount_ComparesWholeSegments(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		mount string
		want  bool
	}{
		{name: "a child of the mount", path: `C:\Users\pat`, mount: `C:\Users`, want: true},
		{name: "a grandchild", path: `C:\Users\pat\Documents`, mount: `C:\Users`, want: true},
		{name: "the mount itself", path: `C:\Users`, mount: `C:\Users`, want: true},
		{name: "the mount with a trailing separator", path: `C:\Users\`, mount: `C:\Users`, want: true},
		{name: "a mount with a trailing separator", path: `C:\Users`, mount: `C:\Users\`, want: true},
		{name: "different capitalisation", path: `c:\users\PAT`, mount: `C:\Users`, want: true},
		{name: "forward slashes in the path", path: `C:/Users/pat`, mount: `C:\Users`, want: true},
		{name: "forward slashes in the mount", path: `C:\Users\pat`, mount: `C:/Users`, want: true},

		// The ones that matter.
		{name: "a sibling sharing a prefix", path: `C:\Users2\pat`, mount: `C:\Users`, want: false},
		{name: "a sibling sharing a prefix exactly", path: `C:\UsersX`, mount: `C:\Users`, want: false},
		{name: "the mount is longer than the path", path: `C:\Users`, mount: `C:\Users\pat`, want: false},
		{name: "another drive", path: `D:\Users\pat`, mount: `C:\Users`, want: false},
		{name: "an empty path", path: "", mount: `C:\`, want: false},
		{name: "an empty mount", path: `C:\Users`, mount: "", want: false},
		{name: "both empty", path: "", mount: "", want: false},

		// POSIX spellings, which is what the synthetic environment and the
		// Linux-side restore deal in.
		{name: "everything is under root", path: "/home/pat", mount: "/", want: true},
		{name: "root is under root", path: "/", mount: "/", want: true},
		{name: "a sibling sharing a prefix, POSIX", path: "/homely", mount: "/home", want: false},
		{name: "a child, POSIX", path: "/home/pat/Documents", mount: "/home/pat", want: true},
		{name: "a relative path is not under an absolute mount", path: "home/pat", mount: "/home", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PathUnderMount(tc.path, tc.mount); got != tc.want {
				t.Fatalf("PathUnderMount(%q, %q) = %v, want %v", tc.path, tc.mount, got, tc.want)
			}
		})
	}
}

// TestVolumeForPath_TakesTheLongestMountNotTheFirst is the mount-point case
// SAFETY.md phase 3 warns about. A volume mounted INSIDE another volume's tree
// is how "D:\backup" ends up on C: — and a lookup that returned the first
// match rather than the deepest would answer with the parent every time.
func TestVolumeForPath_TakesTheLongestMountNotTheFirst(t *testing.T) {
	sys := Volume{GUID: `\\?\Volume{1111}\`, Mount: "/mnt", IsSystem: true}
	inner := Volume{GUID: `\\?\Volume{2222}\`, Mount: "/mnt/usb"}
	deeper := Volume{GUID: `\\?\Volume{3333}\`, Mount: "/mnt/usb/nested"}
	env := NewSynthetic(SyntheticConfig{Vols: []Volume{sys, inner, deeper}})

	cases := []struct {
		path string
		want string
	}{
		{"/mnt", sys.GUID},
		{"/mnt/windows", sys.GUID},
		{"/mnt/usb", inner.GUID},
		{"/mnt/usb/backup", inner.GUID},
		{"/mnt/usb/nested", deeper.GUID},
		{"/mnt/usb/nested/deep/file", deeper.GUID},
		{"/mnt/usbx", sys.GUID}, // a sibling, not the inner volume
	}
	for _, tc := range cases {
		got, err := env.VolumeForPath(tc.path)
		if err != nil {
			t.Errorf("VolumeForPath(%q) = %v", tc.path, err)
			continue
		}
		if got.GUID != tc.want {
			t.Errorf("VolumeForPath(%q) = %s, want %s", tc.path, got.GUID, tc.want)
		}
	}

	// A path no configured volume holds is an ERROR, never a guess. The caller
	// treats "which volume is this?" as a safety question, so there is no
	// sensible default answer.
	if _, err := env.VolumeForPath("/elsewhere"); err == nil {
		t.Error("VolumeForPath invented a volume for a path nothing claims")
	}
}

func TestSystemVolume_RefusesWhenNoVolumeClaimsToBeTheSystemDisk(t *testing.T) {
	env := NewSynthetic(SyntheticConfig{Vols: []Volume{
		{GUID: `\\?\Volume{2222}\`, Mount: "/mnt/usb"},
	}})
	if _, err := env.SystemVolume(); err == nil {
		t.Fatal("SystemVolume picked one with nothing flagged as the system disk")
	}
	// And with nothing configured at all.
	if _, err := NewSynthetic(SyntheticConfig{}).SystemVolume(); err == nil {
		t.Fatal("SystemVolume answered for a machine with no volumes")
	}
}

// TestSyntheticEnv_PropagatesItsFailure makes sure the rehearsal environment
// can be made to fail. A test double that always succeeds cannot stand in for
// a machine where the Win32 call returns an error, and the phase 1 code paths
// that handle that would then never run anywhere.
func TestSyntheticEnv_PropagatesItsFailure(t *testing.T) {
	boom := errors.New("the registry is not available")
	env := NewSynthetic(SyntheticConfig{Err: boom})

	if _, err := env.KnownFolders(); !errors.Is(err, boom) {
		t.Errorf("KnownFolders = %v", err)
	}
	if _, err := env.InstalledPrograms(); !errors.Is(err, boom) {
		t.Errorf("InstalledPrograms = %v", err)
	}
	if _, err := env.Volumes(); !errors.Is(err, boom) {
		t.Errorf("Volumes = %v", err)
	}
	if _, err := env.SystemVolume(); !errors.Is(err, boom) {
		t.Errorf("SystemVolume = %v", err)
	}
	if _, err := env.Firmware(); !errors.Is(err, boom) {
		t.Errorf("Firmware = %v", err)
	}
	if _, err := env.VolumeForPath("/anything"); !errors.Is(err, boom) {
		t.Errorf("VolumeForPath = %v", err)
	}
	if _, err := env.CloudPlaceholders("/anything"); !errors.Is(err, boom) {
		t.Errorf("CloudPlaceholders = %v", err)
	}
}

// TestTriState_UnknownIsNotNo is the rule the BitLocker suspend step depends
// on. Collapsing "we did not check" into "no" is how a TPM 1.2 laptop reaches
// a recovery prompt nobody has the key for.
func TestTriState_UnknownIsNotNo(t *testing.T) {
	var zero TriState
	if zero != Unknown {
		t.Fatal("the zero TriState is not Unknown; a caller who forgets the field gets an answer")
	}
	if zero == No {
		t.Fatal("Unknown compares equal to No")
	}
	if Unknown == Yes || Yes == No {
		t.Fatal("the three states are not distinct")
	}
	for state, want := range map[TriState]string{Unknown: "unknown", Yes: "yes", No: "no"} {
		if got := state.String(); got != want {
			t.Errorf("TriState(%d).String() = %q, want %q", int(state), got, want)
		}
	}
	// Anything outside the three reads as unknown, not as a silent yes or no.
	if got := TriState(99).String(); got != "unknown" {
		t.Errorf("an out-of-range TriState renders as %q", got)
	}
}

// TestDefaultSynthetic_IsTheAwkwardMachineNotTheEasyOne guards the fixture the
// whole rehearsal mode runs against. If somebody "tidies" it into a machine
// with BitLocker off, TPM 2.0 and Secure Boot sorted, every phase-1 warning
// path stops being exercised anywhere and the tool looks fine right up until a
// real 2014 laptop.
func TestDefaultSynthetic_IsTheAwkwardMachineNotTheEasyOne(t *testing.T) {
	cfg := DefaultSynthetic("/system/", "/usb/")

	if cfg.FW.BitLockerOnSystemVolume != Yes {
		t.Error("the default fixture does not have BitLocker on")
	}
	if cfg.FW.TPMVersion != "1.2" {
		t.Errorf("TPM version = %q, want 1.2 (the version that strands users at a recovery prompt)",
			cfg.FW.TPMVersion)
	}
	if cfg.FW.ThirdPartyUEFICATrusted != Unknown {
		t.Error("the third-party UEFI CA state is not Unknown; that is the state we cannot detect")
	}
	if cfg.FW.BootNextSupported != Unknown {
		t.Error("BootNext support is not Unknown; it is not reliably knowable")
	}
	if len(cfg.FW.Notes) == 0 {
		t.Error("the fixture carries no notes, so the user would be told none of this")
	}
	if len(cfg.Programs) == 0 {
		t.Error("the fixture lists no installed programs, so prohibition 4.2's disclosure " +
			"has nothing to disclose")
	}

	var system, dest *Volume
	for i := range cfg.Vols {
		if cfg.Vols[i].IsSystem {
			system = &cfg.Vols[i]
		} else {
			dest = &cfg.Vols[i]
		}
	}
	if system == nil || dest == nil {
		t.Fatal("the fixture does not have both a system volume and a destination")
	}
	if system.GUID == "" || dest.GUID == "" {
		t.Fatal("a fixture volume has no GUID, so nothing could be proven about it")
	}
	if system.GUID == dest.GUID {
		t.Fatal("the fixture's two volumes share a GUID")
	}
	if !dest.Removable {
		t.Error("the fixture's destination is not removable; the case we sell is a USB stick")
	}
}

// A junction or symlink is a link; a OneDrive cloud file is DATA even though it
// is also a reparse point. Calling a cloud file "not data" would skip the
// user's files and say so politely.
func TestIsLinkTag_LinksAreLinksAndCloudFilesAreNever(t *testing.T) {
	for _, c := range []struct {
		name string
		tag  uint32
		want bool
	}{
		{"junction (IO_REPARSE_TAG_MOUNT_POINT)", 0xA0000003, true},
		{"symbolic link (IO_REPARSE_TAG_SYMLINK)", 0xA000000C, true},
		{"app execution alias (IO_REPARSE_TAG_APPEXECLINK)", 0x8000001B, true},
		{"WSL symlink (IO_REPARSE_TAG_LX_SYMLINK)", 0xA000001D, true},
		{"not a reparse point", 0, false},
		{"OneDrive cloud file (IO_REPARSE_TAG_CLOUD_6)", 0x9000601A, false},
		{"OneDrive (IO_REPARSE_TAG_ONEDRIVE)", 0x80000021, false},
		{"dedup (IO_REPARSE_TAG_DEDUP)", 0x80000013, false},
		{"projected file (IO_REPARSE_TAG_PROJFS)", 0x9000001C, false},
	} {
		if got := IsLinkTag(c.tag); got != c.want {
			t.Errorf("%s: IsLinkTag(%#x) = %v, want %v", c.name, c.tag, got, c.want)
		}
	}
}
