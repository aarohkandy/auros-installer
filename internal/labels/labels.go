// Package labels is the one contract the two halves of the migration share
// about paths: the first segment of every manifest path.
//
// The Windows half (internal/winenv) names each known folder it copies with
// one of Folders, and that name becomes the first path segment of every file
// under it. The Linux half (internal/restore) routes on that segment. They are
// different programs built from different entry points, and they disagreed:
// the router was written against Firefox/Chrome/Edge labels the Windows half
// never produces, so browser profiles — which travel INSIDE the AppData
// labels — fell through to "Restored from Windows", and Chrome's password,
// cookie and card databases were restored as ordinary files (SYSTEM-REVIEW
// §2.7). Both sides now spell these names from here and nowhere else.
package labels

// The first path segments the Windows half produces, one per known folder.
const (
	Desktop        = "Desktop"
	Documents      = "Documents"
	Downloads      = "Downloads"
	Pictures       = "Pictures"
	Music          = "Music"
	Videos         = "Videos"
	RoamingAppData = "RoamingAppData" // FOLDERID_RoamingAppData, %APPDATA%
	LocalAppData   = "LocalAppData"   // FOLDERID_LocalAppData, %LOCALAPPDATA%
)

// Folders is every label the Windows half can produce, in the order it copies
// them. internal/winenv's test pins its known-folder table to exactly this list.
var Folders = []string{Desktop, Documents, Downloads, Pictures, Music, Videos, RoamingAppData, LocalAppData}

// Where browser profiles sit inside the AppData labels, as manifest path
// prefixes. These are where the browsers themselves put them on Windows, and
// where the Gate 3 corpus (testharness/gen/generate.go) puts them.
const (
	ChromeUserData = LocalAppData + "/Google/Chrome/User Data"
	EdgeUserData   = LocalAppData + "/Microsoft/Edge/User Data"
	FirefoxRoot    = RoamingAppData + "/Mozilla/Firefox" // holds profiles.ini and Profiles/
)

// Labels the Linux router understands that NO Windows code produces yet
// (SYSTEM-REVIEW §2.8: Wi-Fi and printer export do not exist). They are not in
// Folders, and the join test does not pretend they arrive.
const (
	WiFi     = "WiFi"
	Printers = "Printers"
)
