package winenv

import "github.com/aarohkandy/auros-installer/internal/labels"

// This table is untagged, although only env_windows.go calls Win32 with it, so
// that a test on any platform can see the exact set of first path segments the
// real Windows side produces. The names are internal/labels constants: the
// Linux restore routes on the same ones.

// guid matches the Win32 GUID layout for SHGetKnownFolderPath.
type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// FOLDERID values. These constants are the reason env_windows.go exists: Documents is
// redirected far more often than people expect, and a school laptop with folder
// redirection to a file server is exactly the machine where string-concatenating
// %USERPROFILE% silently copies an empty directory and reports success.
var knownFolderIDs = []struct {
	Name string
	ID   guid
}{
	{labels.Desktop, guid{0xB4BFCC3A, 0xDB2C, 0x424C, [8]byte{0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41}}},
	{labels.Documents, guid{0xFDD39AD0, 0x238F, 0x46AF, [8]byte{0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7}}},
	{labels.Downloads, guid{0x374DE290, 0x123F, 0x4565, [8]byte{0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B}}},
	{labels.Pictures, guid{0x33E28130, 0x4E1E, 0x4676, [8]byte{0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB}}},
	{labels.Music, guid{0x4BD8D571, 0x6D19, 0x48D3, [8]byte{0xBE, 0x97, 0x42, 0x22, 0x20, 0x08, 0x0E, 0x43}}},
	{labels.Videos, guid{0x18989B1D, 0x99B5, 0x455B, [8]byte{0x84, 0x1C, 0xAB, 0x7C, 0x74, 0xE4, 0xDD, 0xFC}}},
	{labels.RoamingAppData, guid{0x3EB685DB, 0x65F9, 0x4CF6, [8]byte{0xA0, 0x3A, 0xE3, 0xEF, 0x65, 0x72, 0x9F, 0x3D}}},
	{labels.LocalAppData, guid{0xF1B32785, 0x6FBA, 0x4FCF, [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}},
}
