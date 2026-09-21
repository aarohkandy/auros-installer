package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/restore"
)

// Every way the finder can come back empty-handed, and what the command does
// about it. Only "nothing that could hold an archive is attached" is a quiet
// exit 0. The first version sent all three of the first rows here to that exit
// — including the case where the archive was on the stick one folder down and
// the Windows disk it came from was already gone.
func TestFindRefusal_OnlyNothingAttachedIsAQuietNoOp(t *testing.T) {
	wrap := func(e error) error { return fmt.Errorf("%w (looked in: /run/media/u/STICK)", e) }
	cases := []struct {
		name    string
		err     error
		require bool
		code    int
		says    string
	}{
		{"a removable drive was searched and held nothing", wrap(restore.ErrNoArchiveOnAttachedMedia), false,
			exitNoArchiveOnMedia, "do not wipe it"},
		{"--archive named a folder with no backup in it", wrap(restore.ErrExplicitArchiveMissing), false,
			exitUsage, "--archive"},
		{"--archive, even with --require-archive", wrap(restore.ErrExplicitArchiveMissing), true,
			exitUsage, "--archive"},
		{"several different archives", wrap(restore.ErrAmbiguous), false, exitAmbiguous, "more than one"},
		{"nothing attached, --require-archive", wrap(restore.ErrNoArchive), true, exitNoArchive, "no archive"},
		{"nothing attached", wrap(restore.ErrNoArchive), false, exitOK, "Nothing to do"},
		{"an error nobody planned for", errors.New("restore: something new"), false, exitArchiveBad, "cannot be read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, msg := findRefusal(tc.err, tc.require)
			if code != tc.code {
				t.Errorf("exit %d, want %d (message: %q)", code, tc.code, msg)
			}
			if !strings.Contains(msg, tc.says) {
				t.Errorf("message %q does not say %q", msg, tc.says)
			}
			if code == exitOK && !errors.Is(tc.err, restore.ErrNoArchive) {
				t.Errorf("%v became a quiet exit 0", tc.err)
			}
		})
	}
}

// The three "not found" sentinels must not wrap one another. If one did,
// errors.Is would match two branches of findRefusal and the ORDER of the switch
// would silently decide whether a user is told their backup was missed.
func TestFindSentinels_AreDistinct(t *testing.T) {
	all := []error{restore.ErrNoArchive, restore.ErrNoArchiveOnAttachedMedia, restore.ErrExplicitArchiveMissing, restore.ErrAmbiguous}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}
