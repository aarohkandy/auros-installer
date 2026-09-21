package winenv

import (
	"slices"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/labels"
)

// The Windows half's first path segments ARE labels.Folders, in order. The
// Linux restore's join test drives labels.Folders through the real router, so
// this is the link that makes that test about what Windows really produces.
func TestKnownFolders_ProduceExactlyTheSharedLabels(t *testing.T) {
	var got []string
	for _, kf := range knownFolderIDs {
		got = append(got, kf.Name)
	}
	if !slices.Equal(got, labels.Folders) {
		t.Fatalf("the Windows half produces first segments %q; labels.Folders is %q. "+
			"The Linux restore routes on labels.Folders: the two halves disagree", got, labels.Folders)
	}
}
