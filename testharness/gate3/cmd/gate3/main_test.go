package main

import (
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/testharness/gate3"
)

func TestGateClaim(t *testing.T) {
	var all []string
	for _, sc := range gate3.Suite() {
		all = append(all, sc.ID)
	}
	if _, err := gateClaim(0, nil, nil); err == nil {
		t.Error("a run that owed nothing must not pass")
	}
	if c, err := gateClaim(100, all, []string{"realistic"}); err != nil || c != "GATE 3 PASSED" {
		t.Errorf("full shape: got %q, %v", c, err)
	}
	for name, tc := range map[string]struct {
		clean    int
		wanted   []string
		profiles []string
	}{
		"push shape":      {2, []string{"F01", "F07", "G01"}, []string{"compact"}},
		"too few clean":   {99, all, []string{"realistic"}},
		"a fault skipped": {100, all[1:], []string{"realistic"}},
		"compact corpus":  {100, all, []string{"realistic", "compact"}},
	} {
		c, err := gateClaim(tc.clean, tc.wanted, tc.profiles)
		if err != nil || strings.Contains(c, "GATE 3 PASSED") {
			t.Errorf("%s: got %q, %v; a partial shape must not claim the gate", name, c, err)
		}
	}
}
