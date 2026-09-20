package main

import (
	"os"
	"runtime"
	"time"
)

// platGOOS is recorded in the manifest so that a reviewer can see at a glance whether a corpus was
// produced on the platform that can actually apply Windows file properties.
func platGOOS() string { return runtime.GOOS }

// platWaitForFile blocks until path exists. Used by `gen hold` to keep exclusive handles open for
// exactly as long as the run needs them.
//
// time.Sleep is used here and nowhere else in this program. Sleeping is run behaviour; the prohibition
// in the package comment is on time.Now, because a clock reading that reaches the CORPUS makes the
// corpus unreproducible. A sleep does not reach the corpus.
func platWaitForFile(path string, pollMS int) {
	if pollMS < 10 {
		pollMS = 10
	}
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(time.Duration(pollMS) * time.Millisecond)
	}
}
