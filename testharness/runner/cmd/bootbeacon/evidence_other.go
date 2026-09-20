//go:build !windows

package main

import "errors"

// The beacon only means anything inside the Windows guest. This build exists so the package compiles
// for review on the operator's machine, and it reports nothing rather than reporting a guess — an empty
// system-state hash makes the boot check FAIL, which is the correct outcome for a beacon that did not
// actually look at a Windows machine.

func secondsSinceBoot() float64 { return 0 }

type eventEvidence struct {
	bugcheck       bool
	bugcheckDetail string
	dirtyShutdown  bool
	chkdsk         bool
	recoveryEnv    bool
}

func collectEventEvidence() eventEvidence { return eventEvidence{} }

func systemState() (string, []string, bool, error) {
	return "", nil, false, errors.New("system state can only be read inside the Windows guest")
}
