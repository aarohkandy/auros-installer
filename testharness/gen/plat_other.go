//go:build !windows

package main

// Everything Windows-specific is unavailable here, and says so rather than pretending.
//
// The generator still runs on macOS and Linux in -manifest-only mode, which is how the corpus layout
// gets reviewed without a VM. What it CANNOT do off Windows is apply read-only bits, alternate data
// streams or the offline attribute, and it will not claim otherwise: platFaithful returns false, the
// manifest records faithful=false, and runner/ refuses to treat a run against an unfaithful corpus as
// evidence. A "100/100" produced from a corpus with no alternate data streams in it would be a number
// that means nothing, published under a heading that says it means something.

func platFaithful() bool { return false }

func platVolumeSerial(path string) (string, error) { return "", errNotSupported }

func platSetReadOnly(path string) error { return errNotSupported }

func platSetOffline(path string) error { return errNotSupported }

func platWriteStream(path, stream string, data []byte) error { return errNotSupported }

func platHoldExclusive(paths []string) (func(), error) { return func() {}, errNotSupported }
