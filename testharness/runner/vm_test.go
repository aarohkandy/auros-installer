package main

// Base-image immutability and the QEMU wrapper. The audit found that `runner` did not compile at all
// (`v.stderr undefined`, twice), so the VM path had never been executed; and that only the SYSTEM base
// was hashed per run, leaving the destination base verified once per suite, before run 1.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBase(t *testing.T, dir, name, content string) (path, sum string) {
	t.Helper()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	sum, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sum
}

// MAJOR, execute.go:399 — "contaminate the destination base image mid-suite: a stray qemu-img commit,
// an operator editing dest-empty-ntfs.qcow2 at run 40." Never detected: only the system base was
// hashed before and after a run.
func TestAContaminatedDestinationBaseIsDetected(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	var s1, s2 string
	cfg.Base.SystemImage, s1 = writeBase(t, dir, "windows-base.qcow2", "system")
	cfg.Base.DestImage, s2 = writeBase(t, dir, "dest-empty-ntfs.qcow2", "empty ntfs")
	cfg.Base.SystemSHA256, cfg.Base.DestSHA256 = s1, s2

	if err := AssertBasesUnchanged(cfg); err != nil {
		t.Fatalf("a pristine pair should verify: %v", err)
	}

	// Run 40 leaves the previous run's archive in the destination base.
	_ = os.Chmod(cfg.Base.DestImage, 0o644)
	if err := os.WriteFile(cfg.Base.DestImage, []byte("empty ntfs + run 39's archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(cfg.Base.DestImage, 0o444)

	err := AssertBasesUnchanged(cfg)
	if err == nil {
		t.Fatal("run 41 would have been measured against run 39's leftovers, undetected")
	}
	if !strings.Contains(err.Error(), "destination base") {
		t.Fatalf("the refusal must name which image moved: %v", err)
	}
}

func TestAContaminatedSystemBaseIsDetected(t *testing.T) {
	dir := t.TempDir()
	cfg := testConfig()
	var s1, s2 string
	cfg.Base.SystemImage, s1 = writeBase(t, dir, "windows-base.qcow2", "system")
	cfg.Base.DestImage, s2 = writeBase(t, dir, "dest-empty-ntfs.qcow2", "empty ntfs")
	cfg.Base.SystemSHA256, cfg.Base.DestSHA256 = s1, s2
	_ = os.Chmod(cfg.Base.SystemImage, 0o644)
	_ = os.WriteFile(cfg.Base.SystemImage, []byte("system, edited"), 0o644)
	_ = os.Chmod(cfg.Base.SystemImage, 0o444)
	if err := AssertBasesUnchanged(cfg); err == nil || !strings.Contains(err.Error(), "system base") {
		t.Fatalf("want a named system-base failure, got %v", err)
	}
}

// vm.go's second pillar is that the base carries no write bit, and it is checked rather than assumed.
func TestAWritableBaseImageIsRefused(t *testing.T) {
	dir := t.TempDir()
	p, sum := writeBase(t, dir, "windows-base.qcow2", "system")
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	err := AssertBaseUnchanged(p, sum)
	if err == nil {
		t.Fatal("a writable base image is one command away from invalidating the whole suite")
	}
	if !strings.Contains(err.Error(), "WRITABLE") {
		t.Fatalf("unexpected refusal: %v", err)
	}
}

// A config with no recorded hash cannot prove anything, and "unverified" is not "unchanged".
func TestABaseWithNoRecordedHashIsRefused(t *testing.T) {
	dir := t.TempDir()
	p, _ := writeBase(t, dir, "windows-base.qcow2", "system")
	if err := AssertBaseUnchanged(p, ""); err == nil {
		t.Fatal("an unrecorded base hash must stop the suite, not pass it")
	}
}

// MAJOR, vm.go:214 — `runner` did not compile: VM had no `stderr` field and Start assigned to one.
// This test exercises the exact statement, so the field cannot be quietly removed again: a VM whose
// QEMU binary does not exist must still have opened, recorded and closed its stderr file.
func TestVMStartCapturesQemuStderrWhenQemuCannotStart(t *testing.T) {
	// A SHORT directory, not t.TempDir(): unix socket paths are capped near 104 bytes and this test's
	// own name is long enough to blow past that, which is the same trap execute.go documents.
	dir, err := os.MkdirTemp("", "aur")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	spec := VMSpec{
		QemuBinary:  filepath.Join(dir, "there-is-no-qemu-here"),
		MemoryMB:    512,
		CPUs:        1,
		QMPSock:     filepath.Join(dir, "qmp.sock"),
		ControlSock: filepath.Join(dir, "ctl.sock"),
		SerialLog:   filepath.Join(dir, "serial.log"),
	}
	vm := &VM{}
	serr := vm.Start(spec)
	if serr == nil {
		t.Fatal("starting a VM with no QEMU should fail")
	}
	if !strings.Contains(serr.Error(), "there-is-no-qemu-here") {
		t.Fatalf("the failure should be QEMU's absence, not something else: %v", serr)
	}
	if vm.stderr == nil {
		t.Fatal("QEMU's diagnostics were never captured: a QEMU that refuses to start would say so " +
			"into a file nobody holds")
	}
	if _, statErr := os.Stat(spec.SerialLog + ".qemu-stderr"); statErr != nil {
		t.Fatalf("no stderr file: %v", statErr)
	}
	vm.Close()
}
