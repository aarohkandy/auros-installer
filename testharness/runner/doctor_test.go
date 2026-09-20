package main

// `runner doctor` exists to refuse a suite that cannot finish. The audit found it never checked that
// the §4.7 volume serials were set, so a suite could start having minted a token naming nothing — and
// every guest tool would then refuse, one run at a time, inside the VM.

import (
	"os"
	"strings"
	"testing"
)

func doctorableConfig(t *testing.T) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig()
	var s1, s2 string
	cfg.Base.SystemImage, s1 = writeBase(t, dir, "windows-base.qcow2", "system")
	cfg.Base.DestImage, s2 = writeBase(t, dir, "dest-empty-ntfs.qcow2", "empty ntfs")
	cfg.Base.SystemSHA256, cfg.Base.DestSHA256 = s1, s2
	cfg.Host.WorkDir = dir
	cfg.Host.MinFreeGB = 0
	return cfg
}

func TestDoctorRefusesAnEmptyVolumeSerial(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"system", "volume_serial"},
		{"dest", "volume_serial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := doctorableConfig(t)
			if tc.name == "system" {
				cfg.Base.SystemVolumeSerial = ""
			} else {
				cfg.Base.DestVolumeSerial = ""
			}
			err := cmdDoctorQuiet(cfg)
			if err == nil {
				t.Fatal("a suite started with an empty volume serial mints a token no guest tool can accept")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// SAFETY.md phase 3 requires a destination that is not the system disk. A harness that blurs the two
// cannot demonstrate that the installer keeps them apart.
func TestDoctorRefusesWhenTheDestinationIsTheSystemVolume(t *testing.T) {
	cfg := doctorableConfig(t)
	cfg.Base.DestVolumeSerial = cfg.Base.SystemVolumeSerial
	if err := cmdDoctorQuiet(cfg); err == nil ||
		!strings.Contains(err.Error(), "same volume") {
		t.Fatalf("want a same-volume refusal, got %v", err)
	}
}

func TestDoctorRefusesAnUnfaithfulCorpus(t *testing.T) {
	cfg := doctorableConfig(t)
	cfg.Base.CorpusFaithful = false
	if err := cmdDoctorQuiet(cfg); err == nil ||
		!strings.Contains(err.Error(), "corpus_faithful") {
		t.Fatalf("want an unfaithful-corpus refusal, got %v", err)
	}
}

// Both base images, before run 1 as well as before every run after it.
func TestDoctorRefusesAContaminatedDestinationBase(t *testing.T) {
	cfg := doctorableConfig(t)
	_ = os.Chmod(cfg.Base.DestImage, 0o644)
	_ = os.WriteFile(cfg.Base.DestImage, []byte("not empty any more"), 0o644)
	_ = os.Chmod(cfg.Base.DestImage, 0o444)
	if err := cmdDoctorQuiet(cfg); err == nil ||
		!strings.Contains(err.Error(), "destination base") {
		t.Fatalf("want a destination-base refusal, got %v", err)
	}
}

// The control: a complete, honest configuration starts.
func TestDoctorAcceptsAWellFormedSuite(t *testing.T) {
	if err := cmdDoctorQuiet(doctorableConfig(t)); err != nil {
		t.Fatalf("a well-formed suite should start: %v", err)
	}
}
