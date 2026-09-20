package fault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// SPEC §4.7 — "never test the migration installer against the operator's own machine"
//
// A rule written in a document is obeyed until the evening somebody is in a hurry. This is the same
// rule expressed as a thing that does not work.
//
// The runner mints a Token once per suite and writes it to a small marker disk image that is attached
// to the test VM and to nothing else. The token names the volume serial of the disk the harness is
// allowed to destroy — which the runner knows because the base qcow2 was built once and its volume
// serial was recorded then, in base-image.json.
//
// To point any part of this harness at a real machine you would have to: mint a token naming that
// machine's volume serial, put it on a volume labelled AUROS-HARNESS, and attach it. That is not
// impossible — a determined person can do it in ten minutes. It is meant to be AWKWARD, and to leave an
// artefact behind that says, in the operator's own handwriting, that they told the harness this disk was
// disposable.
//
// There is no --force. Adding one would convert a structural guarantee back into a documented
// preference, and the entire reason this check is shaped like this is that documented preferences are
// what Wubi had.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// Token is the file the runner writes to the marker volume.
type Token struct {
	Harness         string `json:"harness"`
	SuiteID         string `json:"suite_id"`
	RunID           string `json:"run_id"`
	BaseImageSHA    string `json:"base_image_sha256"`
	TargetVolSerial string `json:"target_volume_serial"`

	// DestVolSerial is the destination (archive) volume, which the fault agent is also allowed to
	// damage. Separate from the corpus volume because they are separate disks and conflating them is
	// how a harness ends up writing a balloon file onto the volume it is meant to be preserving.
	DestVolSerial string `json:"dest_volume_serial"`

	DestroysEverythingHere bool   `json:"destroys_everything_on_target_volume"`
	CorpusDigest           string `json:"corpus_digest,omitempty"`
	Note                   string `json:"note"`
}

func LoadToken(path string) (*Token, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("harness token unreadable (%s): %w", path, err)
	}
	var t Token
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("harness token malformed: %w", err)
	}
	if t.Harness == "" || t.SuiteID == "" || t.TargetVolSerial == "" {
		return nil, errors.New("harness token incomplete")
	}
	if !t.DestroysEverythingHere {
		return nil, errors.New("harness token does not assert destroys_everything_on_target_volume")
	}
	return &t, nil
}

// AssertScratch fails closed. Any error, any mismatch, any inability to read a volume serial, and the
// caller must exit without touching anything.
func AssertScratch(tokenPath, corpusRoot, destRoot string) (*Token, error) {
	tok, err := LoadToken(tokenPath)
	if err != nil {
		return nil, err
	}
	corpusSerial, err := VolumeSerial(corpusRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot read the volume serial of %s: %w", corpusRoot, err)
	}
	if !strings.EqualFold(corpusSerial, tok.TargetVolSerial) {
		return nil, fmt.Errorf(
			"REFUSING: the corpus root %s is on volume %s; the harness token vouches only for %s.\n"+
				"Spec §4.7: the migration installer is never tested against the operator's own machine.",
			corpusRoot, corpusSerial, tok.TargetVolSerial)
	}
	if destRoot != "" && tok.DestVolSerial != "" {
		destSerial, err := VolumeSerial(destRoot)
		if err != nil {
			return nil, fmt.Errorf("cannot read the volume serial of %s: %w", destRoot, err)
		}
		if !strings.EqualFold(destSerial, tok.DestVolSerial) {
			return nil, fmt.Errorf(
				"REFUSING: the destination %s is on volume %s; the token vouches only for %s",
				destRoot, destSerial, tok.DestVolSerial)
		}
		if strings.EqualFold(destSerial, corpusSerial) {
			return nil, errors.New(
				"REFUSING: the destination and the corpus are the same volume. SAFETY.md phase 3 requires " +
					"a destination that is not the system disk, and a harness that blurs the two cannot " +
					"prove the installer keeps them apart")
		}
	}
	return tok, nil
}
