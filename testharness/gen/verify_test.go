package main

// `gen verify` is the only thing in the harness that measures data. The runner now calls it TWICE per
// verify boot — once for the source corpus and once for the archive the installer materialised — and
// reads both back off one serial line, so the label and the delivery path are load-bearing.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusFixture writes a tiny corpus and its manifest, and returns (root, manifestPath, manifestSHA).
func corpusFixture(t *testing.T, files map[string]string) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "corpus")
	if err := os.MkdirAll(filepath.Join(root, "Documents"), 0o755); err != nil {
		t.Fatal(err)
	}
	var lines []string
	i := 0
	for _, rel := range sortedKeys(files) {
		body := files[rel]
		abs := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(body))
		rec := FileRec{Index: i, Path: rel, WinPath: `C:\Users\student\` + rel,
			Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Cohort: "doc"}
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
		i++
	}
	man := filepath.Join(dir, "golden-manifest.jsonl")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(man, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(body))
	return root, man, hex.EncodeToString(h[:])
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// captureStdout runs fn with os.Stdout redirected and returns what it printed.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

// The runner reads both verifications off one serial line. Without the label, two structurally
// identical JSON objects are told apart only by the order they arrive in.
func TestVerifyReportsItsLabelAndTheManifestItUsed(t *testing.T) {
	root, man, msha := corpusFixture(t, map[string]string{
		"Documents/a.docx": "hello",
		"Documents/b.txt":  "world!!",
	})
	out := captureStdout(t, func() {
		if err := cmdVerify([]string{"-root", root, "-manifest", man, "-label", "archive", "-stdout-json"}); err != nil {
			t.Error(err)
		}
	})
	body := between(t, out, "verify-begin archive", "verify-end archive")
	var res VerifyResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("the block between the markers is not JSON: %v\n%s", err, out)
	}
	if res.Label != "archive" {
		t.Errorf("label = %q", res.Label)
	}
	if res.ManifestSHA != msha {
		t.Errorf("manifest_sha256 = %s, want %s — P4 pins this to the suite's corpus digest, so a "+
			"guest verifying against a smaller manifest is visible", res.ManifestSHA, msha)
	}
	if res.Expected != 2 || res.HashMatches != 2 || !res.Clean {
		t.Errorf("unexpected counts: %+v", res)
	}
	if res.PresentBytes != int64(len("hello")+len("world!!")) {
		t.Errorf("present_bytes = %d; on an aborted run this is the number that says whether the "+
			"installer was copying at all", res.PresentBytes)
	}
}

// An unknown label would let a third block appear that the runner silently ignores.
func TestVerifyRejectsAnUnknownLabel(t *testing.T) {
	root, man, _ := corpusFixture(t, map[string]string{"Documents/a.docx": "hello"})
	err := cmdVerify([]string{"-root", root, "-manifest", man, "-label", "whatever"})
	if err == nil || !strings.Contains(err.Error(), "-label must be") {
		t.Fatalf("want a rejected label, got %v", err)
	}
}

func between(t *testing.T, s, start, end string) string {
	t.Helper()
	i := strings.Index(s, start)
	j := strings.Index(s, end)
	if i < 0 || j < 0 || j <= i {
		t.Fatalf("no %q…%q block in:\n%s", start, end, s)
	}
	return strings.TrimSpace(s[i+len(start) : j])
}

// The LocalAppData hazards are not data, so they are not in the golden manifest; the plan is the only
// place a runner can learn that the installer was made to meet them. A plan without them is a Gate 3
// that is blind to SYSTEM-REVIEW §2.20 again.
func TestPlanNamesTheLocalAppDataJunctionsAndTheDeniedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := cmdGenerate([]string{"-seed", "7", "-root", `C:\Users\student`, "-count", "200",
		"-profile", "compact", "-manifest-only", "-manifest-dir", dir}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "corpus-plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`C:\Users\student\AppData\Local\Application Data`,
		`C:\Users\student\AppData\Local\History`,
		`C:\Users\student\AppData\Local\Temporary Internet Files`,
	}
	if strings.Join(p.Junctions, "|") != strings.Join(want, "|") {
		t.Errorf("junctions = %q, want %q", p.Junctions, want)
	}
	if len(p.DenyACLDirs) != 1 || !strings.HasPrefix(p.DenyACLDirs[0], `C:\Users\student\AppData\Local\`) {
		t.Errorf("deny_acl_dirs = %q, want one directory under LocalAppData", p.DenyACLDirs)
	}
}
