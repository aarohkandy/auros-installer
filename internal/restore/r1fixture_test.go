package restore

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aarohkandy/auros-installer/internal/copyengine"
	"github.com/aarohkandy/auros-installer/internal/manifest"
)

// auros-base's check R1 is the only end-to-end test of the migration, and it
// runs in a CI job that has neither Go nor a checkout of this repository. So it
// builds its archive with a second implementation of the format
// (auros-base/matrix/run/lib/mkarchive.mjs). Two implementations of one format
// drift unless something ties them together. This test is this repository's
// half of that tie:
//
//	testdata/r1-fixture.spec.json  --copyengine.Run (the REAL writer)-->  archive
//	archive/_auros/manifest.tsv    ==  testdata/r1-fixture.manifest.tsv  (byte for byte)
//	archive                        --Find/BuildPlan/Execute (the REAL reader)-->  a clean report
//
// auros-base/tests/r1-archive.test.sh holds the other half: its generator must
// produce the same bytes from the same spec. Both files are copied verbatim
// between the repositories. Change the manifest format and this goes red here;
// regenerate with `go test ./internal/restore -run R1 -update-r1` and copy both
// testdata files into auros-base/matrix/run/lib/.
//
// It also pins the report lines R1 reads off the desktop, so a reworded report
// breaks here rather than silently in a VM.
var updateR1 = flag.Bool("update-r1", false, "rewrite testdata/r1-fixture.manifest.tsv from the real writer")

type r1Spec struct {
	MtimeUnixNS int64             `json:"mtime_unix_ns"`
	Files       map[string]string `json:"files"`
}

func TestR1Fixture_TheRealWriterProducesTheGoldenAndTheRealReaderRestoresIt(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "r1-fixture.spec.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec r1Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}

	// Materialise the source tree. Each top-level directory is one Label.
	src := t.TempDir()
	labels := map[string]bool{}
	mt := time.Unix(0, spec.MtimeUnixNS)
	for logical, content := range spec.Files {
		label, _, _ := strings.Cut(logical, "/")
		labels[label] = true
		p := filepath.Join(src, filepath.FromSlash(logical))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	var sources []copyengine.Source
	for l := range labels {
		sources = append(sources, copyengine.Source{Root: filepath.Join(src, l), Label: l})
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Label < sources[j].Label })

	archive := t.TempDir()
	res, err := copyengine.Run(context.Background(), copyengine.Options{Sources: sources, DestRoot: archive})
	if err != nil {
		t.Fatalf("copyengine.Run: %v", err)
	}
	if res.Manifest.Len() != len(spec.Files) {
		t.Fatalf("the writer recorded %d of %d files; the fixture must not depend on quarantine", res.Manifest.Len(), len(spec.Files))
	}
	got, err := os.ReadFile(filepath.Join(archive, manifest.MetaDir, manifest.FileName))
	if err != nil {
		t.Fatal(err)
	}

	golden := filepath.Join("testdata", "r1-fixture.manifest.tsv")
	if *updateR1 {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("the real writer no longer produces %s.\nauros-base's R1 generator is pinned to those bytes and is now testing a format this program does not write.\n--- got\n%s\n--- want\n%s", golden, got, want)
	}

	// The real reader, end to end, into a clean home.
	_, l := newHome(t)
	s := runIt(t, context.Background(), archive, l, Options{})
	if !s.Clean() {
		t.Fatalf("the R1 fixture does not restore cleanly:\n%s", RenderReport(s, l))
	}
	n := len(spec.Files)
	if s.FilesRestored() != n {
		t.Errorf("restored %d, want %d", s.FilesRestored(), n)
	}
	reportPath, err := WriteReport(s, l)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(reportPath) != "Your files are here.txt" {
		t.Errorf("report written as %q; R1 looks for %q", filepath.Base(reportPath), "Your files are here.txt")
	}
	body := mustRead(t, reportPath)
	for _, line := range []string{
		// These are the strings auros-base's R1 parses (run-update.sh, R1). They
		// are spelled out here, not taken from report.go, so a rewording
		// breaks this test instead of R1.
		fmt.Sprintf("  in the backup's list      %d files\n", n),
		fmt.Sprintf("    %d read back, %d matched, 0 disagreed\n", n, n),
		fmt.Sprintf("    %d of %d entries accounted for\n", n, n),
	} {
		if !strings.Contains(body, line) {
			t.Errorf("report is missing the line R1 reads: %q\n%s", line, body)
		}
	}
}
