package runlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clock() func() time.Time {
	t := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

func TestOpen_RefusesTheSystemVolume(t *testing.T) {
	// SAFETY.md rule 5. The log is the one artefact you need when the machine
	// will not boot, so it does not live on the disk that is about to change.
	o := Options{}
	o.DestRoot = t.TempDir()
	o.DestIsSystemVolume = true
	if _, err := Open(o); !errors.Is(err, ErrSystemVolume) {
		t.Fatalf("err = %v, want ErrSystemVolume", err)
	}
}

func TestOpen_WritesToTheDestinationVolume(t *testing.T) {
	dest := t.TempDir()
	o := Options{}
	o.DestRoot = dest
	o.Stamp = "TEST"
	o.Clock = clock()
	l, err := Open(o)
	if err != nil {
		t.Fatal(err)
	}
	l.Event("5-verify", "verified", Fields{"file_count": 18000})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(dest, "_auros", "run-TEST.jsonl")
	if l.Path() != want {
		t.Errorf("Path = %q, want %q", l.Path(), want)
	}
	b, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("the log was not written to the destination: %v", err)
	}
	if !strings.Contains(string(b), `"file_count":18000`) {
		t.Errorf("log does not carry the event: %s", b)
	}
}

func TestEvent_KeysAreInAFixedOrder(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf, clock())
	l.Event("4-copy", "progress", Fields{"zebra": 1, "alpha": 2, "middle": 3})
	line := strings.TrimSpace(buf.String())

	wantPrefix := `{"seq":1,"ts":"2026-09-20T12:00:00Z","phase":"4-copy","kind":"progress",`
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("line = %s\nwant prefix %s", line, wantPrefix)
	}
	if !strings.Contains(line, `"alpha":2,"middle":3,"zebra":1`) {
		t.Errorf("payload keys are not sorted: %s", line)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatalf("the line is not valid JSON: %v\n%s", err, line)
	}
}

func TestEvent_IsDeterministicAcrossRuns(t *testing.T) {
	var a, b bytes.Buffer
	for _, w := range []*bytes.Buffer{&a, &b} {
		l := NewWriter(w, clock())
		l.Event("1-inventory", "found", Fields{"files": 18000, "bytes": 42})
		l.Event("3-destination", "chosen", Fields{"guid": "{1234}"})
	}
	if a.String() != b.String() {
		t.Fatalf("two identical runs produced different logs:\n%s\n%s", a.String(), b.String())
	}
}

func TestEvent_ReservedKeysCannotBeOverridden(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf, clock())
	l.Event("6-arm", "armed", Fields{"seq": 999, "phase": "1-inventory", "kind": "nothing-happened"})
	line := buf.String()
	if strings.Contains(line, "999") || strings.Contains(line, "nothing-happened") {
		t.Fatalf("a payload field overwrote a reserved field: %s", line)
	}
	if !strings.Contains(line, `"phase":"6-arm"`) {
		t.Errorf("the real phase was lost: %s", line)
	}
}

func TestEvent_SequenceIncrements(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf, clock())
	for i := 0; i < 3; i++ {
		l.Event("4-copy", "file", nil)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	for i, want := range []string{`"seq":1`, `"seq":2`, `"seq":3`} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d = %s, want %s", i, lines[i], want)
		}
	}
}

func TestNilLoggerIsSafe(t *testing.T) {
	// Every call site passes a logger that may be nil. A nil log must never be
	// the reason a migration stops.
	var l *Logger
	l.Event("1-inventory", "x", Fields{"a": 1})
	if err := l.Close(); err != nil {
		t.Errorf("Close on a nil logger: %v", err)
	}
}

func TestOpen_RefusesWithoutADestination(t *testing.T) {
	if _, err := Open(Options{}); err == nil {
		t.Fatal("a log was opened with no destination")
	}
}

func TestConcurrentEvents(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriter(&buf, clock())
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 25; j++ {
				l.Event("4-copy", "file", Fields{"n": j})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 200 {
		t.Fatalf("lines = %d, want 200", len(lines))
	}
	for _, line := range lines {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Fatalf("interleaved write produced invalid JSON: %v\n%s", err, line)
		}
	}
}
