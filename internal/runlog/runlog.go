// Package runlog writes the structured record of a run.
//
// SAFETY.md rule 5: the run log goes to the DESTINATION volume, not the system
// disk, so the post-mortem survives a machine that will not boot. Open refuses a
// destination it was told is the system volume — the log is the one artefact you
// need when everything else went wrong, and putting it on the disk you are about
// to change is how you lose it.
//
// Format is JSON Lines with keys emitted in a fixed order, so two runs diff
// cleanly. It is append-only and flushed after every event: a log buffered at the
// moment of a power cut is not a log.
package runlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrSystemVolume is returned by Open when the destination is the system volume.
var ErrSystemVolume = errors.New("runlog: refusing to write the run log to the system volume")

// Logger is concurrency-safe.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	c    io.Closer
	seq  int
	now  func() time.Time
	path string
}

// Options configures Open.
type Options struct {
	// DestRoot is the destination volume root. The log lands in
	// DestRoot/_auros/run-<stamp>.jsonl.
	DestRoot string
	// DestIsSystemVolume must be the result of a real volume-identity check
	// (GUID, not drive letter). Open refuses when it is true.
	DestIsSystemVolume bool
	// MetaDir overrides the metadata directory name. Empty means "_auros".
	MetaDir string
	// Stamp names the file. Empty means a UTC timestamp.
	Stamp string
	// Clock may be nil.
	Clock func() time.Time
}

// Open creates a run log on the destination volume.
func Open(opts Options) (*Logger, error) {
	if opts.DestIsSystemVolume {
		return nil, ErrSystemVolume
	}
	if opts.DestRoot == "" {
		return nil, errors.New("runlog: no destination root")
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	meta := opts.MetaDir
	if meta == "" {
		meta = "_auros"
	}
	stamp := opts.Stamp
	if stamp == "" {
		stamp = clock().UTC().Format("20060102T150405Z")
	}
	dir := filepath.Join(opts.DestRoot, meta)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("runlog: %w", err)
	}
	p := filepath.Join(dir, "run-"+stamp+".jsonl")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("runlog: %w", err)
	}
	return &Logger{w: f, c: f, now: clock, path: p}, nil
}

// NewWriter wraps an arbitrary writer. Tests use it; it does not enforce the
// destination rule, which is why Open exists and is what production calls.
func NewWriter(w io.Writer, clock func() time.Time) *Logger {
	if clock == nil {
		clock = time.Now
	}
	return &Logger{w: w, now: clock}
}

// Path is where the log is being written, for display to the user.
func (l *Logger) Path() string { return l.path }

// Fields is an event's payload.
type Fields map[string]any

// Event appends one record. Keys are emitted in a fixed order — seq, ts, phase,
// kind, then the payload sorted by name — so a diff between two runs shows real
// differences rather than map ordering.
func (l *Logger) Event(phase, kind string, f Fields) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	var b strings.Builder
	b.WriteByte('{')
	writeKV(&b, "seq", l.seq, false)
	writeKV(&b, "ts", l.now().UTC().Format(time.RFC3339Nano), true)
	writeKV(&b, "phase", phase, true)
	writeKV(&b, "kind", kind, true)
	keys := make([]string, 0, len(f))
	for k := range f {
		switch k {
		case "seq", "ts", "phase", "kind":
			// Reserved. A payload field must never be able to rewrite the
			// phase or the sequence number a post-mortem is read by.
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		writeKV(&b, k, f[k], true)
	}
	b.WriteString("}\n")
	// Best effort: a failing log must never take down a run that is otherwise
	// fine, but it must also never be silent, so the failure goes to stderr.
	if _, err := io.WriteString(l.w, b.String()); err != nil {
		fmt.Fprintf(os.Stderr, "auros: run log write failed: %v\n", err)
	}
	if s, ok := l.w.(interface{ Sync() error }); ok {
		_ = s.Sync()
	}
}

func writeKV(b *strings.Builder, k string, v any, comma bool) {
	if comma {
		b.WriteByte(',')
	}
	kb, _ := json.Marshal(k)
	b.Write(kb)
	b.WriteByte(':')
	vb, err := json.Marshal(v)
	if err != nil {
		vb, _ = json.Marshal(fmt.Sprintf("%v", v))
	}
	b.Write(vb)
}

// Close flushes and closes the underlying file, if there is one.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.c != nil {
		return l.c.Close()
	}
	return nil
}
