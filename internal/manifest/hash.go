package manifest

import (
	"context"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// DefaultBufSize is the streaming chunk size. Every read path in this repository
// is streamed through a fixed buffer, so a file larger than available RAM is an
// ordinary file, not a special case. Nothing anywhere reads a whole file into
// memory.
const DefaultBufSize = 1 << 20 // 1 MiB

// Sum renders a hash as the lowercase hex the manifest format requires.
func Sum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

// CopyHashed streams src to dst through buf, hashing the SAME bytes it writes,
// and returns the digest and the byte count.
//
// This is the function SAFETY.md phase 4 is about. The digest comes from the read
// that produced the written bytes. Hashing the source again afterwards would hash
// a file that may have changed in between — on a live Windows machine, with
// OneDrive and antivirus and an open document, it frequently has.
//
// ctx is checked between chunks, so cancelling mid-file stops promptly and the
// caller can delete the partial file it was writing.
func CopyHashed(ctx context.Context, dst io.Writer, src io.Reader, h hash.Hash, buf []byte) (string, int64, error) {
	if len(buf) == 0 {
		buf = make([]byte, DefaultBufSize)
	}
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return "", written, err
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			// Hash before writing: if the write fails we still know what we read,
			// and we never write a byte we did not hash.
			h.Write(buf[:n])
			w, werr := dst.Write(buf[:n])
			written += int64(w)
			if werr != nil {
				return "", written, werr
			}
			if w != n {
				return "", written, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return Sum(h), written, nil
			}
			return "", written, rerr
		}
	}
}

// HashFile re-reads a file from disk and returns its digest and size. This is the
// SECOND read, used only by phase 5 against the DESTINATION. It must never be
// pointed at the source to produce a manifest entry.
func HashFile(ctx context.Context, path string, h hash.Hash, buf []byte) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	return CopyHashed(ctx, io.Discard, f, h, buf)
}
