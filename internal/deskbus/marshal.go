// Package deskbus speaks just enough D-Bus to put a notification on the user's
// desktop, over the session bus's unix socket, with no third-party dependency
// and without running a command.
//
// # Why not just run notify-send
//
// SAFETY.md's wall confines os/exec to internal/sysdisk, and that rule is worth
// more than the convenience of a subprocess. It is what makes "only one place
// in this repository can reach outside the process" a mechanical fact rather
// than a habit. Widening it so the Linux half can pop a toast would be paying
// for a notification with the strongest structural guarantee in the product.
//
// notify-send is also not guaranteed to be installed, it is a different binary
// on different desktops, and its failure mode is a non-zero exit nobody reads.
// The bus is the actual interface; notify-send is a wrapper around it.
//
// # The whole protocol we implement
//
// Connect to $DBUS_SESSION_BUS_ADDRESS, do the SASL EXTERNAL handshake, call
// org.freedesktop.DBus.Hello, call org.freedesktop.Notifications.Notify. That
// is all. No signals, no properties, no introspection, no big-endian encoding,
// no file descriptor passing.
package deskbus

import (
	"encoding/binary"
	"fmt"
	"math"
)

// encoder builds a little-endian D-Bus message body.
//
// D-Bus alignment is the whole game: every basic type is written at an offset
// that is a multiple of its own size, measured FROM THE START OF THE MESSAGE.
// Getting that wrong produces a message the bus rejects with a parse error and
// no useful detail, so the padding is done in exactly one place — align — and
// every writer calls it.
type encoder struct {
	buf []byte
	// base is the offset this encoder's bytes will sit at in the final
	// message. A body starts at a multiple of 8, so a body encoder has base 0
	// and its alignment is its own; a header-field encoder is spliced into the
	// header and carries the offset it starts at.
	base int
}

func (e *encoder) pos() int { return e.base + len(e.buf) }

// align pads to the next multiple of n with zero bytes.
func (e *encoder) align(n int) {
	for e.pos()%n != 0 {
		e.buf = append(e.buf, 0)
	}
}

func (e *encoder) byte(b byte) { e.buf = append(e.buf, b) }

func (e *encoder) uint32(v uint32) {
	e.align(4)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *encoder) int32(v int32) { e.uint32(uint32(v)) }

func (e *encoder) uint64(v uint64) {
	e.align(8)
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	e.buf = append(e.buf, b[:]...)
}

func (e *encoder) double(v float64) { e.uint64(math.Float64bits(v)) }

// str writes a STRING or OBJECT_PATH: a uint32 length, the bytes, a NUL.
func (e *encoder) str(s string) {
	e.uint32(uint32(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
}

// sig writes a SIGNATURE: a single length byte, the bytes, a NUL. Signatures
// are capped at 255 bytes by the specification; ours are compile-time
// constants, so a longer one is a programming error and says so.
func (e *encoder) sig(s string) {
	if len(s) > 255 {
		panic("deskbus: signature longer than 255 bytes: " + s)
	}
	e.byte(byte(len(s)))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0)
}

// array runs write between a length prefix and the data, then backfills the
// length. elemAlign is the alignment of the ELEMENT type, which is applied
// after the length word even when the array turns out to be empty — an empty
// array of structs still carries its padding, and a decoder that expects it
// rejects a message that does not.
func (e *encoder) array(elemAlign int, write func()) {
	e.align(4)
	lenAt := len(e.buf)
	e.buf = append(e.buf, 0, 0, 0, 0)
	e.align(elemAlign)
	start := len(e.buf)
	write()
	binary.LittleEndian.PutUint32(e.buf[lenAt:lenAt+4], uint32(len(e.buf)-start))
}

// variant writes a VARIANT: a signature then the value.
func (e *encoder) variant(signature string, write func()) {
	e.sig(signature)
	write()
}

// emptyStringArray writes `as` with no elements. The notification spec's
// `actions` parameter is required and we never send actions: a notification
// with a button that this program cannot service would be a lie in the shape
// of a UI.
func (e *encoder) emptyStringArray() { e.array(4, func() {}) }

// hints writes `a{sv}`. Only the hints we actually mean are sent.
func (e *encoder) hints(urgency byte, category string) {
	e.array(8, func() {
		// urgency: 0 low, 1 normal, 2 critical
		e.align(8)
		e.str("urgency")
		e.variant("y", func() { e.byte(urgency) })
		if category != "" {
			e.align(8)
			e.str("category")
			e.variant("s", func() { e.str(category) })
		}
	})
}

// msgType and flags per the D-Bus specification.
const (
	typeMethodCall   = 1
	typeMethodReturn = 2
	typeError        = 3
	typeSignal       = 4

	flagNoReplyExpected = 0x1
)

// Header field codes.
const (
	fieldPath        = 1
	fieldInterface   = 2
	fieldMember      = 3
	fieldErrorName   = 4
	fieldReplySerial = 5
	fieldDestination = 6
	fieldSender      = 7
	fieldSignature   = 8
)

// call is one outgoing method call.
type call struct {
	path        string
	iface       string
	member      string
	destination string
	signature   string
	body        []byte
	serial      uint32
	noReply     bool
}

// marshal renders a method call to the wire.
//
// The fixed header is 12 bytes, then the header-field array, then padding to a
// multiple of 8, then the body. The body's own encoder therefore starts at
// offset 0 modulo 8, which is why a body can be built independently of the
// header it will be attached to.
func (c call) marshal() []byte {
	h := &encoder{}
	h.byte('l') // little-endian
	h.byte(typeMethodCall)
	flags := byte(0)
	if c.noReply {
		flags |= flagNoReplyExpected
	}
	h.byte(flags)
	h.byte(1) // protocol version
	h.uint32(uint32(len(c.body)))
	h.uint32(c.serial)

	h.array(8, func() {
		field := func(code byte, sigStr string, write func()) {
			h.align(8)
			h.byte(code)
			h.variant(sigStr, write)
		}
		field(fieldPath, "o", func() { h.str(c.path) })
		field(fieldInterface, "s", func() { h.str(c.iface) })
		field(fieldMember, "s", func() { h.str(c.member) })
		if c.destination != "" {
			field(fieldDestination, "s", func() { h.str(c.destination) })
		}
		if c.signature != "" {
			field(fieldSignature, "g", func() { h.sig(c.signature) })
		}
	})
	h.align(8)
	return append(h.buf, c.body...)
}

// header is a decoded reply header, enough to tell a return from an error.
type header struct {
	Type       byte
	BodyLen    uint32
	Serial     uint32
	Fields     map[byte]string
	HeaderSize int
}

// parseHeader decodes just enough of an incoming message to route it. It
// returns the total length of the fixed header plus the field array plus its
// padding, so the caller knows where the body starts.
func parseHeader(b []byte) (header, error) {
	if len(b) < 16 {
		return header{}, fmt.Errorf("deskbus: short message header (%d bytes)", len(b))
	}
	if b[0] != 'l' {
		// Everything we talk to is the local session bus on the same machine,
		// which is little-endian on every platform this product ships to. A
		// big-endian reply means something unexpected is on the other end.
		return header{}, fmt.Errorf("deskbus: reply is not little-endian (byte order %q)", b[0])
	}
	h := header{
		Type:    b[1],
		BodyLen: binary.LittleEndian.Uint32(b[4:8]),
		Serial:  binary.LittleEndian.Uint32(b[8:12]),
		Fields:  map[byte]string{},
	}
	fieldsLen := int(binary.LittleEndian.Uint32(b[12:16]))
	if fieldsLen < 0 || 16+fieldsLen > len(b) {
		return header{}, fmt.Errorf("deskbus: header field array claims %d bytes, message has %d",
			fieldsLen, len(b)-16)
	}
	end := 16 + fieldsLen
	p := 16
	// Every path out of this loop either advances p or leaves the loop. A
	// `break` inside the switch below would break the SWITCH and spin here
	// forever on a malformed reply, which is the shape of hang this kind of
	// parser is famous for, so the decoding is done in helpers that return a
	// new offset and an ok.
	for p < end {
		p = alignUp(p, 8)
		if p+2 > end {
			break
		}
		code := b[p]
		sigStr, np, ok := readSignature(b, p+1, end)
		if !ok {
			break
		}
		p = np
		switch sigStr {
		case "s", "o":
			val, np, ok := readString(b, p, end)
			if !ok {
				p = end
				break
			}
			h.Fields[code] = val
			p = np
		case "g":
			val, np, ok := readSignature(b, p, end)
			if !ok {
				p = end
				break
			}
			h.Fields[code] = val
			p = np
		case "u":
			p = alignUp(p, 4)
			if p+4 > end {
				p = end
				break
			}
			p += 4
		default:
			// A type this decoder does not know the width of. It cannot be
			// skipped, so stop rather than misread everything after it.
			p = end
		}
	}
	h.HeaderSize = alignUp(end, 8)
	return h, nil
}

// readSignature reads a SIGNATURE (one length byte, bytes, NUL) at p.
func readSignature(b []byte, p, end int) (string, int, bool) {
	if p >= end {
		return "", p, false
	}
	n := int(b[p])
	p++
	if p+n+1 > end {
		return "", p, false
	}
	return string(b[p : p+n]), p + n + 1, true
}

// readString reads a STRING or OBJECT_PATH (4-aligned uint32 length, bytes, NUL).
func readString(b []byte, p, end int) (string, int, bool) {
	p = alignUp(p, 4)
	if p+4 > end {
		return "", p, false
	}
	n := int(binary.LittleEndian.Uint32(b[p : p+4]))
	p += 4
	if n < 0 || p+n+1 > end {
		return "", p, false
	}
	return string(b[p : p+n]), p + n + 1, true
}

func alignUp(v, n int) int {
	if r := v % n; r != 0 {
		return v + (n - r)
	}
	return v
}
