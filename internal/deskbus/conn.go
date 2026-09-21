package deskbus

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrNoBus means we could not work out where the session bus is. It is a
// perfectly ordinary outcome — a machine with no graphical session has no
// session bus — and the caller reports it rather than treating it as a failure
// of the restore.
var ErrNoBus = errors.New("deskbus: no session bus address")

// unixNetwork is the ONLY network this package ever dials.
//
// SAFETY.md rule 4 says the migration has no network dependency, and it means a
// school's uplink, not a socket in /run. The wall test in this package asserts
// that this constant is the only thing passed to net.Dial, so "local socket
// only" is a mechanical fact rather than a promise in a comment.
const unixNetwork = "unix"

// Conn is a session-bus connection.
type Conn struct {
	c      net.Conn
	r      *bufio.Reader
	serial uint32
	// Name is the unique bus name the daemon gave us, e.g. ":1.57". It is
	// evidence the handshake really completed: a connection that never got one
	// has not finished connecting, whatever the socket says.
	Name string
}

// Address returns the session bus socket path and how it was found.
//
// Probed in the order the specification gives, and the fallback is derived from
// the real uid rather than remembered: /run/user/1000/bus is right on one
// machine and wrong on the next one.
func Address(env func(string) string, uid int) (network, addr, how string, err error) {
	if env == nil {
		env = os.Getenv
	}
	if a := env("DBUS_SESSION_BUS_ADDRESS"); a != "" {
		n, ad, perr := parseAddress(a)
		if perr != nil {
			return "", "", "DBUS_SESSION_BUS_ADDRESS=" + a, perr
		}
		return n, ad, "DBUS_SESSION_BUS_ADDRESS", nil
	}
	runtimeDir := env("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = "/run/user/" + strconv.Itoa(uid)
	}
	p := runtimeDir + "/bus"
	if st, serr := os.Stat(p); serr != nil {
		return "", "", "", fmt.Errorf("%w: DBUS_SESSION_BUS_ADDRESS is unset and %s is not there (%v)",
			ErrNoBus, p, serr)
	} else if st.Mode()&os.ModeSocket == 0 {
		return "", "", "", fmt.Errorf("%w: %s is a %s, not a socket", ErrNoBus, p, st.Mode().String())
	}
	return unixNetwork, p, "XDG_RUNTIME_DIR", nil
}

// parseAddress handles the transport list in DBUS_SESSION_BUS_ADDRESS. Only
// the unix transport is supported, and an address naming any other transport is
// an error rather than something to fall back from — a tcp: bus address on a
// school laptop is a thing to ask about, not to quietly ignore.
func parseAddress(a string) (network, addr string, err error) {
	for _, one := range strings.Split(a, ";") {
		one = strings.TrimSpace(one)
		if !strings.HasPrefix(one, "unix:") {
			continue
		}
		for _, kv := range strings.Split(strings.TrimPrefix(one, "unix:"), ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			v = unescapeAddr(v)
			switch k {
			case "path":
				return unixNetwork, v, nil
			case "abstract":
				// Go spells a Linux abstract socket with a leading '@'.
				return unixNetwork, "@" + v, nil
			}
		}
	}
	return "", "", fmt.Errorf("%w: %q names no unix socket", ErrNoBus, a)
}

// unescapeAddr reverses the %XX escaping D-Bus applies to address values.
func unescapeAddr(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+2 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		n, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil || len(n) != 1 {
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(n[0])
		i += 2
	}
	return b.String()
}

// Dial connects and completes the SASL EXTERNAL handshake and the Hello call.
//
// EXTERNAL is credential passing over the unix socket: the kernel tells the bus
// who we are, and we send no secret at all. That is the whole reason this is
// safe to do from a program that handles somebody's files — there is no
// password here to get wrong.
func Dial(network, addr string, uid int, timeout time.Duration) (*Conn, error) {
	if network != unixNetwork {
		return nil, fmt.Errorf("deskbus: refusing to dial %q; only %q is permitted", network, unixNetwork)
	}
	c, err := net.DialTimeout(unixNetwork, addr, timeout)
	if err != nil {
		return nil, err
	}
	if derr := c.SetDeadline(time.Now().Add(timeout)); derr != nil {
		c.Close()
		return nil, derr
	}
	conn := &Conn{c: c, r: bufio.NewReader(c)}
	if err := conn.handshake(uid); err != nil {
		c.Close()
		return nil, err
	}
	if err := conn.hello(); err != nil {
		c.Close()
		return nil, err
	}
	return conn, nil
}

// Close releases the socket.
func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) handshake(uid int) error {
	// The leading NUL byte is required by the specification and is not part of
	// any command: it is how the bus distinguishes a D-Bus client from anything
	// else that happened to connect.
	if _, err := c.c.Write([]byte{0}); err != nil {
		return err
	}
	authID := hex.EncodeToString([]byte(strconv.Itoa(uid)))
	if _, err := fmt.Fprintf(c.c, "AUTH EXTERNAL %s\r\n", authID); err != nil {
		return err
	}
	line, err := c.readLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "OK ") {
		return fmt.Errorf("deskbus: the bus refused the connection: %q", line)
	}
	_, err = c.c.Write([]byte("BEGIN\r\n"))
	return err
}

func (c *Conn) readLine() (string, error) {
	s, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (c *Conn) nextSerial() uint32 {
	c.serial++
	return c.serial
}

func (c *Conn) hello() error {
	h, _, err := c.callMethod(call{
		path:        "/org/freedesktop/DBus",
		iface:       "org.freedesktop.DBus",
		member:      "Hello",
		destination: "org.freedesktop.DBus",
	})
	if err != nil {
		return err
	}
	if h.Type == typeError {
		return fmt.Errorf("deskbus: Hello failed: %s", h.Fields[fieldErrorName])
	}
	c.Name = h.Fields[fieldSender]
	return nil
}

// callMethod writes one call and reads until the reply to it arrives.
//
// "Until": the bus may deliver a NameAcquired signal before our reply, and a
// client that treats the first message it receives as its answer misreads that
// signal as a result. Replies carry REPLY_SERIAL, which is how they are
// matched.
func (c *Conn) callMethod(m call) (header, []byte, error) {
	m.serial = c.nextSerial()
	if _, err := c.c.Write(m.marshal()); err != nil {
		return header{}, nil, err
	}
	if m.noReply {
		return header{Type: typeMethodReturn}, nil, nil
	}
	for i := 0; i < 32; i++ {
		h, body, err := c.readMessage()
		if err != nil {
			return header{}, nil, err
		}
		if h.Type == typeSignal {
			continue
		}
		return h, body, nil
	}
	return header{}, nil, errors.New("deskbus: no reply after 32 messages")
}

func (c *Conn) readMessage() (header, []byte, error) {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(c.r, fixed); err != nil {
		return header{}, nil, err
	}
	fieldsLen := int(binary.LittleEndian.Uint32(fixed[12:16]))
	if fieldsLen < 0 || fieldsLen > 1<<20 {
		return header{}, nil, fmt.Errorf("deskbus: implausible header field length %d", fieldsLen)
	}
	rest := make([]byte, alignUp(fieldsLen, 8))
	if _, err := io.ReadFull(c.r, rest); err != nil {
		return header{}, nil, err
	}
	full := append(append([]byte{}, fixed...), rest...)
	h, err := parseHeader(full)
	if err != nil {
		return header{}, nil, err
	}
	if h.BodyLen > 1<<24 {
		return header{}, nil, fmt.Errorf("deskbus: implausible body length %d", h.BodyLen)
	}
	body := make([]byte, h.BodyLen)
	if _, err := io.ReadFull(c.r, body); err != nil {
		return header{}, nil, err
	}
	return h, body, nil
}

// Notification is what appears on the desktop.
type Notification struct {
	AppName string
	Summary string
	Body    string
	Icon    string
	// Urgency: 0 low, 1 normal, 2 critical. Critical notifications are not
	// dismissed on a timer by most shells, which is what we want when a
	// stranger's files did not all come across.
	Urgency byte
	// ExpireMS is -1 for "the shell decides" and 0 for "never expire".
	ExpireMS int32
}

// NotifyBody renders the Notify call body. Exported for the test that checks
// the wire format against a byte-for-byte golden, because a marshaller with no
// golden is a marshaller nobody has read.
func NotifyBody(n Notification) []byte {
	e := &encoder{}
	e.str(n.AppName)
	e.uint32(0) // replaces_id: 0 means "a new notification"
	e.str(n.Icon)
	e.str(n.Summary)
	e.str(n.Body)
	e.emptyStringArray()
	urgency := n.Urgency
	if urgency > 2 {
		urgency = 2
	}
	e.hints(urgency, "transfer.complete")
	e.int32(n.ExpireMS)
	return e.buf
}

// Notify puts a notification on the desktop and returns the id the shell gave
// it.
func (c *Conn) Notify(n Notification) (uint32, error) {
	h, body, err := c.callMethod(call{
		path:        "/org/freedesktop/Notifications",
		iface:       "org.freedesktop.Notifications",
		member:      "Notify",
		destination: "org.freedesktop.Notifications",
		signature:   "susssasa{sv}i",
		body:        NotifyBody(n),
	})
	if err != nil {
		return 0, err
	}
	if h.Type == typeError {
		return 0, fmt.Errorf("deskbus: the desktop refused the notification: %s",
			h.Fields[fieldErrorName])
	}
	if len(body) < 4 {
		return 0, nil
	}
	return binary.LittleEndian.Uint32(body[:4]), nil
}

// Send is the one call the restore makes: connect, notify, disconnect. It
// returns a sentence describing what happened, which goes into the report
// verbatim — including when it did NOT work, because "we told you on the
// desktop" is a claim and an unchecked claim is the thing this project keeps
// finding in its own code.
func Send(n Notification, env func(string) string, uid int, timeout time.Duration) (ok bool, detail string) {
	network, addr, how, err := Address(env, uid)
	if err != nil {
		return false, "not shown as a pop-up: " + err.Error()
	}
	c, err := Dial(network, addr, uid, timeout)
	if err != nil {
		return false, fmt.Sprintf("not shown as a pop-up: could not reach the desktop at %s (found via %s): %v",
			addr, how, err)
	}
	defer c.Close()
	id, err := c.Notify(n)
	if err != nil {
		return false, "not shown as a pop-up: " + err.Error()
	}
	return true, fmt.Sprintf("shown on the desktop (notification %d, via %s)", id, how)
}
