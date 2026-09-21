package deskbus

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAddress_ParsesTheFormsARealSessionUses(t *testing.T) {
	cases := []struct {
		in       string
		wantAddr string
	}{
		{"unix:path=/run/user/1000/bus", "/run/user/1000/bus"},
		{"unix:path=/run/user/1000/bus,guid=abc123", "/run/user/1000/bus"},
		{"unix:abstract=/tmp/dbus-AbCd,guid=x", "@/tmp/dbus-AbCd"},
		{"unix:path=/run/user/1000/bus%20with%20spaces", "/run/user/1000/bus with spaces"},
		{"tcp:host=localhost,port=1;unix:path=/run/user/1000/bus", "/run/user/1000/bus"},
	}
	for _, c := range cases {
		n, a, err := parseAddress(c.in)
		if err != nil {
			t.Errorf("parseAddress(%q): %v", c.in, err)
			continue
		}
		if n != unixNetwork || a != c.wantAddr {
			t.Errorf("parseAddress(%q) = %q,%q want %q,%q", c.in, n, a, unixNetwork, c.wantAddr)
		}
	}
}

func TestAddress_ANonUnixBusIsRefusedRatherThanIgnored(t *testing.T) {
	// SAFETY.md rule 4 is about a school's uplink, and this is a local socket,
	// but a tcp: bus address on a school laptop is a thing to stop at.
	if _, _, err := parseAddress("tcp:host=10.0.0.1,port=9000"); !errors.Is(err, ErrNoBus) {
		t.Fatalf("err = %v, want ErrNoBus", err)
	}
}

func TestAddress_NoBusAtAllIsAnOrdinaryAnswerThatNamesWhatItLookedFor(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return dir
		}
		return ""
	}
	_, _, _, err := Address(env, 1000)
	if !errors.Is(err, ErrNoBus) {
		t.Fatalf("err = %v, want ErrNoBus", err)
	}
	if !strings.Contains(err.Error(), filepath.Join(dir, "bus")) {
		t.Errorf("the error does not say what it looked for:\n%v", err)
	}
}

func TestAddress_AFileWhereTheSocketShouldBeIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bus"), []byte("not a socket"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return dir
		}
		return ""
	}
	_, _, _, err := Address(env, 1000)
	if !errors.Is(err, ErrNoBus) {
		t.Fatalf("err = %v, want ErrNoBus", err)
	}
	if !strings.Contains(err.Error(), "not a socket") {
		t.Errorf("the error does not say what IS there:\n%v", err)
	}
}

func TestDial_RefusesAnyNetworkThatIsNotAUnixSocket(t *testing.T) {
	_, err := Dial("tcp", "10.0.0.1:9000", 1000, time.Second)
	if err == nil {
		t.Fatal("Dial accepted a tcp address")
	}
	if !strings.Contains(err.Error(), "only") {
		t.Errorf("err = %v, want a refusal naming the permitted network", err)
	}
}

// fakeBus is a session bus that records what it was sent. It speaks only the
// parts of the protocol this client uses, which is the point: if the client
// starts needing more, this stops working and somebody has to look at why.
type fakeBus struct {
	t        *testing.T
	ln       net.Listener
	path     string
	Notified chan []byte
	// failNotify makes the bus answer Notify with an ERROR, so the client's
	// failure branch is exercised rather than assumed.
	failNotify bool
}

func newFakeBus(t *testing.T) *fakeBus {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bus")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Skipf("cannot listen on a unix socket here: %v", err)
	}
	b := &fakeBus{t: t, ln: ln, path: p, Notified: make(chan []byte, 4)}
	go b.serve()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *fakeBus) serve() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		go b.session(c)
	}
}

func (b *fakeBus) session(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	// The leading NUL, then AUTH, then BEGIN.
	if _, err := r.ReadByte(); err != nil {
		return
	}
	line, err := r.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "AUTH EXTERNAL ") {
		return
	}
	if _, err := c.Write([]byte("OK 1234deadbeef\r\n")); err != nil {
		return
	}
	if line, err = r.ReadString('\n'); err != nil || !strings.HasPrefix(line, "BEGIN") {
		return
	}
	for {
		h, body, err := readOne(r)
		if err != nil {
			return
		}
		switch h.Fields[fieldMember] {
		case "Hello":
			// A real bus sends NameAcquired BEFORE the reply. A client that
			// treats the first message as its answer misreads it, so the fake
			// reproduces the ordering rather than the convenient version.
			_, _ = c.Write(signal("NameAcquired", h.Serial))
			_, _ = c.Write(methodReturn(h.Serial, ":1.99", nil))
		case "Notify":
			b.Notified <- body
			if b.failNotify {
				_, _ = c.Write(errorReply(h.Serial, "org.freedesktop.DBus.Error.ServiceUnknown"))
				continue
			}
			var id [4]byte
			binary.LittleEndian.PutUint32(id[:], 7)
			_, _ = c.Write(methodReturn(h.Serial, "", id[:]))
		}
	}
}

func readOne(r *bufio.Reader) (header, []byte, error) {
	fixed := make([]byte, 16)
	if _, err := io.ReadFull(r, fixed); err != nil {
		return header{}, nil, err
	}
	fieldsLen := int(binary.LittleEndian.Uint32(fixed[12:16]))
	rest := make([]byte, alignUp(fieldsLen, 8))
	if _, err := io.ReadFull(r, rest); err != nil {
		return header{}, nil, err
	}
	h, err := parseHeader(append(append([]byte{}, fixed...), rest...))
	if err != nil {
		return header{}, nil, err
	}
	body := make([]byte, h.BodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return header{}, nil, err
	}
	return h, body, nil
}

// reply builds a message of the given type with the given header fields.
func reply(msgType byte, replySerial uint32, sender string, errName string, sig string, body []byte) []byte {
	h := &encoder{}
	h.byte('l')
	h.byte(msgType)
	h.byte(0)
	h.byte(1)
	h.uint32(uint32(len(body)))
	h.uint32(1000 + replySerial)
	h.array(8, func() {
		h.align(8)
		h.byte(fieldReplySerial)
		h.variant("u", func() { h.uint32(replySerial) })
		if sender != "" {
			h.align(8)
			h.byte(fieldSender)
			h.variant("s", func() { h.str(sender) })
		}
		if errName != "" {
			h.align(8)
			h.byte(fieldErrorName)
			h.variant("s", func() { h.str(errName) })
		}
		if sig != "" {
			h.align(8)
			h.byte(fieldSignature)
			h.variant("g", func() { h.sig(sig) })
		}
	})
	h.align(8)
	return append(h.buf, body...)
}

func methodReturn(serial uint32, sender string, body []byte) []byte {
	sig := ""
	if len(body) == 4 {
		sig = "u"
	}
	return reply(typeMethodReturn, serial, sender, "", sig, body)
}

func errorReply(serial uint32, name string) []byte {
	return reply(typeError, serial, "", name, "", nil)
}

func signal(_ string, serial uint32) []byte {
	return reply(typeSignal, serial, "org.freedesktop.DBus", "", "", nil)
}

func TestSend_TalksToARealSocketEndToEnd(t *testing.T) {
	b := newFakeBus(t)
	env := func(k string) string {
		if k == "DBUS_SESSION_BUS_ADDRESS" {
			return "unix:path=" + b.path
		}
		return ""
	}
	ok, detail := Send(Notification{
		AppName: "Auros", Summary: "Your files are here",
		Body: "1234 files came across", Urgency: 1, ExpireMS: -1,
	}, env, os.Getuid(), 3*time.Second)
	if !ok {
		t.Fatalf("Send failed: %s", detail)
	}
	if !strings.Contains(detail, "notification 7") {
		t.Errorf("detail = %q, want the id the bus returned", detail)
	}
	select {
	case body := <-b.Notified:
		// The body is the marshalled arguments. The summary and the body text
		// must both be in there, byte for byte.
		if !strings.Contains(string(body), "Your files are here") {
			t.Error("the summary did not reach the bus")
		}
		if !strings.Contains(string(body), "1234 files came across") {
			t.Error("the count did not reach the bus")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the bus never received a Notify")
	}
}

func TestSend_ADesktopThatRefusesIsReportedNotSwallowed(t *testing.T) {
	b := newFakeBus(t)
	b.failNotify = true
	env := func(k string) string {
		if k == "DBUS_SESSION_BUS_ADDRESS" {
			return "unix:path=" + b.path
		}
		return ""
	}
	ok, detail := Send(Notification{AppName: "Auros", Summary: "x"}, env, os.Getuid(), 3*time.Second)
	if ok {
		t.Fatal("Send reported success when the desktop refused the notification")
	}
	if !strings.Contains(detail, "ServiceUnknown") {
		t.Errorf("detail = %q, want the bus's own error name", detail)
	}
	if !strings.Contains(detail, "not shown") {
		t.Errorf("detail = %q, want it to say plainly that nothing was shown", detail)
	}
}

func TestSend_NoSessionBusIsReportedAsAFactAboutTheMachine(t *testing.T) {
	dir := t.TempDir()
	env := func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return dir
		}
		return ""
	}
	ok, detail := Send(Notification{Summary: "x"}, env, 1000, time.Second)
	if ok {
		t.Fatal("Send claimed to have shown a notification with no bus at all")
	}
	if !strings.HasPrefix(detail, "not shown as a pop-up") {
		t.Errorf("detail = %q", detail)
	}
}

func TestMarshal_TheAlignmentIsTheProtocol(t *testing.T) {
	// D-Bus rejects a message whose padding is wrong, with an error that says
	// nothing useful. These are the invariants, asserted on the bytes.
	c := call{
		path: "/org/freedesktop/Notifications", iface: "org.freedesktop.Notifications",
		member: "Notify", destination: "org.freedesktop.Notifications",
		signature: "susssasa{sv}i", serial: 2,
		body: NotifyBody(Notification{AppName: "Auros", Summary: "s", Body: "b", ExpireMS: -1}),
	}
	msg := c.marshal()
	if msg[0] != 'l' || msg[1] != typeMethodCall || msg[3] != 1 {
		t.Fatalf("fixed header = % x", msg[:4])
	}
	bodyLen := binary.LittleEndian.Uint32(msg[4:8])
	if int(bodyLen) != len(c.body) {
		t.Errorf("declared body length %d, actual %d", bodyLen, len(c.body))
	}
	fieldsLen := int(binary.LittleEndian.Uint32(msg[12:16]))
	bodyStart := alignUp(16+fieldsLen, 8)
	if bodyStart%8 != 0 {
		t.Errorf("the body starts at %d, which is not 8-aligned", bodyStart)
	}
	if len(msg) != bodyStart+len(c.body) {
		t.Errorf("message is %d bytes, want %d", len(msg), bodyStart+len(c.body))
	}
	h, err := parseHeader(msg)
	if err != nil {
		t.Fatalf("our own message does not parse: %v", err)
	}
	for code, want := range map[byte]string{
		fieldPath: "/org/freedesktop/Notifications", fieldMember: "Notify",
		fieldInterface: "org.freedesktop.Notifications", fieldSignature: "susssasa{sv}i",
	} {
		if h.Fields[code] != want {
			t.Errorf("field %d = %q, want %q", code, h.Fields[code], want)
		}
	}
}

func TestParseHeader_AMalformedReplyDoesNotHangOrPanic(t *testing.T) {
	// The shape of bug this kind of parser is famous for: a `break` that
	// leaves the switch instead of the loop, and a truncated field array that
	// spins forever. Every one of these must return promptly.
	good := call{path: "/x", iface: "i", member: "m", serial: 1}.marshal()
	for n := 0; n < len(good); n++ {
		done := make(chan struct{})
		go func(b []byte) {
			defer func() {
				recover()
				close(done)
			}()
			_, _ = parseHeader(b)
		}(good[:n])
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("parseHeader hung on a %d-byte prefix", n)
		}
	}
	// And garbage of the right length.
	junk := make([]byte, 64)
	junk[0] = 'l'
	for i := 12; i < 16; i++ {
		junk[i] = 0xff
	}
	if _, err := parseHeader(junk); err == nil {
		t.Error("a header claiming a 4GB field array was accepted")
	}
}

func TestParseHeader_ABigEndianReplyIsRefused(t *testing.T) {
	b := make([]byte, 32)
	b[0] = 'B'
	if _, err := parseHeader(b); err == nil {
		t.Fatal("a big-endian message was accepted by a little-endian-only decoder")
	}
}

// TestSend_AgainstARealSessionBus is the end-to-end one. It is skipped unless
// tools/dbus-e2e/run.sh set it up, because it needs a real dbus-daemon and a
// real service on the other end.
//
// It exists because every other test in this file drives a fake bus built out
// of THIS PACKAGE'S OWN encoder. That proves the client is self-consistent. If
// the alignment rules are misunderstood, both halves misunderstand them the
// same way and the suite is green while nothing works on a real desktop. The
// arguments this sends are checked by libdbus, on the other side of a real
// daemon, in run.sh.
func TestSend_AgainstARealSessionBus(t *testing.T) {
	if os.Getenv("AUROS_DBUS_E2E") != "1" {
		t.Skip("set up by tools/dbus-e2e/run.sh; needs a real dbus-daemon")
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		t.Fatal("AUROS_DBUS_E2E is set but there is no session bus address")
	}
	ok, detail := Send(Notification{
		AppName: "Auros",
		Icon:    "document-save",
		Summary: "Your files are here",
		// Non-ASCII on purpose: a multi-byte body is where a length written in
		// runes rather than bytes goes wrong, and it goes wrong silently.
		Body:     "18000 files came across from your old computer — éà字",
		Urgency:  2,
		ExpireMS: -1,
	}, os.Getenv, os.Getuid(), 10*time.Second)
	if !ok {
		t.Fatalf("Send failed against a real bus: %s", detail)
	}
	if !strings.Contains(detail, "notification 4242") {
		t.Errorf("detail = %q, want the id the real service returned", detail)
	}
	t.Logf("%s", detail)
}
