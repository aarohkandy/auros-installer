package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// ONE BASE IMAGE, ONE OVERLAY PER RUN, AND NO WAY FOR A RUN TO REACH THE NEXT ONE
//
// The Windows test image is built ONCE from an Evaluation Center ISO (see README.md) into a qcow2 that
// is then never written to again. Every run gets a fresh copy-on-write overlay whose backing file is
// that base, and the overlay is deleted when the run ends.
//
// Three things enforce "a run cannot contaminate the next", and all three are needed:
//
//  1. BOTH base files — the Windows system image and the empty-NTFS destination image — are verified
//     BEFORE AND AFTER every single run, by SHA-256 and by file mode. If either ever changes, the suite
//     stops. It is both images because a run that starts with a destination holding the previous run's
//     archive is the same failure as one that starts with the previous run's Windows, and for eighty
//     runs it would look identical to a pass. See AssertBaseUnchanged.
//  2. The overlay is created fresh per run and deleted per run. Not truncated, not reused.
//  3. The base files carry no write bit for anyone (chmod 0444), and that is CHECKED rather than
//     assumed — the mode is re-read before and after every run alongside the hash. A hash says the file
//     has not changed yet; a mode with no write bit says the ordinary ways of changing it do not work.
//
// What is deliberately NOT claimed here: this file does not pass a backing-file read-only option to
// QEMU. An earlier version of this comment said it did, and the argv below never contained one — which
// is worse than the gap it described, because a reader who checks the three pillars finds two. QEMU
// opens a qcow2 backing file read-only unless it is told otherwise and nothing here tells it otherwise,
// but that is an upstream default, so the guarantee this harness actually stands behind is pillar 1:
// the hash and the mode, measured, on both images, on every run.
//
// This is why 100 consecutive runs means something. Without it, run 74 is being tested against whatever
// runs 1..73 left behind, and the number 100 is decoration.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// PowerCutNote is quoted in REPORT.md. It is here because it is a property of how the VM is configured,
// and losing it would make four of the twenty scenarios quietly less honest than they claim to be.
const PowerCutNote = "Power-cut scenarios SIGKILL the QEMU process. For that to model a real mains " +
	"failure rather than a friendly one, the guest's disks are opened with cache.direct=on: a write the " +
	"guest believes reached the platter is the only kind that survives. With host writeback caching the " +
	"host would flush the guest's unflushed writes after the process died, which is strictly more " +
	"forgiving than the failure we claim to be testing."

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// QMP
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// QMP is a minimal QEMU Machine Protocol client. Minimal on purpose: the harness issues five commands
// and a full client would be five hundred lines of surface area protecting nothing.
type QMP struct {
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder
}

func DialQMP(sockPath string, timeout time.Duration) (*QMP, error) {
	deadline := time.Now().Add(timeout)
	var conn net.Conn
	var err error
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", sockPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		return nil, fmt.Errorf("QMP socket %s never accepted a connection: %w", sockPath, err)
	}
	q := &QMP{conn: conn, dec: json.NewDecoder(conn), enc: json.NewEncoder(conn)}
	// Greeting.
	var greeting map[string]json.RawMessage
	if err := q.dec.Decode(&greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("QMP greeting: %w", err)
	}
	if _, err := q.Execute("qmp_capabilities", nil); err != nil {
		conn.Close()
		return nil, err
	}
	return q, nil
}

// Execute sends one command and waits for its reply, skipping asynchronous events.
func (q *QMP) Execute(cmd string, args map[string]any) (json.RawMessage, error) {
	req := map[string]any{"execute": cmd}
	if args != nil {
		req["arguments"] = args
	}
	if err := q.enc.Encode(req); err != nil {
		return nil, err
	}
	for {
		var msg map[string]json.RawMessage
		if err := q.dec.Decode(&msg); err != nil {
			return nil, fmt.Errorf("QMP %s: %w", cmd, err)
		}
		if e, ok := msg["error"]; ok {
			return nil, fmt.Errorf("QMP %s failed: %s", cmd, string(e))
		}
		if r, ok := msg["return"]; ok {
			return r, nil
		}
		// An event (SHUTDOWN, RESET, DEVICE_DELETED, …). Keep reading.
	}
}

func (q *QMP) Close() error {
	if q == nil || q.conn == nil {
		return nil
	}
	return q.conn.Close()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// VM
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// VMSpec is everything one run's virtual machine needs. All paths are host paths.
type VMSpec struct {
	QemuBinary string
	Accel      string // kvm | hvf | tcg
	MemoryMB   int
	CPUs       int

	SystemOverlay string // qcow2 overlay on the immutable Windows base
	DestOverlay   string // qcow2 overlay on the immutable empty-NTFS destination base; attached over USB
	MarkerImage   string // FAT image: token, golden manifest, binaries, run.cmd. Read-only. May be empty.

	QMPSock     string
	ControlSock string // COM2 in the guest: the fault/beacon channel
	SerialLog   string // COM1 in the guest: the boot beacon and anything Windows prints

	Headless bool
}

type VM struct {
	spec VMSpec
	cmd  *exec.Cmd
	qmp  *QMP

	// stderr is QEMU's own diagnostics, kept open for the life of the VM and closed by Close. Without
	// it, a QEMU that refuses to start says so into a file nobody holds and the run reports only "the
	// guest never opened the control channel".
	stderr *os.File

	ctlListener net.Listener
	ctlConn     net.Conn
}

// Start boots the VM and returns once QMP is answering.
//
// The destination is attached as USB STORAGE rather than as another virtio disk, so that
// DetachDestination is a faithful "somebody pulled the stick out of the trolley" rather than a
// simulation of one. F05 and F06 are only worth running if the removal is real.
func (v *VM) Start(spec VMSpec) error {
	v.spec = spec

	// The control channel is a unix socket QEMU connects to as a client, so the runner is listening
	// before the guest exists and cannot miss the first line.
	ln, err := net.Listen("unix", spec.ControlSock)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	v.ctlListener = ln

	args := []string{
		"-machine", "q35",
		"-m", fmt.Sprintf("%d", spec.MemoryMB),
		"-smp", fmt.Sprintf("%d", spec.CPUs),
		"-rtc", "base=utc",
		"-qmp", "unix:" + spec.QMPSock + ",server=on,wait=off",
		"-serial", "file:" + spec.SerialLog,
		"-chardev", "socket,id=ctl,path=" + spec.ControlSock + ",server=off",
		"-device", "isa-serial,chardev=ctl",
		"-netdev", "user,id=n0,restrict=on",
		"-device", "virtio-net-pci,netdev=n0",
	}
	if spec.Accel != "" && spec.Accel != "tcg" {
		args = append(args, "-accel", spec.Accel, "-cpu", "host")
	} else {
		args = append(args, "-accel", "tcg")
	}
	if spec.Headless {
		args = append(args, "-display", "none", "-vga", "std")
	}

	// cache.direct=on: see PowerCutNote. This costs throughput and buys the only thing that makes the
	// power-cut scenarios honest.
	args = append(args,
		"-drive", "file="+spec.SystemOverlay+",if=virtio,format=qcow2,cache.direct=on,cache.no-flush=off",
	)
	if spec.DestOverlay != "" {
		args = append(args,
			"-drive", "id=destdrv,file="+spec.DestOverlay+",if=none,format=qcow2,cache.direct=on",
			"-device", "qemu-xhci,id=xhci",
			"-device", "usb-storage,id=usbdest,bus=xhci.0,drive=destdrv",
		)
	}
	if spec.MarkerImage != "" {
		// readonly=on so the guest cannot alter the golden manifest or the harness token it is being
		// measured against. A harness whose own evidence lives on a volume the subject can write to is
		// not measuring anything.
		args = append(args,
			"-drive", "file="+spec.MarkerImage+",if=virtio,format=raw,readonly=on",
		)
	}

	cmd := exec.Command(spec.QemuBinary, args...)
	cmd.Stdout = io.Discard
	stderr, err := os.Create(spec.SerialLog + ".qemu-stderr")
	if err != nil {
		ln.Close()
		return err
	}
	cmd.Stderr = stderr
	v.stderr = stderr
	if err := cmd.Start(); err != nil {
		ln.Close()
		stderr.Close()
		return fmt.Errorf("starting %s: %w", spec.QemuBinary, err)
	}
	v.cmd = cmd

	q, err := DialQMP(spec.QMPSock, 30*time.Second)
	if err != nil {
		v.PowerCut()
		return err
	}
	v.qmp = q
	return nil
}

// Control accepts the guest's connection to the control channel. It blocks until the guest's serial
// driver opens the port, which happens when the fault agent starts.
func (v *VM) Control(timeout time.Duration) (net.Conn, error) {
	if v.ctlConn != nil {
		return v.ctlConn, nil
	}
	if l, ok := v.ctlListener.(*net.UnixListener); ok {
		_ = l.SetDeadline(time.Now().Add(timeout))
	}
	c, err := v.ctlListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("the guest never opened the control channel: %w", err)
	}
	v.ctlConn = c
	return c, nil
}

// PowerCut is the mains being pulled. SIGKILL, no ACPI, no flush, no chance for the guest to tidy up.
func (v *VM) PowerCut() error {
	if v.cmd == nil || v.cmd.Process == nil {
		return errors.New("no VM process")
	}
	return v.cmd.Process.Kill()
}

// DetachDestination removes the USB device carrying the destination volume.
func (v *VM) DetachDestination() error {
	if v.qmp == nil {
		return errors.New("no QMP connection")
	}
	_, err := v.qmp.Execute("device_del", map[string]any{"id": "usbdest"})
	return err
}

// Screendump saves what is on the guest's screen. Not a machine check — the event log is the machine
// check — but the artefact that lets a human see a BitLocker recovery prompt or a blue screen for what
// it is, months later, without re-running anything.
func (v *VM) Screendump(path string) error {
	if v.qmp == nil {
		return errors.New("no QMP connection")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	_, err = v.qmp.Execute("screendump", map[string]any{"filename": abs})
	return err
}

// Snapshot takes an internal qcow2 snapshot of the running overlay, so a failed run can be re-entered
// and poked at rather than only re-run.
func (v *VM) Snapshot(name string) error {
	if v.qmp == nil {
		return errors.New("no QMP connection")
	}
	_, err := v.qmp.Execute("human-monitor-command",
		map[string]any{"command-line": "savevm " + name})
	return err
}

// Wait waits for QEMU to exit, returning whether it exited on its own before the timeout.
func (v *VM) Wait(timeout time.Duration) (exited bool, code int) {
	if v.cmd == nil {
		return true, -1
	}
	done := make(chan error, 1)
	go func() { done <- v.cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			return true, 0
		}
		if ee, ok := err.(*exec.ExitError); ok {
			return true, ee.ExitCode()
		}
		return true, -1
	case <-time.After(timeout):
		return false, -1
	}
}

// Close tears the VM down and releases the sockets. Safe to call more than once.
func (v *VM) Close() {
	if v.ctlConn != nil {
		v.ctlConn.Close()
		v.ctlConn = nil
	}
	if v.ctlListener != nil {
		v.ctlListener.Close()
		v.ctlListener = nil
	}
	if v.qmp != nil {
		v.qmp.Close()
		v.qmp = nil
	}
	if v.cmd != nil && v.cmd.Process != nil {
		// Kill only. Wait() is owned by VM.Wait's goroutine, and calling Process.Wait() here as well
		// would be two reapers racing for one child — which shows up as a flaky "wait: no child
		// processes" once every few dozen runs and costs an afternoon to find.
		_ = v.cmd.Process.Kill()
	}
	if v.stderr != nil {
		v.stderr.Close()
		v.stderr = nil
	}
	_ = os.Remove(v.spec.QMPSock)
	_ = os.Remove(v.spec.ControlSock)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// IMAGE HANDLING
// ─────────────────────────────────────────────────────────────────────────────────────────────────

// CreateOverlay makes a throwaway copy-on-write layer over an immutable base.
func CreateOverlay(qemuImg, base, overlay string) error {
	_ = os.Remove(overlay)
	cmd := exec.Command(qemuImg, "create", "-q", "-f", "qcow2",
		"-F", "qcow2", "-b", base, overlay)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("qemu-img create overlay: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FileSHA256 is how the base images prove they have not moved under us.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// AssertBaseUnchanged is called on BOTH base images before and after every run.
//
// "Before" catches an edited base. "After" catches a run that somehow wrote through its overlay — which
// should be impossible, which is exactly why it is worth checking: the impossible things are the ones
// nobody notices for eighty runs.
//
// It checks the mode as well as the hash. The hash is the stronger statement about the past; the mode
// is the statement about the next five minutes, and an operator who has just made a base image writable
// in order to "quickly fix something" is the case the hash catches one run too late.
func AssertBaseUnchanged(path, expect string) error {
	if expect == "" {
		return fmt.Errorf("no expected SHA-256 recorded for %s: a base image the config cannot identify "+
			"cannot be proven not to have moved, and 'unverified' is not 'unchanged'", path)
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if mode := st.Mode().Perm(); mode&0o222 != 0 {
		return fmt.Errorf("THE BASE IMAGE IS WRITABLE: %s is mode %04o. README §3 step 7 requires 0444 "+
			"on both base images; a writable base is one command away from making every result in this "+
			"suite a measurement of a different machine. chmod 0444 it and re-run", path, mode)
	}
	got, err := FileSHA256(path)
	if err != nil {
		return err
	}
	if got != expect {
		return fmt.Errorf("THE BASE IMAGE CHANGED: %s is now %s, expected %s. Every result in this suite "+
			"is measured against a different machine than the one it claims. Stop", path, got, expect)
	}
	return nil
}

// AssertBasesUnchanged checks both images and names which one moved.
//
// There is no variant that checks only the system image. The destination base used to be hashed once
// per suite, in doctor, before run 1 — so "every run starts with a genuinely empty destination" was
// true of run 1 and unverified for the other 119. A contaminated destination base is the same class of
// failure as a contaminated system base and is harder to see, because a destination that already holds
// the previous run's archive makes a broken copy look complete.
func AssertBasesUnchanged(cfg *Config) error {
	if err := AssertBaseUnchanged(cfg.Base.SystemImage, cfg.Base.SystemSHA256); err != nil {
		return fmt.Errorf("system base: %w", err)
	}
	if err := AssertBaseUnchanged(cfg.Base.DestImage, cfg.Base.DestSHA256); err != nil {
		return fmt.Errorf("destination base: %w", err)
	}
	return nil
}

// ReclaimDiskGuard refuses to start a run that would take the working set below the configured floor.
//
// BLOCKED.md B1: the only x86_64 KVM host available was last seen with 17 GB free, running other
// people's work. Filling that disk would OOM or ENOSPC somebody else's job, so the runner checks first
// and stops rather than discovering it at run 61.
func ReclaimDiskGuard(dir string, minFreeGB int) error {
	free, err := freeSpaceBytes(dir)
	if err != nil {
		// Unable to measure is not permission to proceed.
		return fmt.Errorf("cannot measure free space on %s: %w", dir, err)
	}
	need := int64(minFreeGB) << 30
	if free < need {
		return fmt.Errorf("only %.1f GB free on %s, floor is %d GB. Serialize the suite (host_profile."+
			"parallel = 1) or free space; see BLOCKED.md B1", float64(free)/(1<<30), dir, minFreeGB)
	}
	return nil
}
