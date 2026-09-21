//go:build windows

package winenv

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aarohkandy/auros-installer/internal/printers"
)

// Wi-Fi profiles and printers, read through the Native Wifi API and the print
// spooler. Both are reads: nothing here changes a profile, a queue or a port.
//
// Why the API and not `netsh wlan export profile key=clear`: running a
// command is os/exec, which the wall confines to internal/sysdisk
// (TestWall_ForbiddenImports), and netsh writes its XML files to a folder —
// by default the current directory, which is on the system disk. The API
// hands the same XML back in memory.

var (
	wlanapi  = syscall.NewLazyDLL("wlanapi.dll")
	winspool = syscall.NewLazyDLL("winspool.drv")

	procWlanOpenHandle     = wlanapi.NewProc("WlanOpenHandle")
	procWlanCloseHandle    = wlanapi.NewProc("WlanCloseHandle")
	procWlanEnumInterfaces = wlanapi.NewProc("WlanEnumInterfaces")
	procWlanGetProfileList = wlanapi.NewProc("WlanGetProfileList")
	procWlanGetProfile     = wlanapi.NewProc("WlanGetProfile")
	procWlanFreeMemory     = wlanapi.NewProc("WlanFreeMemory")

	procEnumPrintersW      = winspool.NewProc("EnumPrintersW")
	procGetDefaultPrinterW = winspool.NewProc("GetDefaultPrinterW")
)

const (
	// wlanapi.h. WLAN_PROFILE_GET_PLAINTEXT_KEY is an INPUT flag to
	// WlanGetProfile (Windows 7+): the key comes back in plain text in
	// <keyMaterial> if the caller has wlan_secure_get_plaintext_key, which by
	// default only Administrators do. Without it the call still SUCCEEDS and
	// returns the encrypted key — no error — so the only way to know which one
	// we got is <protected> in the XML, which internal/netprofile reads.
	// https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlangetprofile
	wlanProfileGetPlaintextKey = 0x00000004
	wlanClientVersionVista     = 2
	wlanMaxNameLength          = 256

	errServiceNotActive = 1062 // ERROR_SERVICE_NOT_ACTIVE: WLAN AutoConfig is stopped
	errInsufficientBuf  = 122  // ERROR_INSUFFICIENT_BUFFER

	// winspool.h
	printerEnumLocal       = 0x00000002
	printerEnumConnections = 0x00000004
	printerAttrNetwork     = 0x00000010

	tcpPortsKey = `SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports`
)

// wlanInterfaceInfo is WLAN_INTERFACE_INFO: GUID, WCHAR[256], enum.
type wlanInterfaceInfo struct {
	InterfaceGUID guid
	Description   [wlanMaxNameLength]uint16
	State         uint32
}

type wlanInterfaceInfoList struct {
	NumberOfItems uint32
	Index         uint32
	Items         [1]wlanInterfaceInfo
}

// wlanProfileInfo is WLAN_PROFILE_INFO: WCHAR[256], DWORD.
type wlanProfileInfo struct {
	Name  [wlanMaxNameLength]uint16
	Flags uint32
}

type wlanProfileInfoList struct {
	NumberOfItems uint32
	Index         uint32
	Items         [1]wlanProfileInfo
}

func (w *winEnv) WiFiProfiles() ([]WiFiProfile, error) {
	if err := wlanapi.Load(); err != nil {
		return nil, fmt.Errorf("%w (wlanapi.dll: %v)", ErrNoWLAN, err)
	}
	var negotiated uint32
	var h syscall.Handle
	r, _, _ := procWlanOpenHandle.Call(wlanClientVersionVista, 0,
		uintptr(unsafe.Pointer(&negotiated)), uintptr(unsafe.Pointer(&h)))
	if r == errServiceNotActive {
		return nil, fmt.Errorf("%w (WLAN AutoConfig is not running)", ErrNoWLAN)
	}
	if r != 0 {
		return nil, fmt.Errorf("winenv: WlanOpenHandle: %w", syscall.Errno(r))
	}
	defer procWlanCloseHandle.Call(uintptr(h), 0)

	var ifs *wlanInterfaceInfoList
	if r, _, _ := procWlanEnumInterfaces.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&ifs))); r != 0 {
		return nil, fmt.Errorf("winenv: WlanEnumInterfaces: %w", syscall.Errno(r))
	}
	defer procWlanFreeMemory.Call(uintptr(unsafe.Pointer(ifs)))

	var out []WiFiProfile
	var errs []error
	seen := make(map[string]int) // profile name -> index in out
	for _, itf := range unsafe.Slice(&ifs.Items[0], ifs.NumberOfItems) {
		g := itf.InterfaceGUID
		var list *wlanProfileInfoList
		if r, _, _ := procWlanGetProfileList.Call(uintptr(h), uintptr(unsafe.Pointer(&g)), 0,
			uintptr(unsafe.Pointer(&list))); r != 0 {
			errs = append(errs, fmt.Errorf("WlanGetProfileList: %w", syscall.Errno(r)))
			continue
		}
		for _, pi := range unsafe.Slice(&list.Items[0], list.NumberOfItems) {
			name := utf16ToString(pi.Name[:])
			np, err := syscall.UTF16PtrFromString(name)
			if err != nil {
				continue
			}
			var xmlPtr *uint16
			flags := uint32(wlanProfileGetPlaintextKey)
			var access uint32
			r, _, _ := procWlanGetProfile.Call(uintptr(h), uintptr(unsafe.Pointer(&g)),
				uintptr(unsafe.Pointer(np)), 0, uintptr(unsafe.Pointer(&xmlPtr)),
				uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&access)))
			if r != 0 || xmlPtr == nil {
				// The profile NAME is not a secret; the error never carries XML.
				errs = append(errs, fmt.Errorf("WlanGetProfile(%q): %w", name, syscall.Errno(r)))
				continue
			}
			p := WiFiProfile{Name: name, XML: utf16PtrToString(xmlPtr)}
			procWlanFreeMemory.Call(uintptr(unsafe.Pointer(xmlPtr)))
			// The same profile name on two adapters is one network. Keep the
			// copy that carries a readable key, if either does.
			if i, dup := seen[name]; dup {
				if strings.Contains(out[i].XML, "<protected>true</protected>") &&
					!strings.Contains(p.XML, "<protected>true</protected>") {
					out[i] = p
				}
				continue
			}
			seen[name] = len(out)
			out = append(out, p)
		}
		procWlanFreeMemory.Call(uintptr(unsafe.Pointer(list)))
	}
	return out, errors.Join(errs...)
}

// printerInfo2 is PRINTER_INFO_2W. Every string points into the same buffer
// EnumPrintersW filled, which stays alive for as long as this is read.
type printerInfo2 struct {
	ServerName, PrinterName, ShareName, PortName, DriverName, Comment, Location *uint16
	DevMode, SepFile, PrintProcessor, Datatype, Parameters, SecurityDescriptor  uintptr
	Attributes, Priority, DefaultPriority, StartTime, UntilTime, Status, Jobs   uint32
	AveragePPM                                                                  uint32
}

// Printers enumerates local printers and per-user printer connections at
// level 2. https://learn.microsoft.com/en-us/windows/win32/printdocs/enumprinters
func (w *winEnv) Printers() ([]printers.Printer, error) {
	if err := winspool.Load(); err != nil {
		return nil, fmt.Errorf("winenv: winspool.drv: %w", err)
	}
	flags := uintptr(printerEnumLocal | printerEnumConnections)
	var needed, returned uint32
	r, _, e := procEnumPrintersW.Call(flags, 0, 2, 0, 0,
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)))
	if r == 0 && e != syscall.Errno(errInsufficientBuf) {
		return nil, fmt.Errorf("winenv: EnumPrinters: %v", e)
	}
	if needed == 0 {
		return nil, nil // no printers at all
	}
	// Backed by uintptr so the buffer is pointer-aligned for the struct cast.
	buf := make([]uintptr, (needed+uint32(unsafe.Sizeof(uintptr(0)))-1)/uint32(unsafe.Sizeof(uintptr(0))))
	r, _, e = procEnumPrintersW.Call(flags, 0, 2, uintptr(unsafe.Pointer(&buf[0])), uintptr(needed),
		uintptr(unsafe.Pointer(&needed)), uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		return nil, fmt.Errorf("winenv: EnumPrinters: %v", e)
	}
	def := defaultPrinter()
	infos := unsafe.Slice((*printerInfo2)(unsafe.Pointer(&buf[0])), returned)
	out := make([]printers.Printer, 0, returned)
	for _, pi := range infos {
		p := printers.Printer{
			Name:     utf16PtrToString(pi.PrinterName),
			Port:     utf16PtrToString(pi.PortName),
			Driver:   utf16PtrToString(pi.DriverName),
			Location: utf16PtrToString(pi.Location),
			Comment:  utf16PtrToString(pi.Comment),
		}
		p.Default = def != "" && strings.EqualFold(p.Name, def)
		switch {
		case strings.HasPrefix(p.Name, `\\`) || pi.Attributes&printerAttrNetwork != 0:
			// A connection to a queue on a print server. Its PortName is the
			// SERVER's port, and pointing Linux straight at that address would
			// bypass the server the school put in the way (quotas, release
			// codes). internal/printers names these and does not create them,
			// and it recognises them by a \\server\queue port.
			if strings.HasPrefix(p.Name, `\\`) {
				p.Port = p.Name
			} else if s := utf16PtrToString(pi.ServerName); s != "" {
				p.Port = `\\` + strings.TrimPrefix(s, `\\`) + `\` + utf16PtrToString(pi.ShareName)
			}
		default:
			if host := tcpPortHost(p.Port); host != "" {
				p.Port = host
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// tcpPortHost returns the address a Standard TCP/IP port prints to.
//
// The port NAME is only a label — Windows proposes "IP_10.0.0.5" but anyone
// can rename it "Office printer" — so the address is read from the port
// monitor's own configuration. That registry layout is what the Standard
// TCP/IP Port monitor has used since Windows 2000 but is not a documented
// API; when it is not there, the name is passed on unchanged and
// internal/printers decides whether it is an address at all.
func tcpPortHost(port string) string {
	if port == "" || strings.ContainsAny(port, `\,`) {
		return ""
	}
	h, err := regOpen(hkeyLocalMachine, tcpPortsKey+`\`+port, 0)
	if err != nil {
		return ""
	}
	defer regClose(h)
	if s := strings.TrimSpace(regString(h, "HostName")); s != "" {
		return s
	}
	return strings.TrimSpace(regString(h, "IPAddress"))
}

func defaultPrinter() string {
	var n uint32
	procGetDefaultPrinterW.Call(0, uintptr(unsafe.Pointer(&n)))
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n)
	if r, _, _ := procGetDefaultPrinterW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r == 0 {
		return ""
	}
	return utf16ToString(buf)
}
