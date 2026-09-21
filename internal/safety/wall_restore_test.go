package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The wall does not stop at the Windows side.
//
// SAFETY.md's phases run 1..7 and the seventh is the Linux restore. The
// original wall tests seal the phase 1-5 packages because those were the only
// ones that existed. The restore packages are phase 7 — they run as an
// unprivileged user on a machine whose disk has already been overwritten, and
// they handle the ONLY copy of somebody's data. The same confinement applies,
// and this file states it for them rather than leaving it implied by a list
// that happened not to mention them.

// restorePackages are the Linux-side packages, sealed the same way phases 1-5
// are.
var restorePackages = map[string]bool{
	"internal/restore":    true,
	"internal/netprofile": true,
	"internal/printers":   true,
	"internal/deskbus":    true,
	"cmd/auros-restore":   true,
}

func TestWall_TheRestoreCannotReachTheSystemDisk(t *testing.T) {
	root := repoRoot(t)
	forbidden := map[string]string{
		sysdiskImport: "the restore runs as the user, after the wall, and has no business " +
			"touching the system disk or firmware",
		modulePath + "/internal/safety": "phase 7 does not need a VerifiedArchive and must not " +
			"acquire the ability to mint one",
		"os/exec": "running a command is how a package reaches outside the process without " +
			"importing internal/sysdisk. The restore wants notify-send, lpadmin and nmcli, and " +
			"it gets none of them: the notification goes over the session bus in internal/deskbus, " +
			"and the privileged steps are a separate, root-owned program",
		"unsafe": "unsafe is the only way to forge a safety.VerifiedArchive",
	}
	checked := 0
	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		if !restorePackages[pkgDir] {
			return
		}
		checked++
		for _, imp := range imports {
			base := imp
			if strings.HasPrefix(imp, "golang.org/x/sys/") {
				base = "unsafe" // same capability, different spelling
			}
			if why, bad := forbidden[base]; bad {
				t.Errorf("WALL BREACH: restore package %q imports %q (in %s)\n  %s",
					pkgDir, imp, relPath, why)
			}
		}
	})
	// A wall that passes because it found nothing is not a wall.
	if checked == 0 {
		t.Fatalf("no files were examined in %v: either the restore moved or this test is vacuous",
			sortedKeys(restorePackages))
	}
	for pkg := range restorePackages {
		if _, err := os.Stat(filepath.Join(root, pkg)); err != nil {
			t.Errorf("this test names %q, which does not exist (%v): a rename has made it "+
				"partly vacuous", pkg, err)
		}
	}
}

// TestWall_OnlyDeskbusTalksToASocket confines the `net` import.
//
// internal/deskbus dials the session bus. That is a unix socket in /run and
// not a network dependency in the sense SAFETY.md rule 4 forbids — the rule is
// about a school's uplink being in the safety path. But "it only dials a local
// socket" is a claim, and an unchecked claim is exactly what this project keeps
// finding in its own code. So: only deskbus may import net, and the only
// network string it may pass is the one constant.
func TestWall_OnlyDeskbusTalksToASocket(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{"internal/deskbus": true}
	seen := false
	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		for _, imp := range imports {
			if imp != "net" && !strings.HasPrefix(imp, "net/") {
				continue
			}
			if imp == "net/url" {
				continue // parsing a URL reaches nothing
			}
			seen = true
			if !allowed[pkgDir] {
				t.Errorf("WALL BREACH: package %q imports %q (in %s)\n"+
					"  The migration has no network dependency. Only internal/deskbus may open a "+
					"socket, and only the local session bus.", pkgDir, imp, relPath)
			}
		}
	})
	if !seen {
		t.Fatal("nothing in the repository imports net: this test is vacuous")
	}
}

// TestWall_DeskbusDialsUnixAndNothingElse reads the source of internal/deskbus
// and asserts that every network string literal handed to a dial function is
// the unixNetwork constant.
//
// The import-level test above says deskbus is the only package that CAN open a
// socket. This one says what it opens. Together they are the mechanical form
// of "no network dependency"; separately, either one is half an answer.
func TestWall_DeskbusDialsUnixAndNothingElse(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "deskbus")
	fset := token.NewFileSet()
	dialCalls := 0

	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		// Test files stand up fake buses; they are not the shipped program.
		if strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Errorf("parsing %s: %v", p, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok || pkg.Name != "net" {
				return true
			}
			if !strings.HasPrefix(sel.Sel.Name, "Dial") && !strings.HasPrefix(sel.Sel.Name, "Listen") {
				return true
			}
			dialCalls++
			arg := call.Args[0]
			switch a := arg.(type) {
			case *ast.Ident:
				if a.Name != "unixNetwork" && a.Name != "network" {
					t.Errorf("WALL BREACH: net.%s is called with %q in %s; it must be the "+
						"unixNetwork constant", sel.Sel.Name, a.Name, p)
				}
			case *ast.BasicLit:
				lit, uerr := strconv.Unquote(a.Value)
				if uerr != nil || lit != "unix" {
					t.Errorf("WALL BREACH: net.%s is called with the literal %s in %s",
						sel.Sel.Name, a.Value, p)
				}
			default:
				t.Errorf("WALL BREACH: net.%s in %s is called with an expression this test "+
					"cannot read, so the network it opens is decided at runtime",
					sel.Sel.Name, p)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	if dialCalls == 0 {
		t.Fatal("internal/deskbus opens no socket at all: this test is vacuous")
	}
	// And the `network` identifier it is allowed to pass must itself be
	// checked against the constant before the dial. Asserted by reading the
	// guard, so deleting the guard fails this test rather than silently
	// widening what the program can dial.
	src, rerr := os.ReadFile(filepath.Join(dir, "conn.go"))
	if rerr != nil {
		t.Fatalf("reading conn.go: %v", rerr)
	}
	if !strings.Contains(string(src), "if network != unixNetwork {") {
		t.Error("Dial no longer refuses a network other than unix before dialing it")
	}
}
