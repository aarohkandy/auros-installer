package safety

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// THIS TEST IS THE WALL.
//
// SAFETY.md: "Phase 6 (ARM) is the only place we cross. It is one function. It is
// the only code in the repository permitted to write to the system disk or to
// firmware variables."
//
// The VerifiedArchive type makes it impossible to CALL Arm without having
// verified. This test makes it impossible to BYPASS Arm: it parses the imports
// of every .go file in the repository and fails if any package other than
// internal/safety imports internal/sysdisk.
//
// If someone adds a second path to the system disk in two years, this test names
// the file and the line and the build goes red. That is the entire mechanism,
// and it is why it is a test and not a comment.

const (
	modulePath    = "github.com/aarohkandy/auros-installer"
	sysdiskImport = modulePath + "/internal/sysdisk"
)

// allowedImporters is deliberately one entry long. Adding to it is a change to
// the safety architecture and should be argued for in a pull request, not made
// to get a build green.
var allowedImporters = map[string]bool{
	"internal/safety": true,
}

func TestWall_OnlySafetyImportsSysdisk(t *testing.T) {
	root := repoRoot(t)

	type hit struct {
		pkgDir string
		file   string
	}
	var violations []hit
	sawAllowed := false
	sawSysdiskPkg := false

	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		if pkgDir == "internal/sysdisk" {
			sawSysdiskPkg = true
		}
		for _, imp := range imports {
			if imp != sysdiskImport {
				continue
			}
			if allowedImporters[pkgDir] {
				sawAllowed = true
				continue
			}
			violations = append(violations, hit{pkgDir: pkgDir, file: relPath})
		}
	})

	// A test that passes because it found nothing is not a wall. Assert that the
	// package it is guarding exists and that the one legitimate importer was
	// actually seen, so a rename cannot make this test vacuously green.
	if !sawSysdiskPkg {
		t.Fatalf("no files found in internal/sysdisk: this test is no longer guarding anything")
	}
	if !sawAllowed {
		t.Fatalf("internal/safety does not import %s: either the wall moved or this test is vacuous", sysdiskImport)
	}

	for _, v := range violations {
		t.Errorf("WALL BREACH: package %q imports %s (in %s)\n"+
			"  Only internal/safety may import the system-disk package.\n"+
			"  Reach the system disk through safety.Arm, which requires a VerifiedArchive.",
			v.pkgDir, sysdiskImport, v.file)
	}
}

// TestWall_ForbiddenImports is the second half, and it is wider than it used to
// be on purpose.
//
// The previous version confined os/exec to internal/sysdisk and its comment
// claimed that closed the category: "that is how the system disk gets touched
// without importing it". It closed one of the two doors. The other one is
// `syscall`: syscall.NewLazyDLL plus `unsafe` is the ability to call any Win32
// export — DeleteFileW, SetFirmwareEnvironmentVariableW — from any package,
// without importing internal/sysdisk and without importing os/exec.
//
// `unsafe` is also the one tool that can forge a safety.VerifiedArchive. The
// type's unexported fields stop every safe-Go path: a literal, a setter,
// embedding, encoding/json, and reflection (which sets flagRO and panics on
// SetBool). Two pointer writes through unsafe.Pointer do not care about any of
// that. So the guarantee in verified.go is "cannot be constructed by any
// safe-Go path, and the unsafe path is forbidden by this test", and this is the
// test it names.
//
// Allowing a package here is a change to the safety architecture. Each entry
// below carries the reason it exists.
func TestWall_ForbiddenImports(t *testing.T) {
	root := repoRoot(t)

	// import path -> the packages allowed to have it
	type rule struct {
		why     string
		allowed map[string]bool
	}
	rules := map[string]rule{
		"os/exec": {
			why:     "running external commands is how the system disk gets touched without importing internal/sysdisk",
			allowed: map[string]bool{"internal/sysdisk": true},
		},
		// `syscall` is not banned by import path, because errno and signal
		// CONSTANTS are ordinary values that phase 1-5 code legitimately needs
		// (ENOSPC is how a full destination is recognised). It is banned by
		// IDENTIFIER instead, in TestWall_SyscallIsConstantsOnly below, which is
		// the check that actually matters: the danger is syscall.NewLazyDLL and
		// syscall.Syscall, not syscall.ENOSPC.
		"x-sys": {
			why:     "golang.org/x/sys is syscall by another name and gets the same treatment",
			allowed: map[string]bool{"internal/winenv": true, "internal/sysdisk": true},
		},
		"unsafe": {
			why: "unsafe is the only way to forge a VerifiedArchive, and the only way to pass a " +
				"pointer to a Win32 call; it belongs where Win32 lives and nowhere else",
			allowed: map[string]bool{"internal/winenv": true},
		},
	}

	// Packages that must never have ANY of the above, whatever the rules say.
	// internal/safety mints the proof; phases 1-5 are read-only with respect to
	// the system disk.
	sealed := map[string]bool{
		"internal/safety":     true,
		"internal/manifest":   true,
		"internal/copyengine": true,
		"internal/verify":     true,
		"internal/quarantine": true,
		"internal/runlog":     true,
	}

	seen := map[string]bool{}
	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		for _, imp := range imports {
			base := imp
			if strings.HasPrefix(imp, "golang.org/x/sys/") {
				base = "x-sys" // the same capability under another name
			}
			r, guarded := rules[base]
			if !guarded {
				continue
			}
			seen[base] = true
			if sealed[pkgDir] {
				t.Errorf("WALL BREACH: sealed package %q imports %q (in %s)\n  %s",
					pkgDir, imp, relPath, r.why)
				continue
			}
			if !r.allowed[pkgDir] {
				t.Errorf("WALL BREACH: package %q imports %q (in %s)\n  %s\n  Allowed only in: %s",
					pkgDir, imp, relPath, r.why, strings.Join(sortedKeys(r.allowed), ", "))
			}
		}
	})

	// A wall that passes because nothing matched is not a wall. At least one
	// legitimate use of each guarded import must actually exist. x-sys is
	// exempt: the module has no external dependencies and must not acquire one.
	for imp := range rules {
		if imp == "x-sys" {
			continue
		}
		if !seen[imp] {
			t.Errorf("no file in the repository imports %q: either it moved or this test is vacuous", imp)
		}
	}
}

// TestWall_SyscallIsConstantsOnly is the identifier-level half of the wall.
//
// Banning the `syscall` import outright would ban syscall.ENOSPC, which is how
// the copy engine recognises a full destination — a phase 4 concern with nothing
// to do with the system disk. Banning it nowhere leaves syscall.NewLazyDLL
// available from any package, and NewLazyDLL plus unsafe is the ability to call
// DeleteFileW or SetFirmwareEnvironmentVariableW without importing
// internal/sysdisk and without importing os/exec.
//
// So the constants are allowed everywhere and everything else is allowed only in
// the two packages whose job is Win32. Aliased imports are resolved first, so
// `import s "syscall"` is checked exactly the same way.
func TestWall_SyscallIsConstantsOnly(t *testing.T) {
	root := repoRoot(t)
	mayCallWin32 := map[string]bool{"internal/winenv": true, "internal/sysdisk": true}

	// Errno and signal constants: pure values, no capability attached.
	constant := regexp.MustCompile(`^(SIG[A-Z0-9]+|E[A-Z0-9]+|Errno)$`)

	fset := token.NewFileSet()
	checked, sawConstantUse := 0, false
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return fs.SkipDir
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr == nil && rel != "." {
				top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
				if top != "internal" && top != "cmd" {
					if _, serr := os.Stat(filepath.Join(p, "go.mod")); serr == nil {
						return fs.SkipDir
					}
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		pkgDir := filepath.ToSlash(filepath.Dir(rel))
		if mayCallWin32[pkgDir] {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Errorf("parsing %s: %v", rel, perr)
			return nil
		}
		// Resolve whatever local name syscall was bound to in THIS file.
		local := ""
		for _, spec := range f.Imports {
			path, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				continue
			}
			if path != "syscall" && !strings.HasPrefix(path, "golang.org/x/sys/") {
				continue
			}
			local = "syscall"
			if spec.Name != nil {
				local = spec.Name.Name
			}
		}
		if local == "" {
			return nil
		}
		checked++
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != local {
				return true
			}
			if constant.MatchString(sel.Sel.Name) {
				sawConstantUse = true
				return true
			}
			t.Errorf("WALL BREACH: package %q uses syscall.%s (in %s)\n"+
				"  Outside internal/winenv and internal/sysdisk, only errno and signal "+
				"constants may be taken from syscall. Anything else is a path to every "+
				"Win32 export from a package the wall does not watch.",
				pkgDir, sel.Sel.Name, rel)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if checked == 0 || !sawConstantUse {
		t.Fatal("no package outside internal/winenv and internal/sysdisk uses syscall at all: this test is vacuous")
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestWall_NonDestructivePackagesAreClean asserts that the phase 1–5 packages —
// the ones SAFETY.md calls read-only with respect to the system disk — do not
// import anything that could reach it, directly or transitively through safety.
func TestWall_NonDestructivePackagesAreClean(t *testing.T) {
	root := repoRoot(t)
	nonDestructive := map[string]bool{
		"internal/manifest":   true,
		"internal/copyengine": true,
		"internal/verify":     true,
		"internal/quarantine": true,
		"internal/runlog":     true,
		"internal/winenv":     true,
		"internal/labels":     true,
	}
	forbidden := map[string]bool{}
	forbidden[sysdiskImport] = true
	forbidden[modulePath+"/internal/safety"] = true
	forbidden["os/exec"] = true
	checked := 0
	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		if !nonDestructive[pkgDir] {
			return
		}
		checked++
		for _, imp := range imports {
			if forbidden[imp] {
				t.Errorf("phase 1-5 package %q imports %q (in %s): "+
					"the non-destructive packages must not be able to reach the system disk",
					pkgDir, imp, relPath)
			}
		}
	})
	if checked == 0 {
		t.Fatal("no phase 1-5 files were examined: this test is vacuous")
	}
}

// walkGoFiles parses every .go file under root (including _test.go files, since
// a test that touches the system disk is still code that touches the system
// disk) and hands the caller its repo-relative path and its import paths.
func walkGoFiles(t *testing.T, root string, fn func(relPath string, imports []string)) {
	t.Helper()
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return fs.SkipDir
			}
			// A nested Go module is a separate program that is never linked into the shipped exe —
			// `testharness/` is one, and its whole job is to drive QEMU, so of course it runs
			// commands. The wall guards what we HAND TO A CUSTOMER, not the rig that tests it.
			//
			// But that exemption is exactly how someone would evade the wall in two years: drop a
			// go.mod into internal/sneaky and shell out from there. So it does not apply to anything
			// under internal/ or cmd/, which are the directories that become the binary. Those are
			// walked whatever files they contain.
			rel, rerr := filepath.Rel(root, p)
			if rerr == nil && rel != "." {
				top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
				if top != "internal" && top != "cmd" {
					if _, serr := os.Stat(filepath.Join(p, "go.mod")); serr == nil {
						return fs.SkipDir
					}
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if perr != nil {
			t.Errorf("parsing %s: %v", p, perr)
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		imports := make([]string, 0, len(f.Imports))
		for _, spec := range f.Imports {
			path, uerr := strconv.Unquote(spec.Path.Value)
			if uerr != nil {
				continue
			}
			imports = append(imports, path)
		}
		fn(filepath.ToSlash(rel), imports)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
}

// repoRoot finds the module root from this source file's own location, so the
// test does not depend on the working directory `go test` happened to use.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine this test file's location")
	}
	dir := filepath.Dir(thisFile)
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not find go.mod above " + thisFile)
	return ""
}
