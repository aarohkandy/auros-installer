package safety

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

// TestWall_OnlySysdiskRunsCommands is the second half. A package that does not
// import internal/sysdisk can still shell out to manage-bde or bcdedit and touch
// the system disk that way, so os/exec is confined to the same one package.
func TestWall_OnlySysdiskRunsCommands(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{"internal/sysdisk": true}

	walkGoFiles(t, root, func(relPath string, imports []string) {
		pkgDir := filepath.ToSlash(filepath.Dir(relPath))
		if allowed[pkgDir] {
			return
		}
		for _, imp := range imports {
			if imp == "os/exec" {
				t.Errorf("WALL BREACH: package %q imports os/exec (in %s)\n"+
					"  Running external commands is confined to internal/sysdisk, "+
					"because that is how the system disk gets touched without importing it.",
					pkgDir, relPath)
			}
		}
	})
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
