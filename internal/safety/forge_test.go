package safety

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/aarohkandy/auros-installer/internal/testsupport"
)

// Can a VerifiedArchive be forged?
//
// verified.go states the guarantee carefully, and the careful wording is the
// point: the value cannot be constructed by any SAFE-Go path outside this
// package, and the unsafe path is closed by the wall tests rather than by the
// type. This file is the evidence for both halves. Each test is one way
// somebody could try to manufacture permission to touch a stranger's system
// disk.
//
// Every one of them ends the same way: Arm refuses, the wall is not crossed,
// and the stand-in system disk is byte-identical.

// ---------- the declared value ----------

func TestForge_ZeroValueIsRefusedEverywhereItCouldBeUsed(t *testing.T) {
	f := newFixture(t, sampleFiles())
	var zero VerifiedArchive

	if zero.IsVerified() {
		t.Fatal("the zero value claims to be verified")
	}
	if zero.FileCount() != 0 || zero.TotalBytes() != 0 {
		t.Error("the zero value claims to describe files")
	}
	if zero.RunID() != "" || zero.ManifestDigest() != "" || zero.VolumeGUID() != "" {
		t.Error("the zero value claims an identity")
	}
	if !zero.VerifiedAt().IsZero() {
		t.Error("the zero value claims a verification moment")
	}

	// Every door into phase 6, tried with it.
	m := atVerifyBoundary(t, ModeCommit, f.log)
	if _, err := Arm(context.Background(), m, zero, armReq(f.log)); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Arm = %v, want ErrNotVerified", err)
	}
	if err := m.CrossWall(zero); !errors.Is(err, ErrNotVerified) {
		t.Errorf("CrossWall = %v, want ErrNotVerified", err)
	}
	if err := m.DryRunWall(zero); !errors.Is(err, ErrNotVerified) {
		t.Errorf("DryRunWall = %v, want ErrNotVerified", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with a declared value")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// TestForge_NoExportedFieldSoNoLiteralCanSetAnything is the compiler rule,
// asserted rather than assumed.
//
// A struct literal written in another package can only set EXPORTED fields. If
// this type ever grows one — even an innocuous-looking Note or Label — a caller
// elsewhere in the module acquires the ability to write `safety.VerifiedArchive{
// Note: "x"}`, and while that single literal still would not set `valid`, it
// would mean the type had stopped being uninhabitable from outside. This test
// fails on the day that changes.
func TestForge_NoExportedFieldSoNoLiteralCanSetAnything(t *testing.T) {
	typ := reflect.TypeOf(VerifiedArchive{})
	if typ.Kind() != reflect.Struct {
		t.Fatalf("VerifiedArchive is a %s, not a struct", typ.Kind())
	}
	if typ.NumField() == 0 {
		t.Fatal("VerifiedArchive has no fields at all: this test is vacuous")
	}
	for i := 0; i < typ.NumField(); i++ {
		fld := typ.Field(i)
		if fld.IsExported() {
			t.Errorf("VerifiedArchive.%s is exported: a caller in another package can now "+
				"write a literal for this type", fld.Name)
		}
		if fld.Anonymous {
			t.Errorf("VerifiedArchive embeds %s: an embedded exported type carries its own "+
				"settable fields into this one", fld.Name)
		}
	}

	// And no exported method may take an argument: a proof with a setter is not
	// a proof, and a "read-only" accessor that accepts something is a setter
	// waiting to be written.
	if typ.NumMethod() == 0 {
		t.Fatal("VerifiedArchive has no exported methods: this loop is vacuous")
	}
	for i := 0; i < typ.NumMethod(); i++ {
		meth := typ.Method(i)
		mt := meth.Type
		for a := 1; a < mt.NumIn(); a++ {
			t.Errorf("VerifiedArchive.%s takes an argument: a proof with a setter is not a proof", meth.Name)
		}
		if mt.NumOut() != 1 {
			t.Errorf("VerifiedArchive.%s returns %d values, want 1 read-only answer", meth.Name, mt.NumOut())
		}
	}
}

func TestForge_ReflectionCannotSetTheField(t *testing.T) {
	// reflect sets flagRO on fields obtained through an unexported name, so
	// CanSet is false and Set panics. Asserted here because "reflection cannot
	// do it" is a claim verified.go makes, and an unchecked claim in a safety
	// document is a claim that rots.
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	genuine, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}

	var forged VerifiedArchive
	rv := reflect.ValueOf(&forged).Elem()
	fld := rv.FieldByName("valid")
	if !fld.IsValid() {
		t.Fatal("there is no `valid` field any more; this test has stopped guarding anything")
	}
	if fld.CanSet() {
		t.Fatal("reflection can set VerifiedArchive.valid: the type no longer protects itself")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("reflect.Value.SetBool on an unexported field did not panic")
			}
		}()
		fld.SetBool(true)
	}()

	if forged.IsVerified() {
		t.Fatal("reflection forged a VerifiedArchive")
	}
	if _, aerr := Arm(context.Background(), m, forged, armReq(f.log)); !errors.Is(aerr, ErrNotVerified) {
		t.Errorf("Arm with the reflected value = %v, want ErrNotVerified", aerr)
	}
	// The genuine one still works, so the test above is not passing because
	// everything is broken.
	if !genuine.IsVerified() {
		t.Fatal("the genuine archive is not verified; the negative results above prove nothing")
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// TestForge_SerialisationRoundTripsToNothing covers the "it came back from
// disk" route. A proof that could be written down and read back is a proof that
// can be copied from a machine where verification succeeded onto one where it
// did not.
func TestForge_SerialisationRoundTripsToNothing(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	genuine, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("json", func(t *testing.T) {
		blob, merr := json.Marshal(genuine)
		if merr != nil {
			t.Fatalf("marshalling: %v", merr)
		}
		if string(blob) != "{}" {
			t.Errorf("a VerifiedArchive marshals to %s; it must carry nothing across a serialisation "+
				"boundary, because anything it carries can be written by hand", blob)
		}
		var back VerifiedArchive
		if uerr := json.Unmarshal(blob, &back); uerr != nil {
			t.Fatalf("unmarshalling: %v", uerr)
		}
		if back.IsVerified() {
			t.Fatal("a JSON round trip produced a verified archive")
		}
	})

	t.Run("hand-written json", func(t *testing.T) {
		// The forgery somebody would actually try.
		hand := []byte(`{"valid":true,"Valid":true,"runID":"x","RunID":"x","fileCount":9000,"FileCount":9000}`)
		var back VerifiedArchive
		if uerr := json.Unmarshal(hand, &back); uerr != nil {
			t.Fatalf("unmarshalling: %v", uerr)
		}
		if back.IsVerified() {
			t.Fatal("hand-written JSON forged a VerifiedArchive")
		}
		if back.FileCount() != 0 || back.RunID() != "" {
			t.Fatal("hand-written JSON set fields on a VerifiedArchive")
		}
		if _, aerr := Arm(context.Background(), m, back, armReq(f.log)); !errors.Is(aerr, ErrNotVerified) {
			t.Errorf("Arm = %v, want ErrNotVerified", aerr)
		}
	})

	t.Run("gob", func(t *testing.T) {
		var buf bytes.Buffer
		eerr := gob.NewEncoder(&buf).Encode(genuine)
		if eerr == nil {
			var back VerifiedArchive
			if derr := gob.NewDecoder(&buf).Decode(&back); derr == nil && back.IsVerified() {
				t.Fatal("a gob round trip produced a verified archive")
			}
		}
		// An encoder that refuses a type with no exported fields is the right
		// answer too; either way nothing verified comes back out.
	})

	if m.Crossed() {
		t.Fatal("the wall was crossed")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// embedder is the "I will just wrap it" route.
type embedder struct {
	VerifiedArchive
	Pretend bool
}

func TestForge_EmbeddingCarriesNoAuthority(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)

	e := embedder{Pretend: true}
	if e.IsVerified() {
		t.Fatal("an embedded zero value claims to be verified")
	}
	if _, err := Arm(context.Background(), m, e.VerifiedArchive, armReq(f.log)); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Arm with an embedded value = %v, want ErrNotVerified", err)
	}
	// Promoting the methods promotes the ANSWERS, never the ability to change
	// them: the embedded struct's fields are still unexported and still belong
	// to this package.
	if e.FileCount() != 0 {
		t.Error("an embedded zero value describes files")
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed with an embedded value")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- the run binding ----------

// TestForge_RunIDBindingRejectsAnotherRunsProof is the case that is not about
// Go's type system at all. Two migrations can be in flight on one machine — a
// first attempt the user abandoned, a second one running now — and the proof
// from the first describes a destination the second knows nothing about.
func TestForge_RunIDBindingRejectsAnotherRunsProof(t *testing.T) {
	first := newFixture(t, sampleFiles())
	m1 := atVerifyBoundary(t, ModeCommit, first.log)
	stale, _, err := Verify(context.Background(), m1, first.req())
	if err != nil {
		t.Fatal(err)
	}
	if !stale.IsVerified() {
		t.Fatal("the first run produced no proof; this test would prove nothing")
	}

	second := newFixture(t, sampleFiles())
	m2 := atVerifyBoundary(t, ModeCommit, second.log)
	if _, _, verr := Verify(context.Background(), m2, second.req()); verr != nil {
		t.Fatal(verr)
	}

	if _, aerr := Arm(context.Background(), m2, stale, armReq(second.log)); !errors.Is(aerr, ErrWrongRun) {
		t.Fatalf("Arm with another run's proof = %v, want ErrWrongRun", aerr)
	}
	if err := m2.CrossWall(stale); !errors.Is(err, ErrWrongRun) {
		t.Errorf("CrossWall with another run's proof = %v, want ErrWrongRun", err)
	}
	if err := m2.DryRunWall(stale); !errors.Is(err, ErrWrongRun) {
		t.Errorf("DryRunWall with another run's proof = %v, want ErrWrongRun", err)
	}
	if m2.Crossed() {
		t.Fatal("the second run crossed the wall on the first run's proof")
	}
	testsupport.AssertUnchanged(t, second.sysDir, second.sysBefore)
	testsupport.AssertUnchanged(t, first.sysDir, first.sysBefore)
}

// TestForge_RelabellingARunIDDoesNotMakeAProofTrue is the same attack with the
// binding filed off. Even with the right run ID, the archive still has to name
// a system volume that is not the volume holding the second copy — the proof is
// several claims, not one.
func TestForge_RelabellingARunIDDoesNotMakeAProofTrue(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	genuine, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}

	// A forger inside this package — the only place that can do this at all —
	// takes a real proof and points it at the disk holding the only copy.
	relabelled := genuine
	relabelled.destVolumeGUID = relabelled.systemVolumeGUID
	if _, aerr := Arm(context.Background(), m, relabelled, armReq(f.log)); !errors.Is(aerr, ErrArchiveOnSystemVolume) {
		t.Fatalf("Arm = %v, want ErrArchiveOnSystemVolume", aerr)
	}
	if err := m.CrossWall(relabelled); !errors.Is(err, ErrArchiveOnSystemVolume) {
		t.Errorf("CrossWall = %v, want ErrArchiveOnSystemVolume", err)
	}

	// And a proof with no system volume proves nothing about one.
	blind := genuine
	blind.systemVolumeGUID = ""
	if err := m.CrossWall(blind); !errors.Is(err, ErrWrongVolume) {
		t.Errorf("CrossWall with no system volume = %v, want ErrWrongVolume", err)
	}
	if m.Crossed() {
		t.Fatal("the wall was crossed")
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

func TestForge_AProofIsSpentOnceEvenWhenItIsGenuine(t *testing.T) {
	f := newFixture(t, sampleFiles())
	m := atVerifyBoundary(t, ModeCommit, f.log)
	va, _, err := Verify(context.Background(), m, f.req())
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CrossWall(va); err != nil {
		t.Fatalf("the first crossing failed: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := m.CrossWall(va); !errors.Is(err, ErrAlreadyArmed) {
			t.Fatalf("crossing %d = %v, want ErrAlreadyArmed", i+2, err)
		}
	}
	// Copies are not fresh permissions either.
	copied := va
	if err := m.CrossWall(copied); !errors.Is(err, ErrAlreadyArmed) {
		t.Errorf("crossing with a copy = %v, want ErrAlreadyArmed", err)
	}
	testsupport.AssertUnchanged(t, f.sysDir, f.sysBefore)
}

// ---------- the unsafe route, and the source-level guarantees ----------

// TestForge_UnsafeIsConfinedToTheOnePackageThatNeedsWin32 is the half of the
// guarantee the type cannot provide.
//
// Two pointer writes through unsafe.Pointer set `valid` and `runID` on a zero
// value and forge this type. Nothing in Go stops that. What stops it is that
// `unsafe` does not appear in any package that becomes the shipped binary
// except internal/winenv, whose job is Win32 — and this test is what makes
// adding it elsewhere a red build rather than a review somebody has to catch.
//
// It overlaps TestWall_ForbiddenImports deliberately. That test guards the wall
// as an architecture; this one guards the sentence in verified.go, and the two
// are allowed to fail for different reasons.
func TestForge_UnsafeIsConfinedToTheOnePackageThatNeedsWin32(t *testing.T) {
	allowed := map[string]bool{"internal/winenv": true}

	importers := map[string][]string{}
	forEachShippedGoFile(t, func(rel string, imports []string) {
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, imp := range imports {
			if imp == "unsafe" {
				importers[pkg] = append(importers[pkg], rel)
			}
		}
	})

	if len(importers) == 0 {
		t.Fatal("nothing in the shipped tree imports unsafe at all: this test is vacuous, " +
			"which means it would also be vacuous on the day somebody adds it")
	}
	for pkg, files := range importers {
		if allowed[pkg] {
			continue
		}
		t.Errorf("package %q imports unsafe (%s).\n"+
			"  unsafe is the only way to forge a safety.VerifiedArchive, and therefore the only "+
			"way to reach a stranger's system disk without verifying their data first.\n"+
			"  It belongs where Win32 lives and nowhere else.",
			pkg, strings.Join(files, ", "))
	}
}

// TestForge_OnlyOneLineInTheProgramSetsValid is the strongest statement this
// suite can make, and it is a statement about the source rather than about a
// running program.
//
// `valid: true` appears exactly once, at the end of a successful phase 5. If a
// second one ever appears — in a helper, in a test fixture, in a "temporary"
// shortcut — this test names the file and the line.
func TestForge_OnlyOneLineInTheProgramSetsValid(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "internal", "safety")
	fset := token.NewFileSet()

	type site struct {
		file string
		fn   string
		line int
	}
	var sites []site
	var assignments []site

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	seenFiles := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", e.Name(), perr)
		}
		seenFiles++
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fn, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					id, ok := x.Type.(*ast.Ident)
					if !ok || id.Name != "VerifiedArchive" {
						return true
					}
					for _, elt := range x.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok || key.Name != "valid" {
							continue
						}
						sites = append(sites, site{
							file: e.Name(),
							fn:   fn.Name.Name,
							line: fset.Position(kv.Pos()).Line,
						})
					}
				case *ast.AssignStmt:
					for _, lhs := range x.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if ok && sel.Sel.Name == "valid" {
							assignments = append(assignments, site{
								file: e.Name(),
								fn:   fn.Name.Name,
								line: fset.Position(sel.Pos()).Line,
							})
						}
					}
				}
				return true
			})
		}
	}

	if seenFiles == 0 {
		t.Fatal("no Go files were parsed in internal/safety: this test is vacuous")
	}
	if len(sites) != 1 {
		t.Fatalf("`valid:` is set in %d composite literals, want exactly 1: %+v\n"+
			"  Exactly one place in the program may declare a run verified, and it is "+
			"the end of a successful phase 5.", len(sites), sites)
	}
	if sites[0].fn != "Verify" {
		t.Errorf("`valid:` is set inside %s (%s:%d), want Verify",
			sites[0].fn, sites[0].file, sites[0].line)
	}
	if sites[0].file != "arm.go" {
		t.Errorf("`valid:` is set in %s, want arm.go (the file that holds both sides of the wall)",
			sites[0].file)
	}
	if len(assignments) != 0 {
		t.Errorf("something assigns to a `valid` field after construction: %+v\n"+
			"  A proof that can be switched on later is not a proof.", assignments)
	}
}

// TestForge_NoPackageOutsideSafetyNamesTheType is the "struct literal from
// another package" case, answered at the only level it can be answered at.
//
// A literal in another package cannot compile — the fields are unexported — so
// there is no test that can run one. What CAN rot is the boundary itself:
// someone exports a constructor, or a helper in another package starts passing
// VerifiedArchive values around and eventually one of them is built rather than
// received. This test says which packages are allowed to name the type at all.
func TestForge_NoPackageOutsideSafetyNamesTheType(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		"internal/safety": true,
		// main receives one from safety.Verify and hands it to safety.Arm. It
		// never constructs one, which is asserted below.
		"cmd/auros-migrate": true,
	}

	fset := token.NewFileSet()
	namedBy := map[string]bool{}
	constructedIn := map[string][]string{}
	// The scanner has to prove it can see anything at all. These two calls
	// exist in cmd/auros-migrate today; if the scan stops finding them it is
	// broken, and the empty result below would be a false all-clear rather
	// than a guarantee.
	sawVerifyCall, sawArmCall := false, false

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "node_modules":
				return fs.SkipDir
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
		pkg := filepath.ToSlash(filepath.Dir(rel))
		top := strings.SplitN(filepath.ToSlash(rel), "/", 2)[0]
		if top != "internal" && top != "cmd" {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			t.Errorf("parsing %s: %v", rel, perr)
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				if !ok || id.Name != "safety" {
					return true
				}
				switch x.Sel.Name {
				case "VerifiedArchive":
					namedBy[pkg] = true
				case "Verify":
					sawVerifyCall = true
				case "Arm":
					sawArmCall = true
				}
			case *ast.CompositeLit:
				sel, ok := x.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != "safety" || sel.Sel.Name != "VerifiedArchive" {
					return true
				}
				if len(x.Elts) > 0 {
					constructedIn[pkg] = append(constructedIn[pkg],
						filepath.ToSlash(rel)+":"+itoaLine(fset, x.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	if !sawVerifyCall || !sawArmCall {
		t.Fatalf("the scan did not find safety.Verify (%v) and safety.Arm (%v) anywhere: "+
			"it is not seeing the source, so its empty findings mean nothing",
			sawVerifyCall, sawArmCall)
	}
	for pkg := range namedBy {
		if !allowed[pkg] {
			t.Errorf("package %q names safety.VerifiedArchive.\n"+
				"  The proof travels from safety.Verify to safety.Arm and nowhere else. "+
				"A package that holds one is a package that will eventually try to make one.", pkg)
		}
	}
	for pkg, sites := range constructedIn {
		t.Errorf("package %q writes a safety.VerifiedArchive literal with fields set (%s)",
			pkg, strings.Join(sites, ", "))
	}
}

// forEachShippedGoFile walks internal/ and cmd/ — the directories that become
// the binary — and hands the caller each file's import paths. It is separate
// from walkGoFiles in wall_test.go on purpose: these two tests guard different
// promises and must not be able to go vacuous together.
func forEachShippedGoFile(t *testing.T, fn func(rel string, imports []string)) {
	t.Helper()
	root := repoRoot(t)
	fset := token.NewFileSet()
	seen := 0
	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return werr
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return fs.SkipDir
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
			seen++
			fn(filepath.ToSlash(rel), imports)
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}
	if seen == 0 {
		t.Fatal("no shipped Go files were found: this test is vacuous")
	}
}

func itoaLine(fset *token.FileSet, pos token.Pos) string {
	return strconv.Itoa(fset.Position(pos).Line)
}
