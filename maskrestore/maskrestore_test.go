package maskrestore

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- 围栏 1：零外部依赖 -------------------------------------------------------

// TestFence_NoExternalDependencies pins the module's whole point: it is a pure
// algorithm any consumer can take without dragging in a dependency tree.
//
// stdlib is allowed (the algorithm needs regexp/sort/strconv/strings/sync).
// ANY non-stdlib import is a red: the first one turns "copy this module into
// your product" from a one-line go.mod edit into a negotiation.
//
// 能红验证：给 maskrestore.go 加一行 `import "golang.org/x/text/unicode/norm"` ⇒ 红。
func TestFence_NoExternalDependencies(t *testing.T) {
	bad := scanExternalImports(t, ".")
	for _, v := range bad {
		t.Errorf("%s imports %q — this module must stay dependency-free so any "+
			"consumer can adopt it without inheriting a dependency tree", v.file, v.path)
	}
}

// TestFence_NoExternalDependencies_CanGoRed proves the scanner above actually
// reports something, by running it against a fixture that deliberately violates
// the rule.
//
// 🔴 WHY this companion test exists: the obvious way to drill the fence — add an
// external import to maskrestore.go — cannot work. This module has an empty
// `require` block, so the COMPILER rejects the import before the fence ever
// runs, and the drill goes red for the wrong reason. A fence whose only observed
// red comes from the compiler has not been shown to work; this test is what
// closes that gap. The fixture lives under testdata/ so the go tool never
// builds it.
func TestFence_NoExternalDependencies_CanGoRed(t *testing.T) {
	bad := scanExternalImports(t, filepath.Join("testdata", "badimport"))
	if len(bad) != 1 || bad[0].path != "golang.org/x/text/unicode/norm" {
		t.Fatalf("scanner failed to flag the known-bad fixture: %+v", bad)
	}
}

type importViolation struct{ file, path string }

// scanExternalImports returns every non-stdlib import in the non-test Go files
// of dir. A stdlib path has no dot in its first segment.
func scanExternalImports(t *testing.T, dir string) []importViolation {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("parsed 0 packages in %s — the scan checked nothing", dir)
	}
	var out []importViolation
	files := 0
	for _, pkg := range pkgs {
		for name, f := range pkg.Files {
			files++
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
					out = append(out, importViolation{file: name, path: path})
				}
			}
		}
	}
	if files == 0 {
		t.Fatalf("scanned 0 files in %s — the scan checked nothing", dir)
	}
	return out
}

// --- 围栏 2：business-blind ---------------------------------------------------

// TestFence_NoBusinessVocabulary pins the contract in the package doc: this
// package must never learn what an entity IS. It knows "token T stands for
// these byte spans" and nothing more.
//
// WHY it matters concretely: the moment an entity name appears here, the entity
// table has two homes — the detector's policy and this file — and the two will
// drift. The drift symptom is the worst kind: a placeholder that restores to
// the wrong person's data.
//
// The scan is over CODE ONLY, not comments: the comments legitimately explain
// the history using real examples like `{{ADDR_1}}`, and stripping that
// explanation to satisfy a linter would trade understanding for tidiness.
//
// 能红验证：在 Renumber 里加 `if r.Token == "{{ADDR}}" { … }` ⇒ 红。
func TestFence_NoBusinessVocabulary(t *testing.T) {
	src, err := os.ReadFile("maskrestore.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	code := stripComments(t, string(src))
	if strings.TrimSpace(code) == "" {
		t.Fatal("stripped source is empty — the fence checked nothing")
	}
	// Entity vocabulary that must never appear in executable code here.
	for _, word := range []string{
		"ADDR", "PHONE", "EMAIL", "IDCARD", "BANKCARD", "PASSWD", "JWT", "NSFW",
		"CREDENTIAL", "地址", "手机", "邮箱", "身份证", "密码", "entity", "Entity",
	} {
		if strings.Contains(code, word) {
			t.Errorf("executable code contains business vocabulary %q — this package is "+
				"business-blind by contract (see the package doc). Entity knowledge belongs "+
				"to the caller; a copy here is a second entity table that will drift.", word)
		}
	}
}

// stripComments removes // and /* */ comments so the vocabulary fence judges
// code, not the explanations the code is required to carry.
func stripComments(t *testing.T, src string) string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "maskrestore.go", src, 0) // 0 = drop comments
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var sb strings.Builder
	if err := printNode(&sb, fset, f); err != nil {
		t.Fatalf("print: %v", err)
	}
	return sb.String()
}

func printNode(w io.Writer, fset *token.FileSet, node ast.Node) error {
	return printer.Fprint(w, fset, node)
}

// --- 行为：与 aikey-proxy 的黄金围栏同源的最小回归 ----------------------------

func TestRenumber_SharedCounterInTextOrder(t *testing.T) {
	head := "a AAA b BBB c CCC"
	masked := "a <X> b <Y> c <X>"
	tbl := NewTable()
	got, spanLabels, rep := Renumber(head, masked, []Restorable{
		{Token: "<X>", NumberedPrefix: "<X", NumberedSuffix: ">", Spans: [][2]int{{2, 5}, {14, 17}}},
		{Token: "<Y>", NumberedPrefix: "<Y", NumberedSuffix: ">", Spans: [][2]int{{8, 11}}},
	}, tbl)
	if want := "a <X1> b <Y2> c <X3>"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(spanLabels) != 3 {
		t.Fatalf("spanLabels = %v", spanLabels)
	}
	if rep.DuplicateTokenDropped != 0 || len(rep.AlignMismatches) != 0 || rep.Overlap {
		t.Fatalf("unexpected degrade report: %+v", rep)
	}
	if got := tbl.Restore("<X1> <Y2> <X3>"); got != "AAA BBB CCC" {
		t.Fatalf("restore: %q", got)
	}
}

func TestRenumber_DuplicateTokenIsReportedNotLogged(t *testing.T) {
	head := "a AAA b BBB"
	tbl := NewTable()
	got, spanLabels, rep := Renumber(head, "a <X> b <X>", []Restorable{
		{Token: "<X>", NumberedPrefix: "<X", NumberedSuffix: ">", Spans: [][2]int{{2, 5}}},
		{Token: "<X>", NumberedPrefix: "<X", NumberedSuffix: ">", Spans: [][2]int{{8, 11}}},
	}, tbl)
	if got != "a <X> b <X>" || spanLabels != nil {
		t.Fatalf("duplicate token must keep the numberless mask: %q / %v", got, spanLabels)
	}
	if rep.DuplicateTokenDropped != 2 || rep.Usable != 0 {
		t.Fatalf("report should name the drop: %+v", rep)
	}
}

func TestRestore_UnknownIDStaysVerbatim(t *testing.T) {
	tbl := NewTable()
	tbl.Add("{{ADDR_1}}", "北京朝阳建国路88号")
	if got := tbl.Restore("{{ADDR_1}} 与 {{ADDR_7}}"); got != "北京朝阳建国路88号 与 {{ADDR_7}}" {
		t.Fatalf("unknown id must stay verbatim, got %q", got)
	}
}

func TestHooks_FireOncePerLabel(t *testing.T) {
	var issued, restored int
	tbl := NewTable()
	tbl.OnIssue = func(string) { issued++ }
	tbl.OnFirstRestore = func(string) { restored++ }
	tbl.Add("{{A_1}}", "one")
	tbl.Add("{{A_2}}", "two")
	tbl.Restore("{{A_1}} {{A_1}} {{A_1}}")
	if issued != 2 || restored != 1 {
		t.Fatalf("issued=%d restored=%d, want 2/1 (restore counts DISTINCT labels)", issued, restored)
	}
}

// TestNoObserver_AllocatesNothing pins the "no observer pays nothing" property:
// with OnFirstRestore nil the dedup map must never be allocated.
func TestNoObserver_AllocatesNothing(t *testing.T) {
	tbl := NewTable()
	tbl.Add("{{A_1}}", "one")
	tbl.Restore("{{A_1}}")
	if tbl.restoredIDs != nil {
		t.Fatal("dedup map allocated with no observer wired")
	}
}

func TestSourceFileNameIsStable(t *testing.T) {
	// The proxy-side fence reads this exact path. Renaming the file silently
	// would turn that cross-repo fence into a Fatal for the wrong reason.
	if _, err := os.Stat(filepath.Join(".", "maskrestore.go")); err != nil {
		t.Fatalf("maskrestore.go must keep its name (a sibling fence reads it by path): %v", err)
	}
}
