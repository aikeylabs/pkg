package mcpwire

// userdoc_errorcodes_test.go — the user-facing error tables must match the enum
// (阶段8 P12 task 12.5).
//
// # Why this is a test and not a review checklist
//
// An error code is the one string a customer types into a search box at 2am. If
// the quickstart documents a code the product cannot emit, they find a page
// describing a situation they are not in; if the product emits a code the
// quickstart never mentions, they find nothing at all and open a ticket.
//
// 🔴 Both directions matter, and they rot in opposite ways. A code ADDED to the
// enum without touching the docs is the common case (nobody remembers the
// docs); a code REMOVED from the enum while the docs keep it is the quiet one,
// because nothing ever fails.
//
// 🔴 Both language editions are checked. A translated document that silently
// drops a row is worse than an untranslated one — the reader has no way to know
// they are looking at an older list.
//
// spec: workflow/CI/requirements/2026-08-20-mcp-gateway.md
// docs: workflow/CD/installer/quickstart-mcp-gateway{,.zh}.md

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// userDocs are the customer-facing files that carry an error table.
var userDocs = []string{
	"workflow/CD/installer/quickstart-mcp-gateway.md",
	"workflow/CD/installer/quickstart-mcp-gateway.zh.md",
}

// anyMCPCode finds anything shaped like one of our codes, so a code the docs
// invented is caught alongside one they omitted.
var anyMCPCode = regexp.MustCompile(`\b(?:MCP|EXT_MCP)_[A-Z0-9_]+\b`)

func repoRootForDocs(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "aikey-proxy")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repo root not found from this checkout; the user-doc fence needs the whole tree")
	return ""
}

func TestUserDocsDocumentEveryErrorCodeAndInventNone(t *testing.T) {
	root := repoRootForDocs(t)

	// The CATALOG is the source of truth. 🔴 Iterated, not retyped: a fence that
	// restates the list agrees with itself no matter what the product does, and
	// TestEveryErrorCodeIsCatalogued already guarantees the catalog and the
	// constants match.
	want := map[string]bool{}
	for _, spec := range ErrorCodeCatalog {
		want[string(spec.Code)] = true
	}
	if len(want) == 0 {
		t.Fatal("the error-code enum is empty; this fence would pass vacuously")
	}

	for _, rel := range userDocs {
		path := filepath.Join(root, rel)
		raw, err := os.ReadFile(path) //nolint:gosec // fixed, in-repo path
		if err != nil {
			t.Errorf("%s cannot be read: %v — the customer-facing error table is part of "+
				"the deliverable, not an optional extra", rel, err)
			continue
		}
		doc := string(raw)

		for code := range want {
			if !strings.Contains(doc, code) {
				t.Errorf("%s does not document %s.\n"+
					"🔴 A customer who hits this code searches for exactly that string and "+
					"finds nothing, then opens a ticket. Adding a code to the enum includes "+
					"adding its row here, in the same change.", rel, code)
			}
		}

		for _, found := range anyMCPCode.FindAllString(doc, -1) {
			if !want[found] {
				t.Errorf("%s documents %s, which this build cannot emit.\n"+
					"🔴 A page describing a code that does not exist sends the reader to "+
					"diagnose a situation they are not in. Either the code was renamed and "+
					"the doc was not, or the doc invented it.", rel, found)
			}
		}
	}
}

// TestBothLanguageEditionsCoverTheSameCodes.
//
// 🔴 The comparison is between the two DOCUMENTS, not each against the enum.
// Both could pass the test above while one of them buried a code in prose and
// the other put it in the table — and the reader of the weaker edition would
// never know they were looking at less.
func TestBothLanguageEditionsCoverTheSameCodes(t *testing.T) {
	root := repoRootForDocs(t)

	seen := make([]map[string]bool, len(userDocs))
	for i, rel := range userDocs {
		raw, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // fixed path
		if err != nil {
			t.Skipf("%s unreadable: %v", rel, err)
		}
		seen[i] = map[string]bool{}
		for _, c := range anyMCPCode.FindAllString(string(raw), -1) {
			seen[i][c] = true
		}
	}

	for code := range seen[0] {
		if !seen[1][code] {
			t.Errorf("%s documents %s and %s does not — a translated page that drops a row "+
				"is worse than an untranslated one, because the reader cannot tell",
				userDocs[0], code, userDocs[1])
		}
	}
	for code := range seen[1] {
		if !seen[0][code] {
			t.Errorf("%s documents %s and %s does not", userDocs[1], code, userDocs[0])
		}
	}
}
