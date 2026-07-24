package providerregistry

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrySHA256_SourceEqualsBuildCopy is the drift gate, modelled on
// pkg/providerroutes' TestFingerprintSHA256_SourceEqualsBuildCopy. It asserts
// two hops, because a stale copy can enter at either one:
//
//	embedded bytes == data/provider_registry.yaml   (stale go:embed)
//	data/provider_registry.yaml == aikey-cli/data/  (sync never ran)
//
// bugfix 2026-06-12-restart-personal-stale-web-embed is the cost of not having
// this: an embedded asset silently lagged its source and the mismatch was only
// found after a long manual hunt.
//
// A missing canonical source is a FAILURE, not a skip. An env-gated or
// skip-on-missing gate gives false confidence — the file is always present in
// the monorepo checkout, so absence means the layout moved and the gate stopped
// guarding anything.
func TestRegistrySHA256_SourceEqualsBuildCopy(t *testing.T) {
	buildCopy := filepath.Join("data", "provider_registry.yaml")
	canonical := filepath.Join("..", "..", "aikey-cli", "data", "provider_registry.yaml")

	buildBytes, err := os.ReadFile(buildCopy)
	if err != nil {
		t.Fatalf("read build copy: %v", err)
	}
	canonBytes, err := os.ReadFile(canonical)
	if err != nil {
		t.Fatalf("read canonical source %s: %v (sync-provider-registry must run before build)", canonical, err)
	}
	if sha256.Sum256(buildBytes) != sha256.Sum256(EmbeddedYAML()) {
		t.Fatal("embedded yaml != on-disk build copy (stale go:embed?)")
	}
	if sha256.Sum256(buildBytes) != sha256.Sum256(canonBytes) {
		t.Fatalf("SHA256 drift: build copy %s != canonical source %s — run `make sync-provider-registry`", buildCopy, canonical)
	}
}

// TestParseEmbedded_AntiEmpty guards the fence itself. A registry that parsed to
// zero rows would make every table-driven assertion below pass vacuously, which
// is how a fence becomes a decoration (the phrasing pkg/providerroutes uses for
// the same check).
func TestParseEmbedded_AntiEmpty(t *testing.T) {
	r := Default()
	if len(r.Entries()) == 0 {
		t.Fatal("embedded registry parsed to zero providers — anti-empty assertion")
	}
	if len(r.Codes()) != len(r.Entries()) {
		t.Fatalf("Codes()=%d != Entries()=%d", len(r.Codes()), len(r.Entries()))
	}
}

// TestFourIdentifiersStayDistinct pins the exact rows where code / family /
// proxy_path / alias diverge. These three are the ONLY divergent rows in the
// registry today and they are precisely the ones that produced the 2026-05-08
// pair of bugs, so they are asserted by name rather than by a property that a
// future edit could satisfy accidentally.
//
// If a change makes one of these assertions fail, the correct response is almost
// never to update the expectation — it is to check whether a caller just started
// conflating two axes again.
func TestFourIdentifiersStayDistinct(t *testing.T) {
	r := Default()

	// kimi_code: all four identifiers differ. Folding family into code here is
	// what made `aikey use moonshot` route to kimi.
	e, ok := r.Lookup("kimi_code")
	if !ok {
		t.Fatal("kimi_code missing from registry")
	}
	if e.Code != "kimi_code" {
		t.Errorf("kimi_code Code = %q, want kimi_code", e.Code)
	}
	if e.Family != "kimi" {
		t.Errorf("kimi_code Family = %q, want kimi (UI grouping only)", e.Family)
	}
	if e.ProxyPath != "kimi/v1" {
		t.Errorf("kimi_code ProxyPath = %q, want kimi/v1 (NOT the canonical code)", e.ProxyPath)
	}

	// moonshot shares kimi_code's FAMILY but has no aliases. The historical bug
	// resolved it to "kimi"; canonicalization must leave it alone.
	if got := r.Canonical("moonshot"); got != "moonshot" {
		t.Errorf("Canonical(moonshot) = %q, want moonshot — folding it into kimi is bugfix 2026-05-08 #1", got)
	}
	mf, ok := r.Family("moonshot")
	if !ok || mf != "kimi" {
		t.Errorf("Family(moonshot) = %q,%v; want kimi,true", mf, ok)
	}
	if got := r.Canonical("kimi"); got != "kimi_code" {
		t.Errorf("Canonical(kimi) = %q, want kimi_code (kimi is an alias OF kimi_code)", got)
	}

	// mock has an empty proxy_path; the accessor must report it verbatim rather
	// than substituting the code, so a caller cannot mistake "" for a route.
	mp, ok := r.ProxyPath("mock")
	if !ok {
		t.Fatal("mock missing from registry")
	}
	if mp != "" {
		t.Errorf("mock ProxyPath = %q, want empty (no proxy route)", mp)
	}
}

// TestCanonicalMatchesRustSemantics locks the alias table and the unknown-input
// behaviour against Rust's provider_registry::canonical(). Divergence here means
// the same provider string resolves differently per language.
func TestCanonicalMatchesRustSemantics(t *testing.T) {
	r := Default()
	for _, tc := range []struct{ in, want string }{
		{"claude", "anthropic"},
		{"anthropic", "anthropic"},
		{"gpt", "openai"},
		{"chatgpt", "openai"},
		{"codex", "openai"},
		{"gemini", "google"},
		{"kimi", "kimi_code"},
		{"grok", "xai"},
		{"xai_grok", "xai"},
		{"pplx", "perplexity"},
		{"glm", "zhipu"},
		{"zhipuai", "zhipu"},
		{"dashscope", "qwen"},
		{"tongyi", "qwen"},
		{"ark", "doubao"},
		{"volcengine", "doubao"},
		// Case and whitespace normalize, matching Rust's to_lowercase()/trim.
		{"  Claude  ", "anthropic"},
		{"ANTHROPIC", "anthropic"},
		// Unknown input passes through lowercased — Rust returns the leaked
		// lowercase copy. Turning this into an error would diverge the two.
		{"not-a-provider", "not-a-provider"},
		{"  MADE-UP  ", "made-up"},
		{"", ""},
	} {
		if got := r.Canonical(tc.in); got != tc.want {
			t.Errorf("Canonical(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEveryAliasResolves walks the FULL registry instead of a white-list.
// pkg/providerroutes learned (design D-9) that white-lists do not guard the rows
// nobody remembered to add, so this discovers rows automatically: every declared
// alias must resolve to its own code, and every code must be idempotent.
func TestEveryAliasResolves(t *testing.T) {
	r := Default()
	seenAlias := 0
	for _, e := range r.Entries() {
		if got := r.Canonical(e.Code); got != e.Code {
			t.Errorf("Canonical(%q) = %q — canonical codes must be idempotent", e.Code, got)
		}
		if e.Family == "" {
			t.Errorf("provider %q has empty family (should default to code)", e.Code)
		}
		aliases, ok := r.Aliases(e.Code)
		if !ok {
			t.Errorf("Aliases(%q) reported missing", e.Code)
			continue
		}
		for _, a := range aliases {
			seenAlias++
			if got := r.Canonical(a); got != e.Code {
				t.Errorf("alias %q of %q resolved to %q", a, e.Code, got)
			}
			if _, isCode := r.byCode[a]; isCode {
				t.Errorf("alias %q is also a canonical code — ambiguous", a)
			}
		}
	}
	if seenAlias == 0 {
		t.Fatal("registry declared zero aliases — anti-empty assertion")
	}
}

// TestParseRejectsMalformed proves the loader fails loudly on the same shapes
// the Rust loader panics on. Without these, a bad registry would degrade
// silently instead of failing the build.
func TestParseRejectsMalformed(t *testing.T) {
	for name, y := range map[string]string{
		"empty":          "providers: []\n",
		"missing key":    "something_else: 1\n",
		"empty code":     "providers:\n  - code: \"\"\n",
		"duplicate code": "providers:\n  - code: anthropic\n  - code: anthropic\n",
		"alias collides with code": "providers:\n" +
			"  - code: anthropic\n" +
			"  - code: openai\n    oauth_aliases: [anthropic]\n",
		"alias collides with alias": "providers:\n" +
			"  - code: anthropic\n    oauth_aliases: [brand]\n" +
			"  - code: openai\n    oauth_aliases: [brand]\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("Parse(%s) accepted a malformed registry, want error", name)
		}
	}
}
