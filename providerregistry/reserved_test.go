package providerregistry

import (
	"strings"
	"testing"
)

// TestReservedPrefixRejectsMcpProxyPath is the registry half of fence 1.F1.
//
// Writing `mcp` into a provider's proxy_path would, before reserved.go, have
// made /mcp/... resolve to that provider's forwarding path — silently
// hijacking the whole MCP gateway surface, with "cannot connect" as the only
// symptom the customer ever sees.
//
// 🔴 The assertion is that Parse REFUSES. A version of this guard that merely
// skipped the offending prefix would leave the provider selectable in the CLI
// picker but unroutable, which is defect D-1 all over again
// (see aikey-proxy internal/proxy/pathprefix_table.go:22-31).
func TestReservedPrefixRejectsMcpProxyPath(t *testing.T) {
	_, err := Parse([]byte(`
providers:
  - code: acme
    proxy_path: mcp
`))
	if err == nil {
		t.Fatal("a provider claiming proxy_path `mcp` must be REFUSED, not accepted")
	}
	if !strings.Contains(err.Error(), "reserved path prefix") {
		t.Errorf("error should name the reserved-prefix rule, got: %v", err)
	}
	if !strings.Contains(err.Error(), "MCP gateway") {
		t.Errorf("error should name the owner so the reader knows why, got: %v", err)
	}
}

// TestReservedPrefixIsCheckedOnEveryDerivedField — a row can reach the proxy's
// prefix table through four different fields. Guarding only proxy_path would
// leave the hole open through the other three.
func TestReservedPrefixIsCheckedOnEveryDerivedField(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"code", `
providers:
  - code: mcp
    proxy_path: acme/v1
`},
		{"proxy_path whole value", `
providers:
  - code: acme
    proxy_path: health
`},
		{"proxy_path first segment", `
providers:
  - code: acme
    proxy_path: mcp/v1
`},
		{"oauth_aliases", `
providers:
  - code: acme
    proxy_path: acme/v1
    oauth_aliases: ["mcp"]
`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.yaml)); err == nil {
				t.Fatalf("a reserved prefix reached through %s was accepted", tc.name)
			}
		})
	}
}

// TestReservedPrefixMatchingIsCaseAndSpaceInsensitive — the proxy normalises
// before matching, so the guard must normalise too or `MCP` walks straight
// past it.
func TestReservedPrefixMatchingIsCaseAndSpaceInsensitive(t *testing.T) {
	if _, err := Parse([]byte("providers:\n  - code: acme\n    proxy_path: \"  MCP  \"\n")); err == nil {
		t.Fatal("`  MCP  ` must be recognised as the reserved prefix `mcp`")
	}
}

// TestReservedPrefixSetHasNotShrunk pins the four owned segments. Removing one
// re-opens a hijack path, so a deletion has to be a deliberate edit here.
func TestReservedPrefixSetHasNotShrunk(t *testing.T) {
	want := []string{".well-known", "health", "mcp", "version"}
	got := ReservedPrefixes()
	if len(got) != len(want) {
		t.Fatalf("reserved set is %v, expected %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("reserved[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	for _, p := range want {
		owner, ok := IsReservedPrefix(p)
		if !ok || owner == "" {
			t.Errorf("reserved prefix %q has no named owner; a future maintainer cannot tell if it is still load-bearing", p)
		}
	}
}

// TestOrdinaryProvidersStillParse — the guard must not have made the real
// registry unparseable. This is the "did I break the 28 shipping providers"
// check that keeps the fence from being a regression.
func TestOrdinaryProvidersStillParse(t *testing.T) {
	r := Default()
	if len(r.Codes()) == 0 {
		t.Fatal("the embedded registry no longer parses after adding the reserved-prefix guard")
	}
	for _, code := range r.Codes() {
		if _, reserved := IsReservedPrefix(code); reserved {
			t.Errorf("shipping provider %q collides with a reserved prefix", code)
		}
	}
}
