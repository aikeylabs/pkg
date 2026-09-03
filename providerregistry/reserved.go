package providerregistry

// reserved.go — path prefixes the provider registry may NOT claim.
//
// # The hole this closes (I9)
//
// The proxy's client path-prefix table is derived 100% from this registry
// (aikey-proxy internal/proxy/pathprefix_table.go:131). Every row contributes
// its proxy_path, its code, the first segment of its proxy_path, and each of
// its oauth_aliases as a routable top-level prefix.
//
// Until this file existed there was no notion of a prefix being SPOKEN FOR by
// something other than a provider. So a row whose proxy_path was written as
// `mcp` would have made /mcp/... resolve to that provider's forwarding path,
// silently hijacking the entire MCP gateway surface — and the symptom would
// have been MCP clients failing to connect with no indication why.
//
// The same latent hazard applies to /health, /version and /.well-known, which
// the server has always mounted directly. Those survive today only because
// nobody happened to write them into the yaml.
//
// # Why this REFUSES rather than skips
//
// Parse returns an error instead of quietly dropping the offending prefix.
// Silently skipping is precisely the failure shape recorded in
// pathprefix_table.go:22-31 (defect D-1): a provider stayed selectable in the
// CLI picker while its path-prefix branch never matched, so `aikey use <it>`
// produced an error telling the user to do the thing they were already doing.
// A loud parse failure at build/startup is cheap; a provider that is offered
// but cannot work is expensive and takes a long time to diagnose.
//
// spec: R13 (`mcp` is a reserved path prefix) @
// workflow/CI/requirements/2026-08-20-mcp-gateway.md
// fence: TestReservedPrefixRejectsMcpProxyPath, and on the proxy side
// TestMcpPrefixIsNotDerivable (fence 1.F1).

import (
	"fmt"
	"sort"
	"strings"
)

// reservedPrefixes are the top-level URL segments the HTTP surface owns
// directly. A registry row may not claim any of them through its code,
// proxy_path (whole value or first segment), or oauth_aliases.
//
// Each entry names WHO owns it, so a future maintainer can tell whether an
// entry is still load-bearing before deleting it.
var reservedPrefixes = map[string]string{
	// The MCP gateway's public surface: POST/GET/DELETE /mcp/{toolset-slug}
	// and GET /mcp/capabilities. Frozen contract — third-party MCP clients
	// write it into their own config files.
	"mcp": "MCP gateway (POST/GET/DELETE /mcp/{toolset-slug}, GET /mcp/capabilities)",
	// RFC 9728 protected-resource metadata and any other well-known document.
	".well-known": "RFC 9728 protected-resource metadata (GET /.well-known/oauth-protected-resource)",
	// The proxy's own health surface, including GET /health/mcp.
	"health": "proxy health surface (GET /health, /health/mcp, /health/providers, ...)",
	// Build metadata.
	"version": "proxy build metadata (GET /version)",
}

// ReservedPrefixes returns the reserved segments, sorted, for diagnostics and
// for tests that assert the set has not silently shrunk.
func ReservedPrefixes() []string {
	out := make([]string, 0, len(reservedPrefixes))
	for p := range reservedPrefixes {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// IsReservedPrefix reports whether seg is claimed by the HTTP surface, and by
// whom. seg is normalised (lower-cased, trimmed) before lookup.
func IsReservedPrefix(seg string) (owner string, reserved bool) {
	owner, reserved = reservedPrefixes[norm(seg)]
	return owner, reserved
}

// checkReserved verifies one registry entry claims no reserved prefix.
//
// It checks every value the proxy's derivation would turn into a routable
// prefix — not just proxy_path — because a row can reach the prefix table
// through four different fields and blocking only one of them would leave the
// hole open through the other three.
func checkReserved(e Entry) error {
	type candidate struct{ field, value string }
	cands := []candidate{
		{"code", e.Code},
		{"proxy_path", e.ProxyPath},
	}
	// The proxy also derives the FIRST SEGMENT of proxy_path ("groq/v1" → "groq").
	if seg, _, found := strings.Cut(norm(e.ProxyPath), "/"); found && seg != "" {
		cands = append(cands, candidate{"proxy_path first segment", seg})
	}
	for _, a := range e.OAuthAliases {
		cands = append(cands, candidate{"oauth_aliases entry", a})
	}

	for _, c := range cands {
		v := norm(c.value)
		if v == "" {
			continue
		}
		if owner, reserved := IsReservedPrefix(v); reserved {
			return fmt.Errorf(
				"providerregistry: provider %q claims reserved path prefix %q via %s — that prefix belongs to %s; "+
					"pick a different value (a silent skip here would make this provider selectable but unroutable)",
				e.Code, v, c.field, owner)
		}
	}
	return nil
}
