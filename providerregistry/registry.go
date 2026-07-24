// Package providerregistry exposes aikey-cli/data/provider_registry.yaml — the
// declared single source of truth for provider capability — to Go consumers.
//
// FOUR IDENTIFIERS, DELIBERATELY NOT UNIFIED
//
// A provider row carries up to four distinct strings, and conflating any two of
// them has caused production bugs twice on the same day:
//
//	code         canonical provider_code; what bindings/vault/routing store
//	family       UI grouping only; several codes may share one family
//	proxy_path   the URL path segment aikey-proxy serves the provider under
//	oauth_aliases  brand names users type that normalize INTO code
//
// The rows where these diverge are exactly where things broke:
//
//	code=kimi_code  family=kimi  proxy_path=kimi/v1      aliases=[kimi]
//	code=moonshot   family=kimi  proxy_path=moonshot/v1  aliases=[]
//
//   - bugfix 2026-05-08-provider-info-canonical-code-folded-into-family: Rust's
//     provider_info() returned entry.family as canonical_code, so `aikey use
//     moonshot` resolved to "kimi" and wrote the wrong env vars, base_url and
//     binding. Fix was splitting canonical_code (entry.code) from family.
//   - bugfix 2026-05-08-events-provider-uses-url-prefix-not-canonical: usage
//     events recorded the URL prefix ("kimi") instead of the canonical code
//     ("kimi_code"), so one key's traffic was billed as two providers.
//
// Both records note the same trap: before the kimi split these strings were
// always equal, so a conflated call site looked correct until the day it wasn't.
// This package therefore offers FOUR narrow accessors and deliberately provides
// no catch-all "provider" lookup — a caller must state which identifier it wants.
//
// See also requirement spec
// workflow/CI/requirements/2026-07-18-provider-protocol-compatibility-and-baseurl.md
// §3 (this file owns display + product entry; provider_routes owns protocol,
// compatibility and base_url) and §10 (no hardcoded switch as a second source).
package providerregistry

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one provider row. Only the fields Go consumers need are modelled;
// unknown yaml keys (clients, extra_env_vars, picker, …) are ignored, which also
// keeps older binaries forward-compatible with newer registry files.
type Entry struct {
	// Code is the canonical provider_code stored in bindings and vault rows.
	Code string `yaml:"code"`
	// Family groups brand-distinct codes for UI aggregation (kimi_code and
	// moonshot both report "kimi"). NEVER use it for routing — see package doc.
	Family string `yaml:"family"`
	// OAuthAliases are brand names that normalize into Code.
	OAuthAliases []string `yaml:"oauth_aliases"`
	// ProxyPath is the URL path segment aikey-proxy serves this provider under.
	// It is NOT always Code (kimi_code serves under "kimi/v1").
	ProxyPath string `yaml:"proxy_path"`
	// DefaultBaseURL is the upstream default shown in probes and drawer hints.
	// Routing must resolve base_url through provider_routes instead — this field
	// exists for display parity with the Rust/TS consumers.
	DefaultBaseURL string `yaml:"default_base_url"`
	// Display / DisplayAlias are human labels; DisplayAlias is the muted brand
	// parenthetical (zhipu(GLM)).
	Display      string `yaml:"display"`
	DisplayAlias string `yaml:"display_alias"`
}

// Registry is an immutable parsed view of provider_registry.yaml.
type Registry struct {
	entries []Entry
	byCode  map[string]int // canonical code → index
	byAny   map[string]int // canonical code AND every alias → index
}

// Parse reads provider_registry.yaml bytes. It enforces the same invariants the
// Rust loader panics on, so a malformed registry fails identically in both
// languages instead of one side silently tolerating it:
//   - non-empty code
//   - no duplicate code
//   - no alias colliding with another entry's code or alias
func Parse(yamlBytes []byte) (*Registry, error) {
	var raw struct {
		Providers []Entry `yaml:"providers"`
	}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return nil, fmt.Errorf("providerregistry: yaml unmarshal: %w", err)
	}
	if len(raw.Providers) == 0 {
		return nil, fmt.Errorf("providerregistry: top-level \"providers\" is empty or missing")
	}

	r := &Registry{
		entries: make([]Entry, 0, len(raw.Providers)),
		byCode:  make(map[string]int, len(raw.Providers)),
		byAny:   make(map[string]int, len(raw.Providers)*2),
	}
	for i, e := range raw.Providers {
		code := norm(e.Code)
		if code == "" {
			return nil, fmt.Errorf("providerregistry: provider row %d has empty code", i)
		}
		if _, dup := r.byCode[code]; dup {
			return nil, fmt.Errorf("providerregistry: duplicate code %q", code)
		}
		e.Code = code
		// family defaults to code — mirrors the Rust loader so both languages
		// report the same family for rows that omit the field.
		if f := norm(e.Family); f != "" {
			e.Family = f
		} else {
			e.Family = code
		}
		idx := len(r.entries)
		r.entries = append(r.entries, e)
		r.byCode[code] = idx
		if prior, dup := r.byAny[code]; dup {
			return nil, fmt.Errorf("providerregistry: code %q collides with entry #%d", code, prior)
		}
		r.byAny[code] = idx
		for _, a := range e.OAuthAliases {
			alias := norm(a)
			if alias == "" {
				continue
			}
			if prior, dup := r.byAny[alias]; dup {
				return nil, fmt.Errorf("providerregistry: alias %q on %q collides with entry #%d", alias, code, prior)
			}
			r.byAny[alias] = idx
		}
	}
	return r, nil
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Canonical resolves a canonical code or brand alias to the canonical code.
//
// An input that is not in the registry is returned lowercased/trimmed, NOT
// rejected. This is not a convenience fallback: it is exactly what Rust's
// provider_registry::canonical() does for unknown input, and the two must agree
// or the same provider string would resolve differently per language. Do not
// "improve" it into an error or a guess — bugfix
// 20260603-drawer-base-url-source-of-truth-split showed that adding a fallback
// which the source of truth does not describe is how a split starts; there the
// fix was deleting one.
func (r *Registry) Canonical(providerOrAlias string) string {
	key := norm(providerOrAlias)
	if idx, ok := r.byAny[key]; ok {
		return r.entries[idx].Code
	}
	return key
}

// Lookup returns the full entry for a canonical code or alias.
func (r *Registry) Lookup(providerOrAlias string) (Entry, bool) {
	if idx, ok := r.byAny[norm(providerOrAlias)]; ok {
		return r.entries[idx], true
	}
	return Entry{}, false
}

// Family returns the UI grouping family. Routing must never use this — see the
// package doc and bugfix 2026-05-08-provider-info-canonical-code-folded-into-family.
func (r *Registry) Family(providerOrAlias string) (string, bool) {
	e, ok := r.Lookup(providerOrAlias)
	if !ok {
		return "", false
	}
	return e.Family, true
}

// ProxyPath returns the URL path segment the provider is served under. It is not
// interchangeable with Code — see bugfix
// 2026-05-08-events-provider-uses-url-prefix-not-canonical.
func (r *Registry) ProxyPath(providerOrAlias string) (string, bool) {
	e, ok := r.Lookup(providerOrAlias)
	if !ok {
		return "", false
	}
	return e.ProxyPath, true
}

// Aliases returns the brand aliases declared for a provider, in yaml order.
func (r *Registry) Aliases(providerOrAlias string) ([]string, bool) {
	e, ok := r.Lookup(providerOrAlias)
	if !ok {
		return nil, false
	}
	out := make([]string, len(e.OAuthAliases))
	for i, a := range e.OAuthAliases {
		out[i] = norm(a)
	}
	return out, true
}

// Codes returns every canonical provider code, sorted. Consumers that need a
// deterministic allowlist should derive it from here rather than restating one.
func (r *Registry) Codes() []string {
	out := make([]string, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.Code)
	}
	sort.Strings(out)
	return out
}

// Entries returns all rows in yaml order.
func (r *Registry) Entries() []Entry {
	out := make([]Entry, len(r.entries))
	copy(out, r.entries)
	return out
}
