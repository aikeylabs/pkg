package providerroutes

import (
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"
)

// Route mirrors one row of the yaml provider_routes table.
//
// Field tags use both yaml (for parsing the source file) and json (for
// callers that want to re-emit the table over an API — aikey-control's
// RulesHandler does this).
type Route struct {
	Host     string `yaml:"host" json:"host"`
	Protocol string `yaml:"protocol" json:"protocol"`
	Provider string `yaml:"provider" json:"provider"`
	BaseURL  string `yaml:"base_url" json:"base_url"`
	Version  string `yaml:"version" json:"version"`
	// PathPrefix (P1b / design D-2b) is the second half of the row key.
	// A host may now carry multiple rows distinguished by the path prefix
	// of the stored base_url (e.g. GLM's open.bigmodel.cn has separate
	// /api/anthropic and /api/coding/paas/v4 endpoints). Lookup does a
	// segment-aligned longest-prefix match on this field. Default "" is
	// the host's fallback row — with all-empty prefixes the longest-prefix
	// match degrades to exact host match, so the pre-P1b 18 rows keep
	// identical behaviour. omitempty keeps the JSON re-emission (rules
	// endpoint) backward compatible for the web consumer.
	PathPrefix string `yaml:"path_prefix,omitempty" json:"path_prefix,omitempty"`
	// Default explicitly selects the canonical endpoint when one
	// Provider+Protocol pair has multiple hosts. It avoids making YAML order a
	// routing decision (for example api.kimi.com vs www.kimi.com).
	Default bool `yaml:"default,omitempty" json:"default,omitempty"`
}

// Table is an indexed read-only view of the parsed provider_routes rows.
// Build via Parse; lookup via Lookup (host+path), ByHost, ByProvider, or
// ByProviderProtocol.
type Table struct {
	rows       []Route
	byHost     map[string][]Route  // host (lowercased) → rows (yaml order)
	firstByPro map[string]Route    // provider → first row matching (insertion order)
	modelMaps  map[string]ModelMap // provider code (lowercased) → model_map (design D-2)
}

// Parse reads the yaml bytes (the full provider_fingerprint.yaml content)
// and returns a Table covering the `provider_routes` section. Other yaml
// keys are ignored. Returns an error if the bytes don't decode as yaml or
// if a row violates basic invariants (empty host, duplicate (host,
// path_prefix) key).
func Parse(yamlBytes []byte) (*Table, error) {
	var raw struct {
		ProviderRoutes    []Route    `yaml:"provider_routes"`
		ProviderModelMaps []ModelMap `yaml:"provider_model_maps"`
	}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return nil, fmt.Errorf("providerroutes: yaml unmarshal: %w", err)
	}
	t := &Table{
		rows:       make([]Route, 0, len(raw.ProviderRoutes)),
		byHost:     make(map[string][]Route, len(raw.ProviderRoutes)),
		firstByPro: make(map[string]Route),
		modelMaps:  make(map[string]ModelMap, len(raw.ProviderModelMaps)),
	}
	for _, mm := range raw.ProviderModelMaps {
		if mm.Provider == "" {
			return nil, fmt.Errorf("providerroutes: provider_model_maps entry has empty provider")
		}
		code := strings.ToLower(mm.Provider)
		if _, dup := t.modelMaps[code]; dup {
			return nil, fmt.Errorf("providerroutes: duplicate provider_model_maps for %q", code)
		}
		t.modelMaps[code] = mm
	}
	// dedup key is now (host, path_prefix), not host alone (design D-2b).
	seenKey := make(map[string]struct{}, len(raw.ProviderRoutes))
	for i, r := range raw.ProviderRoutes {
		if r.Host == "" {
			return nil, fmt.Errorf("providerroutes: row %d has empty host", i)
		}
		host := strings.ToLower(r.Host)
		r.Host = host
		key := host + "\x00" + r.PathPrefix
		if _, dup := seenKey[key]; dup {
			return nil, fmt.Errorf("providerroutes: duplicate (host,path_prefix) key %q/%q at row %d", host, r.PathPrefix, i)
		}
		seenKey[key] = struct{}{}
		t.byHost[host] = append(t.byHost[host], r)
		if _, seen := t.firstByPro[r.Provider]; !seen {
			t.firstByPro[r.Provider] = r
		}
		t.rows = append(t.rows, r)
	}
	return t, nil
}

// pathPrefixMatches reports whether a row's path_prefix matches a request/
// stored path. Segment-aligned (design D-2b / task 1b.3): "/api/anthropic"
// matches "/api/anthropic" and "/api/anthropic/v1" but NOT
// "/api/anthropicfoo" (avoids "/api/anth" swallowing "/api/anthropic").
// The empty prefix is the host's catch-all fallback row.
func pathPrefixMatches(prefix, path string) bool {
	if prefix == "" {
		return true
	}
	if path == prefix {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// Lookup resolves the route row for a (host, path) pair using a
// segment-aligned longest-prefix match on path_prefix. The path is the
// path component of the stored/effective base_url. Returns ok=false when
// the host isn't in the table or no row's prefix matches (which for a
// host whose only row is the "" fallback never happens — that row always
// matches). Ties on prefix length cannot occur: (host,path_prefix) is
// unique per Parse.
func (t *Table) Lookup(host, path string) (Route, bool) {
	rows, ok := t.byHost[strings.ToLower(host)]
	if !ok {
		return Route{}, false
	}
	bestLen := -1
	var best Route
	for _, r := range rows {
		if pathPrefixMatches(r.PathPrefix, path) && len(r.PathPrefix) > bestLen {
			bestLen = len(r.PathPrefix)
			best = r
		}
	}
	if bestLen < 0 {
		return Route{}, false
	}
	return best, true
}

// SupportsProviderProtocol reports whether (provider, protocol) is a legal
// combination — i.e. some provider_routes row declares it (design D-14/D-15:
// the routes table IS the compatibility matrix, no separate compat table).
// Case-insensitive. This is the single source both master (import) and proxy
// consult, so their answers can't drift.
func (t *Table) SupportsProviderProtocol(provider, protocol string) bool {
	p, pr := strings.ToLower(provider), strings.ToLower(protocol)
	for _, r := range t.rows {
		if strings.ToLower(r.Provider) == p && strings.ToLower(r.Protocol) == pr {
			return true
		}
	}
	return false
}

// ProtocolsForProvider returns the distinct protocols a provider supports
// (yaml order, de-duplicated). Empty when the provider is unknown. Used by
// master form filtering (select a provider → offer only its protocols).
func (t *Table) ProtocolsForProvider(provider string) []string {
	p := strings.ToLower(provider)
	seen := map[string]struct{}{}
	var out []string
	for _, r := range t.rows {
		if strings.ToLower(r.Provider) == p {
			if _, dup := seen[r.Protocol]; !dup {
				seen[r.Protocol] = struct{}{}
				out = append(out, r.Protocol)
			}
		}
	}
	return out
}

// ProvidersForProtocol returns the distinct providers that speak a protocol
// (yaml order, de-duplicated). Used by master form filtering (select a
// protocol → offer only compatible providers).
func (t *Table) ProvidersForProtocol(protocol string) []string {
	p := strings.ToLower(protocol)
	seen := map[string]struct{}{}
	var out []string
	for _, r := range t.rows {
		if strings.ToLower(r.Protocol) == p {
			if _, dup := seen[r.Provider]; !dup {
				seen[r.Provider] = struct{}{}
				out = append(out, r.Provider)
			}
		}
	}
	return out
}

// LegacyProtocolForProvider answers "which protocol did this provider speak
// before anyone gave it a second face?" — for callers that know only the
// provider code, typically because they are resolving a credential created
// before protocol became a stored axis.
//
// # Why this is not "the first row in YAML order"
//
// Row order is not a routing decision anybody made; it is an editing accident.
// The rule here is semantic instead: a credential that predates path_prefix
// could only ever have been stored against a bare-host URL, and a bare-host URL
// resolves to the host's EMPTY-prefix row. So the protocol of the empty-prefix
// rows IS the face such a credential was created against. Adding a second face
// (which always arrives with an explicit path_prefix) therefore cannot change
// this answer — which is exactly the property legacy credentials need.
//
// Returns ok=false when the provider's empty-prefix rows disagree, or when it
// has none at all (mock: every row carries an explicit prefix). Failing closed
// there is right — such a provider never had a protocol-less era, so a
// protocol-less credential on it is a bug to surface, not a value to guess.
//
// # Why it exists (2026-08-02, provider-credential-cascade)
//
// Before this change, callers resolved a protocol-less credential via "if the
// provider has exactly one protocol, use it". Giving deepseek / moonshot /
// qwen / doubao / minimax their anthropic faces made that premise false for
// five more providers at once, and every legacy credential on them would have
// started answering 502 `Unknown provider protocol: `. (zhipu had been multi-
// protocol since 2026-05 and was ALREADY failing this way — this repairs that
// too.) Widening only: it can turn a previous ok=false into a truthful answer,
// and can never change an answer that already resolved.
func (t *Table) LegacyProtocolForProvider(provider string) (string, bool) {
	p := strings.ToLower(provider)
	var found string
	for _, r := range t.rows {
		if strings.ToLower(r.Provider) != p || r.PathPrefix != "" {
			continue
		}
		switch {
		case found == "":
			found = r.Protocol
		case !strings.EqualFold(found, r.Protocol):
			// Two bare-host faces for one provider: there is no single "before"
			// to point at. Don't guess.
			return "", false
		}
	}
	if found == "" {
		return "", false
	}
	return found, true
}

// LookupByBaseURL resolves the route row for a stored/effective base_url by
// extracting its host and path and running the same segment-aligned
// longest-prefix match as Lookup. Mirrors the Rust route_for_base_url so
// both languages resolve a GLM /api/anthropic base_url to the anthropic
// row (not the /api/paas fallback). Returns ok=false on parse failure or
// host miss.
func (t *Table) LookupByBaseURL(baseURL string) (Route, bool) {
	host := HostFromURL(baseURL)
	if host == "" {
		return Route{}, false
	}
	path := ""
	if u, err := url.Parse(baseURL); err == nil {
		path = u.Path
	}
	return t.Lookup(host, path)
}

// ByHost looks up a host's fallback (path_prefix "") row, or its first row
// if none has an empty prefix. Retained for callers that only have a host
// and no path; path-aware callers must use Lookup. Case-insensitive.
// Returns ok=false when the host isn't in the table.
func (t *Table) ByHost(host string) (Route, bool) {
	rows, ok := t.byHost[strings.ToLower(host)]
	if !ok || len(rows) == 0 {
		return Route{}, false
	}
	for _, r := range rows {
		if r.PathPrefix == "" {
			return r, true
		}
	}
	return rows[0], true
}

// ByProvider returns the first row matching a canonical provider_code
// (insertion-order = yaml order). Used as a non-host fallback when only
// the provider is known (e.g. user picked a provider chip with empty
// base_url). Multi-host providers (kimi) return the yaml-first row,
// which by convention is the canonical official endpoint.
func (t *Table) ByProvider(provider string) (Route, bool) {
	r, ok := t.firstByPro[provider]
	return r, ok
}

// ByProviderProtocol returns the default route for an exact canonical
// (provider, protocol) pair. It is the safe fallback for callers that know
// both axes but do not have a base URL to resolve with LookupByBaseURL.
//
// A pair normally has one row. When it has multiple endpoint rows, a single
// empty-path row is the explicit catch-all and therefore the default. If the
// pair has multiple rows without exactly one catch-all, there is no truthful
// default; return ok=false instead of making YAML insertion order observable.
// Matching is case-insensitive.
func (t *Table) ByProviderProtocol(provider, protocol string) (Route, bool) {
	p, pr := strings.ToLower(provider), strings.ToLower(protocol)
	var (
		matched              Route
		matchedCount         int
		fallback             Route
		fallbackCount        int
		declaredDefault      Route
		declaredDefaultCount int
	)
	for _, r := range t.rows {
		if strings.ToLower(r.Provider) != p || strings.ToLower(r.Protocol) != pr {
			continue
		}
		matched = r
		matchedCount++
		if r.Default {
			declaredDefault = r
			declaredDefaultCount++
		}
		if r.PathPrefix == "" {
			fallback = r
			fallbackCount++
		}
	}
	if declaredDefaultCount == 1 {
		return declaredDefault, true
	}
	if declaredDefaultCount > 1 {
		return Route{}, false
	}
	if matchedCount == 1 {
		return matched, true
	}
	if fallbackCount == 1 {
		return fallback, true
	}
	return Route{}, false
}

// All returns every loaded row in yaml insertion order. Stable for
// tests and for re-emitting the table over an API.
func (t *Table) All() []Route {
	out := make([]Route, len(t.rows))
	copy(out, t.rows)
	return out
}

// Len reports how many rows the table holds.
func (t *Table) Len() int { return len(t.rows) }

// EffectiveUpstream returns the user-facing "official" upstream URL for a
// route — base_url + version. UI layers use this when they want to show
// "where will the proxy actually route requests for this host". When
// version is empty (e.g. perplexity), the base_url is returned as-is.
func EffectiveUpstream(r Route) string {
	if r.Version == "" {
		return r.BaseURL
	}
	return r.BaseURL + r.Version
}

// HostFromURL extracts the lowercase hostname from a URL string. Returns
// "" on parse failure or empty host. Convenience wrapper used by Stitch
// and UI helpers.
func HostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}
