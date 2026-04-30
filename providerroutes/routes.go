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
}

// Table is an indexed read-only view of the parsed provider_routes rows.
// Build via Parse; lookup via ByHost / ByProvider.
type Table struct {
	rows       []Route
	byHost     map[string]Route // host (lowercased) → row
	firstByPro map[string]Route // provider → first row matching (insertion order)
}

// Parse reads the yaml bytes (the full provider_fingerprint.yaml content)
// and returns a Table covering the `provider_routes` section. Other yaml
// keys are ignored. Returns an error if the bytes don't decode as yaml or
// if a row violates basic invariants (empty host, duplicate host).
func Parse(yamlBytes []byte) (*Table, error) {
	var raw struct {
		ProviderRoutes []Route `yaml:"provider_routes"`
	}
	if err := yaml.Unmarshal(yamlBytes, &raw); err != nil {
		return nil, fmt.Errorf("providerroutes: yaml unmarshal: %w", err)
	}
	t := &Table{
		rows:       make([]Route, 0, len(raw.ProviderRoutes)),
		byHost:     make(map[string]Route, len(raw.ProviderRoutes)),
		firstByPro: make(map[string]Route),
	}
	for i, r := range raw.ProviderRoutes {
		if r.Host == "" {
			return nil, fmt.Errorf("providerroutes: row %d has empty host", i)
		}
		host := strings.ToLower(r.Host)
		r.Host = host
		if _, dup := t.byHost[host]; dup {
			return nil, fmt.Errorf("providerroutes: duplicate host %q at row %d", host, i)
		}
		t.byHost[host] = r
		if _, seen := t.firstByPro[r.Provider]; !seen {
			t.firstByPro[r.Provider] = r
		}
		t.rows = append(t.rows, r)
	}
	return t, nil
}

// ByHost looks up the route declaration for an exact host (case-insensitive).
// Returns ok=false when the host isn't in the table.
func (t *Table) ByHost(host string) (Route, bool) {
	r, ok := t.byHost[strings.ToLower(host)]
	return r, ok
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
