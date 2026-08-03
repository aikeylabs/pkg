package providerroutes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// baselineEntry is one frozen row of the pre-cascade routing table plus the
// result of round-tripping it through LookupByBaseURL(EffectiveUpstream(r)).
// Both halves matter: the row identity proves the row still exists, the hit
// proves it still resolves to ITSELF rather than to some newly added sibling.
type baselineEntry struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	Protocol   string `json:"protocol"`
	Provider   string `json:"provider"`
	BaseURL    string `json:"base_url"`
	Version    string `json:"version"`
	Default    bool   `json:"default"`

	EffectiveUpstream string `json:"effective_upstream"`
	LookupOK          bool   `json:"lookup_ok"`
	HitHost           string `json:"hit_host"`
	HitPathPrefix     string `json:"hit_path_prefix"`
	HitProtocol       string `json:"hit_protocol"`
	HitProvider       string `json:"hit_provider"`
}

// TestExportBaseline regenerates testdata/baseline_routes_pre_cascade.json —
// the frozen I-3 zero-regression fixture (task P0.1 / P1c.1).
//
// It is a generator, not an assertion, so it is gated behind an env var:
// the whole point of the fixture is that the cascade expansion PR must NOT
// be able to rewrite it. Running the suite normally leaves it untouched.
//
//	AIKEY_REGEN_ROUTE_BASELINE=1 go test ./... -run TestExportBaseline
//
// The fixture is generated from the table as it stood BEFORE the cascade
// expansion. Regenerating it after adding rows would make the fence assert
// that the new table agrees with itself — which is not a fence at all.
func TestExportBaseline(t *testing.T) {
	if os.Getenv("AIKEY_REGEN_ROUTE_BASELINE") != "1" {
		t.Skip("generator; set AIKEY_REGEN_ROUTE_BASELINE=1 to rewrite the fixture")
	}
	tbl := Default()
	entries := make([]baselineEntry, 0, tbl.Len())
	for _, r := range tbl.All() {
		eff := EffectiveUpstream(r)
		hit, ok := tbl.LookupByBaseURL(eff)
		entries = append(entries, baselineEntry{
			Host:              r.Host,
			PathPrefix:        r.PathPrefix,
			Protocol:          r.Protocol,
			Provider:          r.Provider,
			BaseURL:           r.BaseURL,
			Version:           r.Version,
			Default:           r.Default,
			EffectiveUpstream: eff,
			LookupOK:          ok,
			HitHost:           hit.Host,
			HitPathPrefix:     hit.PathPrefix,
			HitProtocol:       hit.Protocol,
			HitProvider:       hit.Provider,
		})
	}
	blob, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	blob = append(blob, '\n')
	out := filepath.Join("testdata", "baseline_routes_pre_cascade.json")
	if err := os.MkdirAll("testdata", 0o755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile(out, blob, 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("wrote %s (%d rows)", out, len(entries))
}
