package providerroutes

import "testing"

const mmYAML = `
provider_routes:
  - { host: "open.bigmodel.cn", protocol: openai_compatible, provider: zhipu, base_url: "https://open.bigmodel.cn/api/paas", version: "" }
provider_model_maps:
  - provider: zhipu
    unmatched: reject
    models:
      - { match: "opus",   requested_model: "glm-4.6" }
      - { match: "sonnet", requested_model: "glm-4.5" }
      - { match: "claude-opus-4-8", requested_model: "glm-4.6-pinned" }
      - { match: "*", requested_model: "glm-4.6" }
`

func TestResolveModelPrecedence(t *testing.T) {
	tbl := mustParse(t, mmYAML)
	cases := []struct {
		requested string
		want      string
		matched   bool
	}{
		{"claude-opus-4-8", "glm-4.6-pinned", true}, // exact beats role+wildcard
		{"claude-opus-4-9", "glm-4.6", true},        // role opus (升版本不失效)
		{"claude-sonnet-4-6", "glm-4.5", true},      // role sonnet
		{"gpt-4o", "glm-4.6", true},                 // wildcard (no role/exact)
	}
	for _, c := range cases {
		got, matched, _ := tbl.ResolveModel("zhipu", c.requested)
		if got != c.want || matched != c.matched {
			t.Errorf("ResolveModel(zhipu,%q) = (%q,%v), want (%q,%v)", c.requested, got, matched, c.want, c.matched)
		}
	}
}

func TestResolveModelUnmatchedPolicy(t *testing.T) {
	// no-wildcard map → reject policy surfaces on miss
	src := `
provider_model_maps:
  - provider: zhipu
    unmatched: reject
    models:
      - { match: "opus", requested_model: "glm-4.6" }
`
	tbl := mustParse(t, src)
	got, matched, policy := tbl.ResolveModel("zhipu", "gpt-4o")
	if matched {
		t.Errorf("expected no match for gpt-4o")
	}
	if policy != UnmatchedReject {
		t.Errorf("policy = %q, want reject", policy)
	}
	if got != "gpt-4o" {
		t.Errorf("unmatched passthrough value = %q, want original", got)
	}
	// provider with no map at all → passthrough default
	_, matched2, policy2 := tbl.ResolveModel("no_such_provider", "x")
	if matched2 || policy2 != UnmatchedPassthrough {
		t.Errorf("no-map provider: matched=%v policy=%q, want false/passthrough", matched2, policy2)
	}
}

func TestModelMapForEmbedded(t *testing.T) {
	// The shipped yaml must parse a zhipu map with the flagship mapping.
	tbl := Default()
	got, matched, _ := tbl.ResolveModel("zhipu", "claude-opus-4-8")
	if !matched || got != "glm-4.6" {
		t.Errorf("embedded zhipu opus-4-8 → (%q,%v), want glm-4.6/true", got, matched)
	}
}

// TestValidateModelMaps_ShippedIsValid: the shipped registry must pass all
// build-time model_map checks. Default (non-env-gated) → fails the build if
// someone commits an ambiguous/secret-shaped/invalid map.
func TestValidateModelMaps_ShippedIsValid(t *testing.T) {
	if err := Default().ValidateModelMaps(); err != nil {
		t.Fatalf("shipped provider_model_maps invalid: %v", err)
	}
}

func TestValidateModelMaps_CatchesViolations(t *testing.T) {
	bad := []struct {
		name string
		src  string
	}{
		{"ambiguous_exact", `
provider_model_maps:
  - provider: zhipu
    models:
      - { match: "claude-opus-4-8", requested_model: "glm-4.6" }
      - { match: "claude-opus-4-8", requested_model: "glm-4.5" }
`},
		{"duplicate_role", `
provider_model_maps:
  - provider: zhipu
    models:
      - { match: "opus", requested_model: "glm-4.6" }
      - { match: "opus", requested_model: "glm-4.5" }
`},
		{"double_wildcard", `
provider_model_maps:
  - provider: zhipu
    models:
      - { match: "*", requested_model: "glm-4.6" }
      - { match: "*", requested_model: "glm-4.5" }
`},
		{"secret_shaped", `
provider_model_maps:
  - provider: zhipu
    models:
      - { match: "opus", requested_model: "sk-ant-api03-leaked" }
`},
		{"claude_unsafe_match", `
provider_model_maps:
  - provider: zhipu
    models:
      - { match: "claude-typo", requested_model: "glm-4.6" }
`},
		{"bad_unmatched", `
provider_model_maps:
  - provider: zhipu
    unmatched: explode
    models:
      - { match: "opus", requested_model: "glm-4.6" }
`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			tbl := mustParse(t, c.src)
			if err := tbl.ValidateModelMaps(); err == nil {
				t.Errorf("expected validation failure for %s", c.name)
			}
		})
	}
}

// P1i (design D-14/D-15): the routes table IS the compatibility matrix.
func TestCompatibilityMatrix(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	// zhipu supports BOTH anthropic (from /api/anthropic row) and
	// openai_compatible (fallback + coding rows) — the N:M point.
	if !tbl.SupportsProviderProtocol("zhipu", "anthropic") {
		t.Error("zhipu×anthropic must be supported (GLM anthropic endpoint)")
	}
	if !tbl.SupportsProviderProtocol("zhipu", "openai_compatible") {
		t.Error("zhipu×openai_compatible must be supported")
	}
	// illegal combos
	if tbl.SupportsProviderProtocol("zhipu", "gemini") {
		t.Error("zhipu×gemini must be unsupported")
	}
	if tbl.SupportsProviderProtocol("anthropic", "openai_compatible") {
		t.Error("anthropic×openai_compatible must be unsupported")
	}
	// case-insensitive
	if !tbl.SupportsProviderProtocol("ZHIPU", "Anthropic") {
		t.Error("matrix must be case-insensitive")
	}
	// filtering
	protos := tbl.ProtocolsForProvider("zhipu")
	if len(protos) != 2 {
		t.Errorf("zhipu protocols = %v, want 2 distinct", protos)
	}
	provs := tbl.ProvidersForProtocol("anthropic")
	// anthropic protocol: anthropic (official) + zhipu (GLM) in glmYAML
	if len(provs) != 2 {
		t.Errorf("anthropic providers = %v, want [anthropic zhipu]", provs)
	}
}

func TestParseDuplicateModelMapRejected(t *testing.T) {
	dup := `
provider_model_maps:
  - provider: zhipu
    models: [ { match: "opus", requested_model: "glm-4.6" } ]
  - provider: zhipu
    models: [ { match: "sonnet", requested_model: "glm-4.5" } ]
`
	if _, err := Parse([]byte(dup)); err == nil {
		t.Fatal("expected duplicate provider_model_maps rejection")
	}
}
