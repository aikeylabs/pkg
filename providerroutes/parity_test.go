package providerroutes

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// P1c (design D-9): cross-language consistency gate. These tests are static,
// have no external dependencies, and run by default (NOT env-gated) so drift
// fails the build — see the drift-history rationale in design D-9.

// TestFingerprintSHA256_SourceEqualsBuildCopy is gate #1: the build-time copy
// embedded here (pkg/providerroutes/data) MUST be byte-identical to the
// canonical source (aikey-cli/data). A stale `make sync-fingerprint` copy is
// exactly the drift this catches. Fails loud if the source is missing rather
// than silently passing (no fail-open).
func TestFingerprintSHA256_SourceEqualsBuildCopy(t *testing.T) {
	buildCopy := filepath.Join("data", "provider_fingerprint.yaml")
	canonical := filepath.Join("..", "..", "aikey-cli", "data", "provider_fingerprint.yaml")

	buildBytes, err := os.ReadFile(buildCopy)
	if err != nil {
		t.Fatalf("read build copy: %v", err)
	}
	canonBytes, err := os.ReadFile(canonical)
	if err != nil {
		// Fail loud: in the monorepo workspace the canonical source must exist.
		// A missing source means the SHA gate can't run — that's a red, not a skip.
		t.Fatalf("read canonical source %s: %v (sync-fingerprint must run before build)", canonical, err)
	}
	// The embedded bytes must equal the build copy on disk too.
	if sha256.Sum256(buildBytes) != sha256.Sum256(EmbeddedYAML()) {
		t.Fatal("embedded yaml != on-disk build copy (stale go:embed?)")
	}
	if sha256.Sum256(buildBytes) != sha256.Sum256(canonBytes) {
		t.Fatalf("SHA256 drift: build copy %s != canonical source %s — run `make sync-fingerprint`", buildCopy, canonical)
	}
}

// goldenRegistry mirrors the golden fixture shape. Both this Go test and the
// Rust cross-language test (aikey-cli provider_fingerprint tests) deserialize
// the SAME golden file with their own structs and assert their yaml-parse
// matches it. Divergent serde/yaml.v3 defaults surface as one side failing.
type goldenRegistry struct {
	ProviderRoutes    []Route    `json:"provider_routes"`
	ProviderModelMaps []ModelMap `json:"provider_model_maps"`
}

// TestGoldenFixtureParity_Go is gate #2 (Go half): the parsed embedded registry
// must deep-equal the checked-in golden. Iterates the FULL set (no white-list)
// and asserts non-empty (防空断言) so an empty table can't vacuously pass.
func TestGoldenFixtureParity_Go(t *testing.T) {
	goldenBytes, err := os.ReadFile(filepath.Join("testdata", "registry_golden.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden goldenRegistry
	if err := json.Unmarshal(goldenBytes, &golden); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	// 防空断言: an empty golden or empty parse would make the fence a decoration.
	if len(golden.ProviderRoutes) == 0 {
		t.Fatal("golden has zero routes — anti-empty assertion")
	}

	tbl := Default()
	gotRoutes := tbl.All()
	if !reflect.DeepEqual(gotRoutes, golden.ProviderRoutes) {
		t.Errorf("provider_routes parse != golden.\n got %d rows\n want %d rows\n(regenerate golden AND mirror the change in the Rust registry test)", len(gotRoutes), len(golden.ProviderRoutes))
	}
	gotMaps := tbl.AllModelMaps()
	if !reflect.DeepEqual(gotMaps, golden.ProviderModelMaps) {
		t.Errorf("provider_model_maps parse != golden (regenerate + mirror in Rust)")
	}
	// Every route row round-trips a non-empty host+provider+protocol — auto
	// discovered, no white-list (design D-9 教训: white-lists don't guard the
	// invariant itself).
	for i, r := range gotRoutes {
		if r.Host == "" || r.Provider == "" || r.Protocol == "" {
			t.Errorf("row %d has empty host/provider/protocol: %+v", i, r)
		}
	}
}
