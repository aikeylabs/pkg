package providerregistry

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"sync"
)

// Embedded copy of aikey-cli/data/provider_registry.yaml.
//
// WHY THIS PACKAGE EXISTS (2026-07-24)
//
// provider_registry.yaml declares itself "single source of truth for provider
// capability" and owns the oauth alias table (claude→anthropic, kimi→kimi_code,
// …). Until now only Rust (include_str!) and the web bundles (codegen to TS)
// could read it; Go had NO path to it at all, so every Go call site that needed
// an alias resolved it with a hand-maintained switch. Requirement spec
// 2026-07-18-provider-protocol-compatibility-and-baseurl.md §10 forbids exactly
// that: "不得维护硬编码 switch 作为第二套静默真相源". This package closes the
// Go half of 重构总纲 1.5 (真相源病 #1).
//
// WHY go:embed AND NOT THE EXISTING TS CODEGEN
//
// The web side must codegen (a bundler cannot read yaml at runtime), and that
// generator is a Node script. Routing Go through it would put Node +
// node_modules on aikey-proxy's build path, which is pure Go today — a real
// regression for the offline / air-gapped enterprise delivery this project
// targets. Go embeds and parses at runtime instead, exactly like
// pkg/providerroutes does for provider_fingerprint.yaml. Same yaml, two
// consumption models, because the two toolchains have different constraints.
//
// The copy under data/ is CHECKED IN (same posture as pkg/providerroutes, design
// D-7) so every consumer wired via a go.mod replace compiles without a per-service
// sync step. The canonical source lives in aikey-cli/data/; editing this copy
// directly is wrong — `make sync-provider-registry` regenerates it and
// TestRegistrySHA256_SourceEqualsBuildCopy fails the build when the two diverge.
//
//go:embed data/provider_registry.yaml
var embeddedYAML []byte

var (
	defaultOnce     sync.Once
	defaultRegistry *Registry
	defaultErr      error
)

// Default returns the process-wide Registry parsed from the embedded yaml.
// Subsequent calls return the same pointer (Once caches it).
//
// Panics on parse failure, mirroring pkg/providerroutes.Default: the yaml is a
// build-time asset, so malformed bytes mean a broken build. A binary that would
// canonicalize providers against a half-parsed registry must refuse to start
// rather than silently misroute. Tests wanting a custom registry call Parse.
func Default() *Registry {
	defaultOnce.Do(func() {
		defaultRegistry, defaultErr = Parse(embeddedYAML)
	})
	if defaultErr != nil {
		panic("providerregistry: malformed embedded provider_registry.yaml: " + defaultErr.Error())
	}
	return defaultRegistry
}

// EmbeddedYAML returns a copy of the raw embedded yaml bytes.
func EmbeddedYAML() []byte {
	out := make([]byte, len(embeddedYAML))
	copy(out, embeddedYAML)
	return out
}

// Digest returns the first 12 hex chars of SHA256(embedded yaml) — the registry
// provenance stamp, same convention as providerroutes.Digest so diagnostics can
// report which registry a running binary carries.
func Digest() string {
	sum := sha256.Sum256(embeddedYAML)
	return hex.EncodeToString(sum[:])[:12]
}
