package providerroutes

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"sync"
)

// Embedded copy of aikey-cli/data/provider_fingerprint.yaml.
//
// The yaml file MUST be present at pkg/providerroutes/data/ before this
// package is compiled. It's synced by:
//
//   - Each consumer's `make sync-fingerprint` target (transitive dep of
//     `make build`)
//   - workflow/CD/publish/release.sh `Step 0.5: sync provider_fingerprint`
//
// P1c / design D-7: this copy is CHECKED IN (no longer gitignored) so every
// Go consumer reading pkg/providerroutes via go.mod replace gets a present,
// correct file without a per-service sync step. The canonical source lives in
// aikey-cli/data/; editing this copy directly is wrong — sync-fingerprint
// regenerates it and TestFingerprintSHA256_SourceEqualsBuildCopy fails the
// build if the two diverge (the drift gate).
//
//go:embed data/provider_fingerprint.yaml
var embeddedYAML []byte

var (
	defaultOnce  sync.Once
	defaultTable *Table
	defaultErr   error
)

// Default returns the process-wide Table parsed from the embedded yaml.
// Subsequent calls return the same Table pointer (Once caches it).
//
// Panics on parse failure — the embedded yaml is a build-time asset, so
// malformed bytes mean the build is broken; the binary should refuse to
// start rather than route requests with no table. (Tests and consumers
// that want a custom table should call Parse directly.)
func Default() *Table {
	defaultOnce.Do(func() {
		defaultTable, defaultErr = Parse(embeddedYAML)
	})
	if defaultErr != nil {
		panic("providerroutes: malformed embedded provider_fingerprint.yaml: " + defaultErr.Error())
	}
	return defaultTable
}

// EmbeddedYAML returns the raw embedded yaml bytes. Useful for callers
// that need to re-emit the source for debugging or for the rules-endpoint
// fallback path that wants to mirror the table verbatim.
func EmbeddedYAML() []byte {
	out := make([]byte, len(embeddedYAML))
	copy(out, embeddedYAML)
	return out
}

// Digest returns the first 12 hex chars of SHA256(embedded yaml) — the
// registry provenance stamp ("mapping comes from registry vX"). Used by the
// proxy's read-only diagnostics endpoint (task 7.9) and the four-surface
// visibility (3.5) so the client can prove WHICH embedded registry is live.
// Since the yaml is compiled in, the digest changes only when the binary does
// (P7.14: editing a mapping line = source change = a new digest = a re-release).
func Digest() string {
	sum := sha256.Sum256(embeddedYAML)
	return hex.EncodeToString(sum[:])[:12]
}
