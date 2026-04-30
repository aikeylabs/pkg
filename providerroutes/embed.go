package providerroutes

import (
	_ "embed"
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
// The file is gitignored at this location: the canonical source lives in
// aikey-cli/data/. Editing the copy here is wrong; subsequent syncs will
// overwrite it.
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
