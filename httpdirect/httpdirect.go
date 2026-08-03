// Package httpdirect builds the HTTP clients used for CONTROL-PLANE calls.
//
// # Why this exists
//
// A control-plane call is aikey talking to aikey: proxy → master writeback and
// polls, collector upload, CLI-JWT refresh, cluster register, master → hub /
// cluster node / agent-route reads. Those destinations are internal — LAN or
// loopback — and are always reachable directly.
//
// Go's default transport disagrees. http.DefaultTransport honors HTTP_PROXY /
// HTTPS_PROXY / ALL_PROXY for EVERY destination with no LAN exception, and an
// aikey process very commonly inherits an egress proxy in its env (Clash on
// 127.0.0.1:7890 on a CN dev box; a corporate proxy on an enterprise server).
// That proxy exists for the USER's AI egress — reaching the model platform —
// and it typically cannot reach the internal control plane at all. Left alone,
// every control-plane call is routed into it and dies on timeout. That is not
// hypothetical: it is the 2026-06-30 OAuth member-token writeback "context
// deadline exceeded" incident, whose fix was aikey-proxy's local
// httpx.NewDirectClient. This package is that fix, lifted to a shared module on
// its second consumer (the master console makes the same LAN calls and had the
// same latent bug), so ONE definition states the invariant for both binaries.
//
// # Why not NO_PROXY
//
// The obvious alternative — teach the environment to exempt the control plane
// by appending its host to NO_PROXY — was considered and rejected (2026-08-03):
//
//   - Config drift: the control-plane base URL is runtime-configurable (a team
//     server moves, a cluster swaps its ingress). A NO_PROXY string has to be
//     re-synced on every such change and silently routes through the proxy when
//     someone forgets. A direct client follows the URL automatically.
//   - Side-effect leakage: env vars are inherited by child processes, and aikey
//     spawns third-party CLIs (claude / codex). Editing proxy env to fix an
//     aikey-internal concern would change the USER's AI egress — out of scope
//     and dangerous.
//   - Matching semantics: NO_PROXY behaviour differs across implementations
//     (port participation, suffix rules, CIDR support). "Proxy = nil" has no
//     such ambiguity.
//   - Testability: a direct client is a code invariant a fence test can hold
//     (see the package tests and each consumer's registry test); an env var is
//     runtime state that nothing can hold.
//
// # The escape hatch
//
// "The control plane is always direct-reachable" is true of every deployment
// shipped so far, but it is an assumption about the customer's network, not a
// law. A site whose master is reachable ONLY across a corporate proxy would be
// unfixable without a code change. SetProxyOverride turns that assumption into
// a configurable default: empty (the default) means direct, and an operator can
// point control-plane traffic at an explicit proxy without a new build.
//
// The override is read PER REQUEST, so changing it at runtime takes effect on
// clients that already exist — consumers do not have to rebuild their clients.
//
// # What does NOT belong here
//
// AI-egress / upstream-provider / request-forwarding clients, and calls to
// third-party services (OAuth token brokers, customer webhooks, remote
// registries). Those deliberately honor the environment (or the configured
// per-account egress) to get OUT of the network. Using this package for them
// would strand them behind a firewall.
package httpdirect

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// override holds the parsed control-plane proxy URL, or nil for direct.
// atomic.Pointer so a runtime change is visible to in-flight clients without a
// lock on the request path.
var override atomic.Pointer[url.URL]

// ErrInvalidProxyURL is returned by SetProxyOverride for a spec it cannot use.
var ErrInvalidProxyURL = errors.New("invalid control-plane proxy URL")

// SetProxyOverride points control-plane traffic at an explicit proxy. An empty
// string restores the default (direct). Call it once at boot from config; it is
// safe to call again later (a config reload takes effect immediately, including
// on clients already built).
//
// Accepts http / https / socks5 with an explicit host:port — the same shape the
// node-upstream validator accepts for a single URL, so an operator does not
// have to learn a second spec format.
func SetProxyOverride(rawURL string) error {
	s := strings.TrimSpace(rawURL)
	if s == "" {
		override.Store(nil)
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalidProxyURL, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("%w: scheme must be http/https/socks5, got %q", ErrInvalidProxyURL, u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return fmt.Errorf("%w: host:port required (e.g. http://10.0.0.5:3128)", ErrInvalidProxyURL)
	}
	override.Store(u)
	return nil
}

// ProxyOverride reports the configured control-plane proxy, or "" when
// control-plane traffic goes direct. For diagnostics / status endpoints.
func ProxyOverride() string {
	if u := override.Load(); u != nil {
		return u.Redacted()
	}
	return ""
}

// Transport returns a transport for control-plane calls: a clone of
// http.DefaultTransport (keeping its connection-pool and dial-timeout defaults)
// whose proxy lookup ignores the environment and consults the override instead.
func Transport() *http.Transport {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// A per-request func rather than a fixed URL: nil result means direct, and
	// reading the override here is what makes a runtime change take effect on
	// clients that were built earlier.
	tr.Proxy = func(*http.Request) (*url.URL, error) { return override.Load(), nil }
	return tr
}

// NewClient returns an *http.Client for control-plane calls. See the package
// doc for what belongs here and what does not.
func NewClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: Transport()}
}
