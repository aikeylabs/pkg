// testdial.go — shared egress connectivity probe (§ egress connectivity test).
//
// TestDial builds the egress through the SAME engine registry the proxy dials
// with (BuildEgressOnlyDialContext, the builder administrator login dials with
// too), then makes one real HTTP GET to an IP-echo endpoint THROUGH that egress
// and reports the observed exit IP + latency. A single http:// or https:// proxy
// URL, which no engine claims, is measured through that explicit proxy instead
// (http.ProxyURL, the way the real single-URL paths use it). It is the single
// source of truth for "is this egress reachable and what IP does it exit from",
// reused by the proxy's diagnostics and the master console's "test" buttons — so
// a green test exercises the real dial path, not a re-implementation.
//
// It dials through a caller-supplied egress to a caller-supplied echo host;
// callers decide who may trigger it (master: administrators on the admin
// endpoints, pool members and owners on the member egress editor; aikey-proxy:
// its non-public admin face).
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpProxyEngine is TestResult.Engine for a single http(s):// proxy URL. It is
// the same label aikey-proxy's node egress test reports for that shape.
const httpProxyEngine = "http-proxy"

// TestResult is the outcome of a single egress connectivity probe.
type TestResult struct {
	// Engine that claimed the spec (e.g. "builtin-socks5" or "mihomo"), or
	// "http-proxy" for a single http(s):// proxy URL.
	Engine string
	// ExitIP is the echo endpoint's view of the source IP — the egress exit IP.
	// Empty if the echo body could not be reduced to an IP.
	ExitIP string
	// Body is the raw echo response (trimmed), for echoes that return more than a
	// bare IP.
	Body string
	// LatencyMs is wall time from dial start to response body read.
	LatencyMs int64
	// StatusCode is the echo endpoint's HTTP status.
	StatusCode int
	// Bypassed reports that the ECHO TARGET ITSELF matched a DIRECT bypass rule
	// in the spec, so this probe never went through the proxy — ExitIP is then
	// the PROBING HOST's own IP, not the egress exit.
	//
	// WHY THIS FIELD EXISTS (2026-07-30): without it a bypass-ruled echo target
	// produces a green result showing a plausible IP, and an operator reads
	// "egress verified" from a probe that proved nothing about the egress. A
	// connectivity check that can silently measure the wrong path is worse than
	// no check. Always false for specs with no bypass rules.
	Bypassed bool
	// BypassRule is the rule line that matched, for the UI to quote verbatim.
	BypassRule string
}

// BypassReporter is an OPTIONAL interface a built dialer may implement to say
// whether a given address would skip the proxy. Engines that route everything
// through the chain simply do not implement it (the zero behavior is "nothing
// is bypassed"), so this is additive — the Engine contract is unchanged.
type BypassReporter interface {
	// BypassInfo reports whether addr (host:port) is routed DIRECT, and which
	// rule decided it.
	BypassInfo(addr string) (bypassed bool, rule string)
}

// TestDial resolves spec through the engine registry, dials echoURL through it,
// and returns the observed exit IP + latency. A non-nil error means the egress
// could not be built or the echo could not be reached through it (i.e. the
// egress is not usable) — the actionable reason is in the error.
//
// It closes what it builds before returning: the engine's dialer when it holds
// background resources, and the transport's idle connections.
func TestDial(ctx context.Context, spec, echoURL string, timeout time.Duration) (*TestResult, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty egress spec")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	// bugfix: workflow/CI/bugfix/2026-09-24-testdial-single-http-proxy-and-dialer-leak.md
	// Why: no engine claims a single http(s):// URL (mihomo claims it and then
	// fails; builds without mihomo have no engine for it), so a proxy the real
	// single-URL paths use every day was reported as failed. Checked before the
	// registry, or mihomo would claim it.
	if proxyURL, ok, err := singleHTTPProxyURL(spec); ok {
		if err != nil {
			return nil, err
		}
		transport := newProbeTransport(timeout)
		// Only the proxy it was given: never HTTP(S)_PROXY or NO_PROXY, so the
		// probe measures this egress and nothing else.
		transport.Proxy = http.ProxyURL(proxyURL)
		// Negotiate HTTP/2 as Go's default transport and the real single-URL
		// paths do. In production this changes nothing (no TLS config and no
		// dialer, so Go already offers h2); it stops testDialRootCAs, which
		// sets a TLS config, from switching h2 off in the fences only.
		transport.ForceAttemptHTTP2 = true
		defer transport.CloseIdleConnections()
		return probeEcho(ctx, transport, httpProxyEngine, echoURL, timeout)
	}

	engineName := engineClaiming(spec)
	// The egress-only builder has no NO_PROXY or loopback bypass. Administrator
	// login dials with the same builder, so what this measures is what login uses
	// (DEC-master-central-login-14).
	dial, dialer, closer, err := BuildEgressOnlyDialContext(spec)
	if err != nil {
		return nil, err
	}
	// bugfix: workflow/CI/bugfix/2026-09-24-testdial-single-http-proxy-and-dialer-leak.md
	// Why: a proxy-group dialer runs health-check goroutines until Close; every
	// test of a proxy-group egress (the console's Test egress button, `aikey
	// doctor`) used to leak one set.
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	transport := newProbeTransport(timeout)
	transport.DialContext = dial
	defer transport.CloseIdleConnections()

	res, err := probeEcho(ctx, transport, engineName, echoURL, timeout)
	if err != nil {
		return nil, err
	}
	// Did the probe actually traverse the proxy? Ask the dialer about the echo
	// target itself; a DIRECT verdict means ExitIP describes this host, not the
	// egress (see TestResult.Bypassed).
	if br, ok := dialer.(BypassReporter); ok {
		if host := echoHostPort(echoURL); host != "" {
			res.Bypassed, res.BypassRule = br.BypassInfo(host)
		}
	}
	return res, nil
}

// singleHTTPProxyURL reports whether spec is exactly one http:// or https://
// forward-proxy URL, and parses it. A comma-separated chain is never this
// shape; it stays on the engine registry.
//
// The errors name the URL only as RedactSpec renders it and never wrap
// url.Parse's error: a *url.Error quotes the raw URL, and even its inner error
// can quote the password (DEC-master-central-login-15).
func singleHTTPProxyURL(spec string) (*url.URL, bool, error) {
	lower := strings.ToLower(spec)
	if strings.Contains(spec, ",") ||
		!(strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")) {
		return nil, false, nil
	}
	u, err := url.Parse(spec)
	if err != nil {
		return nil, true, fmt.Errorf("invalid http-proxy egress %q: %w", RedactSpec(spec), ErrUnparseableProxyURL)
	}
	if u.Hostname() == "" {
		return nil, true, fmt.Errorf("invalid http-proxy egress %q: the URL has no host (expected http://host:port or https://host:port)", RedactSpec(spec))
	}
	return u, true, nil
}

// testDialRootCAs is nil in production: an https:// proxy and an https echo are
// verified against the system roots. Only this package's tests set it, so the
// https fences can reach local TLS servers (on macOS the platform verifier
// cannot be pointed at a test CA any other way). It changes the trust anchors
// and nothing else: the TLS config it adds would switch Go's automatic HTTP/2
// off, which is why the http-proxy path sets ForceAttemptHTTP2
// (TestTestDial_RootCASeamKeepsTheProductionHandshake). Same pattern as the
// broker's ManagedLoginEgress.testRootCAs. A test that sets it must not run in
// parallel.
var testDialRootCAs *x509.CertPool

// newProbeTransport is where both TestDial paths start: a timeout and, in
// tests only, the test root CAs. It sets no Proxy field, so the process proxy
// environment is never consulted. The paths then differ in what they
// negotiate: the engine path adds a DialContext, which keeps Go on HTTP/1.1;
// the http-proxy path adds an explicit Proxy and offers HTTP/2 like Go's
// default transport.
func newProbeTransport(timeout time.Duration) *http.Transport {
	t := &http.Transport{TLSHandshakeTimeout: timeout}
	if testDialRootCAs != nil {
		t.TLSClientConfig = &tls.Config{RootCAs: testDialRootCAs}
	}
	return t
}

// probeEcho makes the one GET to echoURL over transport and reads the exit IP
// the echo reports. Both TestDial paths share it, so the request, its timeout
// and the IP extraction cannot drift between them.
func probeEcho(ctx context.Context, transport *http.Transport, engineName, echoURL string, timeout time.Duration) (*TestResult, error) {
	client := &http.Client{Transport: transport, Timeout: timeout}

	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, echoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("bad echo url %q: %w", echoURL, err)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("egress unreachable via %s: %w", engineName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	elapsed := time.Since(start).Milliseconds()

	trimmed := strings.TrimSpace(string(body))
	return &TestResult{
		Engine:     engineName,
		ExitIP:     extractIP(trimmed),
		Body:       trimmed,
		LatencyMs:  elapsed,
		StatusCode: resp.StatusCode,
	}, nil
}

// echoHostPort renders echoURL as the host:port the transport would dial,
// filling in the scheme's default port (url.Host omits it). "" when the URL is
// unparseable — the caller then simply skips the bypass annotation.
func echoHostPort(echoURL string) string {
	u, err := url.Parse(echoURL)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	switch u.Scheme {
	case "https":
		return net.JoinHostPort(u.Hostname(), "443")
	case "http":
		return net.JoinHostPort(u.Hostname(), "80")
	}
	return u.Host
}

// engineClaiming returns the name of the engine that would claim spec, for
// diagnostics — "" if none (BuildDialer will then error).
func engineClaiming(spec string) string {
	for _, e := range engines {
		if e.Claims(spec) {
			return e.Name()
		}
	}
	return ""
}

// extractIP reduces an echo body to a bare IP when possible. Handles a plain IP
// body (most "what's my IP" echoes) and a whitespace/quote-wrapped one; returns
// "" if the body is not a recognizable single IP (caller falls back to Body).
func extractIP(body string) string {
	s := strings.Trim(body, "\"' \t\r\n")
	// A single token that parses as an IP is the common echo shape.
	if net.ParseIP(s) != nil {
		return s
	}
	// Some echoes return "ip=1.2.3.4" or a first-line IP; take the first token
	// that parses as an IP.
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == ' ' || r == '=' || r == ':' || r == ','
	}) {
		if net.ParseIP(f) != nil {
			return f
		}
	}
	return ""
}
