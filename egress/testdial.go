// testdial.go — shared egress connectivity probe (§ egress connectivity test).
//
// TestDial builds the egress chain through the SAME engine registry the proxy
// dials with (BuildDialer), then makes one real HTTP GET to an IP-echo endpoint
// THROUGH that chain and reports the observed exit IP + latency. It is the single
// source of truth for "is this egress reachable and what IP does it exit from",
// reused by the proxy's diagnostics and the master console's per-account "test"
// button — so a green test exercises the real dial path, not a re-implementation.
//
// It performs a network dial to a caller-supplied echo host; callers gate who may
// trigger it (the master endpoint is admin-only).
package egress

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// TestResult is the outcome of a single egress connectivity probe.
type TestResult struct {
	// Engine that claimed the spec (e.g. "builtin-socks5" or "mihomo").
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
}

// TestDial resolves spec through the engine registry, dials echoURL through it,
// and returns the observed exit IP + latency. A non-nil error means the chain
// could not be built or the echo could not be reached through it (i.e. the egress
// is not usable) — the actionable reason is in the error.
func TestDial(ctx context.Context, spec, echoURL string, timeout time.Duration) (*TestResult, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty egress spec")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	engineName := engineClaiming(spec)
	dialer, err := BuildDialer(spec)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if cd, ok := dialer.(interface {
				DialContext(context.Context, string, string) (net.Conn, error)
			}); ok {
				return cd.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: timeout,
	}
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
