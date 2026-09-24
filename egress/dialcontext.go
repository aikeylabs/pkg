package egress

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	xproxy "golang.org/x/net/proxy"
)

// DialContextFunc is the dial half of an egress chain, in the shape every Go
// HTTP client accepts (net/http Transport.DialContext, tls-client
// WithDialContext, x/net/http2 DialTLSContext wrappers, …).
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// BuildDialContext builds spec through the engine registry (BuildDialer) and
// returns it as a DialContextFunc with the same NO_PROXY/loopback direct-dial
// bypass the data plane applies (aikey-proxy dialerToTransport /
// BuildEgressDialContext): loopback is IPC, not a public egress, and operator
// NO_PROXY declarations must hold regardless of which consumer dials.
//
// Why here and not only in aikey-proxy (2026-08-27, SessionKey 复合出口统一桥接):
// aikey-auth-broker and aikey-control-master both need the identical bridge for
// Session Key exchange, and master deliberately does not import aikey-proxy
// internals. Keeping the bridge next to the registry keeps "spec → dial" a
// single truth source for every consumer.
//
// The closer contract matches BuildDialer's: non-nil for group-backed dialers
// (mihomo proxy-group health probes run in goroutines) and MUST be Closed when
// the caller is done, or those goroutines leak. Errors keep BuildDialer's
// fail-loud contract — a spec no engine claims errors out; nothing here ever
// falls back to a direct dial for a non-bypassed destination.
func BuildDialContext(spec string) (DialContextFunc, io.Closer, error) {
	d, err := BuildDialer(spec)
	if err != nil {
		return nil, nil, err
	}
	closer := dialerCloser(d)
	dial := dialerDialContext(d)
	bypass := noProxyBypass()
	// Mirror the data plane's direct-dial parameters (proxy.dialerToTransport)
	// so a bypassed destination behaves identically on both paths.
	directDial := (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, herr := net.SplitHostPort(addr); herr == nil && bypass(host) {
			return directDial(ctx, network, addr)
		}
		return dial(ctx, network, addr)
	}, closer, nil
}

// BuildEgressOnlyDialContext builds spec through the engine registry and
// returns a dial function that ALWAYS rides the egress: unlike BuildDialContext
// there is no NO_PROXY and no loopback direct-dial bypass. It also returns the
// built dialer itself, so the caller can ask it (EgressBypassesHost) whether a
// fragment's own rules would route a destination DIRECT — the one bypass this
// function cannot remove, because it runs inside the engine.
//
// Why a second builder (DEC-master-central-login-13, 2026-09-24): master-side
// administrator login must leave through the selected egress even when the
// master process's NO_PROXY names a provider host. NO_PROXY exists for
// internal destinations (2026-07-16 option ②); a provider endpoint is not one,
// and silently going direct would sign the account in from master's own IP
// while the audit still says "pool egress". BuildDialContext keeps its bypass
// for every other caller (member Session Key, renewal, the data plane).
//
// Why the dialer is returned (Ruling-9): the caller needs BypassInfo on the SAME
// dialer it dials with. Building a second one to ask would pay a group-backed
// fragment's synchronous health-check warm-up twice (up to ~5s each, not
// cancellable) inside a 22-second login budget.
//
// The closer contract is BuildDialContext's: non-nil for group-backed dialers,
// and it MUST be closed when the caller is done.
func BuildEgressOnlyDialContext(spec string) (DialContextFunc, xproxy.Dialer, io.Closer, error) {
	d, err := BuildDialer(spec)
	if err != nil {
		return nil, nil, nil, err
	}
	return dialerDialContext(d), d, dialerCloser(d), nil
}

// EgressBypassesHost reports whether dialer d would route host DIRECT because
// of its own rules (a mihomo fragment's `rules:` DIRECT exception), and which
// rule decided it. A dialer without rules (built-in socks5 chain, rule-less
// fragment) never bypasses, so the answer is false.
//
// host may be a bare host or host:port; a bare host is asked about port 443
// (fragment rules match on the destination host, never the port).
func EgressBypassesHost(d xproxy.Dialer, host string) (bool, string) {
	reporter, ok := d.(BypassReporter)
	if !ok {
		return false, ""
	}
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(strings.Trim(host, "[]"), "443")
	}
	return reporter.BypassInfo(addr)
}

// NoProxyBypasses reports whether BuildDialContext would dial host direct:
// loopback, or a NO_PROXY / no_proxy match (suffix or CIDR). It is the SAME
// predicate BuildDialContext applies (noProxyBypass), read from the process
// environment at call time — never a second matcher that could drift.
//
// Administrator login uses it to REPORT (not to honour) a provider host that
// NO_PROXY would have sent direct: the login rides the egress anyway and the
// caller logs one WARN naming the host (DEC-master-central-login-13).
//
// host is a bare host or IP literal, as net.SplitHostPort yields it.
func NoProxyBypasses(host string) bool {
	return noProxyBypass()(host)
}

// dialerCloser returns d as an io.Closer when it holds background resources
// (group health checks), nil otherwise.
func dialerCloser(d xproxy.Dialer) io.Closer {
	if c, ok := d.(io.Closer); ok {
		return c
	}
	return nil
}

func dialerDialContext(d xproxy.Dialer) DialContextFunc {
	if cd, ok := d.(xproxy.ContextDialer); ok {
		return cd.DialContext
	}
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
}

// noProxyBypass mirrors aikey-proxy sysproxy.NoProxyBypass: loopback hosts are
// always direct, plus anything matching NO_PROXY/no_proxy (suffix or CIDR),
// delegated to x/net/httpproxy's canon via a sentinel proxy (nil result ⇒
// bypass). Duplicated here rather than imported because pkg/egress must not
// depend on aikey-proxy; both delegate the actual matching to httpproxy, so
// there is no hand-rolled matcher to drift.
func noProxyBypass() func(host string) bool {
	cfg := &httpproxy.Config{
		HTTPProxy:  "http://sentinel.invalid:1",
		HTTPSProxy: "http://sentinel.invalid:1",
		NoProxy:    os.Getenv("NO_PROXY") + "," + os.Getenv("no_proxy"),
	}
	pf := cfg.ProxyFunc()
	return func(host string) bool {
		if host == "" {
			return false
		}
		u, _ := pf(&url.URL{Scheme: "https", Host: host})
		return u == nil
	}
}
