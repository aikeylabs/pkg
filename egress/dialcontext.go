package egress

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
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
	var closer io.Closer
	if c, ok := d.(io.Closer); ok {
		closer = c
	}
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
