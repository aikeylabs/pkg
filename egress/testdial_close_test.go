package egress

// testdial_close_test.go — fences for what task 2.0 changes in TestDial
// (master-central-oauth-login, DEC-master-central-login-14; bugfix
// workflow/CI/bugfix/2026-09-24-testdial-single-http-proxy-and-dialer-leak.md):
//
//   - TestDial closes what it builds: a closable dialer (a mihomo proxy-group
//     dialer runs health-check goroutines until Close) and the transport's idle
//     keep-alive connections;
//   - a single http:// or https:// proxy URL is measured through that explicit
//     proxy (Engine "http-proxy"), never through the process proxy environment;
//   - errors on that path never echo the proxy credentials;
//   - the http branch wins over an engine that claims the same URL (mihomo
//     claims every non-socks5 URL), the caller's ctx stops either branch,
//     both shape guards hold, and the production default shape (CONNECT to an
//     https echo, credentials on the CONNECT) works — review-2.0 I1, m1, m4, m2;
//   - the test root CAs do not change the handshake (review-2.0 m3), and the
//     engine path never offers HTTP/2 (review-2.0 D1, task 2.6).
//
// The fixtures (ipEcho, recordingHTTPProxy, redirectDialer, the child-process
// helpers) live in testdial_callchain_test.go.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Made-up proxy credentials; they must never appear in an error.
const (
	fixtureProxyUser = "fixture-user-5e1d"
	fixtureProxyPass = "FIXTURE-PASS-5e1d"
)

// closeCountingDialer is a closable test-engine dialer, the shape of a mihomo
// proxy-group dialer. It refuses to dial once closed, so a Close that came
// before the probe finished would fail the probe instead of passing unnoticed.
type closeCountingDialer struct {
	redirectDialer
	closes atomic.Int64
}

func (d *closeCountingDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *closeCountingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.closes.Load() > 0 {
		return nil, errors.New("test dialer: dial after Close")
	}
	return d.redirectDialer.DialContext(ctx, network, addr)
}

func (d *closeCountingDialer) Close() error {
	d.closes.Add(1)
	return nil
}

func TestTestDial_ClosesCloserDialer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    string
		dead    bool // the egress refuses every connection
		wantErr bool
	}{
		{"probe succeeds", "proxies:\n  - {name: close-ok, type: ss, server: 198.51.100.5, port: 8388}", false, false},
		{"egress refuses the connection", "proxies:\n  - {name: close-dead, type: ss, server: 198.51.100.5, port: 8388}", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echo := startIPEcho(t)
			to := echo.addr()
			if tc.dead {
				to = "127.0.0.1:1"
			}
			d := &closeCountingDialer{redirectDialer: redirectDialer{to: to}}
			useSentinelEngine(t, tc.spec, d)

			_, err := TestDial(context.Background(), tc.spec, echo.urlByName(), 5*time.Second)
			if (err != nil) != tc.wantErr {
				t.Fatalf("TestDial error = %v, want an error: %t", err, tc.wantErr)
			}
			if n := d.closes.Load(); n != 1 {
				t.Fatalf("the closable dialer was closed %d times, want exactly 1: a proxy-group dialer leaks its health-check goroutines until Close", n)
			}
		})
	}
}

func TestTestDial_ClosesIdleConnections(t *testing.T) {
	t.Run("engine egress", func(t *testing.T) {
		echo := startIPEcho(t)
		const spec = "proxies:\n  - {name: idle-conns, type: ss, server: 198.51.100.6, port: 8388}"
		useSentinelEngine(t, spec, &redirectDialer{to: echo.addr()})
		if _, err := TestDial(context.Background(), spec, echo.urlByName(), 5*time.Second); err != nil {
			t.Fatalf("TestDial: %v", err)
		}
		// Nothing relays in between, so the echo's connection IS the prober's
		// keep-alive connection: it closes only when the prober closes it.
		wantAllClosed(t, "echo", &echo.conns)
	})
	t.Run("single http proxy", func(t *testing.T) {
		echo := startIPEcho(t)
		p := startRecordingHTTPProxy(t, true)
		if _, err := TestDial(context.Background(), p.url(), echo.urlByName(), 5*time.Second); err != nil {
			t.Fatalf("TestDial: %v", err)
		}
		wantAllClosed(t, "http proxy", &p.conns)
	})
}

// wantAllClosed waits briefly for the server to see the prober close its
// keep-alive connections. A keep-alive connection nobody closes stays open
// for good (the probe's transport sets no IdleConnTimeout), so a leak ends
// this wait red rather than flaky.
func wantAllClosed(t *testing.T, who string, c *connStates) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		open, accepted := c.counts()
		if accepted == 0 {
			t.Fatalf("%s accepted no connection; the fence exercised nothing", who)
		}
		if open == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still has %d of %d connections open after TestDial returned: the probe's idle keep-alive connections were not closed", who, open, accepted)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// trustTestServer lets TestDial verify a local TLS server's certificate (a
// proxy or an echo) for the rest of the test.
func trustTestServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	previous := testDialRootCAs
	testDialRootCAs = pool
	t.Cleanup(func() { testDialRootCAs = previous })
}

func TestTestDial_SingleHTTPProxyMeasuresThroughProxy(t *testing.T) {
	if runTestDialChildIfRequested(t) {
		return
	}
	t.Run("http:// proxy with credentials", func(t *testing.T) {
		echo := startIPEcho(t)
		p := startRecordingHTTPProxy(t, true)
		spec := "http://" + fixtureProxyUser + ":" + fixtureProxyPass + "@" + p.addr()

		res, err := TestDial(context.Background(), spec, echo.urlByName(), 5*time.Second)

		assertOutcome(t, observe(t, res, err), outcome{exitIP: "203.0.113.7", engine: "http-proxy"})
		wantSeen(t, "http proxy", p.seen(), echo.hostTarget())
		// An authenticated company proxy only works if the URL's credentials
		// are presented to it.
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(fixtureProxyUser+":"+fixtureProxyPass))
		if got := p.proxyAuthorizations(); len(got) != 1 || got[0] != wantAuth {
			t.Fatalf("http proxy got %d requests; Proxy-Authorization carries the URL's credentials: %t", len(got), len(got) == 1 && got[0] == wantAuth)
		}
	})
	t.Run("https:// proxy (TLS to the proxy)", func(t *testing.T) {
		echo := startIPEcho(t)
		p := startRecordingHTTPSProxy(t, true)
		trustTestServer(t, p.srv)

		res, err := TestDial(context.Background(), p.url(), echo.urlByName(), 5*time.Second)

		assertOutcome(t, observe(t, res, err), outcome{exitIP: "203.0.113.7", engine: "http-proxy"})
		wantSeen(t, "https proxy", p.seen(), echo.hostTarget())
	})
	t.Run("the process proxy environment is never read", func(t *testing.T) {
		echo := startIPEcho(t)
		p := startRecordingHTTPProxy(t, true)
		envProxy := startRecordingHTTPProxy(t, false)

		got := testDialInFreshProcess(t, proxyEnvPointingAt(envProxy.url()), p.url(), echo.urlByName())

		assertOutcome(t, got, outcome{exitIP: "203.0.113.7", engine: "http-proxy"})
		wantSeen(t, "explicit http proxy", p.seen(), echo.hostTarget())
		wantSeen(t, "process-environment proxy", envProxy.seen())
	})
}

func TestTestDial_SingleHTTPProxyErrorNeverEchoesCredentials(t *testing.T) {
	echo := startIPEcho(t)
	creds := fixtureProxyUser + ":" + fixtureProxyPass
	for _, tc := range []struct{ name, spec string }{
		// url.Parse's own error quotes the whole raw URL, credentials included.
		{"space in the host", "http://" + creds + "@proxy host.testdial.test:3128"},
		// Without '@' the password is parsed as the port, so even the error
		// url.Parse wraps quotes it.
		{"no @, the password lands in the port", "http://" + creds},
		{"unclosed IPv6 bracket", "https://" + creds + "@[::1:3128"},
		{"no host", "http://" + creds + "@:3128"},
		{"http proxy refuses the connection", "http://" + creds + "@127.0.0.1:1"},
		{"https proxy refuses the connection", "https://" + creds + "@127.0.0.1:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := TestDial(context.Background(), tc.spec, echo.urlByName(), 2*time.Second)
			if err == nil {
				t.Fatalf("TestDial succeeded with %+v, want an error", res)
			}
			msg := err.Error()
			if strings.Contains(msg, fixtureProxyPass) || strings.Contains(msg, fixtureProxyUser) {
				t.Fatal("the error carries the proxy credentials (text withheld from the test log on purpose)")
			}
			// The error must come from the http-proxy path under test; an error
			// from any other path would pass the check above without testing it.
			if !strings.Contains(msg, "http-proxy") {
				t.Fatalf("error %q does not come from the http-proxy path", msg)
			}
		})
	}
}

// Review-2.0 I1. mihomo's Claims takes every non-socks5 URL, a single http://
// included, and then fails to parse it as a fragment. The fix therefore works
// in the Production and Cluster builds only because the http branch runs
// BEFORE the engine registry; no other fence tells the two orders apart. The
// test engine claims exactly this URL to stand in for mihomo.
func TestTestDial_SingleHTTPWinsOverAClaimingEngine(t *testing.T) {
	echo := startIPEcho(t)
	p := startRecordingHTTPProxy(t, true)
	useSentinelEngine(t, p.url(), &countingEgressDialer{})

	res, err := TestDial(context.Background(), p.url(), echo.urlByName(), 5*time.Second)

	assertOutcome(t, observe(t, res, err), outcome{exitIP: "203.0.113.7", engine: "http-proxy"})
	if n := sentinelBuildCount(p.url()); n != 0 {
		t.Fatalf("the engine claiming the URL was built %d times, want 0: the http branch must run before the registry", n)
	}
}

// Review-2.0 m1. `aikey doctor` bounds the whole self-check with a budget ctx
// and waits for every probe, so a probe that ignores its caller's ctx stretches
// the command to the per-probe timeout.
func TestTestDial_CallerCtxStopsTheProbe(t *testing.T) {
	stall := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	})
	for _, branch := range []string{"engine", "http-proxy"} {
		t.Run(branch, func(t *testing.T) {
			echo := &ipEcho{}
			echo.srv = httptest.NewServer(stall)
			t.Cleanup(echo.srv.Close)
			spec := "proxies:\n  - {name: ctx-stop, type: ss, server: 198.51.100.9, port: 8388}"
			if branch == "engine" {
				useSentinelEngine(t, spec, &redirectDialer{to: echo.addr()})
			} else {
				spec = startRecordingHTTPProxy(t, true).url()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			start := time.Now()
			_, err := TestDial(ctx, spec, echo.urlByName(), 10*time.Second)

			if elapsed := time.Since(start); err == nil || elapsed > 2*time.Second {
				t.Fatalf("TestDial returned after %v with err=%v; want an error within 2s of the caller's 100ms deadline", elapsed, err)
			}
		})
	}
}

// Review-2.0 m4. The two guards that decide "is this a single http(s) proxy
// URL": a URL without a host must be refused before any dial (otherwise the
// transport dials this machine's own :3128), and an http-first CHAIN is not a
// single URL, so it stays on the engine registry.
func TestTestDial_SingleHTTPShapeGuards(t *testing.T) {
	echo := startIPEcho(t)

	_, err := TestDial(context.Background(), "http://:3128", echo.urlByName(), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "the URL has no host") {
		t.Fatalf("no-host URL: err=%v, want the fixed no-host message", err)
	}

	_, err = TestDial(context.Background(), "http://127.0.0.1:1,socks5://127.0.0.1:2", echo.urlByName(), 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no egress engine handles this proxy spec") {
		t.Fatalf("http-first chain: err=%v, want the registry's no-engine error", err)
	}
}

// Review-2.0 m2. The production default: the echo is https (api.ipify.org),
// so an http proxy is asked to CONNECT, the probe speaks TLS to the echo inside
// the tunnel, and the proxy's credentials must ride on the CONNECT. The
// recording proxy refuses CONNECT on purpose (every other fence uses an http://
// echo), so this fence brings its own tunnelling proxy.
func TestTestDial_HTTPProxyConnectToHTTPSEcho(t *testing.T) {
	echo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, tdEchoIP)
	}))
	t.Cleanup(echo.Close)
	_, echoPort, _ := net.SplitHostPort(echo.Listener.Addr().String())
	trustTestServer(t, echo)

	var mu sync.Mutex
	var requests, auths []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.Host)
		auths = append(auths, r.Header.Get("Proxy-Authorization"))
		mu.Unlock()
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusBadGateway)
			return
		}
		// The client never resolves the echo's name; the proxy dials loopback.
		up, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", echoPort))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		c, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			_ = up.Close()
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
		go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
		_, _ = io.Copy(c, up)
		_ = c.Close()
	}))
	t.Cleanup(proxy.Close)

	// example.com is a name httptest's certificate covers.
	spec := "http://" + fixtureProxyUser + ":" + fixtureProxyPass + "@" + proxy.Listener.Addr().String()
	res, err := TestDial(context.Background(), spec, "https://example.com:"+echoPort+"/", 5*time.Second)

	assertOutcome(t, observe(t, res, err), outcome{exitIP: "203.0.113.7", engine: "http-proxy"})
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(fixtureProxyUser+":"+fixtureProxyPass))
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 || requests[0] != "CONNECT example.com:"+echoPort || auths[0] != wantAuth {
		t.Fatalf("proxy saw %q; Proxy-Authorization on the CONNECT carries the URL's credentials: %t", requests, len(auths) == 1 && auths[0] == wantAuth)
	}
}

// Review-2.0 m3. testDialRootCAs exists only so fences can trust local TLS
// servers; it must not change what TestDial offers them. The TLS config it
// adds would switch Go's automatic HTTP/2 off, so without the http-proxy
// path's ForceAttemptHTTP2 the https fences would run a handshake production
// never makes. Production is observed directly: with the system roots the
// handshake fails on the test certificate, but only after the proxy has read
// the ClientHello.
func TestTestDial_RootCASeamKeepsTheProductionHandshake(t *testing.T) {
	echo := startIPEcho(t)
	var mu sync.Mutex
	var offered [][]string
	p := &recordingHTTPProxy{relay: true}
	p.srv = httptest.NewUnstartedServer(p)
	p.srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		offered = append(offered, slices.Clone(hello.SupportedProtos))
		mu.Unlock()
		return nil, nil
	}}
	// The production half fails the handshake on purpose; keep the server's
	// "TLS handshake error" line out of the test output.
	p.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	p.srv.StartTLS()
	t.Cleanup(p.srv.Close)

	if _, err := TestDial(context.Background(), p.url(), echo.urlByName(), 5*time.Second); err == nil {
		t.Fatal("with the system roots the test certificate must be rejected; the production half observed nothing")
	}
	trustTestServer(t, p.srv)
	if _, err := TestDial(context.Background(), p.url(), echo.urlByName(), 5*time.Second); err != nil {
		t.Fatalf("with the test root CAs: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(offered) != 2 || !slices.Equal(offered[0], offered[1]) {
		t.Fatalf("ALPN offered to the https proxy: %q (system roots first, test root CAs second); want two identical offers", offered)
	}
	t.Logf("ALPN offered to an https proxy, production and fences alike: %q", offered[0])
}

// Review-2.0 D1 (task 2.6). The engine path dials with a custom DialContext,
// which keeps Go on HTTP/1.1. The http-proxy path's ForceAttemptHTTP2 must not
// spread to it: in production that would change what every socks5 and fragment
// probe negotiates with the echo. Observed at an https echo as the ALPN in the
// ClientHello, once with the system roots (production: the handshake fails on
// the test certificate, after the echo has read the ClientHello) and once with
// the test root CAs.
func TestTestDial_EngineBranchStaysOnHTTP1(t *testing.T) {
	var mu sync.Mutex
	var offered [][]string
	echo := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, tdEchoIP)
	}))
	echo.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		offered = append(offered, slices.Clone(hello.SupportedProtos))
		mu.Unlock()
		return nil, nil
	}}
	// The production half fails the handshake on purpose; keep the server's
	// "TLS handshake error" line out of the test output.
	echo.Config.ErrorLog = log.New(io.Discard, "", 0)
	echo.StartTLS()
	t.Cleanup(echo.Close)
	_, port, _ := net.SplitHostPort(echo.Listener.Addr().String())
	const spec = "proxies:\n  - {name: stays-on-http1, type: ss, server: 198.51.100.8, port: 8388}"
	useSentinelEngine(t, spec, &redirectDialer{to: echo.Listener.Addr().String()})
	// example.com is a name httptest's certificate covers; the redirect dialer
	// reaches the echo whatever the name.
	echoURL := "https://example.com:" + port + "/"

	if _, err := TestDial(context.Background(), spec, echoURL, 5*time.Second); err == nil {
		t.Fatal("with the system roots the test certificate must be rejected; the production half observed nothing")
	}
	trustTestServer(t, echo)
	res, err := TestDial(context.Background(), spec, echoURL, 5*time.Second)
	assertOutcome(t, observe(t, res, err), outcome{exitIP: "203.0.113.7", engine: "test-sentinel"})

	mu.Lock()
	defer mu.Unlock()
	if len(offered) != 2 {
		t.Fatalf("the echo saw %d ClientHellos, want 2 (system roots, then test root CAs)", len(offered))
	}
	for i, protos := range offered {
		if slices.Contains(protos, "h2") {
			t.Fatalf("handshake %d: the engine path offered %q; it must stay on HTTP/1.1", i+1, protos)
		}
	}
}
