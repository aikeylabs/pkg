package egress

// testdial_callchain_test.go — characterization of TestDial, one cell per egress
// shape its callers can hand it (master-central-oauth-login task 2.0, step 0;
// DEC-master-central-login-14).
//
// Why this file exists: TestDial is the one "walk through this egress once and
// report the exit IP" probe behind every egress test in the product — master's
// Test egress endpoint, the member egress editor (its test button and its
// save-time re-test), the admin login's start-time exit-IP measurement, and
// aikey-proxy's `aikey doctor` self-check, admin egress-test endpoint and
// probe-ping fallback. The owner approved changing it only on condition that
// these cells were pinned first (2026-09-24). Every expectation is a
// hand-written literal; none is computed by the code under test.
//
// Task 2.0 changed exactly two cells on purpose (TODO-12, the owner's option A):
// "single http:// proxy URL" and "single https:// proxy URL" used to fail with
// "no egress engine handles this proxy spec" without contacting the proxy; they
// are now measured through that proxy. Every other cell is as it was pinned
// before the change and must stay that way.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Fixture names. `.test` is reserved and never resolves, so a request that
// reaches the echo by this name was carried by the egress under test: a direct
// dial would fail DNS. The echo answers a TEST-NET-3 address no real exit has.
const (
	tdEchoHost = "echo.testdial.test"
	tdEchoIP   = "203.0.113.7"
)

// outcome is what TestDial's callers read: the exit IP, the engine, the bypass
// verdict, and on failure the error text. A non-nil errWords means TestDial
// must fail with an error that contains every word.
type outcome struct {
	exitIP, engine, bypassRule string
	bypassed                   bool
	errWords                   []string
}

// observed is one TestDial call reduced to the fields callers read. It is JSON
// so a child process can report it back to the parent test.
type observed struct {
	ExitIP     string `json:"exit_ip"`
	Engine     string `json:"engine"`
	Bypassed   bool   `json:"bypassed"`
	BypassRule string `json:"bypass_rule"`
	Err        string `json:"err"`
}

func observe(t *testing.T, res *TestResult, err error) observed {
	t.Helper()
	if err != nil {
		if res != nil {
			t.Fatalf("TestDial returned a result together with an error (%v); callers read the result only when err is nil", err)
		}
		return observed{Err: err.Error()}
	}
	if res == nil {
		t.Fatal("TestDial returned neither a result nor an error")
	}
	return observed{ExitIP: res.ExitIP, Engine: res.Engine, Bypassed: res.Bypassed, BypassRule: res.BypassRule}
}

func assertOutcome(t *testing.T, got observed, want outcome) {
	t.Helper()
	if want.errWords != nil {
		if got.Err == "" {
			t.Fatalf("TestDial succeeded with %+v, want an error containing %q", got, want.errWords)
		}
		for _, w := range want.errWords {
			if !strings.Contains(got.Err, w) {
				t.Fatalf("TestDial error %q does not contain %q", got.Err, w)
			}
		}
		return
	}
	wantObs := observed{ExitIP: want.exitIP, Engine: want.engine, Bypassed: want.bypassed, BypassRule: want.bypassRule}
	if got != wantObs {
		t.Fatalf("TestDial = %+v, want %+v", got, wantObs)
	}
}

func wantSeen(t *testing.T, who string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s saw %q, want %q", who, got, want)
	}
}

// connStates records the latest state of every connection a test server
// accepted, so a fence can tell whether the prober closed its keep-alive
// connection.
type connStates struct {
	mu   sync.Mutex
	last map[net.Conn]http.ConnState
}

func (c *connStates) track(conn net.Conn, s http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[net.Conn]http.ConnState{}
	}
	c.last[conn] = s
}

// counts reports how many accepted connections are still open, and how many
// were accepted in total.
func (c *connStates) counts() (open, accepted int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, s := range c.last {
		accepted++
		if s != http.StateClosed && s != http.StateHijacked {
			open++
		}
	}
	return open, accepted
}

// ipEcho is the "what's my IP" endpoint a probe reads its exit IP from.
type ipEcho struct {
	srv   *httptest.Server
	conns connStates
}

func startIPEcho(t *testing.T) *ipEcho {
	t.Helper()
	e := &ipEcho{}
	e.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, tdEchoIP)
	}))
	e.srv.Config.ConnState = e.conns.track
	e.srv.Start()
	t.Cleanup(e.srv.Close)
	return e
}

// addr is the echo's real (loopback) listening address.
func (e *ipEcho) addr() string { return e.srv.Listener.Addr().String() }

func (e *ipEcho) port() string {
	_, port, _ := net.SplitHostPort(e.addr())
	return port
}

// hostTarget is the host:port an egress is asked for when the echo is reached
// by its fake name.
func (e *ipEcho) hostTarget() string { return net.JoinHostPort(tdEchoHost, e.port()) }

// urlByName is the echo URL a caller passes: the fake name that only the
// egress under test resolves.
func (e *ipEcho) urlByName() string { return "http://" + e.hostTarget() + "/" }

// recordingHTTPProxy is a forward HTTP proxy that records every request it is
// asked to carry. With relay set it fetches tdEchoHost from 127.0.0.1 (the
// echo); without it, it is a tripwire that answers 502 and relays nothing.
// Every echo URL in these fences is http://, so only absolute-form requests
// need relaying; a CONNECT is recorded and refused.
type recordingHTTPProxy struct {
	srv   *httptest.Server
	conns connStates
	relay bool

	mu      sync.Mutex
	targets []string
	auths   []string
}

func startRecordingHTTPProxy(t *testing.T, relay bool) *recordingHTTPProxy {
	t.Helper()
	return startRecordingProxy(t, relay, false)
}

// startRecordingHTTPSProxy is the same proxy behind TLS: the client speaks TLS
// to the proxy itself, which is what an https:// proxy URL means in net/http.
func startRecordingHTTPSProxy(t *testing.T, relay bool) *recordingHTTPProxy {
	t.Helper()
	return startRecordingProxy(t, relay, true)
}

func startRecordingProxy(t *testing.T, relay, useTLS bool) *recordingHTTPProxy {
	t.Helper()
	p := &recordingHTTPProxy{relay: relay}
	p.srv = httptest.NewUnstartedServer(p)
	p.srv.Config.ConnState = p.conns.track
	if useTLS {
		p.srv.StartTLS()
	} else {
		p.srv.Start()
	}
	t.Cleanup(p.srv.Close)
	return p
}

// url is the proxy's own URL: http://127.0.0.1:port or https://127.0.0.1:port.
func (p *recordingHTTPProxy) url() string { return p.srv.URL }

func (p *recordingHTTPProxy) addr() string { return p.srv.Listener.Addr().String() }

func (p *recordingHTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Host
	if r.Method == http.MethodConnect {
		target = r.Host
	}
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.auths = append(p.auths, r.Header.Get("Proxy-Authorization"))
	p.mu.Unlock()
	if !p.relay || r.Method == http.MethodConnect || r.URL.Hostname() != tdEchoHost {
		http.Error(w, "recording proxy: not relayed", http.StatusBadGateway)
		return
	}
	port := r.URL.Port()
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	// No Proxy field: the relay must never follow the developer's own proxy
	// environment, and it dials the echo by address, not by the fake name.
	relay := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}
	defer relay.CloseIdleConnections()
	resp, err := relay.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *recordingHTTPProxy) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *recordingHTTPProxy) proxyAuthorizations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.auths...)
}

// redirectDialer stands in for a multi-protocol egress built by a test engine:
// it records every destination it is asked for and connects to one fixed
// loopback address (the echo) whatever the name, so the fake echo host is
// reachable only by riding this dialer.
type redirectDialer struct {
	to string

	mu      sync.Mutex
	targets []string
}

func (d *redirectDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *redirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.mu.Lock()
	d.targets = append(d.targets, addr)
	d.mu.Unlock()
	var nd net.Dialer
	return nd.DialContext(ctx, network, d.to)
}

func (d *redirectDialer) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.targets...)
}

// ruleRedirectDialer adds a fragment's DIRECT rule on top: like the mihomo rule
// router, it answers BypassInfo "DIRECT" for any destination under suffix.
type ruleRedirectDialer struct {
	redirectDialer
	suffix, rule string

	askMu sync.Mutex
	asked []string
}

func (d *ruleRedirectDialer) BypassInfo(addr string) (bool, string) {
	d.askMu.Lock()
	d.asked = append(d.asked, addr)
	d.askMu.Unlock()
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !strings.HasSuffix(host, d.suffix) {
		return false, ""
	}
	return true, d.rule
}

func (d *ruleRedirectDialer) askedAbout() []string {
	d.askMu.Lock()
	defer d.askMu.Unlock()
	return append([]string(nil), d.asked...)
}

func TestTestDial_CallChainShapes(t *testing.T) {
	type arranged struct {
		spec, echoURL string
		// saw checks what the egress under test was asked to reach.
		saw func(t *testing.T)
	}
	resolveEcho := map[string]string{tdEchoHost: "127.0.0.1"}
	for _, tc := range []struct {
		name    string
		arrange func(t *testing.T, echo *ipEcho) arranged
		want    outcome
	}{
		{
			// Reaches TestDial from every caller chain (account / pool egress,
			// control-plane upstream proxy, node upstream, per-account egress).
			name: "socks5 single hop",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				hop := startMiniSocks5(t, resolveEcho)
				return arranged{"socks5://" + hop.addr(), echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "socks5 hop", hop.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "builtin-socks5"},
		},
		{
			name: "socks5 chain",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				entry := startMiniSocks5(t, nil)
				exit := startMiniSocks5(t, resolveEcho)
				return arranged{"socks5://" + entry.addr() + ",socks5://" + exit.addr(), echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "entry hop", entry.seen(), exit.addr())
					wantSeen(t, "exit hop", exit.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "builtin-socks5"},
		},
		{
			// Stands in for the mihomo engine, which this module cannot link.
			name: "fragment built by a multi-protocol engine",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				const spec = "proxies:\n  - {name: callchain-exit, type: ss, server: 198.51.100.2, port: 8388}"
				d := &redirectDialer{to: echo.addr()}
				useSentinelEngine(t, spec, d)
				return arranged{spec, echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "engine dialer", d.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "test-sentinel"},
		},
		{
			// TestResult.Bypassed: the IP is the prober's own, not the egress's.
			name: "fragment DIRECT rule matches the echo host",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				const spec = "rules:\n  - DOMAIN-SUFFIX,testdial.test,DIRECT\nproxies:\n  - {name: callchain-exit, type: ss, server: 198.51.100.2, port: 8388}"
				d := &ruleRedirectDialer{redirectDialer: redirectDialer{to: echo.addr()}, suffix: ".testdial.test", rule: "DOMAIN-SUFFIX,testdial.test,DIRECT"}
				useSentinelEngine(t, spec, d)
				return arranged{spec, echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "BypassInfo", d.askedAbout(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "test-sentinel", bypassed: true, bypassRule: "DOMAIN-SUFFIX,testdial.test,DIRECT"},
		},
		{
			// The rule router splits host:port; an echo URL without a port must
			// be asked about with the scheme's default port.
			name: "fragment DIRECT rule, echo URL without a port",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				const spec = "rules:\n  - DOMAIN-SUFFIX,testdial.test,DIRECT\nproxies:\n  - {name: callchain-exit-noport, type: ss, server: 198.51.100.2, port: 8388}"
				d := &ruleRedirectDialer{redirectDialer: redirectDialer{to: echo.addr()}, suffix: ".testdial.test", rule: "DOMAIN-SUFFIX,testdial.test,DIRECT"}
				useSentinelEngine(t, spec, d)
				return arranged{spec, "http://" + tdEchoHost + "/", func(t *testing.T) {
					wantSeen(t, "BypassInfo", d.askedAbout(), "echo.testdial.test:80")
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "test-sentinel", bypassed: true, bypassRule: "DOMAIN-SUFFIX,testdial.test,DIRECT"},
		},
		{
			// Negative control for the two rows above: the verdict comes from the
			// rule's answer, not from the dialer merely having rules.
			name: "fragment rule that does not match the echo host",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				const spec = "rules:\n  - DOMAIN-SUFFIX,other.test,DIRECT\nproxies:\n  - {name: callchain-exit-other, type: ss, server: 198.51.100.2, port: 8388}"
				d := &ruleRedirectDialer{redirectDialer: redirectDialer{to: echo.addr()}, suffix: ".other.test", rule: "DOMAIN-SUFFIX,other.test,DIRECT"}
				useSentinelEngine(t, spec, d)
				return arranged{spec, echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "BypassInfo", d.askedAbout(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "test-sentinel"},
		},
		{
			// An internal echo (AIKEY_EGRESS_TEST_ECHO) can be loopback; the probe
			// still rides the egress (no loopback bypass).
			name: "echo on loopback still rides the egress",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				hop := startMiniSocks5(t, nil)
				return arranged{"socks5://" + hop.addr(), "http://" + echo.addr() + "/", func(t *testing.T) {
					wantSeen(t, "socks5 hop", hop.seen(), echo.addr())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "builtin-socks5"},
		},
		{
			// NO_PROXY is read fresh on every build by the bypassing builder
			// (BuildDialContext), so an in-process setting is enough to catch a
			// switch to it. HTTP(S)_PROXY needs a fresh process — see
			// TestTestDial_IgnoresProcessProxyEnvironment.
			name: "NO_PROXY naming the echo host is not honoured",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				t.Setenv("NO_PROXY", tdEchoHost)
				t.Setenv("no_proxy", tdEchoHost)
				hop := startMiniSocks5(t, resolveEcho)
				return arranged{"socks5://" + hop.addr(), echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "socks5 hop", hop.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "builtin-socks5"},
		},
		{
			name: "egress unreachable",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				return arranged{"socks5://127.0.0.1:1", echo.urlByName(), nil}
			},
			want: outcome{errWords: []string{"egress unreachable via builtin-socks5"}},
		},
		{
			name: "malformed: socks5 hop without a port",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				return arranged{"socks5://127.0.0.1", echo.urlByName(), nil}
			},
			want: outcome{errWords: []string{"not a dialable host:port"}},
		},
		{
			name: "malformed: a scheme no engine claims",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				return arranged{"ftp://proxy.testdial.test:21", echo.urlByName(), nil}
			},
			want: outcome{errWords: []string{"no egress engine handles this proxy spec"}},
		},
		{
			name: "malformed: whitespace only",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				return arranged{"   ", echo.urlByName(), nil}
			},
			want: outcome{errWords: []string{"empty egress spec"}},
		},
		{
			// Trial and the open-source build link no multi-protocol engine.
			name: "fragment on a build without the multi-protocol engine",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				return arranged{"proxies:\n  - {name: callchain-unclaimed, type: ss, server: 198.51.100.3, port: 8388}", echo.urlByName(), nil}
			},
			want: outcome{errWords: []string{"no egress engine handles this proxy spec", "offline enterprise package"}},
		},
		{
			// Control-plane upstream proxy (Nodes page) and admin login when it
			// falls back to it. Changed by task 2.0: before it, no engine claimed
			// this shape and the proxy was never contacted.
			name: "single http:// proxy URL",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				p := startRecordingHTTPProxy(t, true)
				return arranged{p.url(), echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "http proxy", p.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "http-proxy"},
		},
		{
			name: "single https:// proxy URL",
			arrange: func(t *testing.T, echo *ipEcho) arranged {
				p := startRecordingHTTPSProxy(t, true)
				trustTestServer(t, p.srv)
				return arranged{p.url(), echo.urlByName(), func(t *testing.T) {
					wantSeen(t, "https proxy", p.seen(), echo.hostTarget())
				}}
			},
			want: outcome{exitIP: "203.0.113.7", engine: "http-proxy"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			echo := startIPEcho(t)
			a := tc.arrange(t, echo)
			res, err := TestDial(context.Background(), a.spec, a.echoURL, 5*time.Second)
			assertOutcome(t, observe(t, res, err), tc.want)
			if a.saw != nil {
				a.saw(t)
			}
		})
	}
}

// Child-process mode. net/http reads HTTP(S)_PROXY once per process
// (http.ProxyFromEnvironment caches it on first use), so an in-process
// t.Setenv cannot prove TestDial ignores the proxy environment: whichever
// earlier test first used a default transport would decide the answer. A child
// of this same test binary starts with the environment already set. Same
// approach as the broker's TestManagedLoginEgress_LeavesProcessDefaultTransportAlone.
const (
	tdChildRoleEnv = "AIKEY_PKG_EGRESS_TESTDIAL_CHILD"
	tdChildSpecEnv = "AIKEY_PKG_EGRESS_TESTDIAL_SPEC"
	tdChildEchoEnv = "AIKEY_PKG_EGRESS_TESTDIAL_ECHO"
	tdChildMarker  = "TESTDIAL-CHILD-OBSERVED "
)

var tdProxyEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// proxyEnvPointingAt sets every proxy variable except NO_PROXY to proxyURL, so
// any code path that consults the environment is routed to that proxy.
func proxyEnvPointingAt(proxyURL string) map[string]string {
	env := map[string]string{}
	for _, k := range tdProxyEnvKeys {
		if strings.ToUpper(k) != "NO_PROXY" {
			env[k] = proxyURL
		}
	}
	return env
}

// runTestDialChildIfRequested is the child half: when this process is the
// child it dials once with the spec and echo it was handed, prints what it
// observed, and reports true so the calling test returns immediately.
func runTestDialChildIfRequested(t *testing.T) bool {
	t.Helper()
	if os.Getenv(tdChildRoleEnv) != "1" {
		return false
	}
	res, err := TestDial(context.Background(), os.Getenv(tdChildSpecEnv), os.Getenv(tdChildEchoEnv), 5*time.Second)
	b, merr := json.Marshal(observe(t, res, err))
	if merr != nil {
		t.Fatalf("child: encode result: %v", merr)
	}
	fmt.Println(tdChildMarker + string(b))
	return true
}

// testDialInFreshProcess re-runs the calling top-level test in a child process
// whose proxy variables are exactly proxyEnv from process start, and returns
// what the child's TestDial call observed.
func testDialInFreshProcess(t *testing.T, proxyEnv map[string]string, spec, echoURL string) observed {
	t.Helper()
	env := make([]string, 0, len(os.Environ())+len(proxyEnv)+3)
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(tdProxyEnvKeys, key) {
			env = append(env, kv)
		}
	}
	for k, v := range proxyEnv {
		env = append(env, k+"="+v)
	}
	env = append(env, tdChildRoleEnv+"=1", tdChildSpecEnv+"="+spec, tdChildEchoEnv+"="+echoURL)

	// Bounded by this test's own deadline so a hung child cannot outlive it.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if deadline, ok := t.Deadline(); ok {
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	// The run pattern comes from the test's own name, so a rename cannot make
	// the child run zero tests; a missing result line is a failure below.
	top, _, _ := strings.Cut(t.Name(), "/")
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+top+"$", "-test.count=1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child process failed: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if rest, ok := strings.CutPrefix(line, tdChildMarker); ok {
			var got observed
			if err := json.Unmarshal([]byte(rest), &got); err != nil {
				t.Fatalf("child result %q: %v", rest, err)
			}
			return got
		}
	}
	t.Fatalf("child process printed no result line:\n%s", out)
	return observed{}
}

func TestTestDial_IgnoresProcessProxyEnvironment(t *testing.T) {
	if runTestDialChildIfRequested(t) {
		return
	}
	echo := startIPEcho(t)
	hop := startMiniSocks5(t, map[string]string{tdEchoHost: "127.0.0.1"})
	envProxy := startRecordingHTTPProxy(t, false)

	got := testDialInFreshProcess(t, proxyEnvPointingAt(envProxy.url()), "socks5://"+hop.addr(), echo.urlByName())

	assertOutcome(t, got, outcome{exitIP: "203.0.113.7", engine: "builtin-socks5"})
	wantSeen(t, "socks5 hop", hop.seen(), echo.hostTarget())
	wantSeen(t, "process-environment proxy", envProxy.seen())
}
