package egress

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// countingListener accepts TCP connections and counts them; connections are
// closed immediately (enough to observe "the chain's first hop was dialed").
func countingListener(t *testing.T) (net.Listener, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, &hits
}

func TestBuildDialContext_UnclaimedSpecFailsLoudly(t *testing.T) {
	// A mihomo fragment in the OSS test build (no multi-protocol engine
	// registered) must error — never fall back to a direct dial.
	if _, _, err := BuildDialContext(`proxies:\n- {name: x}`); err == nil {
		t.Fatal("fragment spec must fail on a build without the multi-protocol engine")
	}
}

func TestBuildDialContext_NonLoopbackRidesTheChain(t *testing.T) {
	hop, hits := countingListener(t)
	dial, closer, err := BuildDialContext("socks5://" + hop.Addr().String())
	if err != nil {
		t.Fatalf("chain spec must build via the builtin engine: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// TEST-NET-3 address: never routable, so a successful direct dial is
	// impossible — any observed hop hit proves the chain path was taken.
	_, _ = dial(ctx, "tcp", "203.0.113.1:80")
	if hits.Load() == 0 {
		t.Fatal("dial to a public address bypassed the egress chain (would leak the node IP)")
	}
}

func TestBuildDialContext_LoopbackBypassesTheChain(t *testing.T) {
	// The chain's hop is a dead port: riding the chain can only fail. A
	// loopback destination must still connect (direct IPC bypass).
	dial, closer, err := BuildDialContext("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatalf("chain spec must build: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	target, hits := countingListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", target.Addr().String())
	if err != nil {
		t.Fatalf("loopback destination must bypass the egress chain and dial direct: %v", err)
	}
	_ = conn.Close()
	// The kernel completes the connect before the listener goroutine accepts
	// and counts it, so wait for the count (TODO-21: 19/300 single-run and 4/15
	// loaded full-package failures came from reading it too early).
	if waitForCount(hits, 1, 2*time.Second) == 0 {
		t.Fatal("loopback listener saw no connection — bypass did not dial direct")
	}
}

// --- master-central-oauth-login tasks 1.2: egress-only builder + shared NO_PROXY verdict ---
//
// spec: R-master-central-login-3.S9 管理员登录只经选定出口，NO_PROXY 命中照走
// DEC-master-central-login-13: administrator login must ride the selected egress
// even for loopback / NO_PROXY destinations, while BuildDialContext (member,
// renewal, data plane) keeps its bypass. These fences pin both halves.

// sentinelDialers maps a test-only spec to the dialer a test wants built for it.
// The engine registry has no Unregister, so ONE dispatcher engine is registered
// per process and each test swaps its own dialer in under its own sentinel spec
// — which also keeps `go test -count=N` correct (a per-test Register would leave
// the first run's engine claiming the spec forever).
var (
	sentinelMu      sync.Mutex
	sentinelDialers = map[string]xproxy.Dialer{}
	sentinelBuilds  = map[string]int{}
	sentinelOnce    sync.Once
)

type sentinelDispatchEngine struct{}

func (sentinelDispatchEngine) Name() string { return "test-sentinel" }

// Claims only the specs a running test has mapped — never the multi-protocol
// probe, so MultiProtocolAvailable stays false for the OSS-shape fences.
func (sentinelDispatchEngine) Claims(spec string) bool {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	_, ok := sentinelDialers[strings.TrimSpace(spec)]
	return ok
}

func (sentinelDispatchEngine) Build(spec string) (xproxy.Dialer, error) {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	key := strings.TrimSpace(spec)
	sentinelBuilds[key]++
	return sentinelDialers[key], nil
}

func useSentinelEngine(t *testing.T, spec string, d xproxy.Dialer) {
	t.Helper()
	sentinelOnce.Do(func() { Register(sentinelDispatchEngine{}) })
	sentinelMu.Lock()
	sentinelDialers[spec] = d
	sentinelBuilds[spec] = 0
	sentinelMu.Unlock()
	t.Cleanup(func() {
		sentinelMu.Lock()
		delete(sentinelDialers, spec)
		delete(sentinelBuilds, spec)
		sentinelMu.Unlock()
	})
}

func sentinelBuildCount(spec string) int {
	sentinelMu.Lock()
	defer sentinelMu.Unlock()
	return sentinelBuilds[spec]
}

// countingEgressDialer stands in for the egress: it records every dial and never
// connects (reaching it IS the assertion; refusing keeps the fence hermetic).
type countingEgressDialer struct{ dials atomic.Int64 }

func (d *countingEgressDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *countingEgressDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	d.dials.Add(1)
	return nil, fmt.Errorf("test egress refused %s (hermetic)", addr)
}

func clearNoProxyEnv(t *testing.T, value string) {
	t.Helper()
	t.Setenv("NO_PROXY", value)
	t.Setenv("no_proxy", value)
}

// waitForCount polls an async accept counter; the accept goroutine may record a
// connection a moment after the dialing side already returned.
func waitForCount(counter *atomic.Int64, want int64, within time.Duration) int64 {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if got := counter.Load(); got >= want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return counter.Load()
}

func TestBuildEgressOnlyDialContext_IgnoresNoProxyAndLoopback(t *testing.T) {
	const spec = "proxies: [test-egress-only-noproxy]"
	target, directHits := countingListener(t) // 127.0.0.1: a direct dial lands here
	host, _, _ := net.SplitHostPort(target.Addr().String())
	clearNoProxyEnv(t, host+",localhost")
	eng := &countingEgressDialer{}
	useSentinelEngine(t, spec, eng)

	// Control: the SAME spec and target under BuildDialContext take the
	// loopback/NO_PROXY direct path. Without this the fence below could pass on
	// a setup that never exercised the bypass at all.
	bypassDial, bypassCloser, err := BuildDialContext(spec)
	if err != nil {
		t.Fatalf("BuildDialContext(sentinel): %v", err)
	}
	if bypassCloser != nil {
		defer bypassCloser.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if c, err := bypassDial(ctx, "tcp", target.Addr().String()); err == nil {
		_ = c.Close()
	}
	cancel()
	if got := waitForCount(directHits, 1, 2*time.Second); got != 1 || eng.dials.Load() != 0 {
		t.Fatalf("control: BuildDialContext must dial NO_PROXY loopback direct (direct=%d egress=%d)", got, eng.dials.Load())
	}

	dial, dialer, closer, err := BuildEgressOnlyDialContext(spec)
	if err != nil {
		t.Fatalf("BuildEgressOnlyDialContext(sentinel): %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	if dialer != xproxy.Dialer(eng) {
		t.Fatalf("returned dialer must be the one the engine built (BypassInfo is asked on it), got %T", dialer)
	}
	if n := sentinelBuildCount(spec); n != 2 {
		t.Fatalf("engine Build calls = %d, want 2 (one per builder call): the egress-only builder must build exactly once", n)
	}
	const requests = 3
	for i := 0; i < requests; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if c, err := dial(ctx, "tcp", target.Addr().String()); err == nil {
			_ = c.Close()
		}
		cancel()
	}
	if got := eng.dials.Load(); got != requests {
		t.Fatalf("egress dials = %d, want %d: a NO_PROXY / loopback destination must still ride the egress", got, requests)
	}
	time.Sleep(100 * time.Millisecond) // give a stray direct connect time to be counted
	if got := directHits.Load(); got != 1 {
		t.Fatalf("direct connections = %d, want only the control's 1: the egress-only dial went direct", got)
	}
}

func TestNoProxyBypasses_SameVerdictAsBuildDialContext(t *testing.T) {
	const spec = "proxies: [test-noproxy-verdict]"
	// TEST-NET-2 (198.51.100.0/24) is never routable, so the CIDR case cannot
	// accidentally reach a real host; *.fixture.test never resolves publicly.
	clearNoProxyEnv(t, ".corp.fixture.test,198.51.100.0/24")
	eng := &countingEgressDialer{}
	useSentinelEngine(t, spec, eng)
	dial, closer, err := BuildDialContext(spec)
	if err != nil {
		t.Fatalf("BuildDialContext(sentinel): %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	for _, tc := range []struct {
		name, host string
		want       bool
	}{
		{"loopback", "127.0.0.1", true},
		{"no_proxy_suffix", "svc.corp.fixture.test", true},
		{"no_proxy_cidr", "198.51.100.7", true},
		{"no_match", "api.provider.fixture.test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := eng.dials.Load()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			if c, err := dial(ctx, "tcp", net.JoinHostPort(tc.host, "443")); err == nil {
				_ = c.Close()
			}
			cancel()
			wentDirect := eng.dials.Load() == before
			if wentDirect != tc.want {
				t.Fatalf("setup: BuildDialContext direct=%t for %s, want %t", wentDirect, tc.host, tc.want)
			}
			if got := NoProxyBypasses(tc.host); got != wentDirect {
				t.Fatalf("NoProxyBypasses(%q) = %t but BuildDialContext direct = %t — two verdicts drifted", tc.host, got, wentDirect)
			}
		})
	}
}

// recordingReporter is a dialer that answers BypassInfo and records the exact
// address it was asked about.
type recordingReporter struct {
	countingEgressDialer
	asked []string
}

func (r *recordingReporter) BypassInfo(addr string) (bool, string) {
	r.asked = append(r.asked, addr)
	return true, "rule-for:" + addr
}

// EgressBypassesHost promises that a bare host is asked about port 443, an
// IPv6 literal gets brackets, host:port passes through, and a dialer without
// rules never bypasses (review m-4). A mihomo ruleRouter answers "not direct"
// for an address it cannot split, so a dropped normalisation would silently let
// a DIRECT-ruled login host through.
func TestEgressBypassesHost_BareHostAndIPv6(t *testing.T) {
	for _, tc := range []struct{ in, asked string }{
		{"api.fixture.test", "api.fixture.test:443"},
		{"[::1]", "[::1]:443"},
		{"::1", "[::1]:443"},
		{"api.fixture.test:8443", "api.fixture.test:8443"},
		{"[::1]:8443", "[::1]:8443"},
	} {
		r := &recordingReporter{}
		bypassed, rule := EgressBypassesHost(r, tc.in)
		if len(r.asked) != 1 || r.asked[0] != tc.asked {
			t.Fatalf("EgressBypassesHost(%q) asked BypassInfo %v, want [%s]", tc.in, r.asked, tc.asked)
		}
		if !bypassed || rule != "rule-for:"+tc.asked {
			t.Fatalf("EgressBypassesHost(%q) = (%t, %q), want the reporter's answer passed through", tc.in, bypassed, rule)
		}
	}
	if bypassed, rule := EgressBypassesHost(&countingEgressDialer{}, "api.fixture.test"); bypassed || rule != "" {
		t.Fatalf("a dialer without BypassReporter must answer (false, \"\"), got (%t, %q)", bypassed, rule)
	}
}
