package httpdirect

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

// The core invariant: a control-plane client never routes through the env
// proxy. Set the env vars a real box would carry (Clash on a dev machine, a
// corporate proxy on an enterprise server) and assert the transport still
// resolves to a direct dial.
func TestNewClient_IgnoresEnvProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:7890")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
	t.Setenv("ALL_PROXY", "socks5://127.0.0.1:7891")

	tr, ok := NewClient(5 * time.Second).Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is not *http.Transport")
	}
	if tr.Proxy == nil {
		t.Fatal("Transport.Proxy is nil — a nil func means Go falls back to no proxy by accident, not by design; the override must be consulted")
	}
	for _, target := range []string{"https://master.internal:3000/v1/x", "http://10.0.0.9:8080/health"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		got, err := tr.Proxy(req)
		if err != nil {
			t.Fatalf("%s: proxy func errored: %v", target, err)
		}
		if got != nil {
			t.Fatalf("%s: control-plane call would route through %s", target, got)
		}
	}
}

// The escape hatch: an operator can send control-plane traffic through an
// explicit proxy, and clearing it restores direct.
func TestSetProxyOverride_RoundTrip(t *testing.T) {
	t.Cleanup(func() { _ = SetProxyOverride("") })

	if err := SetProxyOverride("http://10.0.0.5:3128"); err != nil {
		t.Fatalf("set override: %v", err)
	}
	if got := ProxyOverride(); got != "http://10.0.0.5:3128" {
		t.Fatalf("ProxyOverride() = %q", got)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://master.internal:3000/v1/x", nil)
	tr := Transport()
	u, err := tr.Proxy(req)
	if err != nil || u == nil || u.Host != "10.0.0.5:3128" {
		t.Fatalf("override not applied: u=%v err=%v", u, err)
	}

	if err := SetProxyOverride(""); err != nil {
		t.Fatalf("clear override: %v", err)
	}
	if u, _ := tr.Proxy(req); u != nil {
		t.Fatalf("cleared override still routes through %s", u)
	}
	if got := ProxyOverride(); got != "" {
		t.Fatalf("ProxyOverride() after clear = %q", got)
	}
}

// A client built BEFORE the override is set must pick it up — that is the whole
// point of resolving per request, and it is what lets a config reload work
// without rebuilding every client.
func TestOverride_AppliesToPreexistingClient(t *testing.T) {
	t.Cleanup(func() { _ = SetProxyOverride("") })
	tr := NewClient(time.Second).Transport.(*http.Transport)
	req, _ := http.NewRequest(http.MethodGet, "https://master.internal:3000/x", nil)

	if u, _ := tr.Proxy(req); u != nil {
		t.Fatalf("default should be direct, got %s", u)
	}
	if err := SetProxyOverride("socks5://10.0.0.5:1080"); err != nil {
		t.Fatal(err)
	}
	u, _ := tr.Proxy(req)
	if u == nil || u.Scheme != "socks5" {
		t.Fatalf("pre-existing client did not pick up the override: %v", u)
	}
}

// Bad specs are rejected loudly at config time rather than silently ignored —
// a typo'd proxy that degrades to direct looks like a working config until the
// day it is needed.
func TestSetProxyOverride_RejectsBadSpecs(t *testing.T) {
	t.Cleanup(func() { _ = SetProxyOverride("") })
	for _, bad := range []string{
		"10.0.0.5:3128",       // no scheme
		"ftp://10.0.0.5:3128", // unsupported scheme
		"http://10.0.0.5",     // no port
		"http://:3128",        // no host
	} {
		if err := SetProxyOverride(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
	// A rejected spec must not have disturbed the previous value.
	if got := ProxyOverride(); got != "" {
		t.Fatalf("failed set changed state to %q", got)
	}
}

// Credentials in a proxy URL must not leak into logs/status via ProxyOverride.
func TestProxyOverride_RedactsCredentials(t *testing.T) {
	t.Cleanup(func() { _ = SetProxyOverride("") })
	if err := SetProxyOverride("http://user:s3cret@10.0.0.5:3128"); err != nil {
		t.Fatal(err)
	}
	got := ProxyOverride()
	if got == "" || contains(got, "s3cret") {
		t.Fatalf("ProxyOverride() leaked credentials: %q", got)
	}
	if u, _ := url.Parse(got); u == nil || u.Host != "10.0.0.5:3128" {
		t.Fatalf("redacted form lost the host: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// A rejected spec must never surface the credentials it carries. This is the
// path a failed boot logs, so a leak here lands in a file that outlives the
// process. 能红: return fmt.Errorf("%w: %s", ErrInvalidProxyURL, err) from the
// parse branch and the password appears in the message.
func TestSetProxyOverride_ErrorNeverLeaksCredentials(t *testing.T) {
	t.Cleanup(func() { _ = SetProxyOverride("") })
	for _, bad := range []string{
		"http://user:hunter2@10.0.0.5:3128\x7f", // forces url.Parse to fail
		"ht tp://user:hunter2@10.0.0.5:3128",
		"ftp://user:hunter2@10.0.0.5:3128", // valid parse, rejected scheme
		"http://user:hunter2@10.0.0.5",     // valid parse, missing port
	} {
		err := SetProxyOverride(bad)
		if err == nil {
			t.Fatalf("%q was accepted", bad)
		}
		if contains(err.Error(), "hunter2") {
			t.Errorf("error leaked the password for %q: %v", bad, err)
		}
	}
}

// Redact keeps the parts an operator needs (scheme, host, port) and drops the
// part they must not see, and never echoes an unparseable spec back.
func TestRedact(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"http://user:hunter2@10.0.0.5:3128", "http://user:xxxxx@10.0.0.5:3128"},
		{"socks5://10.0.0.5:1080", "socks5://10.0.0.5:1080"},
		{"ht tp://user:hunter2@x", "(unparseable)"},
		{"nonsense", "(unparseable)"},
	} {
		if got := Redact(tc.in); got != tc.want {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if tc.in != "" && contains(Redact(tc.in), "hunter2") {
			t.Errorf("Redact(%q) leaked the password", tc.in)
		}
	}
}
