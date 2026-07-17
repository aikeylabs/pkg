package egress

import "testing"

// The built-in engine claims socks5-only chains and declines anything with a
// non-socks5 hop or a config-fragment shape (those fall to the mihomo engine,
// present only in the offline enterprise build). The dialing integration tests
// live in aikey-proxy (they need the shared socks5 test rig in internal/
// egresstest, which this standalone module cannot import); here we cover the
// pure spec-shape logic.
func TestBuiltinEngine_Claims(t *testing.T) {
	e := builtinEgressEngine{}
	claims := map[string]bool{
		"socks5://a:1080":                    true,
		"socks5://a:1080,socks5://b:1080":    true,
		" socks5://a:1080 , socks5://b:1080": true,
		"ss://rc4-md5:pw@h:8002":             false,
		"socks5://a:1080,ss://b:8002":        false, // mixed → mihomo
		`{"proxies":[]}`:                     false,
		"":                                   false,
	}
	for spec, want := range claims {
		if got := e.Claims(spec); got != want {
			t.Errorf("Claims(%q) = %v, want %v", spec, got, want)
		}
	}
}

func TestParseSocks5URL(t *testing.T) {
	if _, _, err := parseSocks5URL("http://1.2.3.4:8080"); err == nil {
		t.Fatal("http scheme must be rejected (socks5 only this phase)")
	}
	if _, _, err := parseSocks5URL("socks5h://1.2.3.4:1080"); err == nil {
		t.Fatal("socks5h must be rejected this phase (carry-over)")
	}
	addr, auth, err := parseSocks5URL("socks5://user:pass@1.2.3.4:1080")
	if err != nil {
		t.Fatalf("valid socks5 url: %v", err)
	}
	if addr != "1.2.3.4:1080" {
		t.Fatalf("addr = %q", addr)
	}
	if auth == nil || auth.User != "user" || auth.Password != "pass" {
		t.Fatalf("auth = %+v", auth)
	}
	if _, noAuth, _ := parseSocks5URL("socks5://1.2.3.4:1080"); noAuth != nil {
		t.Fatalf("no userinfo must yield nil auth, got %+v", noAuth)
	}
}

// A spec no engine claims (e.g. a multi-protocol spec without the mihomo engine)
// fails LOUDLY with an actionable message — never silently, never out the wrong
// IP.
func TestEgressRegistry_UnclaimedSpecErrors(t *testing.T) {
	_, err := BuildDialer("ss://rc4-md5:pw@8.8.8.8:8002")
	if err == nil {
		t.Fatal("a multi-protocol spec must error when no engine claims it")
	}
}
