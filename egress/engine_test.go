package egress

import "testing"

// The open-source build registers ONLY the built-in socks5 engine, so the
// multi-protocol probe must be declined. (The enterprise build blank-imports
// the mihomo engine, which flips this — covered by that module's own tests.)
func TestMultiProtocolAvailable_OSS(t *testing.T) {
	if MultiProtocolAvailable() {
		t.Fatal("open-source build must NOT report multi-protocol available (only built-in socks5 is registered)")
	}
}

func TestIsEngineSpec(t *testing.T) {
	cases := []struct {
		spec string
		want bool
	}{
		{"", false},
		{"http://127.0.0.1:7890", false},          // single URL
		{"https://proxy.example:8443", false},     // single URL
		{"socks5://127.0.0.1:1080", false},        // single socks5 → node single-URL path
		{"socks5://a:1080,socks5://b:1080", true}, // chain
		{`{"proxies":[]}`, true},                  // json fragment
		{"proxies:\n  - name: x", true},           // yaml proxies fragment
		{"proxy-groups:\n  - name: g", true},      // yaml groups-first fragment
		{"- {name: x}", true},                     // yaml list fragment
		{"[{}]", true},                            // json array fragment
	}
	for _, c := range cases {
		if got := IsEngineSpec(c.spec); got != c.want {
			t.Errorf("IsEngineSpec(%q) = %v, want %v", c.spec, got, c.want)
		}
	}
}

func TestValidateSpec(t *testing.T) {
	ok := []string{
		"socks5://127.0.0.1:1080",
		"socks5://a:1080,socks5://b:1080",
		`{"proxies":[{"name":"x"}]}`,
		"proxies:\n  - name: x",
		"proxy-groups:\n  - name: g",
	}
	for _, s := range ok {
		if err := ValidateSpec(s); err != nil {
			t.Errorf("ValidateSpec(%q) unexpected error: %v", s, err)
		}
	}
	bad := []string{
		"",                              // empty
		"http://127.0.0.1:7890",         // http not allowed as an engine-spec hop
		"socks5://a:1080,http://b:1080", // mixed non-socks5 hop
		"socks5://",                     // missing host
		",,",                            // empty chain
	}
	for _, s := range bad {
		if err := ValidateSpec(s); err == nil {
			t.Errorf("ValidateSpec(%q) = nil, want error", s)
		}
	}
}

// A `rules:`-first fragment (DIRECT-bypass lists, 2026-07-30) must be
// recognized as a FRAGMENT: the leading key follows the operator's authoring
// order, and the three gates that key off isFragment all mis-handle it
// otherwise. The OSS-build symptom is the load-bearing one — a rules-first
// fragment used to fall through to the socks5-chain validator and produce
// "each hop must be socks5", which sends the operator debugging their proxy
// URL instead of telling them the feature needs the enterprise package.
//
// 能红: drop the `rules:` prefix from isFragment → all three assertions fail.
func TestIsFragment_RecognizesRulesFirstFragment(t *testing.T) {
	spec := "rules:\n  - DOMAIN-SUFFIX,ipify.org,DIRECT\nproxies:\n  - {name: exit, type: socks5, server: h, port: 1080}"

	if !IsFragment(spec) {
		t.Fatal("a rules-first fragment must be a fragment (else the enterprise gate and the validator both misfire)")
	}
	if !IsEngineSpec(spec) {
		t.Fatal("a rules-first fragment must be an engine-spec (it needs the egress engine, not http.ProxyURL)")
	}
	// Shape-accept at write time; the engine does the deep validation.
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("ValidateSpec must shape-accept a rules-first fragment, got: %v", err)
	}
}
