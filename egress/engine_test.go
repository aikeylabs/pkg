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
		{"http://127.0.0.1:7890", false},        // single URL
		{"https://proxy.example:8443", false},   // single URL
		{"socks5://127.0.0.1:1080", false},      // single socks5 → node single-URL path
		{"socks5://a:1080,socks5://b:1080", true}, // chain
		{`{"proxies":[]}`, true},                 // json fragment
		{"proxies:\n  - name: x", true},          // yaml proxies fragment
		{"proxy-groups:\n  - name: g", true},     // yaml groups-first fragment
		{"- {name: x}", true},                    // yaml list fragment
		{"[{}]", true},                           // json array fragment
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
