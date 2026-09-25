package egress

// RedactSpec is the one exit for naming an egress address in an error or a log
// line (DEC-master-central-login-15). These cases pin what it keeps (scheme,
// host, port, hop order) and what it never lets through (user name, password,
// fragment text), including input url.Parse rejects — which is exactly when a
// caller needs to print it.
//
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md

import "testing"

func TestRedactSpec(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"empty", "", ""},
		{"blank", "   ", ""},
		{"no credentials: unchanged", "socks5://proxy.example.test:1080", "socks5://proxy.example.test:1080"},
		{"user and password", "socks5://" + markUser + ":" + markPass + "@proxy.example.test:1080", "socks5://proxy.example.test:1080"},
		{"user only", "https://" + markUser + "@proxy.example.test:443", "https://proxy.example.test:443"},
		{"http proxy", "http://" + markUser + ":" + markPass + "@proxy.example.test:3128", "http://proxy.example.test:3128"},
		{"surrounding blanks", "  socks5://" + markUser + ":" + markPass + "@proxy.example.test:1080  ", "socks5://proxy.example.test:1080"},
		{"upper-case scheme kept as typed", "SOCKS5://" + markUser + ":" + markPass + "@proxy.example.test:1080", "SOCKS5://proxy.example.test:1080"},
		{"no port", "socks5://" + markUser + ":" + markPass + "@portless.example.test", "socks5://portless.example.test"},
		// D2 甲 (2026-09-24): a port that is not a number hides the hop even after
		// an '@' — written backwards as host:port@user:password, the part after the
		// last '@' IS the user name and password (review-2.4 I-2).
		{"port not a number", "socks5://" + markUser + ":" + markPass + "@proxy.example.test:abc", "(unparseable)"},
		{"written backwards: host:port@user:password", "socks5://proxy.example.test:1080@" + markUser + ":" + markPass, "(unparseable)"},
		{"written backwards, http", "http://proxy.example.test:3128@" + markUser + ":" + markPass, "(unparseable)"},
		{"IPv6 host", "socks5://" + markUser + ":" + markPass + "@[2001:db8::1]:1080", "socks5://[2001:db8::1]:1080"},
		{"IPv6 bracket left open", "socks5://" + markUser + ":" + markPass + "@[2001:db8::1:1080", "socks5://[2001:db8::1:1080"},
		// Userinfo ends at the LAST '@', so a password holding '@', '/', '?' or
		// '#' (unescaped: a typo url.Parse rejects or misreads) is still cut out.
		{"'@' in the password", "socks5://" + markUser + ":" + markPass + "@x@proxy.example.test:1080", "socks5://proxy.example.test:1080"},
		{"'/' in the password", "socks5://" + markUser + ":" + markPass + "/x@proxy.example.test:1080", "socks5://proxy.example.test:1080"},
		{"'#' in the password", "socks5://" + markUser + ":" + markPass + "#x@proxy.example.test:1080", "socks5://proxy.example.test:1080"},
		{"path, query and fragment dropped", "http://proxy.example.test:3128/p?token=" + markPass + "#" + markUser, "http://proxy.example.test:3128"},
		{"chain, hop order kept", "socks5://front.example.test:1080, socks5://" + markUser + ":" + markPass + "@exit.example.test:1080", "socks5://front.example.test:1080,socks5://exit.example.test:1080"},
		{"chain, empty segments skipped", ",socks5://a.example.test:1,,socks5://b.example.test:2,", "socks5://a.example.test:1,socks5://b.example.test:2"},
		// Without a well-formed "scheme://" there is no userinfo to cut, so
		// nothing of the hop is shown: it may be a stray piece of a fragment.
		{"no scheme", markUser + ":" + markPass + "@proxy.example.test:1080", "(unparseable)"},
		{"one slash after the scheme", "socks5:/" + markUser + ":" + markPass + "@proxy.example.test:1080", "(unparseable)"},
		{"scheme with a space", "ht tp://" + markUser + ":" + markPass + "@x", "(unparseable)"},
		{"not a URL", "nonsense", "(unparseable)"},
		// No '@': "user:password" typed without its "@host" parses as a host
		// with a bad port, so a non-numeric port is never shown (2.0's fence
		// TestTestDial_SingleHTTPProxyErrorNeverEchoesCredentials has this shape).
		{"no '@': user:password without a host", "http://" + markUser + ":" + markPass, "(unparseable)"},
		{"no '@': port not a number", "socks5://proxy.example.test:abc", "(unparseable)"},
		{"no '@': bare host kept", "socks5://portless.example.test", "socks5://portless.example.test"},
		{"no '@': IPv6 literal left open is shown", "http://[::1", "http://[::1"},
		{"chain with a stray fragment piece", "socks5://front.example.test:1080,password: " + markPass + "}", "socks5://front.example.test:1080,(unparseable)"},
		{"YAML fragment", "proxies:\n  - {name: a, type: ss, server: 198.51.100.4, port: 8388, cipher: aes-128-gcm, password: " + markPass + "}", "(multi-protocol config fragment)"},
		{"JSON fragment", `{"proxies":[{"name":"a","username":"` + markUser + `","password":"` + markPass + `"}]}`, "(multi-protocol config fragment)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSpec(tc.in)
			if got != tc.want {
				t.Errorf("RedactSpec(%q) = %q, want %q", tc.in, got, tc.want)
			}
			assertNoCredentials(t, "RedactSpec", got)
		})
	}
}
