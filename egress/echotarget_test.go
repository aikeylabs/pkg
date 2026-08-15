package egress

import (
	"net"
	"net/url"
	"strings"
	"testing"
)

// providerHostFragments are the provider hostnames a LEAVING probe must never
// default to. Fragments (not exact URLs) so a variant like
// "https://api.anthropic.com/v1/models" is caught too.
var providerHostFragments = []string{
	"anthropic.com",
	"claude.ai",
	"openai.com",
	"chatgpt.com",
	"googleapis.com",
	"moonshot.cn",
	"bigmodel.cn",
}

// TestDefaultEchoURLIsNeutral fences the shared default against a provider host.
// See neutralEchoURL's comment for the security and correctness reasons; this is
// the fence that makes them machine-checked instead of advisory.
func TestDefaultEchoURLIsNeutral(t *testing.T) {
	t.Setenv(EchoURLEnv, "")
	got := strings.ToLower(DefaultEchoURL())
	if got == "" {
		t.Fatal("DefaultEchoURL() is empty — every egress probe would have no target")
	}
	for _, frag := range providerHostFragments {
		if strings.Contains(got, frag) {
			t.Errorf("DefaultEchoURL() = %q, which targets provider host %q.\n"+
				"Egress probes dial OUT through a user-supplied egress; the target must stay a neutral echo.\n"+
				"See neutralEchoURL's comment.", got, frag)
		}
	}
}

// TestDefaultEchoURLIsBareIPEcho fences the SHAPE of the default, not just its
// neutrality. extractIP recovers the exit IP by scanning the response for the
// first IP-shaped token; a rich HTML geo page satisfies "neutral" yet makes that
// scan depend on someone else's page layout. Any replacement must be a bare-IP
// echo — a plain host with no deep path is the cheap proxy for that.
func TestDefaultEchoURLIsBareIPEcho(t *testing.T) {
	t.Setenv(EchoURLEnv, "")
	u, err := url.Parse(DefaultEchoURL())
	if err != nil {
		t.Fatalf("DefaultEchoURL() = %q is not a parseable URL: %v", DefaultEchoURL(), err)
	}
	if u.Scheme != "https" {
		t.Errorf("DefaultEchoURL() scheme = %q, want https — the default target must not "+
			"downgrade the probe to cleartext", u.Scheme)
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		t.Errorf("DefaultEchoURL() = %q has path %q. The default must be a BARE-IP echo, not a "+
			"geo/HTML page: extractIP scans for the first IP-shaped token and a page layout can "+
			"change under us. Point AIKEY_EGRESS_TEST_ECHO at a richer endpoint if a deployment "+
			"needs one.", DefaultEchoURL(), u.Path)
	}
}

// TestDefaultEchoURLHonorsEnv proves the air-gapped override works. One knob for
// every probe is the documented contract — an operator with no external internet
// must not have to discover which probe reads which variable.
func TestDefaultEchoURLHonorsEnv(t *testing.T) {
	const internal = "http://echo.internal.example/ip"
	t.Setenv(EchoURLEnv, internal)
	if got := DefaultEchoURL(); got != internal {
		t.Errorf("DefaultEchoURL() = %q, want the %s override %q", got, EchoURLEnv, internal)
	}
	t.Setenv(EchoURLEnv, "   ")
	if got := DefaultEchoURL(); got != neutralEchoURL {
		t.Errorf("DefaultEchoURL() = %q for a whitespace-only override, want the default %q — "+
			"a blank variable must not leave the probe targetless", got, neutralEchoURL)
	}
}

// TestExtractIPHandlesBareEcho pins the pairing between the default target's
// response shape and the parser that consumes it: a bare-IP body must yield the IP.
func TestExtractIPHandlesBareEcho(t *testing.T) {
	for _, body := range []string{"203.0.113.7", "203.0.113.7\n", "\"203.0.113.7\"", "2001:db8::1"} {
		got := extractIP(body)
		if net.ParseIP(got) == nil {
			t.Errorf("extractIP(%q) = %q, which is not an IP — the bare-IP echo shape must parse", body, got)
		}
	}
}
