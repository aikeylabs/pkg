package providerroutes

import (
	"net/http"
	"net/url"
	"testing"
)

// 2026-05-08 Kimi 双平台拆分: api.kimi.com / api.moonshot.cn 拆为两个独立
// provider_code (kimi_code / moonshot),不再是同一 provider 下两 host。
const minimalYAML = `
provider_routes:
  - { host: "api.anthropic.com", protocol: anthropic,         provider: anthropic,  base_url: "https://api.anthropic.com",       version: "/v1" }
  - { host: "api.openai.com",    protocol: openai_compatible, provider: openai,     base_url: "https://api.openai.com",          version: "/v1" }
  - { host: "api.kimi.com",      protocol: openai_compatible, provider: kimi_code,  base_url: "https://api.kimi.com/coding",     version: "/v1" }
  - { host: "api.moonshot.cn",   protocol: openai_compatible, provider: moonshot,   base_url: "https://api.moonshot.cn",         version: "/v1" }
  - { host: "api.perplexity.ai", protocol: openai_compatible, provider: perplexity, base_url: "https://api.perplexity.ai",       version: "" }
  - { host: "generativelanguage.googleapis.com", protocol: gemini, provider: google_gemini, base_url: "https://generativelanguage.googleapis.com", version: "/v1beta" }
`

func mustParse(t *testing.T, src string) *Table {
	t.Helper()
	tbl, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return tbl
}

func TestParseEmptyHostRejected(t *testing.T) {
	bad := `
provider_routes:
  - { host: "", protocol: anthropic, provider: anthropic, base_url: "https://x", version: "/v1" }
`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected empty-host rejection")
	}
}

func TestParseDuplicateHostRejected(t *testing.T) {
	dup := `
provider_routes:
  - { host: "api.x.com", protocol: openai_compatible, provider: x, base_url: "https://api.x.com", version: "/v1" }
  - { host: "api.x.com", protocol: openai_compatible, provider: y, base_url: "https://api.x.com", version: "/v1" }
`
	if _, err := Parse([]byte(dup)); err == nil {
		t.Fatal("expected duplicate-host rejection")
	}
}

func TestByHostCaseInsensitive(t *testing.T) {
	tbl := mustParse(t, minimalYAML)
	for _, h := range []string{"api.kimi.com", "API.KIMI.COM", "Api.Kimi.Com"} {
		r, ok := tbl.ByHost(h)
		if !ok {
			t.Errorf("ByHost(%q) returned !ok", h)
			continue
		}
		if r.Provider != "kimi_code" {
			t.Errorf("ByHost(%q).Provider = %q, want kimi_code", h, r.Provider)
		}
	}
}

// 2026-05-08 Kimi 双平台拆分: api.kimi.com → kimi_code,api.moonshot.cn → moonshot,
// 两个独立 provider_code,各自只有一行,不再有 first-match-wins 的隐性 bug。
func TestByProviderKimiCodeAndMoonshot(t *testing.T) {
	tbl := mustParse(t, minimalYAML)
	cases := []struct {
		provider string
		wantHost string
	}{
		{"kimi_code", "api.kimi.com"},
		{"moonshot", "api.moonshot.cn"},
	}
	for _, c := range cases {
		r, ok := tbl.ByProvider(c.provider)
		if !ok {
			t.Errorf("ByProvider(%q) returned !ok", c.provider)
			continue
		}
		if r.Host != c.wantHost {
			t.Errorf("ByProvider(%q).Host = %q, want %q", c.provider, r.Host, c.wantHost)
		}
	}
}

func TestByProviderProtocolIsIndependentOfProtocolRowOrder(t *testing.T) {
	const anthropicFirst = `
provider_routes:
  - { host: "mock.internal", path_prefix: "/anthropic", protocol: anthropic, provider: mock, base_url: "http://mock.internal/anthropic", version: "/v1" }
  - { host: "mock.internal", path_prefix: "/openai", protocol: openai_compatible, provider: mock, base_url: "http://mock.internal/openai", version: "/v1" }
`
	const openAIFirst = `
provider_routes:
  - { host: "mock.internal", path_prefix: "/openai", protocol: openai_compatible, provider: mock, base_url: "http://mock.internal/openai", version: "/v1" }
  - { host: "mock.internal", path_prefix: "/anthropic", protocol: anthropic, provider: mock, base_url: "http://mock.internal/anthropic", version: "/v1" }
`

	for _, src := range []string{anthropicFirst, openAIFirst} {
		tbl := mustParse(t, src)
		anthropic, ok := tbl.ByProviderProtocol("MOCK", "Anthropic")
		if !ok || anthropic.BaseURL != "http://mock.internal/anthropic" {
			t.Fatalf("mock/anthropic = (%+v,%v), want the Anthropic endpoint", anthropic, ok)
		}
		openAI, ok := tbl.ByProviderProtocol("mock", "openai_compatible")
		if !ok || openAI.BaseURL != "http://mock.internal/openai" {
			t.Fatalf("mock/openai_compatible = (%+v,%v), want the OpenAI endpoint", openAI, ok)
		}
	}
}

func TestByProviderProtocolUsesUniqueCatchAllForMultiEndpointPair(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	r, ok := tbl.ByProviderProtocol("zhipu", "openai_compatible")
	if !ok {
		t.Fatal("zhipu/openai_compatible must resolve its unique catch-all row")
	}
	if r.PathPrefix != "" || r.BaseURL != "https://open.bigmodel.cn/api/paas" {
		t.Fatalf("default route = %+v, want the empty-prefix GLM endpoint", r)
	}
}

func TestByProviderProtocolUsesDeclaredDefaultAcrossHosts(t *testing.T) {
	tbl := mustParse(t, `
provider_routes:
  - { host: "alias.example", protocol: openai_compatible, provider: kimi_like, base_url: "https://alias.example", version: "/v1" }
  - { host: "canonical.example", protocol: openai_compatible, provider: kimi_like, base_url: "https://canonical.example", version: "/v1", default: true }
`)
	r, ok := tbl.ByProviderProtocol("kimi_like", "openai_compatible")
	if !ok || r.Host != "canonical.example" {
		t.Fatalf("declared default = (%+v,%v), want canonical.example", r, ok)
	}
}

func TestByProviderProtocolRejectsAmbiguousDefault(t *testing.T) {
	tbl := mustParse(t, `
provider_routes:
  - { host: "one.example", path_prefix: "/v1", protocol: anthropic, provider: aggregate, base_url: "https://one.example/v1", version: "" }
  - { host: "two.example", path_prefix: "/v2", protocol: anthropic, provider: aggregate, base_url: "https://two.example/v2", version: "" }
`)
	if r, ok := tbl.ByProviderProtocol("aggregate", "anthropic"); ok {
		t.Fatalf("ambiguous pair resolved to %+v; want fail-loud", r)
	}
}

func TestEmbeddedMockProviderDeclaresBothProtocols(t *testing.T) {
	tbl := Default()
	for _, protocol := range []string{"anthropic", "openai_compatible"} {
		route, ok := tbl.ByProviderProtocol("mock", protocol)
		if !ok {
			t.Fatalf("embedded Mock Provider route missing for protocol %q", protocol)
		}
		if route.Provider != "mock" || route.Protocol != protocol {
			t.Fatalf("route = (%q,%q), want (mock,%s)", route.Provider, route.Protocol, protocol)
		}
		if route.Host != "mock-provider.aikey.internal" {
			t.Fatalf("route host = %q, want stable Mock Provider logical host", route.Host)
		}
	}
}

func TestEffectiveUpstreamHandlesEmptyVersion(t *testing.T) {
	tbl := mustParse(t, minimalYAML)
	kimi, _ := tbl.ByHost("api.kimi.com")
	if got := EffectiveUpstream(kimi); got != "https://api.kimi.com/coding/v1" {
		t.Errorf("kimi: got %q, want kimi.com/coding/v1", got)
	}
	pplx, _ := tbl.ByHost("api.perplexity.ai")
	if got := EffectiveUpstream(pplx); got != "https://api.perplexity.ai" {
		t.Errorf("perplexity (empty version): got %q, want perplexity.ai", got)
	}
}

func TestStitchContract(t *testing.T) {
	tbl := mustParse(t, minimalYAML)

	cases := []struct {
		name     string
		baseURL  string
		reqPath  string
		wantHost string
		wantPath string
	}{
		{
			name:    "kimi_coding_client_sends_v1",
			baseURL: "https://api.kimi.com/coding/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name:    "kimi_coding_client_omits_v1",
			baseURL: "https://api.kimi.com/coding/v1", reqPath: "/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name:    "kimi_coding_legacy_stored_root",
			baseURL: "https://api.kimi.com/coding", reqPath: "/v1/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name:    "moonshot_in_kimi_family_diff_endpoint",
			baseURL: "https://api.moonshot.cn/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.moonshot.cn", wantPath: "/v1/chat/completions",
		},
		{
			name:    "openai_official",
			baseURL: "https://api.openai.com/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.openai.com", wantPath: "/v1/chat/completions",
		},
		{
			name:    "openai_no_v1_in_request",
			baseURL: "https://api.openai.com/v1", reqPath: "/chat/completions",
			wantHost: "api.openai.com", wantPath: "/v1/chat/completions",
		},
		{
			name:    "anthropic_no_path_prefix",
			baseURL: "https://api.anthropic.com", reqPath: "/v1/messages",
			wantHost: "api.anthropic.com", wantPath: "/v1/messages",
		},
		{
			name:    "perplexity_empty_version",
			baseURL: "https://api.perplexity.ai", reqPath: "/chat/completions",
			wantHost: "api.perplexity.ai", wantPath: "/chat/completions",
		},
		{
			name:    "gemini_v1beta_re_attaches",
			baseURL: "https://generativelanguage.googleapis.com", reqPath: "/models/gemini-pro:generateContent",
			wantHost: "generativelanguage.googleapis.com", wantPath: "/v1beta/models/gemini-pro:generateContent",
		},
		{
			name:    "gemini_v1beta_client_sends_it",
			baseURL: "https://generativelanguage.googleapis.com", reqPath: "/v1beta/models/x",
			wantHost: "generativelanguage.googleapis.com", wantPath: "/v1beta/models/x",
		},
		{
			name:    "openai_v1abc_not_swallowed",
			baseURL: "https://api.openai.com/v1", reqPath: "/v1abc/x",
			wantHost: "api.openai.com", wantPath: "/v1/v1abc/x",
		},
		{
			name:    "unknown_host_literal_prepend",
			baseURL: "https://example.private/api/v9", reqPath: "/foo",
			wantHost: "example.private", wantPath: "/api/v9/foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://placeholder"+tc.reqPath, nil)
			req.URL = &url.URL{Path: tc.reqPath}
			if err := tbl.Stitch(req, tc.baseURL); err != nil {
				t.Fatalf("Stitch: %v", err)
			}
			if req.URL.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", req.URL.Host, tc.wantHost)
			}
			if req.URL.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", req.URL.Path, tc.wantPath)
			}
		})
	}
}

func TestStitchForProviderProtocolPreservesRuntimeRailAndCanonicalVersion(t *testing.T) {
	tbl := Default()
	cases := []struct {
		name     string
		baseURL  string
		reqPath  string
		protocol string
		wantPath string
	}{
		{
			name:    "mock_openai_responses_without_version",
			baseURL: "http://127.0.0.1:3000/mock-provider/openai", reqPath: "/responses",
			protocol: "openai_compatible", wantPath: "/mock-provider/openai/v1/responses",
		},
		{
			name:    "mock_anthropic_deduplicates_client_version",
			baseURL: "http://host.docker.internal:3000/mock-provider/anthropic", reqPath: "/v1/messages",
			protocol: "anthropic", wantPath: "/mock-provider/anthropic/v1/messages",
		},
		{
			name:    "runtime_base_already_contains_version",
			baseURL: "http://127.0.0.1:3000/mock-provider/openai/v1", reqPath: "/v1/responses",
			protocol: "openai_compatible", wantPath: "/mock-provider/openai/v1/responses",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", "http://placeholder"+tc.reqPath, nil)
			req.URL = &url.URL{Path: tc.reqPath}
			target, err := url.Parse(tc.baseURL)
			if err != nil {
				t.Fatal(err)
			}
			if err := tbl.StitchForProviderProtocol(req, tc.baseURL, "mock", tc.protocol); err != nil {
				t.Fatalf("StitchForProviderProtocol: %v", err)
			}
			if req.URL.Host != target.Host {
				t.Errorf("Host = %q, runtime rail was not preserved", req.URL.Host)
			}
			if req.URL.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", req.URL.Path, tc.wantPath)
			}
		})
	}
}

func TestStitchForProviderProtocolRejectsUnknownPair(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://placeholder/messages", nil)
	if err := Default().StitchForProviderProtocol(req, "http://127.0.0.1:3000/custom", "mock", "gemini"); err == nil {
		t.Fatal("expected unsupported provider/protocol pair to fail loud")
	}
	if err := Default().StitchForProviderProtocol(req, "", "mock", "anthropic"); err == nil {
		t.Fatal("expected empty runtime base URL to fail loud")
	}
}

// --- P1b (design D-2b): (host, path_prefix) key + longest-prefix lookup ---

// glmYAML models the extended zhipu/GLM rows: one "" fallback (paas) plus
// two explicit-prefix endpoints. Mirrors the shipped data.
const glmYAML = `
provider_routes:
  - { host: "api.anthropic.com", protocol: anthropic, provider: anthropic, base_url: "https://api.anthropic.com", version: "/v1" }
  - { host: "open.bigmodel.cn", protocol: openai_compatible, provider: zhipu, base_url: "https://open.bigmodel.cn/api/paas", version: "" }
  - { host: "open.bigmodel.cn", path_prefix: "/api/anthropic", protocol: anthropic, provider: zhipu, base_url: "https://open.bigmodel.cn/api/anthropic", version: "/v1" }
  - { host: "open.bigmodel.cn", path_prefix: "/api/coding/paas/v4", protocol: openai_compatible, provider: zhipu, base_url: "https://open.bigmodel.cn/api/coding/paas", version: "/v4" }
`

// TestParseAllowsSameHostDifferentPathPrefix: extended key permits multi-row
// hosts. (Contrast TestParseDuplicateHostRejected: same (host,"") still errors.)
func TestParseAllowsSameHostDifferentPathPrefix(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	if got := tbl.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4 (multi-row host accepted)", got)
	}
}

func TestParseDuplicateHostSamePrefixRejected(t *testing.T) {
	dup := `
provider_routes:
  - { host: "open.bigmodel.cn", path_prefix: "/api/anthropic", protocol: anthropic, provider: zhipu, base_url: "https://open.bigmodel.cn/api/anthropic", version: "/v1" }
  - { host: "open.bigmodel.cn", path_prefix: "/api/anthropic", protocol: openai_compatible, provider: zhipu, base_url: "https://open.bigmodel.cn/api/anthropic", version: "/v1" }
`
	if _, err := Parse([]byte(dup)); err == nil {
		t.Fatal("expected duplicate (host,path_prefix) rejection")
	}
}

// TestLookupLongestPrefixGLM: the P1b exit gate — a stored base_url path
// selects the correct GLM endpoint/protocol via longest-prefix.
func TestLookupLongestPrefixGLM(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	cases := []struct {
		path         string
		wantProtocol string
		wantBaseURL  string
	}{
		{"/api/anthropic", "anthropic", "https://open.bigmodel.cn/api/anthropic"},
		{"/api/anthropic/v1", "anthropic", "https://open.bigmodel.cn/api/anthropic"},
		{"/api/coding/paas/v4", "openai_compatible", "https://open.bigmodel.cn/api/coding/paas"},
		{"/api/paas", "openai_compatible", "https://open.bigmodel.cn/api/paas"}, // "" fallback
		{"", "openai_compatible", "https://open.bigmodel.cn/api/paas"},          // bare host → fallback
	}
	for _, c := range cases {
		r, ok := tbl.Lookup("open.bigmodel.cn", c.path)
		if !ok {
			t.Errorf("Lookup(%q) !ok", c.path)
			continue
		}
		if r.Protocol != c.wantProtocol {
			t.Errorf("Lookup(%q).Protocol = %q, want %q", c.path, r.Protocol, c.wantProtocol)
		}
		if r.BaseURL != c.wantBaseURL {
			t.Errorf("Lookup(%q).BaseURL = %q, want %q", c.path, r.BaseURL, c.wantBaseURL)
		}
	}
}

// TestLookupSegmentAligned (task 1b.3): "/api/anth" must NOT swallow
// "/api/anthropic"; "/api/anthropicfoo" must NOT match the anthropic row.
func TestLookupSegmentAligned(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	// A path that shares a non-segment-aligned prefix with the anthropic row
	// falls through to the "" fallback (paas), not the anthropic row.
	r, ok := tbl.Lookup("open.bigmodel.cn", "/api/anthropicfoo")
	if !ok {
		t.Fatal("expected fallback match")
	}
	if r.Protocol != "openai_compatible" {
		t.Errorf("/api/anthropicfoo matched %q row; want fallback openai_compatible (segment alignment)", r.Protocol)
	}
}

// TestBackwardCompatFence (task 1b.4): every pre-P1b single-row host with an
// empty prefix resolves identically regardless of request path — i.e. the
// extended key degrades to exact host match. This fence must be able to go
// red: if Lookup ever stopped treating "" as a catch-all, a single-row host
// would fail to resolve for a non-empty path.
func TestBackwardCompatFence(t *testing.T) {
	tbl := mustParse(t, minimalYAML)
	for _, h := range []string{"api.anthropic.com", "api.openai.com", "api.kimi.com", "generativelanguage.googleapis.com"} {
		byHost, ok1 := tbl.ByHost(h)
		if !ok1 {
			t.Fatalf("ByHost(%q) !ok", h)
		}
		for _, p := range []string{"", "/", "/v1/messages", "/anything/deep/path"} {
			r, ok := tbl.Lookup(h, p)
			if !ok {
				t.Errorf("Lookup(%q,%q) !ok — single-row host must resolve for any path", h, p)
				continue
			}
			if r.Provider != byHost.Provider || r.BaseURL != byHost.BaseURL {
				t.Errorf("Lookup(%q,%q) = %q/%q, want host-exact %q/%q", h, p, r.Provider, r.BaseURL, byHost.Provider, byHost.BaseURL)
			}
		}
	}
}

// TestStitchGLMAnthropic: end-to-end stitch for the GLM anthropic endpoint —
// proves EffectiveUpstream/stitch land on /api/anthropic/v1 (exit gate).
func TestStitchGLMAnthropic(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	req, _ := http.NewRequest("POST", "http://placeholder/v1/messages", nil)
	req.URL = &url.URL{Path: "/v1/messages"}
	if err := tbl.Stitch(req, "https://open.bigmodel.cn/api/anthropic"); err != nil {
		t.Fatalf("Stitch: %v", err)
	}
	if req.URL.Host != "open.bigmodel.cn" {
		t.Errorf("Host = %q", req.URL.Host)
	}
	if req.URL.Path != "/api/anthropic/v1/messages" {
		t.Errorf("Path = %q, want /api/anthropic/v1/messages", req.URL.Path)
	}
	// And the openai coding endpoint keeps its own base path.
	req2, _ := http.NewRequest("POST", "http://placeholder/chat/completions", nil)
	req2.URL = &url.URL{Path: "/chat/completions"}
	if err := tbl.Stitch(req2, "https://open.bigmodel.cn/api/coding/paas/v4"); err != nil {
		t.Fatalf("Stitch2: %v", err)
	}
	if req2.URL.Path != "/api/coding/paas/v4/chat/completions" {
		t.Errorf("coding Path = %q, want /api/coding/paas/v4/chat/completions", req2.URL.Path)
	}
}

// TestLookupByBaseURL (P1d safe slice): resolve the route row directly from a
// stored base_url, path-awarely — mirrors Rust route_for_base_url.
func TestLookupByBaseURL(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	cases := []struct {
		baseURL      string
		wantProtocol string
		wantOK       bool
	}{
		{"https://open.bigmodel.cn/api/anthropic", "anthropic", true},
		{"https://open.bigmodel.cn/api/coding/paas/v4", "openai_compatible", true},
		{"https://open.bigmodel.cn/api/paas", "openai_compatible", true},
		{"https://open.bigmodel.cn", "openai_compatible", true}, // bare → fallback
		{"https://api.anthropic.com", "anthropic", true},
		{"https://unknown.example", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		r, ok := tbl.LookupByBaseURL(c.baseURL)
		if ok != c.wantOK {
			t.Errorf("LookupByBaseURL(%q) ok=%v, want %v", c.baseURL, ok, c.wantOK)
			continue
		}
		if ok && r.Protocol != c.wantProtocol {
			t.Errorf("LookupByBaseURL(%q).Protocol = %q, want %q", c.baseURL, r.Protocol, c.wantProtocol)
		}
	}
}

// TestDisplayEqualsExecution (P1j / design D-17): the base_url a UI would
// DISPLAY (EffectiveUpstream of the resolved row) must be the same row the
// proxy EXECUTES against (Stitch resolves via the same Lookup). One resolver,
// no drift. GLM's three endpoints each resolve their own base_url.
func TestDisplayEqualsExecution(t *testing.T) {
	tbl := mustParse(t, glmYAML)
	cases := []struct {
		baseURL      string
		wantDisplay  string
		wantExecHost string
		wantExecPath string
	}{
		{"https://open.bigmodel.cn/api/anthropic", "https://open.bigmodel.cn/api/anthropic/v1", "open.bigmodel.cn", "/api/anthropic/v1/messages"},
		{"https://open.bigmodel.cn/api/coding/paas/v4", "https://open.bigmodel.cn/api/coding/paas/v4", "open.bigmodel.cn", "/api/coding/paas/v4/messages"},
		{"https://open.bigmodel.cn/api/paas", "https://open.bigmodel.cn/api/paas", "open.bigmodel.cn", "/api/paas/messages"},
	}
	for _, c := range cases {
		// DISPLAY side (what master/UI shows via the resolved row)
		row, ok := tbl.LookupByBaseURL(c.baseURL)
		if !ok {
			t.Fatalf("LookupByBaseURL(%q) !ok", c.baseURL)
		}
		if got := EffectiveUpstream(row); got != c.wantDisplay {
			t.Errorf("display EffectiveUpstream(%q) = %q, want %q", c.baseURL, got, c.wantDisplay)
		}
		// EXECUTION side (what proxy forwards) — same row, via Stitch
		req, _ := http.NewRequest("POST", "http://x/messages", nil)
		req.URL = &url.URL{Path: "/messages"}
		if err := tbl.Stitch(req, c.baseURL); err != nil {
			t.Fatalf("Stitch(%q): %v", c.baseURL, err)
		}
		if req.URL.Host != c.wantExecHost || req.URL.Path != c.wantExecPath {
			t.Errorf("execution Stitch(%q) = %s%s, want %s%s", c.baseURL, req.URL.Host, req.URL.Path, c.wantExecHost, c.wantExecPath)
		}
	}
}

func TestHostFromURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://api.kimi.com/coding/v1", "api.kimi.com"},
		{"https://API.Kimi.com/x", "api.kimi.com"},
		{"http://localhost:8080", "localhost:8080"},
		{"", ""},
		{"not a url", ""},
	}
	for _, c := range cases {
		if got := HostFromURL(c.in); got != c.want {
			t.Errorf("HostFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
