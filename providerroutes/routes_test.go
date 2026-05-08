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
			name: "kimi_coding_client_sends_v1",
			baseURL: "https://api.kimi.com/coding/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name: "kimi_coding_client_omits_v1",
			baseURL: "https://api.kimi.com/coding/v1", reqPath: "/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name: "kimi_coding_legacy_stored_root",
			baseURL: "https://api.kimi.com/coding", reqPath: "/v1/chat/completions",
			wantHost: "api.kimi.com", wantPath: "/coding/v1/chat/completions",
		},
		{
			name: "moonshot_in_kimi_family_diff_endpoint",
			baseURL: "https://api.moonshot.cn/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.moonshot.cn", wantPath: "/v1/chat/completions",
		},
		{
			name: "openai_official",
			baseURL: "https://api.openai.com/v1", reqPath: "/v1/chat/completions",
			wantHost: "api.openai.com", wantPath: "/v1/chat/completions",
		},
		{
			name: "openai_no_v1_in_request",
			baseURL: "https://api.openai.com/v1", reqPath: "/chat/completions",
			wantHost: "api.openai.com", wantPath: "/v1/chat/completions",
		},
		{
			name: "anthropic_no_path_prefix",
			baseURL: "https://api.anthropic.com", reqPath: "/v1/messages",
			wantHost: "api.anthropic.com", wantPath: "/v1/messages",
		},
		{
			name: "perplexity_empty_version",
			baseURL: "https://api.perplexity.ai", reqPath: "/chat/completions",
			wantHost: "api.perplexity.ai", wantPath: "/chat/completions",
		},
		{
			name: "gemini_v1beta_re_attaches",
			baseURL: "https://generativelanguage.googleapis.com", reqPath: "/models/gemini-pro:generateContent",
			wantHost: "generativelanguage.googleapis.com", wantPath: "/v1beta/models/gemini-pro:generateContent",
		},
		{
			name: "gemini_v1beta_client_sends_it",
			baseURL: "https://generativelanguage.googleapis.com", reqPath: "/v1beta/models/x",
			wantHost: "generativelanguage.googleapis.com", wantPath: "/v1beta/models/x",
		},
		{
			name: "openai_v1abc_not_swallowed",
			baseURL: "https://api.openai.com/v1", reqPath: "/v1abc/x",
			wantHost: "api.openai.com", wantPath: "/v1/v1abc/x",
		},
		{
			name: "unknown_host_literal_prepend",
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
