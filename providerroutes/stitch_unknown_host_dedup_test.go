package providerroutes

import (
	"net/http"
	"net/url"
	"testing"
)

func TestStitchUnknownHostCollapsesOnlyDuplicateNumericVersionAtJoin(t *testing.T) {
	tbl := Default()
	cases := []struct {
		name       string
		stored     string
		clientPath string
		want       string
	}{
		{name: "v1 duplicate", stored: "https://gw.private.example/v1", clientPath: "/v1/chat/completions", want: "/v1/chat/completions"},
		{name: "nested v3 duplicate", stored: "https://gw.private.example/api/v3", clientPath: "/v3/chat/completions", want: "/api/v3/chat/completions"},
		{name: "version only", stored: "https://gw.private.example/v1", clientPath: "/v1", want: "/v1"},
		{name: "trailing slash", stored: "https://gw.private.example/api/v12/", clientPath: "/v12/models", want: "/api/v12/models"},
		{name: "bare host keeps client version", stored: "https://gw.private.example", clientPath: "/v1/chat/completions", want: "/v1/chat/completions"},
		{name: "mount prefix stays literal", stored: "https://gw.private.example/proxy", clientPath: "/v1/chat/completions", want: "/proxy/v1/chat/completions"},
		{name: "different versions stay literal", stored: "https://gw.private.example/api/v3", clientPath: "/v1/chat/completions", want: "/api/v3/v1/chat/completions"},
		{name: "v1beta is not numeric", stored: "https://gw.private.example/v1beta", clientPath: "/v1/models", want: "/v1beta/v1/models"},
		{name: "v1abc is not numeric", stored: "https://gw.private.example/v1abc", clientPath: "/v1abc/models", want: "/v1abc/v1abc/models"},
		{name: "ordinary path stays literal", stored: "https://gw.private.example/api", clientPath: "/messages", want: "/api/messages"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{URL: &url.URL{Path: tc.clientPath}}
			if err := tbl.Stitch(req, tc.stored); err != nil {
				t.Fatalf("Stitch(%q): %v", tc.stored, err)
			}
			if req.URL.Path != tc.want {
				t.Fatalf("Path = %q, want %q", req.URL.Path, tc.want)
			}
		})
	}
}

func TestTrailingVersionSegmentIsStrict(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"/":            "",
		"/v1":          "/v1",
		"/api/v12/":    "/v12",
		"/api/v1beta":  "",
		"/api/v1abc":   "",
		"/api/version": "",
	}
	for input, want := range cases {
		if got := trailingVersionSegment(input); got != want {
			t.Errorf("trailingVersionSegment(%q) = %q, want %q", input, got, want)
		}
	}
}
