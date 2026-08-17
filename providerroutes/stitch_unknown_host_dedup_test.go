package providerroutes

import (
	"net/http"
	"testing"
)

// The degraded (unknown-host) stitch must never emit the same version segment
// twice — and must change nothing else (2026-08-15).
//
// Context: a host absent from provider_routes takes the literal-prepend branch
// (stitchRequestURL with rowKnown=false). That branch is deliberately left
// shape-agnostic: for a vendor the table does not know we cannot tell a mount
// prefix (https://gw.example/proxy serving /proxy/v1/chat/completions) from a
// complete API root, so we must not decide. See the long 🚫 note in
// stitchRequestURL — that decision stands.
//
// What was still wrong: when the STORED base_url already ended in the exact
// segment the client sends, literal-prepend produced /v1/v1/…, which is wrong
// under every reading of the vendor's shape. Most relays document their
// endpoint WITH the version ("base_url: https://xxx/v1"), so the user who
// pasted the documented URL got a broken route and the one who trimmed it got a
// working one. Same /v1/v1 poison already fixed on the OAuth path
// (stitchOAuthRequestURL) and for known rows (2026-08-03).
//
// 能红: delete the `else if dup := trailingVersionSegment(basePath)` branch in
// stitchRequestURL — the duplicate cases below go back to /v1/v1.

func stitched(t *testing.T, base, clientPath string) string {
	t.Helper()
	req, err := http.NewRequest("POST", "http://ignored"+clientPath, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := Default().Stitch(req, base); err != nil {
		t.Fatalf("stitch %s: %v", base, err)
	}
	return req.URL.Host + req.URL.Path
}

func TestUnknownHostStitch_DoesNotDuplicateVersionSegment(t *testing.T) {
	cases := []struct{ name, base, client, want string }{
		{
			// The documented-URL shape. This is the bug.
			name: "stored base already carries the client's version",
			base: "https://www.cun.ai/v1", client: "/v1/chat/completions",
			want: "www.cun.ai/v1/chat/completions",
		},
		{
			name: "trailing slash on the stored version",
			base: "https://www.cun.ai/v1/", client: "/v1/chat/completions",
			want: "www.cun.ai/v1/chat/completions",
		},
		{
			name: "non-/v1 version, still a duplicate",
			base: "https://relay.example/api/v3", client: "/v3/chat/completions",
			want: "relay.example/api/v3/chat/completions",
		},
		{
			name: "client sends the bare version and nothing else",
			base: "https://relay.example/v1", client: "/v1",
			want: "relay.example/v1",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stitched(t, c.base, c.client); got != c.want {
				t.Errorf("got %s, want %s\nA stored base_url that already ends in the "+
					"client's version segment must not emit it twice — /v1/v1/... is "+
					"wrong for every gateway.", got, c.want)
			}
		})
	}
}

// The other half of the fence, and the more important one: everything the
// degraded path did before MUST still happen. These are the shapes the
// stitchRequestURL note protects — where the vendor's shape is genuinely
// unknowable and we must not decide for it.
func TestUnknownHostStitch_LeavesNonDuplicateShapesAlone(t *testing.T) {
	cases := []struct{ name, base, client, want string }{
		{
			// The note's own counter-example: swallowing this /v1 would break a
			// private gateway that serves /v1/chat/completions off a bare host.
			name: "bare host keeps the client's version",
			base: "https://gw.example", client: "/v1/chat/completions",
			want: "gw.example/v1/chat/completions",
		},
		{
			name: "mount prefix keeps the client's version",
			base: "https://relay.example/proxy", client: "/v1/chat/completions",
			want: "relay.example/proxy/v1/chat/completions",
		},
		{
			// Different version segments are NOT duplicates — we do not know
			// whether /api/v3 is a root or a prefix, so nothing is decided.
			name: "different version segment is not a duplicate",
			base: "https://relay.example/api/v3", client: "/v1/chat/completions",
			want: "relay.example/api/v3/v1/chat/completions",
		},
		{
			// Strictness shared with trimLeadingVersionSegment: digits only.
			name: "v1beta is not a duplicate of v1",
			base: "https://gw.example/v1beta", client: "/v1/models",
			want: "gw.example/v1beta/v1/models",
		},
		{
			name: "v1abc is a real path segment",
			base: "https://gw.example/v1abc", client: "/v1abc/x",
			want: "gw.example/v1abc/v1abc/x",
		},
		{
			name: "the exact shape the user runs today stays byte-identical",
			base: "https://www.cun.ai", client: "/v1/chat/completions",
			want: "www.cun.ai/v1/chat/completions",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stitched(t, c.base, c.client); got != c.want {
				t.Errorf("got %s, want %s\nThe degraded path must stay shape-agnostic "+
					"for unknown vendors: only an exact duplicate of the client's own "+
					"version segment may be collapsed.", got, c.want)
			}
		})
	}
}

func TestTrailingVersionSegment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/v1", "/v1"},
		{"/api/v3", "/v3"},
		{"", ""},
		{"/proxy", ""},
		{"/v1beta", ""}, // not digits-only
		{"/v1abc", ""},
		{"/v", ""},
		{"/version", ""},
	}
	for _, c := range cases {
		if got := trailingVersionSegment(c.in); got != c.want {
			t.Errorf("trailingVersionSegment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
