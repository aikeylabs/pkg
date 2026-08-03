package providerroutes

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// canonicalClientPath is what a real SDK sends AFTER the proxy strips the
// "/<provider>" routing prefix. Both are hard-coded /v1 because that is what
// the vendors' own SDKs emit regardless of which version the upstream serves —
// which is precisely the mismatch this fence exists to police.
var canonicalClientPath = map[string]string{
	"openai_compatible": "/v1/chat/completions",
	"anthropic":         "/v1/messages",
}

// TestFence_StitchedPathCarriesExactlyOneVersionSegment pins the rule the
// stitch doc comment states: final = base_url + version + (reqPath with its
// leading version stripped). Exactly ONE version segment survives — the
// table's.
//
// 🔴 Why this fence had to be added separately from I-2: I-2 asserts that a
// shown URL resolves back to the row that produced it. That is CLASSIFICATION.
// A row can classify perfectly and still build a wrong upstream path. Between
// 2026-05 and 2026-08-03 five rows dialled a doubled version
// (…/api/v3/v1/chat/completions) with every existing fence green.
//
// Restricted to rows that DECLARE a version. Rows with version "" re-attach
// nothing, so "exactly one version segment" is not a rule they can be held to;
// they are enumerated by the companion test below instead of being silently
// dropped from coverage.
func TestFence_StitchedPathCarriesExactlyOneVersionSegment(t *testing.T) {
	tbl := Default()
	checked, skippedNoDefault := 0, 0

	for _, r := range tbl.All() {
		clientPath, ok := canonicalClientPath[r.Protocol]
		if !ok || r.Version == "" {
			continue
		}
		upstream := EffectiveUpstream(r)
		req := &http.Request{URL: &url.URL{Path: clientPath}}
		// Stitch, not StitchForProviderProtocol: this is the API-key
		// forwarding path (aikey-proxy internal/provider/provider.go:18), the
		// one the reported defect was observed on. Stitch resolves the row by
		// (host, path), so each row is judged against its OWN version.
		// StitchForProviderProtocol is the OAuth path and has a separate,
		// already-known problem — see the companion test below.
		if err := tbl.Stitch(req, upstream); err != nil {
			skippedNoDefault++
			continue
		}
		checked++

		u, err := url.Parse(upstream)
		if err != nil {
			t.Errorf("%s/%s: EffectiveUpstream %q does not parse: %v", r.Provider, r.Protocol, upstream, err)
			continue
		}
		wantPrefix := strings.TrimRight(u.Path, "/")
		got := req.URL.Path

		if !strings.HasPrefix(got, wantPrefix) {
			t.Errorf("%s/%s: stitched path %q does not start with the table's own upstream path %q",
				r.Provider, r.Protocol, got, wantPrefix)
			continue
		}
		rest := strings.TrimPrefix(got, wantPrefix)
		if trimmed := trimLeadingVersionSegment(rest); trimmed != rest {
			t.Errorf("%s/%s: SECOND version segment in the stitched path.\n"+
				"  table version : %s\n  client sent   : %s\n"+
				"  stitched      : %s\n  remainder     : %s  (should be %s)\n"+
				"  => the request would be dialled at a path the vendor does not serve",
				r.Provider, r.Protocol, r.Version, clientPath, got, rest, trimmed)
		}
	}

	if checked == 0 {
		t.Fatal("anti-vacuous: zero rows exercised — a fence that checks nothing passes for the wrong reason")
	}
	t.Logf("checked %d versioned row(s); %d skipped for having no unique default (I-5's business)",
		checked, skippedNoDefault)
}

// TestFence_UnversionedRowsAreEnumerated makes the carve-out VISIBLE.
//
// Rows with version "" pass the client's own /v1 straight through. This test
// deliberately asserts NOTHING about correctness — it fails only if the SET
// changes, forcing whoever adds or removes an unversioned row to look at it.
// 🚫 Do not "fix" this by deleting it; that would return the rows to silence.
//
// 2026-08-03, unauthenticated probe results (401/403 = endpoint exists and
// wants auth; 404 = wrong path):
//
//   - zhipu open.bigmodel.cn/api/paas — 🔴 LOOKS WRONG, not fixed here.
//     /api/paas/v4/chat/completions → 401, modern envelope
//     {"error":{"code":"1001",…}}
//     /api/paas/v1/chat/completions → HTTP **200**, LEGACY envelope
//     {"code":1001,"msg":…,"success":false}
//     Both are live, so nothing 404s to warn anyone. With version "" an
//     OpenAI-compatible client is sent to the LEGACY v1 API, which answers an
//     auth failure with 200 and a body carrying no `choices` — the client
//     parses a success that is not one. Its z.ai sibling declares /v4.
//     🚫 Deliberately NOT changed: this is a PRE-EXISTING row (baseline 15)
//     and setting a version re-points every zhipu credential already stored
//     against it. That is a product decision, not a test fixup.
//   - perplexity    — NOT DETERMINED. api.perplexity.ai was unreachable from
//     the probing host (connect timeout), so neither path could be compared.
//   - github_models — NOT DETERMINED. BOTH candidate paths returned 410 Gone,
//     which says the endpoint family moved rather than which path is right.
func TestFence_UnversionedRowsAreEnumerated(t *testing.T) {
	known := map[string]bool{
		"perplexity|openai_compatible|https://api.perplexity.ai":             true,
		"zhipu|openai_compatible|https://open.bigmodel.cn/api/paas":          true,
		"github_models|openai_compatible|https://models.github.ai/inference": true,
	}
	seen := map[string]bool{}
	for _, r := range tblAllUnversioned(Default()) {
		key := r.Provider + "|" + r.Protocol + "|" + EffectiveUpstream(r)
		seen[key] = true
		if !known[key] {
			t.Errorf("NEW unversioned row %q. It will forward the client's own version segment "+
				"verbatim. Confirm against the vendor's documented path before shipping, then add it here.", key)
		}
	}
	for key := range known {
		if !seen[key] {
			t.Errorf("unversioned row %q disappeared — if it was fixed or removed, drop it from `known`.", key)
		}
	}
}

// TestFence_OAuthPathVersionDivergenceIsKnown pins a SECOND, distinct defect
// so it cannot go quiet again.
//
// There are two stitch entry points, split by auth mode:
//   - Stitch                     — API-key path. Resolves the row by (host, path),
//     so every row is judged against its OWN version. Fixed 2026-08-03.
//   - StitchForProviderProtocol  — OAuth path (aikey-proxy
//     internal/proxy/forward_and_resolve.go:1273). Resolves via
//     ByProviderProtocol, i.e. the PAIR'S DEFAULT ROW, and then applies that
//     row's version to a base URL that may belong to a DIFFERENT row.
//
// For a multi-row provider whose default row declares no version, the second
// entry point therefore strips nothing and the client's own /v1 survives.
//
// 🔴 NOT fixed here, deliberately: the OAuth branch is explicitly out of scope
// of the cascade test plan (§8.5 "没有测试 OAuth 分支"), and an open PR already
// targets this family — aikeylabs/aikey-proxy#11 "OAuth upstream double /v1
// 404s every model on protocol-typed credentials" (CONFLICTING, never merged,
// based on develop-v1.0.4). Rewriting OAuth routing blind, in a path with no
// live coverage, would be worse than recording it.
//
// This test asserts the CURRENT divergent set. When #11 (or its successor)
// lands, this test fails — which is the point: come back and delete it.
func TestFence_OAuthPathVersionDivergenceIsKnown(t *testing.T) {
	tbl := Default()
	knownDivergent := map[string]bool{
		"zhipu|openai_compatible|https://open.bigmodel.cn/api/coding/paas/v4": true,
		"zhipu|openai_compatible|https://api.z.ai/api/paas/v4":                true,
	}
	seen := map[string]bool{}

	for _, r := range tbl.All() {
		clientPath, ok := canonicalClientPath[r.Protocol]
		if !ok || r.Version == "" {
			continue
		}
		upstream := EffectiveUpstream(r)
		req := &http.Request{URL: &url.URL{Path: clientPath}}
		if err := tbl.StitchForProviderProtocol(req, upstream, r.Provider, r.Protocol); err != nil {
			continue
		}
		u, err := url.Parse(upstream)
		if err != nil {
			continue
		}
		rest := strings.TrimPrefix(req.URL.Path, strings.TrimRight(u.Path, "/"))
		if trimLeadingVersionSegment(rest) == rest {
			continue // agrees with the API-key path
		}
		key := r.Provider + "|" + r.Protocol + "|" + upstream
		seen[key] = true
		if !knownDivergent[key] {
			t.Errorf("NEW divergence on the OAuth stitch path: %q dials %q.\n"+
				"  The API-key path gets this right; StitchForProviderProtocol does not.\n"+
				"  Either fix it or add it here with a reason.", key, req.URL.Path)
		}
	}
	for key := range knownDivergent {
		if !seen[key] {
			t.Errorf("%q no longer diverges on the OAuth path — if that was fixed "+
				"(e.g. aikey-proxy#11 landed), delete it from knownDivergent.", key)
		}
	}
	t.Logf("OAuth-path divergence still present on %d row(s); tracked, not fixed here", len(seen))
}

func tblAllUnversioned(tbl *Table) []Route {
	var out []Route
	for _, r := range tbl.All() {
		if _, ok := canonicalClientPath[r.Protocol]; ok && r.Version == "" {
			out = append(out, r)
		}
	}
	return out
}
