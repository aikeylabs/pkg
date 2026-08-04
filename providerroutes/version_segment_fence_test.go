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

// TestFence_UnversionedRowsAreEnumerated keeps the version:"" rows VISIBLE, and
// now also pins what they DO.
//
// # What the 2026-08-03 §6 route-table health check settled
//
// The table carried three unversioned rows. All three were unverified, and when
// probed (401/403 = the endpoint exists and wants auth; 404 = wrong path;
// 410 = gone) all three turned out to be broken, each differently:
//
//   - perplexity — /chat/completions → 401, /v1/chat/completions → 404. The row
//     was RIGHT and the STITCH was wrong: with version "" the client's own /v1
//     was forwarded, so the proxy dialled the 404 path. Fixed in stitch.go by
//     making the strip unconditional for a known row. (The first-round report
//     called this host "unreachable"; that was a probing error — the host has
//     HTTPS_PROXY set and the probe passed curl --noproxy '*', a rule that is
//     right for the runbook's localhost probes and wrong for vendor probes.)
//   - zhipu open.bigmodel.cn/api/paas — /api/paas/v4/… → 401 with the modern
//     envelope {"error":{"code":"1001",…}}; /api/paas/v1/… → HTTP **200** with
//     the LEGACY envelope {"code":1001,…,"success":false}. Both live, so nothing
//     404s to warn anyone, and an auth failure arrives as a 200 with no
//     `choices` — the client parses a success that is not one. Row data, not
//     stitch: fixed in the yaml as version "/v4". The upgrade consequence is
//     asserted in cascade_fences_test.go's intentionalRowChanges.
//   - github_models — both candidate paths → 410
//     {"error":{"code":"github_models_retirement_brownout",…}}. The vendor is
//     retiring the Models API; no stitch or row edit reaches it. Row and
//     registry identity deleted.
//
// So perplexity is the only unversioned row left, and "unversioned" now means
// exactly one thing: this vendor serves no version segment, and the client's
// own is stripped like everyone else's. 🚫 Do not weaken this back into a bare
// set-membership check — the assertion that the row STRIPS is the half that
// would have caught the defect.
func TestFence_UnversionedRowsAreEnumerated(t *testing.T) {
	// key → the path the proxy must dial when an OpenAI-compatible client sends
	// its customary /v1/chat/completions.
	known := map[string]string{
		"perplexity|openai_compatible|https://api.perplexity.ai": "/chat/completions",
	}
	seen := map[string]bool{}
	for _, r := range tblAllUnversioned(Default()) {
		key := r.Provider + "|" + r.Protocol + "|" + EffectiveUpstream(r)
		seen[key] = true
		wantPath, listed := known[key]
		if !listed {
			t.Errorf("NEW unversioned row %q. Confirm against the vendor's documented path "+
				"before shipping — an empty version means \"this vendor has no version segment\", "+
				"NOT \"pass the client's segment through\" — then add it here with the path it must dial.", key)
			continue
		}

		clientPath, ok := canonicalClientPath[r.Protocol]
		if !ok {
			continue
		}
		req := &http.Request{URL: &url.URL{Path: clientPath}}
		if err := Default().Stitch(req, EffectiveUpstream(r)); err != nil {
			t.Errorf("%s: Stitch failed: %v", key, err)
			continue
		}
		if req.URL.Path != wantPath {
			t.Errorf("🔴 %s: client sent %s, the proxy would dial %q, want %q.\n"+
				"  A row with no version must still STRIP the client's segment. Forwarding it "+
				"verbatim is what sent perplexity traffic to a 404 while its declared endpoint answered 401.",
				key, clientPath, req.URL.Path, wantPath)
		}
	}
	for key := range known {
		if !seen[key] {
			t.Errorf("unversioned row %q disappeared — if it was fixed or removed, drop it from `known`.", key)
		}
	}
}

// TestFence_UnknownHostStillForwardsTheClientVersion is the other half of the
// unconditional strip: it must NOT reach hosts the table has never heard of.
//
// 🔴 Why this needs its own fence. The natural way to implement "strip
// unconditionally" is to delete the `if version != ""` guard, and the degraded
// literal-prepend branch also produces version "" — so the one-line version of
// the fix silently swallows the /v1 of every private gateway and enterprise
// reverse proxy that is not in the yaml. Those are precisely the deployments
// with no test coverage and no way to notice except a customer's 404.
func TestFence_UnknownHostStillForwardsTheClientVersion(t *testing.T) {
	tbl := Default()
	if _, ok := tbl.ByHost("gw.private.example"); ok {
		t.Fatal("the fence's host is supposed to be ABSENT from the table")
	}
	cases := []struct{ stored, clientPath, want string }{
		// The shape that breaks: nothing in the stored URL supplies a version,
		// so the client's own segment is the only one there is.
		{"https://gw.private.example", "/v1/chat/completions", "/v1/chat/completions"},
		// And the pre-existing literal-prepend behavior, unchanged.
		{"https://gw.private.example/api/v9", "/foo", "/api/v9/foo"},
	}
	for _, c := range cases {
		req := &http.Request{URL: &url.URL{Path: c.clientPath}}
		if err := tbl.Stitch(req, c.stored); err != nil {
			t.Fatalf("Stitch(%q): %v", c.stored, err)
		}
		if req.URL.Path != c.want {
			t.Errorf("unknown host %q + client path %q → %q, want %q.\n"+
				"  The table knows nothing about this vendor's shape; deciding its version segment "+
				"for it is not the same act as deciding one for a vendor we have a row for.",
				c.stored, c.clientPath, req.URL.Path, c.want)
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
//
// # 2026-08-03: the set is now EMPTY, and the defect is NOT fixed
//
// Both entries were zhipu openai rows, and they diverged only because zhipu's
// DEFAULT row (the empty-prefix /api/paas one) declared no version, so
// StitchForProviderProtocol had nothing to strip. Giving that row its correct
// /v4 made all three zhipu openai rows version-uniform, and the mismatch
// vanished — by arithmetic, not by repair. StitchForProviderProtocol still
// applies the PAIR'S DEFAULT row's version to a base URL that may belong to a
// different row; the table simply no longer contains a pair where that is
// observable.
//
// 🚫 So do NOT read an empty set as "#11 landed", and do not delete this test.
// It is now a regression fence: the next multi-row provider whose default row
// disagrees with a sibling reds here, on the day the row is added rather than
// on the day a customer's OAuth credential 404s.
func TestFence_OAuthPathVersionDivergenceIsKnown(t *testing.T) {
	tbl := Default()
	knownDivergent := map[string]bool{}
	seen := map[string]bool{}

	checked := 0
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
		checked++
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
	// An empty `seen` is the expected answer today, so this fence can only be
	// trusted if it actually drove rows through the OAuth stitch. Zero exercised
	// rows would report "no divergence" for the wrong reason.
	if checked == 0 {
		t.Fatal("anti-vacuous: StitchForProviderProtocol was never exercised — 'no divergence' here would mean 'nothing was tried'")
	}
	t.Logf("OAuth-path divergence present on %d of %d exercised row(s); the defect is unobserved in this table, not repaired", len(seen), checked)
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
