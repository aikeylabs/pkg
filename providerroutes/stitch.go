package providerroutes

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Stitch sets req.URL.{Scheme,Host,Path} for an upstream request, given:
//   - vaultBaseURL: the per-key base_url stored in vault.entries (may be
//     empty when the user didn't customise; in that case the table's
//     ByHost lookup is skipped and the fallback path is taken)
//   - reqPath: the request path AFTER the proxy stripped the
//     "/<provider>" routing prefix (e.g. "/v1/chat/completions" or
//     "/chat/completions")
//
// Behaviour:
//   - If vaultBaseURL parses and its host is in the table → use the
//     table's (base_url, version) as the canonical upstream prefix and
//     strip-then-re-attach the version segment from reqPath. Single
//     mathematical rule: final = base_url + version + (reqPath with
//     leading version stripped if present).
//   - If vaultBaseURL parses but its host is NOT in the table →
//     degraded literal-prepend (base_url path + reqPath). Third-party
//     gateways absent from yaml still flow; expected fix is to add
//     them as a yaml row.
//   - If vaultBaseURL is empty → the caller should resolve a default
//     URL (e.g. via ByProvider) before calling Stitch; this function
//     does not synthesise hosts out of thin air.
//
// Why this lives in pkg (not in aikey-proxy alone): aikey-control
// service and any future Go consumer that needs to pre-compute the
// effective upstream URL for a vault entry (for display, audit, sanity
// checks) all share the same algorithm. Centralising prevents drift.
func (t *Table) Stitch(req *http.Request, vaultBaseURL string) error {
	target, err := url.Parse(vaultBaseURL)
	if err != nil {
		return fmt.Errorf("providerroutes: parse base_url: %w", err)
	}
	basePath, version := t.resolveStitchComponents(target.Host, target.Path)
	stitchRequestURL(req, target, basePath, version)
	return nil
}

// StitchForProviderProtocol is the explicit-route counterpart of Stitch for
// deployment-specific upstream addresses. It preserves the runtime host and
// path (for example 127.0.0.1/mock-provider/openai), while taking the version
// segment from the canonical (provider, protocol) fingerprint row.
//
// This is intentionally explicit instead of guessing from an unknown host or
// path suffix: a private third-party gateway must retain Stitch's degraded
// literal-prepend behaviour, while a resident provider whose address changes
// between host and cluster rails still needs deterministic version handling.
func (t *Table) StitchForProviderProtocol(req *http.Request, runtimeBaseURL, provider, protocol string) error {
	target, err := url.Parse(runtimeBaseURL)
	if err != nil {
		return fmt.Errorf("providerroutes: parse runtime base_url: %w", err)
	}
	if target.Scheme == "" || target.Host == "" {
		return fmt.Errorf("providerroutes: runtime base_url must include scheme and host")
	}
	route, ok := t.ByProviderProtocol(provider, protocol)
	if !ok {
		return fmt.Errorf("providerroutes: no unique route for provider %q protocol %q", provider, protocol)
	}

	basePath := strings.TrimRight(target.Path, "/")
	if route.Version != "" {
		basePath = strings.TrimSuffix(basePath, route.Version)
	}
	stitchRequestURL(req, target, basePath, route.Version)
	return nil
}

func stitchRequestURL(req *http.Request, target *url.URL, basePath, version string) {

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host
	reqPath := req.URL.Path
	if version != "" {
		switch {
		case strings.HasPrefix(reqPath, version+"/"):
			reqPath = strings.TrimPrefix(reqPath, version)
		case reqPath == version:
			reqPath = ""
		}
	}

	stitched := basePath + version + reqPath
	if stitched == "" {
		stitched = "/"
	}
	req.URL.Path = stitched
	if req.URL.RawPath != "" {
		req.URL.RawPath = stitched
	}
}

// PathDiscarded reports whether resolving storedBaseURL through this table
// would THROW AWAY path information the stored URL carries — and returns the
// row that swallowed it.
//
// # R-9 (2026-08-02, provider-credential-cascade): why a query for this exists
//
// A host's fallback row (path_prefix "") matches ANY path. So a credential
// stored as https://api.deepseek.com/anthropic/v1 against a table that does not
// yet know the /anthropic row resolves happily to the plain deepseek row, and
// the /anthropic segment is discarded as noise — an Anthropic-shaped body is
// posted to the OpenAI endpoint. Crucially LookupByBaseURL returns ok=TRUE
// (a row really was found), so the existing proxy.route.not_found WARN, which
// fires only on a host MISS, never triggers. The failure is completely silent.
//
// That shape was nearly unreachable while zhipu was the only provider with it.
// This change takes it from 1 provider to 5 (deepseek / moonshot.cn / dashscope
// / ark / zhipu) AND has the console hand those exact URLs to administrators —
// so a rare latent trap moves onto the main road. Callers use this to emit a
// WARN. 🚫 It must NOT change any forwarding decision; see stitchComponents.
//
// The condition is deliberately narrow (only the fallback row, only when the
// stored path carries MORE than the row's own base path). A stored URL that is
// SHORTER than the row's base path discards nothing — the row supplies the rest
// — and must not warn. A WARN that fires for everyone is the same as no WARN.
func (t *Table) PathDiscarded(storedBaseURL string) (matched Route, discarded bool) {
	u, err := url.Parse(storedBaseURL)
	if err != nil || u.Host == "" {
		return Route{}, false
	}
	row, ok := t.Lookup(strings.ToLower(u.Host), u.Path)
	if !ok {
		// A host miss is the OTHER failure shape; it already has its own WARN
		// (proxy.route.not_found). Not ours to report.
		return Route{}, false
	}
	return row, rowDiscardsPath(row, u.Path)
}

// rowDiscardsPath is the single definition of "this row will swallow part of
// the stored path". Both PathDiscarded and the doc comment on
// resolveStitchComponents refer to it so the observability and the routing can
// never describe different conditions.
func rowDiscardsPath(row Route, storedPath string) bool {
	if row.PathPrefix != "" {
		// A row selected by an explicit prefix matched that prefix on purpose;
		// it is not a catch-all swallowing an unrecognised path.
		return false
	}
	rowBase := ""
	if u, err := url.Parse(row.BaseURL); err == nil {
		rowBase = strings.TrimRight(u.Path, "/")
	}
	// Compare like with like: drop the row's version segment from the stored
	// path first, since the stitch re-attaches it explicitly.
	stored := strings.TrimRight(storedPath, "/")
	if row.Version != "" {
		stored = strings.TrimRight(strings.TrimSuffix(stored, row.Version), "/")
	}
	if stored == "" || stored == rowBase {
		return false // nothing of the user's is being dropped
	}
	// If the row's base path EXTENDS the stored path, the row is adding
	// information, not discarding it (e.g. the very common "user pasted the
	// bare domain" shape).
	if pathPrefixMatches(stored, rowBase) {
		return false
	}
	return true
}

// resolveStitchComponents returns (base path, version) for stitching.
// Prefers the table row when host is known, falls back to the parsed
// path with empty version when not (degraded mode).
//
// 🔴 R-9 note: when the matched row satisfies rowDiscardsPath, part of the
// stored path is dropped here. That is the PRE-EXISTING behaviour and this
// change does not alter it — Table.PathDiscarded exists purely so the caller
// can say so in the log. Changing the return in that branch would change
// forwarding, which R-9 explicitly rules out.
func (t *Table) resolveStitchComponents(host, parsedPath string) (basePath, version string) {
	host = strings.ToLower(host)
	// P1b (design D-2b): key by (host, path_prefix). The stored base_url's
	// path segment (parsedPath) selects among a host's rows via
	// segment-aligned longest-prefix match. Single-row hosts (all pre-P1b
	// rows have path_prefix "") behave exactly as the old ByHost exact
	// match. Fail-loud on miss is deferred to P1j (D-17); here the degraded
	// literal-prepend fallback below is retained unchanged.
	if r, ok := t.Lookup(host, parsedPath); ok {
		// Use the table's base_url path (canonical), discarding what the
		// user had stored. This is what makes the stitch deterministic
		// across users with different vault states (some stored the URL
		// with /v1, some without).
		if u, err := url.Parse(r.BaseURL); err == nil {
			return strings.TrimRight(u.Path, "/"), r.Version
		}
	}
	// Fallback: literal-prepend the user's stored path, no version
	// re-attach. Hosts not yet in yaml table still route, just without
	// dedup. This is the correct degraded behaviour — fail open with a
	// best-effort path stitch rather than blocking a request that might
	// well work upstream.
	return strings.TrimRight(parsedPath, "/"), ""
}
