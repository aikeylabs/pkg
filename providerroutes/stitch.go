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

// resolveStitchComponents returns (base path, version) for stitching.
// Prefers the table row when host is known, falls back to the parsed
// path with empty version when not (degraded mode).
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
