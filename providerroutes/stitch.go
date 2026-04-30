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

	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	req.Host = target.Host

	if target.Path == "" || target.Path == "/" {
		// In-table lookup may still apply (table's base_url may carry a
		// path prefix the user's stored base_url didn't have). Continue
		// with the lookup path, otherwise the path stays as-is below.
	}

	basePath, version := t.resolveStitchComponents(target.Host, target.Path)
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
	return nil
}

// resolveStitchComponents returns (base path, version) for stitching.
// Prefers the table row when host is known, falls back to the parsed
// path with empty version when not (degraded mode).
func (t *Table) resolveStitchComponents(host, parsedPath string) (basePath, version string) {
	host = strings.ToLower(host)
	if r, ok := t.ByHost(host); ok {
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
