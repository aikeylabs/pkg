// Package egress is the pluggable per-account egress-engine registry (§11.7 /
// 多协议方案). It lives in a PUBLIC (non-internal) package on purpose: the
// open-source build registers only the built-in socks5 engine here, while the
// offline enterprise build composes in a SEPARATE private module that registers
// a mihomo-backed multi-protocol engine. mihomo is GPL-3.0 and must never be
// linked into the open-source GitHub release, so it lives outside this module
// and registers through this public seam.
//
// Contract: engines are tried in registration order; the first to Claim a spec
// Builds it. A spec no engine claims fails LOUDLY (the open-source build lacks
// the multi-protocol engine) — never silently, never out the wrong IP.
//
// See: 20260716-多协议出口代理-嵌mihomo库-技术方案.md
package egress

import (
	"fmt"
	"net/url"
	"strings"

	xproxy "golang.org/x/net/proxy"
)

// Engine builds a dialer chain from a per-account egress spec. Claims is a cheap
// shape check (no dial); Build is only called after Claims returns true. The
// returned dialer's exit hop IP is what the upstream sees.
type Engine interface {
	Name() string
	Claims(spec string) bool
	Build(spec string) (xproxy.Dialer, error)
}

// engines is the ordered registry (first claim wins). Populated by Register from
// each engine's init(): built-in always; mihomo only in the enterprise build.
var engines []Engine

// Register appends an engine to the registry. Call from init() — registration
// order is priority order.
func Register(e Engine) { engines = append(engines, e) }

// BuildDialer runs the registry: the first engine to Claim(spec) builds it. No
// engine claims → an actionable error (the open-source build lacks the
// multi-protocol engine).
func BuildDialer(spec string) (xproxy.Dialer, error) {
	for _, e := range engines {
		if e.Claims(spec) {
			return e.Build(spec)
		}
	}
	return nil, fmt.Errorf("no egress engine handles this proxy spec: multi-protocol egress (ss/vmess/trojan/…) requires the offline enterprise package; this build supports socks5 chains only")
}

// Validator is an OPTIONAL interface an engine may implement to answer "is this
// spec valid?" WITHOUT building a live dialer — no network, no background
// goroutines. Engines that do not implement it fall back to the shape check.
//
// WHY IT IS SEPARATE FROM Build (2026-07-30): the admin console validates at
// SAVE time. Building a multi-protocol fragment primes each proxy-group's health
// check, which is a real network probe — so a build-based save-time validation
// would reject a perfectly valid config whenever the control plane's network
// hiccups. Validity and reachability are different questions; reachability has
// its own affordance (the 测试 button).
type Validator interface {
	Validate(spec string) error
}

// ValidateDeep runs the strongest validation this build can offer for spec:
// shape first, then the claiming engine's semantic check when it provides one.
//
// It is what a SETTER should call so an invalid spec is refused at write time
// rather than surfacing later as a request-time 503 the operator has to trace
// back to a config they believe is saved and working ("失败要显眼").
//
// Graceful degradation is deliberate: a build without the multi-protocol engine
// has no semantic checker for fragments, so it returns the shape verdict rather
// than refusing everything it cannot deeply verify.
func ValidateDeep(spec string) error {
	s := strings.TrimSpace(spec)
	if err := ValidateSpec(s); err != nil {
		return err
	}
	for _, e := range engines {
		if !e.Claims(s) {
			continue
		}
		if v, ok := e.(Validator); ok {
			return v.Validate(s)
		}
		return nil // engine has no deep checker; shape verdict stands
	}
	return fmt.Errorf("no egress engine handles this proxy spec: multi-protocol egress (ss/vmess/trojan/…) requires the offline enterprise package; this build supports socks5 chains only")
}

// Names returns the registered engine names, for diagnostics / health surfaces.
func Names() []string {
	out := make([]string, 0, len(engines))
	for _, e := range engines {
		out = append(out, e.Name())
	}
	return out
}

// multiProbe is a minimal mihomo config fragment that ONLY a multi-protocol
// engine claims — the always-registered built-in socks5 engine declines it
// (it is not a socks5:// URL). So "some engine claims this" ⟺ the enterprise
// mihomo engine is compiled in.
const multiProbe = `{"proxies":[]}`

// MultiProtocolAvailable reports whether this build has the enterprise
// multi-protocol (mihomo) engine. The open-source build returns false, which
// the node-level upstream (app.buildTransport) uses to degrade to the original
// single-URL mode instead of failing. UI surfaces gate their multi-protocol
// affordances on this too.
func MultiProtocolAvailable() bool {
	for _, e := range engines {
		if e.Claims(multiProbe) {
			return true
		}
	}
	return false
}

// IsEngineSpec reports whether a spec is a multi-hop chain or a config fragment
// (i.e. NOT a plain single proxy URL). It is the node-level dispatch
// discriminator: engine-specs need the egress engine (and, for the node-level
// upstream, the enterprise build); a plain single URL takes the original
// http.ProxyURL path that works in every build.
//
// A single "socks5://host:1080" is intentionally NOT an engine-spec here: the
// node-level upstream serves it via the original single-URL path (net/http
// supports socks5 proxies natively), so single-URL upstreams keep working in
// the open-source build. Chains (comma) and fragments require the engine.
func IsEngineSpec(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "" {
		return false
	}
	if isFragment(s) {
		return true
	}
	return strings.Contains(s, ",")
}

// isFragment matches a mihomo config fragment (proxies and/or proxy-groups:
// fallback/url-test/load-balance). Kept in sync with the admin-side
// validateEgressProxyURL shape check so /user/settings and the master
// per-account editor accept exactly the same forms (config alignment).
func isFragment(s string) bool {
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") ||
		strings.HasPrefix(s, "-") || strings.HasPrefix(s, "proxies:") ||
		strings.HasPrefix(s, "proxy-groups:") ||
		// `rules:` (2026-07-30 DIRECT-bypass lists) is a fragment key like the
		// others — the leading key follows the operator's authoring order. Missing
		// it here made a rules-first fragment fall through to the socks5-chain
		// validator, so an OSS user got "each hop must be socks5" instead of the
		// actionable "this needs the enterprise offline package".
		strings.HasPrefix(s, "rules:")
}

// IsFragment reports whether a trimmed spec is a multi-protocol config fragment
// (vs a single URL or a socks5 chain). Exported so the node-level upstream
// validator can reject fragments early on a build without the multi-protocol
// engine, with an actionable message instead of a dial-time failure.
func IsFragment(spec string) bool { return isFragment(strings.TrimSpace(spec)) }

// ValidateSpec validates an egress spec's shape at write time so a bad value is
// rejected loudly at the setter rather than silently going direct at request
// time. It mirrors the master-side validateEgressProxyURL so both the
// /user/settings node-level upstream and the per-account editor accept the same
// forms (config alignment):
//
//   - config fragment (starts with {, [, -, proxies:, proxy-groups:, rules:) →
//     shape-accept; deep validation happens in the mihomo engine at Build.
//   - socks5 chain → every comma hop must be socks5://host:port; ≥1 hop.
//
// A plain single non-socks5 URL (http/https) is NOT accepted here — the
// node-level caller handles single URLs on its own url.Parse path; ValidateSpec
// only gates engine-specs.
func ValidateSpec(spec string) error {
	s := strings.TrimSpace(spec)
	if s == "" {
		return fmt.Errorf("empty egress spec")
	}
	if isFragment(s) {
		return nil
	}
	hops := 0
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, err := url.Parse(part)
		if err != nil {
			return fmt.Errorf("not a valid URL: %s", part)
		}
		if u.Scheme != "socks5" {
			return fmt.Errorf("each hop must be socks5 (e.g. socks5://host:1080, or socks5://front:1080,socks5://exit:1080): %s", part)
		}
		if u.Host == "" {
			return fmt.Errorf("hop missing host:port: %s", part)
		}
		hops++
	}
	if hops == 0 {
		return fmt.Errorf("empty chain")
	}
	return nil
}
