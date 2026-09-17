package pipewire

// capabilities.go — the PARENT→CHILD capability declaration carried on the spawn
// environment (TODO-114, user decision 2026-09-15 方案 A「能力声明门控」; 需求包
// roadmap20260320/技术实现/阶段9-商业化版本/博时基金合规能力融合/
// task-execution/runs/design-todo-114.md).
//
// # WHY THIS EXISTS
//
// The pipe protocol's handshake only runs CHILD → PARENT: the detector announces
// itself, the proxy does not announce anything back. So a NEW detector has no way
// to ask "can the proxy that spawned me actually process what I am about to hand
// it?" — it just hands it over and hopes.
//
// That gap already produced one release-skew defect. TODO-87 made the detector
// return a content-free CountProjection in Response.Event on the PERSONAL route.
// An OLD proxy decodes Response.Event with the same `findings` decoder on every
// route, so it reads the projection as an event's findings and can refuse the
// request on a cumulative rule — but it only writes the request-verdict audit row
// on the TEAM branch. Net effect: the request is refused and NOTHING anywhere
// records why. And R-compliance-grading-6 prescribes the release order
// master → console → detector → proxy, so "new detector, old proxy" is not an
// accident, it is the specified intermediate state.
//
// The fix is one bit in the other direction: the proxy declares, at spawn, what
// it can process; the detector sends the projection only when it sees the
// declaration. An undeclared (older) proxy gets what it got before TODO-87 —
// nothing — so the personal route simply does not count, which is the behaviour
// that shipped and is not a silent refusal.
//
// # WHY ONE ENV WITH A TOKEN LIST, NOT ONE ENV PER CAPABILITY
//
// A per-capability env (AIKEY_PROXY_ACCEPTS_COUNT_PROJECTION=1) needs no parser,
// but every new capability then adds an env NAME that both repositories spell by
// hand — the exact shape TODO-85 (the action code written three times) and
// TODO-93 (env names hand-copied) were opened for. It also cannot be made
// residue-proof cheaply: the proxy would have to emit an explicit `=0` for every
// capability it lacks, and the one that gets forgotten is a hole.
//
// One env plus ONE parser, defined here and imported by both sides, costs a
// dozen lines and makes the residue defence a single unconditional line (see
// ProxyCapabilitiesEnv in aikey-proxy internal/apphook/capabilities.go).
//
// # PARSING RULES, AND WHY EACH ONE
//
//   - EXACT TOKEN match, comma separated, surrounding whitespace trimmed. A
//     substring match would make `count_projection_v2` satisfy a reader that only
//     understands `count_projection`, i.e. a future incompatible revision would
//     silently be treated as the old one. Semantics change ⇒ NEW TOKEN.
//   - CASE SENSITIVE. The tokens are produced by one function in this file and
//     consumed by one function in this file; nothing types them by hand. Folding
//     case would only ever admit a value that some other, non-declaring process
//     put in the environment.
//   - UNKNOWN TOKENS ARE KEPT AND IGNORED. A newer proxy may declare capabilities
//     this detector has never heard of; dropping them here is fine, failing on
//     them would turn a forward-compatible declaration into a crash.
//   - THE EMPTY SET FORMATS AS "". The caller still emits the `NAME=` line; see
//     ProxyCapabilitiesEnv for why an always-present line is the whole residue
//     defence.
//
// 🔴 NOT AN OPERATIONS SWITCH. This env is written by the proxy for its own
// children and by nothing else — no installer, no template, no proxy.env, no
// documentation. It states a property of the parent BINARY, so a value found in
// a configuration file can only ever be a lie about what that binary can do.

import (
	"sort"
	"strings"
)

// EnvProxyCapabilities is the spawn-environment variable on which the parent
// (aikey-proxy) declares what it can process from its child.
const EnvProxyCapabilities = "AIKEY_PROXY_CAPABILITIES"

const (
	// CapCountProjection: the parent decodes Response.Event on a PERSONAL-routed
	// Detect as a CountProjection and feeds it to its request-level escalation
	// counter (TODO-87). A parent that does NOT declare it must be handed an
	// empty Event slot on that route.
	CapCountProjection = "count_projection"
	// CapCannedAnswer: the parent can SERVE an administrator-authored canned
	// answer (代答) instead of forwarding — it holds the response synthesizer for
	// all three protocol families, streaming and not (aikey-proxy
	// internal/proxy/canned_answer.go writeCannedAnswer).
	//
	// Declared today, CONSUMED BY NOBODY today: the detector deliberately does
	// not read this token yet (TODO-68), because the observation-period safety
	// valve does not cap 代答 yet (TODO-91 open). See the design §2.5 / §9.1
	// ruling — proxy declares the truth, the detector starts consuming in a later
	// release, and that later release needs no proxy change.
	CapCannedAnswer = "canned_answer"
)

// ProxyCapabilities is a parsed capability declaration. The zero value is a
// valid EMPTY set, which is what an absent env must read as — so a caller that
// forgets to check an error still gets the safe answer (nothing is declared).
type ProxyCapabilities struct {
	tokens map[string]struct{}
}

// Has reports whether the parent declared exactly this capability token.
func (c ProxyCapabilities) Has(capability string) bool {
	if c.tokens == nil {
		return false
	}
	_, ok := c.tokens[capability]
	return ok
}

// Len is the number of distinct tokens parsed, unknown ones included. For tests
// and diagnostics only — behaviour is decided by Has, never by the count.
func (c ProxyCapabilities) Len() int { return len(c.tokens) }

// FormatProxyCapabilities renders a capability set as the env VALUE: sorted,
// de-duplicated, comma separated, no spaces. An empty (or all-blank) set renders
// as "" — the caller is expected to still emit `EnvProxyCapabilities + "=" + ""`.
//
// Sorted so the value is a pure function of the SET: the byte string must not
// change because someone reordered a switch statement, or a reader diffing two
// spawns sees a change that is not one.
func FormatProxyCapabilities(capabilities []string) string {
	seen := make(map[string]struct{}, len(capabilities))
	out := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// ParseProxyCapabilities reads the env VALUE back into a set. It never fails:
// anything it cannot make sense of simply is not in the set, and "not declared"
// is the safe direction for every caller.
func ParseProxyCapabilities(raw string) ProxyCapabilities {
	c := ProxyCapabilities{}
	for _, tok := range strings.Split(raw, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if c.tokens == nil {
			c.tokens = make(map[string]struct{}, 4)
		}
		c.tokens[tok] = struct{}{}
	}
	return c
}
