package providerroutes

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ModelRule is one entry of a provider's model_map: rewrite a client-facing
// model name (match) to the real upstream model name (RequestedModel).
//
// match ∈ { literal client id ("claude-opus-4-8") | role ("opus"/"sonnet"/
// "haiku"/"fable") | wildcard "*" }. RequestedModel reuses the provider_model_id
// semantics (the name the upstream actually receives, e.g. "glm-4.6").
type ModelRule struct {
	Match          string `yaml:"match" json:"match"`
	RequestedModel string `yaml:"requested_model" json:"requested_model"`
	// DisplayName (optional) is the Desktop-menu-facing label. When present it
	// must be claude-safe (validated at build time) because Claude Desktop
	// rejects non-conforming model ids.
	DisplayName string `yaml:"display_name,omitempty" json:"display_name,omitempty"`
	Supports1M  bool   `yaml:"supports_1m,omitempty" json:"supports_1m,omitempty"`
}

// ModelMap is a provider's ordered mapping table plus its unmatched policy.
// Keyed by provider CODE (matching provider_routes.provider), which is why it
// lives in its own code-keyed section rather than on the classifier-id-keyed
// `providers` section or duplicated across a provider's multiple route rows
// (design D-2: single source of truth, no per-endpoint duplication).
type ModelMap struct {
	Provider string `yaml:"provider" json:"provider"`
	// Unmatched ∈ {"reject","passthrough"}. Empty defaults to "passthrough"
	// (the officially-same-name case); design D-2 / task 0.4.
	Unmatched string      `yaml:"unmatched,omitempty" json:"unmatched,omitempty"`
	Models    []ModelRule `yaml:"models" json:"models"`
}

const (
	UnmatchedReject      = "reject"
	UnmatchedPassthrough = "passthrough"
)

// rolesInMatchOrder is the role families a `match` may name, in a FIXED
// iteration order (Claude Desktop family menu: opus/sonnet/haiku/fable). The
// order is load-bearing: when two role tokens co-occur in one id (e.g.
// "claude-opus-haiku-1"), roleOfModel returns the first match in THIS order —
// deterministic, unlike Go's randomized map iteration. Single source of truth
// for knownRoles below. Mirrors Rust KNOWN_ROLES.
var rolesInMatchOrder = []string{"opus", "sonnet", "haiku", "fable"}

// knownRoles is the set form of rolesInMatchOrder for O(1) membership tests
// (isRoleToken / ResolveModel role loop). Derived from the ordered slice so the
// two never drift.
var knownRoles = func() map[string]struct{} {
	m := make(map[string]struct{}, len(rolesInMatchOrder))
	for _, r := range rolesInMatchOrder {
		m[r] = struct{}{}
	}
	return m
}()

// roleOfModel extracts the role family from a claude-style model id, e.g.
// "claude-opus-4-8" → "opus". Returns "" when no known role token is present as
// a segment-aligned token.
//
// Segment-aligned ONLY — the role must be a whole "-"-delimited token: exact
// ("opus"), prefix ("opus-…"), suffix ("…-opus"), or infix ("…-opus-…"). A
// loose strings.Contains(lower, "-"+role) fallback used to live here; it made
// the anchored clauses dead code and mis-classified ids like "claude-haikuish-1"
// as haiku. Removed — feeds ResolveModel → wrong upstream model otherwise.
//
// Case-folding parity: Go strings.ToLower (Unicode) and Rust to_ascii_lowercase
// agree on the claude-id charset (ASCII a–z / 0–9 / '-'). They diverge only on
// non-ASCII code points (Kelvin sign, Turkish dotted-I, etc.), none of which
// appear in a claude model id — no residual behavioral difference on real ids.
func roleOfModel(model string) string {
	lower := strings.ToLower(model)
	for _, role := range rolesInMatchOrder {
		if lower == role ||
			strings.HasPrefix(lower, role+"-") ||
			strings.HasSuffix(lower, "-"+role) ||
			strings.Contains(lower, "-"+role+"-") {
			return role
		}
	}
	return ""
}

// AllModelMaps returns every parsed model_map, sorted by provider code for
// deterministic output (golden-fixture / cross-language parity). Iterates the
// full set — no white-list — so a new map is auto-covered by parity tests.
func (t *Table) AllModelMaps() []ModelMap {
	codes := make([]string, 0, len(t.modelMaps))
	for c := range t.modelMaps {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	out := make([]ModelMap, 0, len(codes))
	for _, c := range codes {
		out = append(out, t.modelMaps[c])
	}
	return out
}

// ModelMapFor returns the model_map for a provider code (case-insensitive),
// ok=false when the provider has no mapping (→ callers passthrough).
func (t *Table) ModelMapFor(provider string) (ModelMap, bool) {
	m, ok := t.modelMaps[strings.ToLower(provider)]
	return m, ok
}

// ResolveModel applies a provider's model_map to a client-requested model.
// Match precedence is exact id → role → wildcard (design D-3 / task 0.4:
// "精确优先，歧义不猜"), independent of yaml array order. Returns:
//   - effective: the upstream model name to send
//   - matched: whether any rule matched
//   - policy: the unmatched policy to apply when matched==false
//     ("reject"/"passthrough")
//
// When the provider has no model_map at all, matched=false and policy defaults
// to passthrough (no mapping configured = officially-same-name flow).
func (t *Table) ResolveModel(provider, requested string) (effective string, matched bool, policy string) {
	mm, ok := t.ModelMapFor(provider)
	if !ok {
		return requested, false, UnmatchedPassthrough
	}
	policy = mm.Unmatched
	if policy == "" {
		policy = UnmatchedPassthrough
	}
	// exact
	for _, r := range mm.Models {
		if r.Match == requested {
			return r.RequestedModel, true, policy
		}
	}
	// role
	if role := roleOfModel(requested); role != "" {
		for _, r := range mm.Models {
			if _, isRole := knownRoles[strings.ToLower(r.Match)]; isRole && strings.EqualFold(r.Match, role) {
				return r.RequestedModel, true, policy
			}
		}
	}
	// wildcard
	for _, r := range mm.Models {
		if r.Match == "*" {
			return r.RequestedModel, true, policy
		}
	}
	return requested, false, policy
}

// claudeSafeRe mirrors aikey-cli is_claude_safe_model_id (claude_desktop.rs):
// claude-{opus|sonnet|haiku|fable}-{version…}. A literal `match` that starts
// with "claude-" must be a name Claude Desktop can actually send, else the
// rule is dead. Fail-all at build time (task 1.3).
var claudeSafeRe = regexp.MustCompile(`^claude-(opus|sonnet|haiku|fable)-[0-9][0-9A-Za-z\-]*$`)

func isClaudeSafe(name string) bool { return claudeSafeRe.MatchString(name) }

// secretShaped matches strings that look like credentials — model_map values
// must never contain them (this yaml ships to every customer). Scoped to
// model_map values only, NOT the classifier `providers` regex section (which
// legitimately contains key-prefix patterns).
var secretShaped = regexp.MustCompile(`(?i)(sk-[a-z0-9]|sk_live|sk_test|xai-|gsk_|AKIA[0-9A-Z]|ghp_|xox[bp]-|AIza[0-9A-Za-z])`)

// ValidateModelMaps performs build-time checks over the parsed model_maps:
//  1. no ambiguous rules (duplicate exact match / duplicate role / duplicate
//     wildcard) → MODEL_MAPPING_AMBIGUOUS
//  2. no secret-shaped strings in match / requested_model / display_name
//  3. unmatched ∈ {"", reject, passthrough}
//  4. every rule has non-empty match and requested_model
//
// Returns a joined error describing all violations (empty error = valid). Meant
// to run as a default (non-env-gated) test so a bad yaml fails the build.
func (t *Table) ValidateModelMaps() error {
	var problems []string
	for code, mm := range t.modelMaps {
		if mm.Unmatched != "" && mm.Unmatched != UnmatchedReject && mm.Unmatched != UnmatchedPassthrough {
			problems = append(problems, fmt.Sprintf("provider %q: unmatched %q not in {reject,passthrough}", code, mm.Unmatched))
		}
		seenExact := map[string]struct{}{}
		seenRole := map[string]struct{}{}
		wildcards := 0
		for i, r := range mm.Models {
			if r.Match == "" || r.RequestedModel == "" {
				problems = append(problems, fmt.Sprintf("provider %q rule %d: empty match or requested_model", code, i))
				continue
			}
			for field, v := range map[string]string{"match": r.Match, "requested_model": r.RequestedModel, "display_name": r.DisplayName} {
				if v != "" && secretShaped.MatchString(v) {
					problems = append(problems, fmt.Sprintf("provider %q rule %d: %s %q looks secret-shaped (yaml ships to all customers)", code, i, field, v))
				}
			}
			// is_claude_safe fail-all: a literal claude-* match must be a valid
			// Desktop-sendable id (task 1.3). Role tokens and "*" are exempt.
			if strings.HasPrefix(strings.ToLower(r.Match), "claude-") && !isClaudeSafe(r.Match) {
				problems = append(problems, fmt.Sprintf("provider %q rule %d: match %q not is_claude_safe (Desktop can't send it)", code, i, r.Match))
			}
			switch {
			case r.Match == "*":
				wildcards++
				if wildcards > 1 {
					problems = append(problems, fmt.Sprintf("provider %q: MODEL_MAPPING_AMBIGUOUS — multiple wildcard rules", code))
				}
			case isRoleToken(r.Match):
				if _, dup := seenRole[strings.ToLower(r.Match)]; dup {
					problems = append(problems, fmt.Sprintf("provider %q: MODEL_MAPPING_AMBIGUOUS — duplicate role %q", code, r.Match))
				}
				seenRole[strings.ToLower(r.Match)] = struct{}{}
			default:
				if _, dup := seenExact[r.Match]; dup {
					problems = append(problems, fmt.Sprintf("provider %q: MODEL_MAPPING_AMBIGUOUS — duplicate exact match %q", code, r.Match))
				}
				seenExact[r.Match] = struct{}{}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("model_map validation failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

func isRoleToken(s string) bool {
	_, ok := knownRoles[strings.ToLower(s)]
	return ok
}
