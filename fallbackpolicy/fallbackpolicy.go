// Package fallbackpolicy is the SHARED contract for the five upstream-fallback
// thresholds (openspec change `aliyun-aigw-p0-upstream-fallback`, tasks 0.14 /
// 1b.2 / 1b.3 / 1b.6 / 1b.7).
//
// It lives in pkg/ for the same reason routingwire does: the control plane emits
// these values and the proxy consumes them, so a private copy on each side is a
// wire that can drift silently. One definition, two importers.
//
// # 🔴 The three-state rule (I22) is the whole point of this package
//
// `未配置` / `0` / `a concrete value` are THREE different things:
//
//	unset          → fall through to the next source (local yaml, then builtin)
//	0              → an EXPLICIT choice, and for some fields a legal one
//	concrete value → use it
//
// The worst incident shape this prevents: treating "unset" as 0. On upgrade every
// organization would instantly get cooldown=0 (so every request retries a known-dead
// upstream first) and budget=0 (so every request fails immediately). Nothing would
// look broken in the config UI — the numbers would read as zero because they ARE zero.
//
// That is why the fields are POINTERS, and why this package exposes no plain int64
// getter that could paper over nil. Every read returns a Resolved value carrying its
// Source, so "where did this number come from" is always answerable.
//
// ⚠️ Inherited verbatim from the sister change `aliyun-aigw-p0-rate-limit` (its I1).
// 🚫 Do not re-derive it, and 🚫 do not let the two changes implement it differently.
package fallbackpolicy

import (
	"errors"
	"fmt"
)

// Source names the layer a resolved value came from. Part of the contract, not a
// debugging aid: task 1b.7 requires every threshold to report its origin, because
// "I set it to 10 seconds in the console" and "the default happens to be 10 seconds"
// are otherwise indistinguishable — and that ambiguity is what turns a
// private-deployment call into two hours of mutual disbelief.
type Source string

const (
	// SourceOrg — configured in the control plane for this organization.
	SourceOrg Source = "org"
	// SourceLocalYAML — the proxy's own config file. Only ONE threshold has this
	// layer (see LocalOverrides); inventing it for the others would recreate the
	// four-source base_url drift this project has already paid for.
	SourceLocalYAML Source = "local_yaml"
	// SourceBuiltin — the compiled-in default. Never absent, so resolution always
	// terminates with an answer.
	SourceBuiltin Source = "builtin"
)

// Field identifies one threshold, so both sides spell the names identically.
type Field string

const (
	FieldUpstreamAttemptTimeout Field = "upstream_attempt_timeout_ms"
	FieldChainTotalBudget       Field = "chain_total_budget_ms"
	FieldBindingCooldown        Field = "binding_cooldown_ms"
	FieldIdleGap                Field = "idle_gap_ms"
	FieldMaxStickiness          Field = "max_stickiness_ms"
)

// Builtin defaults (task 0.14 / F-9b). Units are int64 MILLISECONDS throughout,
// matching this repository's existing timestamp convention.
//
// 🔴 These are ENGINEERING PLACEHOLDERS, not calibrated values — F-9b says so
// outright, and it matters: too low an attempt timeout turns a healthy-but-slow
// long-context request into "the upstream is down", which then cools that upstream
// off for minutes. Before release they must be checked against the real
// upstream-latency and session-gap distributions (we have both).
const (
	DefaultUpstreamAttemptTimeoutMs int64 = 120_000
	// DefaultChainTotalBudgetMs — 🔴 MUST stay visibly below
	// (attempt timeout × chain length) or the cap is decorative. Today's
	// 120s × 3 hops = 360s, and a client (Claude Code) gives up long before that:
	// the user sees a hang, kills it, and pays the same 6 minutes again.
	DefaultChainTotalBudgetMs int64 = 180_000
	DefaultBindingCooldownMs  int64 = 300_000   // 5 min
	DefaultIdleGapMs          int64 = 300_000   // 5 min
	DefaultMaxStickinessMs    int64 = 1_800_000 // 30 min
)

// Bounds per field. Enforced in the CONTROL PLANE (task 1b.2) because the API is
// reachable independently of the console: front-end validation is a courtesy,
// back-end validation is the rule.
const (
	MinTimeoutMs int64 = 1_000
	MaxTimeoutMs int64 = 600_000

	MinBudgetMs int64 = 1_000
	MaxBudgetMs int64 = 1_800_000

	MaxCooldownMs   int64 = 3_600_000
	MaxIdleGapMs    int64 = 86_400_000
	MaxStickinessMs int64 = 86_400_000
)

// Policy is one organization's configured thresholds.
//
// 🔴 Every field is a POINTER so "unset" is representable. A struct of plain int64
// cannot distinguish "the admin chose 0" from "the admin chose nothing", and that
// single collapse is the incident described in the package doc.
type Policy struct {
	UpstreamAttemptTimeoutMs *int64 `json:"upstream_attempt_timeout_ms,omitempty"`
	ChainTotalBudgetMs       *int64 `json:"chain_total_budget_ms,omitempty"`
	BindingCooldownMs        *int64 `json:"binding_cooldown_ms,omitempty"`
	IdleGapMs                *int64 `json:"idle_gap_ms,omitempty"`
	MaxStickinessMs          *int64 `json:"max_stickiness_ms,omitempty"`
}

// Resolved is one threshold's effective value together with where it came from.
type Resolved struct {
	Value  int64  `json:"value"`
	Source Source `json:"source"`
}

// Effective is the full resolved set — what the health endpoint reports (task 1b.9)
// and what a single request snapshots (task 1b.6).
type Effective struct {
	UpstreamAttemptTimeout Resolved `json:"upstream_attempt_timeout_ms"`
	ChainTotalBudget       Resolved `json:"chain_total_budget_ms"`
	BindingCooldown        Resolved `json:"binding_cooldown_ms"`
	IdleGap                Resolved `json:"idle_gap_ms"`
	MaxStickiness          Resolved `json:"max_stickiness_ms"`
}

// LocalOverrides carries the proxy's own config-file layer.
//
// 🔴 Only the per-attempt timeout has one, because only it already existed as
// `providers.<name>.timeout`. Task 1b.7 fixes the precedence rather than widening
// it; B8 explicitly declines an emergency local override for the rest and records
// why — machines in one group would disagree, producing contradictory symptoms
// nobody thinks to blame on config.
type LocalOverrides struct {
	UpstreamAttemptTimeoutMs *int64
}

// Resolve applies the frozen precedence — org → local yaml → builtin, first hit
// wins — and stamps each value with its source (task 1b.7).
//
// 🚫 No `unwrap_or(0)`-shaped shortcut anywhere: a nil pointer means "not configured
// at this layer" and FALLS THROUGH; it never becomes a zero. That is I22, and the
// proxy's grep fence exists to keep it.
func Resolve(org *Policy, local LocalOverrides) Effective {
	pick := func(orgVal, localVal *int64, builtin int64) Resolved {
		if orgVal != nil {
			return Resolved{Value: *orgVal, Source: SourceOrg}
		}
		if localVal != nil {
			return Resolved{Value: *localVal, Source: SourceLocalYAML}
		}
		return Resolved{Value: builtin, Source: SourceBuiltin}
	}
	var p Policy
	if org != nil {
		p = *org
	}
	return Effective{
		UpstreamAttemptTimeout: pick(p.UpstreamAttemptTimeoutMs, local.UpstreamAttemptTimeoutMs, DefaultUpstreamAttemptTimeoutMs),
		// The remaining four have no local layer — passing nil is the point, not
		// an oversight.
		ChainTotalBudget: pick(p.ChainTotalBudgetMs, nil, DefaultChainTotalBudgetMs),
		BindingCooldown:  pick(p.BindingCooldownMs, nil, DefaultBindingCooldownMs),
		IdleGap:          pick(p.IdleGapMs, nil, DefaultIdleGapMs),
		MaxStickiness:    pick(p.MaxStickinessMs, nil, DefaultMaxStickinessMs),
	}
}

// ValidationError names the offending field so the console can highlight it and the
// operator learns which number to change.
type ValidationError struct {
	Field   Field
	Message string
}

func (e *ValidationError) Error() string { return string(e.Field) + ": " + e.Message }

// Validate enforces the control-plane rules from task 1b.2.
//
// 🔴 Zero is NOT uniformly legal, and the split is behavioral rather than stylistic:
//
//	binding_cooldown_ms = 0          ✅ legal — "never cool down": the admin accepts
//	                                    hitting a dead upstream once per request in
//	                                    exchange for instant recovery.
//	idle_gap_ms = 0                  ✅ legal — always probe the primary.
//	max_stickiness_ms = 0            ✅ legal — never stick.
//	upstream_attempt_timeout_ms = 0  🚫 rejected — an upstream given zero
//	                                    milliseconds can never answer.
//	chain_total_budget_ms = 0        🚫 rejected — every request would fail
//	                                    instantly, so saving it is never the intent.
//
// 🔴 Cross-field: budget ≥ attempt timeout. Otherwise the FIRST hop is already over
// budget and no fallback is ever reached — the chain the admin configured would be
// dead on arrival, silently.
func (p *Policy) Validate() error {
	if p == nil {
		return nil // nothing configured is always valid
	}
	inRange := func(f Field, v *int64, lo, hi int64) error {
		if v == nil {
			return nil
		}
		if *v < lo || *v > hi {
			return &ValidationError{Field: f, Message: fmt.Sprintf(
				"%d is out of range [%d, %d]", *v, lo, hi)}
		}
		return nil
	}
	// Rejecting 0 follows from the lower bound for these two, but state it
	// explicitly so the operator gets the REASON, not just a range.
	if p.UpstreamAttemptTimeoutMs != nil && *p.UpstreamAttemptTimeoutMs == 0 {
		return &ValidationError{Field: FieldUpstreamAttemptTimeout,
			Message: "0 is not allowed: an upstream given zero milliseconds can never answer"}
	}
	if p.ChainTotalBudgetMs != nil && *p.ChainTotalBudgetMs == 0 {
		return &ValidationError{Field: FieldChainTotalBudget,
			Message: "0 is not allowed: every request would fail immediately, which is never the intent"}
	}
	if err := inRange(FieldUpstreamAttemptTimeout, p.UpstreamAttemptTimeoutMs, MinTimeoutMs, MaxTimeoutMs); err != nil {
		return err
	}
	if err := inRange(FieldChainTotalBudget, p.ChainTotalBudgetMs, MinBudgetMs, MaxBudgetMs); err != nil {
		return err
	}
	if err := inRange(FieldBindingCooldown, p.BindingCooldownMs, 0, MaxCooldownMs); err != nil {
		return err
	}
	if err := inRange(FieldIdleGap, p.IdleGapMs, 0, MaxIdleGapMs); err != nil {
		return err
	}
	if err := inRange(FieldMaxStickiness, p.MaxStickinessMs, 0, MaxStickinessMs); err != nil {
		return err
	}
	// 🔴 Compare EFFECTIVE values, not just the configured pair: setting only the
	// budget must still be checked against the timeout actually in force, or the
	// rule is bypassed by leaving one field unset.
	eff := Resolve(p, LocalOverrides{})
	if eff.ChainTotalBudget.Value < eff.UpstreamAttemptTimeout.Value {
		return &ValidationError{Field: FieldChainTotalBudget, Message: fmt.Sprintf(
			"overall wait limit (%dms) is below the per-attempt limit (%dms): the first hop would "+
				"already exceed the budget, so no fallback upstream would ever be tried",
			eff.ChainTotalBudget.Value, eff.UpstreamAttemptTimeout.Value)}
	}
	return nil
}

// ErrNoSecrets is returned by AssertNoSecretShaped when a payload looks like it is
// carrying credential material.
var ErrNoSecrets = errors.New("fallback policy payload must not contain secret-shaped strings")

// AssertNoSecretShaped backs task 1b.5: the policy rail carries NON-SECRET material
// only. Addresses and key ciphertext keep travelling on the delivery snapshot, where
// the encryption boundary already lives.
//
// It guards a one-way door: once a secret has gone out over a side channel, rotating
// it is the only remedy. Five int64 pointers cannot hold a key today — this exists so
// that stays true when somebody later adds "just one string field".
func AssertNoSecretShaped(jsonPayload string) error {
	for _, marker := range []string{"sk-", "sk_live", "Bearer ", "-----BEGIN", "api_key", "provider_key", "ciphertext"} {
		if containsFold(jsonPayload, marker) {
			return fmt.Errorf("%w: found %q", ErrNoSecrets, marker)
		}
	}
	return nil
}

func containsFold(haystack, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	lower := func(b byte) byte {
		if 'A' <= b && b <= 'Z' {
			return b + ('a' - 'A')
		}
		return b
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if lower(haystack[i+j]) != lower(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
