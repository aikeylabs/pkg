package fallbackpolicy

import (
	"encoding/json"
	"errors"
	"testing"
)

func p(v int64) *int64 { return &v }

// ── 🔴 I22: unset / 0 / value are three distinct states ─────────────────────
//
// This is the assertion the whole package exists for. P6.2's injection is
// "把 `未配置` 当成 `0`" → the "unset falls through to default" case must go red.
func TestThreeStateSemanticsUnsetIsNotZero(t *testing.T) {
	// UNSET → falls through to builtin.
	unset := Resolve(&Policy{}, LocalOverrides{})
	if unset.BindingCooldown.Value != DefaultBindingCooldownMs ||
		unset.BindingCooldown.Source != SourceBuiltin {
		t.Errorf("unset cooldown resolved to %+v, want builtin default %d.\n"+
			"Collapsing unset into 0 is THE incident this package prevents: on upgrade every org "+
			"would silently get cooldown=0, so every request retries a known-dead upstream first, "+
			"and the config UI would look fine because the number really is zero.",
			unset.BindingCooldown, DefaultBindingCooldownMs)
	}

	// EXPLICIT ZERO → honored as a real choice, and reported as org-configured.
	zero := Resolve(&Policy{BindingCooldownMs: p(0)}, LocalOverrides{})
	if zero.BindingCooldown.Value != 0 || zero.BindingCooldown.Source != SourceOrg {
		t.Errorf("explicit 0 cooldown resolved to %+v, want {0 org}. An admin who deliberately "+
			"disables cooling is accepting one wasted attempt per request in exchange for instant "+
			"recovery — silently replacing that with the default overrides their decision",
			zero.BindingCooldown)
	}

	// CONCRETE VALUE → used as given.
	set := Resolve(&Policy{BindingCooldownMs: p(42_000)}, LocalOverrides{})
	if set.BindingCooldown.Value != 42_000 || set.BindingCooldown.Source != SourceOrg {
		t.Errorf("configured cooldown resolved to %+v, want {42000 org}", set.BindingCooldown)
	}

	// And the three states are genuinely distinguishable from each other.
	if unset.BindingCooldown.Value == zero.BindingCooldown.Value {
		t.Error("unset and explicit-0 produced the same value — the two states have collapsed")
	}
}

// ── 1b.7: precedence, and every value reports its source ────────────────────
func TestPrecedenceOrgThenLocalYAMLThenBuiltin(t *testing.T) {
	local := LocalOverrides{UpstreamAttemptTimeoutMs: p(30_000)}

	// org beats local yaml
	got := Resolve(&Policy{UpstreamAttemptTimeoutMs: p(5_000), ChainTotalBudgetMs: p(60_000)}, local)
	if got.UpstreamAttemptTimeout.Value != 5_000 || got.UpstreamAttemptTimeout.Source != SourceOrg {
		t.Errorf("org value must win over local yaml, got %+v", got.UpstreamAttemptTimeout)
	}

	// local yaml beats builtin
	got = Resolve(&Policy{}, local)
	if got.UpstreamAttemptTimeout.Value != 30_000 || got.UpstreamAttemptTimeout.Source != SourceLocalYAML {
		t.Errorf("local yaml must win over builtin, got %+v", got.UpstreamAttemptTimeout)
	}

	// builtin is the terminal layer
	got = Resolve(nil, LocalOverrides{})
	if got.UpstreamAttemptTimeout.Source != SourceBuiltin {
		t.Errorf("with nothing configured the source must be builtin, got %+v", got.UpstreamAttemptTimeout)
	}

	// 🔴 Every field reports a source. A blank one means the console cannot tell
	// the admin whether their save took effect.
	for name, r := range map[string]Resolved{
		"attempt_timeout": got.UpstreamAttemptTimeout,
		"chain_budget":    got.ChainTotalBudget,
		"cooldown":        got.BindingCooldown,
		"idle_gap":        got.IdleGap,
		"max_stickiness":  got.MaxStickiness,
	} {
		if r.Source == "" {
			t.Errorf("%s has no source. Without it, an admin's configured 5 minutes and the "+
				"default 5 minutes look identical, and they can never confirm the save landed", name)
		}
	}
}

// 🔴 Only the per-attempt timeout has a local-yaml layer. Widening it would
// recreate the four-source base_url drift this project has already paid for.
func TestOnlyAttemptTimeoutHasALocalYAMLLayer(t *testing.T) {
	eff := Resolve(&Policy{}, LocalOverrides{UpstreamAttemptTimeoutMs: p(7_000)})
	for name, r := range map[string]Resolved{
		"chain_budget":   eff.ChainTotalBudget,
		"cooldown":       eff.BindingCooldown,
		"idle_gap":       eff.IdleGap,
		"max_stickiness": eff.MaxStickiness,
	} {
		if r.Source == SourceLocalYAML {
			t.Errorf("%s resolved from local yaml. Only the per-attempt timeout has that layer "+
				"(it already existed as providers.<name>.timeout); adding more means two machines "+
				"in one group can disagree, producing contradictory symptoms nobody blames on config",
				name)
		}
	}
}

// ── 1b.2: zero is legal for some fields and rejected for others ─────────────
func TestValidateZeroIsLegalForCooldownButNotForBudgetOrTimeout(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  Policy
		wantErr bool
		field   Field
	}{
		{"cooldown 0 = never cool down", Policy{BindingCooldownMs: p(0)}, false, ""},
		{"idle gap 0 = always probe primary", Policy{IdleGapMs: p(0)}, false, ""},
		{"stickiness 0 = never stick", Policy{MaxStickinessMs: p(0)}, false, ""},
		{"attempt timeout 0 is impossible", Policy{UpstreamAttemptTimeoutMs: p(0)}, true, FieldUpstreamAttemptTimeout},
		{"budget 0 fails every request", Policy{ChainTotalBudgetMs: p(0)}, true, FieldChainTotalBudget},
		{"nothing configured is valid", Policy{}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.policy.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
			if tc.wantErr {
				var ve *ValidationError
				if !errors.As(err, &ve) {
					t.Fatalf("want *ValidationError, got %T", err)
				}
				if ve.Field != tc.field {
					t.Errorf("error names field %q, want %q — the console highlights by field",
						ve.Field, tc.field)
				}
			}
		})
	}
}

// 🔴 The cross-field rule, checked against EFFECTIVE values so it cannot be
// bypassed by leaving one field unset.
func TestValidateRejectsBudgetBelowAttemptTimeout(t *testing.T) {
	// Both configured, budget too small.
	err := (&Policy{UpstreamAttemptTimeoutMs: p(120_000), ChainTotalBudgetMs: p(60_000)}).Validate()
	if err == nil {
		t.Fatal("a budget below the per-attempt limit was accepted. The first hop would already " +
			"exceed it, so no fallback upstream would ever be tried — the admin's chain would be " +
			"dead on arrival, silently")
	}

	// 🔴 Only the budget configured, and it is below the BUILTIN timeout. Comparing
	// just the configured pair would miss this.
	err = (&Policy{ChainTotalBudgetMs: p(5_000)}).Validate()
	if err == nil {
		t.Fatal("budget 5s with the builtin 120s attempt timeout was accepted — the cross-field " +
			"rule must compare EFFECTIVE values, or it is bypassed by leaving one field unset")
	}

	// Equal is fine: exactly one attempt fits.
	if err := (&Policy{UpstreamAttemptTimeoutMs: p(60_000), ChainTotalBudgetMs: p(60_000)}).Validate(); err != nil {
		t.Errorf("budget == timeout should be allowed (one attempt fits exactly), got %v", err)
	}
}

// 🔴 F-9b: the default budget must stay visibly below attempt × chain length, or
// the cap is decorative.
func TestDefaultBudgetIsMeaningfullyBelowAttemptTimesChainLength(t *testing.T) {
	const typicalChain = 3
	naive := DefaultUpstreamAttemptTimeoutMs * typicalChain
	if DefaultChainTotalBudgetMs >= naive {
		t.Errorf("default budget %dms is not below attempt(%d) × %d = %dms, so it caps nothing. "+
			"That product is 6 minutes today, and the client gives up long before it: the user sees "+
			"a hang, kills it, and pays the same 6 minutes again",
			DefaultChainTotalBudgetMs, DefaultUpstreamAttemptTimeoutMs, typicalChain, naive)
	}
	// And it must still allow more than one attempt, or fallback never happens.
	if DefaultChainTotalBudgetMs < DefaultUpstreamAttemptTimeoutMs {
		t.Errorf("default budget %dms is below one attempt (%dms) — no fallback could ever run",
			DefaultChainTotalBudgetMs, DefaultUpstreamAttemptTimeoutMs)
	}
}

// ── 1b.5: the policy payload carries no secret material ─────────────────────
func TestPolicyPayloadCarriesNoSecrets(t *testing.T) {
	body, err := json.Marshal(Resolve(&Policy{
		UpstreamAttemptTimeoutMs: p(5_000),
		ChainTotalBudgetMs:       p(60_000),
	}, LocalOverrides{}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := AssertNoSecretShaped(string(body)); err != nil {
		t.Errorf("a resolved policy payload tripped the secret check: %v", err)
	}

	// And the check actually detects something.
	if err := AssertNoSecretShaped(`{"provider_key":"sk-live-abc"}`); err == nil {
		t.Error("AssertNoSecretShaped accepted an obvious key payload — a check that never fires " +
			"is indistinguishable from no check, and this one guards a one-way door: once a secret " +
			"has gone out over a side channel, rotation is the only remedy")
	}
}

// ── unset must round-trip as ABSENT, not as 0 ───────────────────────────────
//
// omitempty on a pointer omits nil but keeps an explicit 0 — which is exactly the
// distinction the wire has to preserve.
func TestJSONRoundTripPreservesUnsetVersusExplicitZero(t *testing.T) {
	unsetJSON, _ := json.Marshal(Policy{})
	if string(unsetJSON) != "{}" {
		t.Errorf("an unset policy marshalled to %s, want {}. Emitting zeros would make the "+
			"receiver read 'not configured' as 'configured to 0'", unsetJSON)
	}

	zeroJSON, _ := json.Marshal(Policy{BindingCooldownMs: p(0)})
	if string(zeroJSON) == "{}" {
		t.Error("an explicit 0 was omitted from the wire, so the receiver cannot tell it apart " +
			"from unset — the admin's deliberate 'never cool down' would silently become the default")
	}

	var back Policy
	if err := json.Unmarshal(zeroJSON, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.BindingCooldownMs == nil || *back.BindingCooldownMs != 0 {
		t.Errorf("explicit 0 did not survive the round trip: %v", back.BindingCooldownMs)
	}
}
