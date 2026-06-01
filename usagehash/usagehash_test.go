package usagehash

import "testing"

// TestPinnedVectors freezes the wire output for known inputs. These hashes are
// the CROSS-REPO CONTRACT: the proxy stamps them and the collector recomputes
// them. If a change to Input's fields or normalization alters these values, this
// test fails on purpose — that is your signal to BUMP Scheme (so old validators
// skip the new scheme instead of false-quarantining) and update both consumers.
// Do NOT "fix" the test by editing the expected strings without bumping Scheme.
func TestPinnedVectors(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want string
	}{
		{
			name: "anthropic with cache",
			in: Input{
				InputTokens: 100, OutputTokens: 50, TotalTokens: 150,
				CacheReadInputTokens: 10, CacheCreationInputTokens: 20,
				Model: "claude-opus-4-7", ProviderCode: "anthropic",
			},
			want: "sha256:1:3a32164eb6e3e4d025c3d860df13f619fac8e302790b9d1fce56d9d4252cfdc0",
		},
		{
			name: "zero-usage error event (openai, no cache)",
			in:   Input{Model: "gpt-4o", ProviderCode: "openai"},
			want: "sha256:1:1913488422b813415459b99b2fdceda5aa9d5b0613ddd8e895964626389bf71c",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Compute(tc.in); got != tc.want {
				t.Fatalf("Compute() = %s\n   want %s\n(if intentional, BUMP Scheme + update both proxy & collector)", got, tc.want)
			}
		})
	}
}

// TestDeterministic: the same input always yields the same hash (no map
// iteration order, no time, no randomness leaking in).
func TestDeterministic(t *testing.T) {
	in := Input{InputTokens: 7, OutputTokens: 3, TotalTokens: 10, Model: "m", ProviderCode: "p"}
	a, b := Compute(in), Compute(in)
	if a != b {
		t.Fatalf("non-deterministic: %s != %s", a, b)
	}
}

// TestEveryFieldAffectsHash: corrupting ANY metering field changes the hash —
// otherwise a corruption in that field would slip past validation. This is the
// core guarantee C relies on.
func TestEveryFieldAffectsHash(t *testing.T) {
	base := Input{
		InputTokens: 100, OutputTokens: 50, TotalTokens: 150,
		CacheReadInputTokens: 10, CacheCreationInputTokens: 20,
		Model: "claude", ProviderCode: "anthropic",
	}
	baseHash := Compute(base)
	mutations := map[string]Input{
		"input":          {InputTokens: 999, OutputTokens: 50, TotalTokens: 150, CacheReadInputTokens: 10, CacheCreationInputTokens: 20, Model: "claude", ProviderCode: "anthropic"},
		"output":         {InputTokens: 100, OutputTokens: 0, TotalTokens: 150, CacheReadInputTokens: 10, CacheCreationInputTokens: 20, Model: "claude", ProviderCode: "anthropic"},
		"total":          {InputTokens: 100, OutputTokens: 50, TotalTokens: 0, CacheReadInputTokens: 10, CacheCreationInputTokens: 20, Model: "claude", ProviderCode: "anthropic"},
		"cache_read":     {InputTokens: 100, OutputTokens: 50, TotalTokens: 150, CacheReadInputTokens: 0, CacheCreationInputTokens: 20, Model: "claude", ProviderCode: "anthropic"},
		"cache_creation": {InputTokens: 100, OutputTokens: 50, TotalTokens: 150, CacheReadInputTokens: 10, CacheCreationInputTokens: 0, Model: "claude", ProviderCode: "anthropic"},
		"model":          {InputTokens: 100, OutputTokens: 50, TotalTokens: 150, CacheReadInputTokens: 10, CacheCreationInputTokens: 20, Model: "gpt", ProviderCode: "anthropic"},
		"provider":       {InputTokens: 100, OutputTokens: 50, TotalTokens: 150, CacheReadInputTokens: 10, CacheCreationInputTokens: 20, Model: "claude", ProviderCode: "openai"},
	}
	for field, mutated := range mutations {
		if Compute(mutated) == baseHash {
			t.Errorf("mutating %q did not change the hash — that field is unprotected", field)
		}
	}
}

// TestSchemeKnown gates validation: only this package's scheme is recomputed;
// empty (old client) and other schemes are skipped, never failed.
func TestSchemeKnown(t *testing.T) {
	if !SchemeKnown(Compute(Input{InputTokens: 1})) {
		t.Error("own output not recognized as known scheme")
	}
	if SchemeKnown("") {
		t.Error("empty hash must be unknown (old client → skip validation)")
	}
	if SchemeKnown("sha256:2:deadbeef") {
		t.Error("future scheme 2 must be unknown to a scheme-1 validator (→ skip, not quarantine)")
	}
	if SchemeKnown("md5:1:deadbeef") {
		t.Error("different algorithm must be unknown")
	}
}

// TestVerify: matching tuple verifies, corrupted tuple does not.
func TestVerify(t *testing.T) {
	in := Input{InputTokens: 100, OutputTokens: 50, TotalTokens: 150, Model: "m", ProviderCode: "p"}
	stamped := Compute(in)
	if !Verify(in, stamped) {
		t.Error("identical tuple failed to verify")
	}
	corrupted := in
	corrupted.OutputTokens = 0 // the silent-zero bug
	if Verify(corrupted, stamped) {
		t.Error("output_tokens corrupted to 0 still verified — C's core check is broken")
	}
}
