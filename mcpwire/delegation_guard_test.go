package mcpwire

// delegation_guard_test.go — fences for the guard-activity vocabulary
// (P15 · 15.16). Each test names the mutation it must catch.

import (
	"encoding/json"
	"strings"
	"testing"
)

// Mutation: make ParseGuardActivity's default branch return (GuardIdle, true).
//
// Rationale: 🔴 three states, not two. A proxy NEWER than the control plane
// reading it may report a word we do not know; reading that as idle makes the
// newest nodes in a fleet look like the least governed ones. Absence and
// unrecognised must both mean "that node cannot tell us", which sends the reader
// to a different action than "the gate is unused".
func TestGuardUnrecognisedValueIsNotIdle(t *testing.T) {
	if got, ok := ParseGuardActivity("suspended"); ok {
		t.Fatalf("an unknown wire value parsed as %q; it must read as 'cannot tell', not as a state", got)
	}
	if got, ok := ParseGuardActivity(""); ok {
		t.Fatalf("an absent value parsed as %q; absence is not a state", got)
	}
	for _, want := range []GuardActivity{GuardActive, GuardIdle} {
		if got, ok := ParseGuardActivity(string(want)); !ok || got != want {
			t.Fatalf("%q must still parse, got %q ok=%v", want, got, ok)
		}
	}
}

// ---------------------------------------------------------------------------
// 🔴 The wire shape of a tier (bugfix 2026-09-08)
// ---------------------------------------------------------------------------

// Mutation: delete DelegationTier.MarshalJSON, or default ToolsetSlugs to an
// empty slice inside it.
//
// Rationale: `nil` and `[]` are OPPOSITE RULES here — nil means "this tier does
// not narrow", [] means "narrow to nothing", which the evaluator answers with a
// refusal. The control plane's response writer normalises every nil slice to []
// for the whole API; this marshaller is the documented escape hatch from that,
// and without it an administrator who chose "inherit" ships a tier that refuses
// every spawn it matches.
func TestTierPreservesNilToolsetsOnTheWire(t *testing.T) {
	nilTier, err := json.Marshal(DelegationTier{Name: "inherit", AgentTypes: []string{"Explore"}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(nilTier), `"toolset_slugs":null`) {
		t.Fatalf("a tier that does not narrow must serialise toolset_slugs as null, got %s", nilTier)
	}

	emptyTier, err := json.Marshal(DelegationTier{
		Name: "lockout", AgentTypes: []string{"Explore"}, ToolsetSlugs: []string{},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(emptyTier), `"toolset_slugs":[]`) {
		t.Fatalf("a tier that narrows to nothing must serialise toolset_slugs as [], got %s", emptyTier)
	}

	// 🔴 And the other direction: every OTHER collection must keep the shape
	// consumers already receive. A nil AgentTypes must NOT start travelling as
	// null just because this type now marshals itself.
	bare, err := json.Marshal(DelegationTier{Name: "bare"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(bare), `"agent_types":[]`) {
		t.Fatalf("agent_types must stay [] — nil carries no meaning there and changing it "+
			"is an unrelated wire change; got %s", bare)
	}

	// A round trip must be lossless in both directions, or the producer and the
	// evaluator disagree about the same document.
	for _, want := range []DelegationTier{
		{Name: "a", AgentTypes: []string{"x"}},
		{Name: "b", AgentTypes: []string{"x"}, ToolsetSlugs: []string{}},
		{Name: "c", AgentTypes: []string{"x"}, ToolsetSlugs: []string{"ts"}},
	} {
		raw, _ := json.Marshal(want)
		var got DelegationTier
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("round trip %s: %v", want.Name, err)
		}
		if (got.ToolsetSlugs == nil) != (want.ToolsetSlugs == nil) {
			t.Fatalf("tier %q lost the nil/empty distinction across a round trip: %s", want.Name, raw)
		}
	}
}
