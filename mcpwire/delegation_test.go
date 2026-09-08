package mcpwire

// delegation_test.go — the fences for the delegation wire (checklist §D
// D-79/D-80/D-87/D-88/D-89/D-94/D-95).
//
// Every test here names, in its own comment, the mutation it must catch. A
// fence whose breaking change is not written down is a fence nobody can drill.

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// bannedAuthorityWords are the substrings that mark a field as carrying
// authority rather than describing a decision.
var bannedAuthorityWords = []string{
	"token", "secret", "credential", "scope", "key", "bearer", "password", "grant",
}

// fieldNames walks a struct TYPE and returns every field name and json tag it
// declares, recursing into nested and embedded structs.
//
// 🔴 The type, not a marshalled instance. See TestDecisionCarriesNoCredentialShape.
func fieldNames(t reflect.Type) []string {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		out = append(out, f.Name)
		if tag := f.Tag.Get("json"); tag != "" {
			out = append(out, strings.Split(tag, ",")[0])
		}
		if ft := f.Type; ft.Kind() == reflect.Struct || (ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct) {
			out = append(out, fieldNames(ft)...)
		}
	}
	return out
}

// D-80 / I31 — the delegation decision must never be able to carry authority.
//
// Mutation: add a Token / Scope / Secret / Credential field to Decision.
// Rationale: D-24 ratified that the gate issues NOTHING. A second credential is
// a second revocation path, which is to say a revocation that gets forgotten.
//
// 🔴 THIS FENCE WAS VACUOUS ON ITS FIRST DAY, and the reason generalises.
// The first version marshalled one Decision and scanned the resulting keys. But
// a field added the way anybody would actually add it — `json:"token,omitempty"`
// — is ABSENT from the JSON while it holds the zero value, so the drill mutation
// produced identical output and the test stayed green. The 2026-09-03 drill
// caught it.
//
// The lesson is not about this field: **a fence that inspects one marshalled
// instance can only see what that instance happened to populate.** To assert a
// property of the SHAPE, inspect the shape. Reflection over the type sees the
// field whatever its tag, value or omitempty says.
func TestDecisionCarriesNoCredentialShape(t *testing.T) {
	names := fieldNames(reflect.TypeOf(Decision{}))
	if len(names) == 0 {
		t.Fatal("reflected no fields at all — the fence is inspecting the wrong type")
	}
	for _, n := range names {
		lower := strings.ToLower(n)
		for _, b := range bannedAuthorityWords {
			if strings.Contains(lower, b) {
				t.Fatalf("Decision declares %q, which looks like authority material; "+
					"the delegation gate issues nothing (D-24 / R59/R60)", n)
			}
		}
	}
}

// D-87 / I37 / R66 — the hook reply must be structurally unable to rewrite the
// harness's tool input.
//
// Mutation: add an UpdatedInput field to hookSpecificOutput.
// Rationale: measured 2026-09-03 — extra fields never reach the child anyway,
// so the only thing modifiable is the task prompt, which is prompt injection
// (R59), and the parent agent noticed it when we tried.
// 🔴 Same vacuity trap as TestDecisionCarriesNoCredentialShape, caught by the
// same drill: an `updatedInput` field with omitempty is invisible in a
// marshalled zero value. Assert on the TYPE.
func TestHookDecisionCannotCarryUpdatedInput(t *testing.T) {
	names := fieldNames(reflect.TypeOf(HookDecision{}))
	if len(names) == 0 {
		t.Fatal("reflected no fields at all — the fence is inspecting the wrong type")
	}
	for _, n := range names {
		if strings.Contains(strings.ToLower(n), "input") {
			t.Fatalf("the hook reply declares %q; the delegation gate must be "+
				"structurally unable to rewrite business parameters (R66/I37)", n)
		}
	}

	// Second layer: the wire really does carry only the three expected keys, so
	// a custom MarshalJSON could not smuggle one back in.
	raw, err := MarshalHookReply("PreToolUse", Decision{Verdict: VerdictDeny, Reason: "r"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(raw, &outer); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(outer) != 1 {
		t.Fatalf("hook reply has %d top-level keys; want only hookSpecificOutput", len(outer))
	}
	var fields map[string]any
	if err := json.Unmarshal(outer["hookSpecificOutput"], &fields); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	for k := range fields {
		switch k {
		case "hookEventName", "permissionDecision", "permissionDecisionReason":
		default:
			t.Fatalf("hook reply emits unexpected key %q", k)
		}
	}
}

// D-88 / I38 — delegation codes must stay out of the FROZEN MCP wire catalogue.
//
// Mutation: append a DelegationDenied row to ErrorCodeCatalog (needs an explicit
// conversion, which is the point — the separate type makes the accident
// impossible and this test covers the deliberate version).
// Rationale: ErrorCodeCatalog is a published contract third-party MCP clients
// read. A code in it promises an error they can never receive, and the
// catalogue cannot be un-published.
func TestDelegationCodesAreNotInTheMCPWireCatalog(t *testing.T) {
	for _, spec := range DelegationErrorCatalog {
		for _, wire := range ErrorCodeCatalog {
			if string(wire.Code) == string(spec.Code) {
				t.Fatalf("delegation code %s appears in the frozen MCP wire catalogue; "+
					"it can never be delivered over JSON-RPC (I38)", spec.Code)
			}
		}
		if _, found := Spec(ErrorCode(spec.Code)); found {
			t.Fatalf("delegation code %s resolves through Spec(); it must not be a wire code", spec.Code)
		}
	}
}

// Companion to the above: the delegation catalogue must actually enumerate every
// declared code, or the "central enumeration" claim is hollow.
func TestEveryDelegationCodeIsCatalogued(t *testing.T) {
	declared := []DelegationErrorCode{DelegationDenied, DelegationDepthExceeded}
	for _, d := range declared {
		found := false
		for _, spec := range DelegationErrorCatalog {
			if spec.Code == d {
				found = true
				if strings.TrimSpace(spec.Summary) == "" {
					t.Fatalf("%s has an empty summary", d)
				}
			}
		}
		if !found {
			t.Fatalf("%s is declared but not in DelegationErrorCatalog", d)
		}
	}
}

// D-94 — the gate must recognise BOTH names of the spawn tool.
//
// Mutation: make IsDelegationTool compare against one constant only.
// Rationale: measured on Claude Code 2.1.247 — the hook event says
// "tool_name":"Agent" while the run summary says "tool_name":"Task". Matching
// one name leaves a gate that LOOKS installed and stops nothing.
func TestBothDelegationToolNamesAreRecognised(t *testing.T) {
	for _, name := range []string{DelegationToolAgent, DelegationToolTask} {
		if !IsDelegationTool(name) {
			t.Fatalf("IsDelegationTool(%q) = false; the same tool is reported under "+
				"both names and matching one makes the gate fail silently", name)
		}
	}
	if IsDelegationTool("Bash") {
		t.Fatal("IsDelegationTool(\"Bash\") = true; the gate would fire on ordinary tools")
	}
}

// D-95 — "this is the main agent" is FIELD ABSENCE, never an empty string.
//
// Mutation: change HookEvent.AgentID to string and IsMainActor to == "".
// Rationale: measured — main-agent hook events have no agent_id key at all.
// Folding absence together with an empty value merges "main agent" and "decode
// failed" into one verdict, the same way COALESCE would merge null and [].
func TestMainActorIsFieldAbsenceNotEmptyString(t *testing.T) {
	var mainEvt HookEvent
	if err := json.Unmarshal([]byte(`{"hook_event_name":"PreToolUse","tool_name":"Agent"}`), &mainEvt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !mainEvt.IsMainActor() {
		t.Fatal("an event with no agent_id key must be the main actor")
	}
	if _, ok := mainEvt.Actor(); ok {
		t.Fatal("main actor must report no harness actor id")
	}

	var emptyEvt HookEvent
	if err := json.Unmarshal([]byte(`{"agent_id":""}`), &emptyEvt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if emptyEvt.IsMainActor() {
		t.Fatal("agent_id:\"\" is a PRESENT-but-empty field — a decode problem, " +
			"not the main agent. Collapsing the two hides a broken hook contract.")
	}

	var subEvt HookEvent
	if err := json.Unmarshal([]byte(`{"agent_id":"a06ce40d5487ea3ca","agent_type":"Explore"}`), &subEvt); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if subEvt.IsMainActor() {
		t.Fatal("an event carrying agent_id is not the main actor")
	}
	if id, ok := subEvt.Actor(); !ok || id != "a06ce40d5487ea3ca" {
		t.Fatalf("Actor() = %q,%v; want the harness id", id, ok)
	}
}

// D-89 — "allowed but narrowed" must stay its own event.
//
// Mutation: point VerdictNarrow at EventDelegationAllowed.
// Rationale: folded into allow, an administrator sees a wall of green while half
// the delegations in the org are being quietly downgraded — and "is my tier
// actually biting" is the only question a tier configuration exists to answer.
func TestNarrowedIsItsOwnEvent(t *testing.T) {
	if EventForVerdict[VerdictNarrow] == EventForVerdict[VerdictAllow] {
		t.Fatal("narrow and allow share an event name; a narrowed delegation would " +
			"be invisible to the administrator who configured the tier")
	}
	if EventForVerdict[VerdictNarrow] != EventDelegationNarrowed {
		t.Fatalf("narrow maps to %q", EventForVerdict[VerdictNarrow])
	}
}

// Exhaustiveness: a new verdict without an event would be filed under whatever
// the map's zero value is (the empty string) and nobody would find out.
func TestEveryVerdictHasAnEvent(t *testing.T) {
	for _, v := range []Verdict{VerdictAllow, VerdictNarrow, VerdictDeny} {
		if EventForVerdict[v] == "" {
			t.Fatalf("verdict %q has no event name", v)
		}
	}
	if len(EventForVerdict) != 3 {
		t.Fatalf("EventForVerdict has %d entries; add the new verdict's event", len(EventForVerdict))
	}
}

// A narrowed delegation must still ALLOW at the harness. Narrowing is not an
// interruption — the child starts, it just carries fewer toolsets.
//
// Mutation: render narrow as deny.
func TestNarrowRendersAsAllowToTheHarness(t *testing.T) {
	reply := HookReply("PreToolUse", Decision{Verdict: VerdictNarrow, Tier: "read-only"})
	if reply.Specific.PermissionDecision != hookAllow {
		t.Fatalf("narrow rendered as %q; narrowing must not interrupt the developer",
			reply.Specific.PermissionDecision)
	}
	deny := HookReply("PreToolUse", Decision{Verdict: VerdictDeny, Reason: "because"})
	if deny.Specific.PermissionDecision != hookDeny || deny.Specific.PermissionDecisionReason != "because" {
		t.Fatalf("deny rendered as %+v; the reason must reach the developer verbatim", deny.Specific)
	}
}

// UnknownActor must be a word, never blank — same rule app_slug follows with
// unknown-app. A blank cell reads as our bug and invites somebody to fill it in
// by guessing, which R63 forbids.
func TestUnknownActorIsAWordNotABlank(t *testing.T) {
	if strings.TrimSpace(UnknownActor) == "" {
		t.Fatal("UnknownActor must be a verdict, not an empty string (R63)")
	}
}
