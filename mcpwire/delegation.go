package mcpwire

// delegation.go — the shape of a DELEGATION BOUNDARY decision (K1, PRD §3.1
// 取舍八, tech design §3.10).
//
// # What this file is for
//
// A parent Agent asking its harness to spawn a sub-agent is the one hop where
// delegation actually happens. AiKey decides ALLOW / NARROW / DENY there, and
// nowhere else. These types are the contract for that decision: the proxy
// evaluates it, the CLI hook shell carries it, the control plane produces the
// tiers. One definition, three consumers — the same arrangement fallbackpolicy
// and routingwire already use.
//
// # 🔴 The one thing this file must NOT grow
//
// A credential. Not a token, not a scope list, not a secret of any kind.
// Decision D-24 (ratified 2026-09-03) says the delegation gate issues NOTHING:
// there is exactly one credential facing an Agent, the virtual key, and a
// second one would be a second revocation path — which is to say a revocation
// that eventually gets forgotten (see internal/mcp/auth.go for the same rule
// stated for the MCP plane, and requirement R59/R60).
//
// Fence: TestDecisionCarriesNoCredentialShape.
//
// # 🔴 What the gate can and cannot do (this belongs in code, not only in docs)
//
// It stops a parent from SPAWNING a child it should not have. It does NOT stop
// a child that is already running from calling a tool: by the time the child
// talks to the MCP plane, the only identity on the wire is the seat's virtual
// key. Claude Code sends no agent identifier on its MCP requests — the same
// structural reason it sends no conversation id (see CallRecord.ConversationSessionID).
//
// 🚫 Sales may not describe this as "we limit what sub-agents can do". PRD §0.7
// and the forbidden-phrase table carry the wording. It is written here too
// because the next person to read this file is likelier to open the code than
// the PRD, and a boundary nobody can see is a boundary that gets overstated.

import "encoding/json"

// ---------------------------------------------------------------------------
// The delegation tier — what a parent is allowed to spawn
// ---------------------------------------------------------------------------

// DelegationTier is one rule: "an agent of these types may be spawned, and it
// may use these toolsets".
//
// 🔴 It grants NOTHING on its own. A tier can only ever REDUCE what the parent
// already has — the evaluator intersects it with the parent's own toolsets, so
// the subset property holds BY CONSTRUCTION rather than by assertion (R60/I30).
// Writing it as a filter rather than as a grant is what makes
// "child ⊆ parent ⊆ seat" impossible to violate by adding a field later.
type DelegationTier struct {
	// Name is what a human sees in a refusal message. 🔴 Required: a refusal
	// that cannot name the rule that produced it is not actionable, and R61
	// requires every refusal to say what the tier is and who to ask.
	Name string `json:"name"`

	// AgentTypes are the harness-side sub-agent types this tier covers
	// (Claude Code: "Explore", "general-purpose", a custom agent's name).
	// The literal "*" matches any type and is how the default tier is spelled.
	AgentTypes []string `json:"agent_types"`

	// ToolsetSlugs limits which toolsets the spawned child may use.
	//
	// 🔴 nil and empty mean DIFFERENT things, and the difference is the whole
	// safety property:
	//   nil   → "this tier does not narrow the toolsets" (child keeps parent's)
	//   []    → "this tier narrows them to nothing"
	// Collapsing the two — the obvious simplification — turns an unconfigured
	// tier into a total lockout, which is exactly the D-27 failure mode
	// (every existing user's sub-agents stop working on upgrade day).
	// Fence: TestNilToolsetsIsNotAnEmptyToolset.
	ToolsetSlugs []string `json:"toolset_slugs"`

	// MaxDepth is how deep delegation may go under this tier. Three states,
	// deliberately, and 🔴 zero is NOT "unlimited":
	//
	//	nil → not configured; AiKey does not limit depth (the harness still may)
	//	0   → no delegation at all under this tier
	//	N>0 → at most N levels below the human
	//
	// 🔴 This shape exists because the repo has already been bitten by the other
	// one: the rate-limit work found `limit=0` reading as "unlimited", which is
	// precisely the value an operator types when they mean "none". A pointer
	// costs one dereference and removes the ambiguity permanently. Same
	// three-state discipline as pkg/fallbackpolicy.
	// Fence: TestMaxDepthZeroMeansNoneNotUnlimited.
	MaxDepth *int `json:"max_depth,omitempty"`
}

// MarshalJSON makes DelegationTier own its own wire shape.
//
// # 🔴 Why a hand-written marshaller for a struct with no unusual fields
//
// The control plane writes every response through `shared.JSON`, which runs
// `EnsureEmptyCollections` — a reflective walk that replaces every nil slice
// with an empty one so clients never have to handle `null`. That is a good rule
// for the other ~200 collections in that API and a CORRECTNESS BUG for exactly
// this struct, because here `nil` and `[]` are OPPOSITE RULES:
//
//	nil → this tier does not narrow the toolsets (the child keeps the parent's)
//	[]  → narrow to nothing, which the evaluator answers with a REFUSAL
//
// Measured 2026-09-08: an administrator who chose "inherit" got `null` stored
// correctly and `[]` delivered to every proxy — a tier that refused every spawn
// it matched, and a console that showed a different rule than the one just
// saved (R67). The three existing fences all stayed green because they guard the
// EVALUATOR (proxy) and the MODEL (console), and neither of those looks at the
// wire. Nobody fenced the producer's serialised output.
//
// `EnsureEmptyCollections` documents its own escape hatch — "a type that
// marshals itself owns its wire shape — do not look inside" — and this is that
// hatch, taken deliberately.
//
// 🔴 It reproduces the normaliser for every OTHER field on purpose. `AgentTypes`
// nil carries no meaning (a tier matching nothing), and consumers today receive
// `[]` for it; emitting `null` instead would be an unrelated wire change that
// could break a client mid-iteration. The ONLY behaviour this changes is that a
// nil ToolsetSlugs now survives as `null`.
//
// Bugfix: workflow/CI/bugfix/2026-09-08-delegation-nil-toolsets-collapsed-to-empty.md
// Fences: TestTierPreservesNilToolsetsOnTheWire (here) +
// TestDelegationWireKeepsNilToolsets (control plane, through the real writer).
func (t DelegationTier) MarshalJSON() ([]byte, error) {
	// A local type with no methods, so this does not recurse.
	type tierWire DelegationTier
	w := tierWire(t)
	if w.AgentTypes == nil {
		// 🔴 Matches what every consumer receives today. 🚫 Not an oversight:
		// see the header — nil is meaningless here, so it must NOT start
		// travelling as null just because this type now marshals itself.
		w.AgentTypes = []string{}
	}
	// 🚫 ToolsetSlugs is deliberately NOT defaulted. That is the whole point.
	return json.Marshal(w)
}

// DelegationPolicy is the org's whole delegation configuration, as delivered on
// the EXISTING MCP policy rail.
//
// 🔴 D-26: this rides the policy payload that is already polled every 60s. No
// new table, no new DDL, no second delivery rail. A tier is configuration — it
// has no lifecycle of its own, no second consumer and nothing ever queries "who
// is on tier X" — so the three tests in the careful-table-creation rule all
// answer "do not build one".
type DelegationPolicy struct {
	// Tiers are matched in order; the first tier whose AgentTypes match wins.
	//
	// 🔴 ORDER MATTERS and it is the producer's job. First-match is chosen over
	// most-specific-match because most-specific needs a ranking rule, and a
	// ranking rule is a second thing an administrator has to reason about to
	// predict what their own configuration does.
	Tiers []DelegationTier `json:"tiers,omitempty"`

	// DefaultAllow decides what happens when NO tier matches.
	//
	// 🔴 D-27 (ratified 2026-09-03): true. A governance feature must not change
	// behaviour on the day it ships — it must make the current behaviour
	// VISIBLE. Shipping with false would break every existing user's sub-agents
	// at once, which is the same mistake R21 already forbids for adoption
	// ("equivalent migration, not least privilege"). Tightening is the
	// administrator's later, side-channel action.
	// Fence: TestZeroPolicyAllowsEverything.
	DefaultAllow bool `json:"default_allow"`
}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

// Verdict is the closed set of outcomes. 🔴 Exactly three — see Decision.
type Verdict string

const (
	// VerdictAllow — spawn it, unchanged.
	VerdictAllow Verdict = "allow"
	// VerdictNarrow — spawn it, but with fewer toolsets than the parent has.
	//
	// 🔴 Its own verdict rather than a flavour of allow. Folding it into allow
	// shows an administrator a wall of green while half the delegations in their
	// org are being quietly downgraded — and "how often is my tier actually
	// biting" is the one question a tier configuration exists to answer.
	VerdictNarrow Verdict = "narrow"
	// VerdictDeny — do not spawn it.
	VerdictDeny Verdict = "deny"
)

// Decision is the evaluator's answer.
//
// 🔴 There is no field here that could carry authority. Toolsets names an
// EXISTING set the seat is already granted; it is a filter, never a grant.
// Adding a token / scope / secret field is the failure this file's header
// forbids, and TestDecisionCarriesNoCredentialShape scans for it.
type Decision struct {
	Verdict Verdict `json:"verdict"`

	// Tier is the name of the rule that decided. Empty only when no tier
	// matched and DefaultAllow carried it.
	Tier string `json:"tier,omitempty"`

	// Toolsets is the set the child may use, already intersected with the
	// parent's. Meaningful for narrow; equal to the parent's set for allow.
	Toolsets []string `json:"toolsets,omitempty"`

	// Code is the delegation error code for a denial. Empty otherwise.
	//
	// 🔴 Typed as DelegationErrorCode, NOT ErrorCode. These never travel on the
	// MCP wire — see that type's comment.
	Code DelegationErrorCode `json:"code,omitempty"`

	// Reason is the human sentence the developer will actually read.
	//
	// 🔴 R61 + PRD §2.6: it must name the tier, say what IS allowed, and say who
	// to ask. And per the D-24 口径 it must identify AiKey as the refuser —
	// the harness refuses spawns too (depth / concurrency / budget), and a
	// refusal that does not say who spoke leaves the user unable to tell which
	// of two completely different fixes applies.
	// Fence: TestDenialReasonNamesAikeyAndTheTier.
	Reason string `json:"reason,omitempty"`

	// Stale marks a decision made from a policy snapshot that could not be
	// refreshed — including the "never polled at all" case.
	//
	// 🔴 D-29 ratified a deliberate fail-open here, and this flag is the other
	// half of that bargain: the caller MUST emit EventPolicyStale when it is
	// set. A silent fail-open is indistinguishable from a working gate, which
	// is how a control that is not actually controlling anything survives for
	// months. Fences: TestStalePolicyStillDecides + TestStaleDecisionIsFlagged.
	Stale bool `json:"stale,omitempty"`
}

// ---------------------------------------------------------------------------
// 🔴 Error codes — a SEPARATE vocabulary from the frozen MCP wire codes
// ---------------------------------------------------------------------------

// DelegationErrorCode is a refusal produced at the delegation boundary.
//
// 🔴 A DISTINCT Go type from ErrorCode, on purpose. These codes are returned to
// a local harness hook over stdout; they never appear in a JSON-RPC error
// response, because the hop they describe — a parent asking to spawn a child —
// does not speak MCP at all.
//
// ErrorCodeCatalog is a PUBLISHED, frozen contract that third-party MCP clients
// read. Putting a code in it promises clients an error they can never receive.
// Making this a separate type means the compiler refuses the mistake; the fence
// TestDelegationCodesAreNotInTheMCPWireCatalog covers the case where somebody
// converts one deliberately.
//
// They ARE still centrally enumerated (logging conventions forbid error.code
// string literals at call sites) — just in their own catalogue, below.
type DelegationErrorCode string

const (
	// DelegationDenied — the tier does not permit spawning this agent type.
	DelegationDenied DelegationErrorCode = "MCP_DELEGATION_DENIED"
	// DelegationDepthExceeded — the tier's MaxDepth is already reached.
	//
	// 🔴 Its own code rather than reusing DelegationDenied: the two have
	// different fixes ("ask for a wider tier" vs "your chain is too deep"), and
	// two problems with two fixes cannot share one code — the same reasoning
	// that gave MCP_COMPLIANCE_BLOCKED its own code instead of reusing
	// MCP_TOOL_FORBIDDEN.
	DelegationDepthExceeded DelegationErrorCode = "MCP_DELEGATION_DEPTH_EXCEEDED"
)

// DelegationErrorSpec describes one delegation code.
type DelegationErrorSpec struct {
	Code    DelegationErrorCode
	Summary string
}

// DelegationErrorCatalog is the central enumeration for the hook layer.
var DelegationErrorCatalog = []DelegationErrorSpec{
	{DelegationDenied, "The delegation tier does not permit spawning this agent type."},
	{DelegationDepthExceeded, "The delegation tier's maximum depth is already reached."},
}

// ---------------------------------------------------------------------------
// 🔴 The harness event — two traps, both measured on 2026-09-03
// ---------------------------------------------------------------------------

// Delegation tool names.
//
// 🔴 THE SAME TOOL HAS TWO NAMES, and matching only one makes the gate fail
// SILENTLY — it looks installed and does not stop anything. Measured against
// Claude Code 2.1.247 (see baseline-forensics.md §五 修正三):
//
//	hook event  →  "tool_name": "Agent"
//	run result  →  "permission_denials":[{"tool_name":"Task", ...}]
//
// Fence: TestBothDelegationToolNamesAreRecognised.
const (
	DelegationToolAgent = "Agent"
	DelegationToolTask  = "Task"
)

// IsDelegationTool reports whether a harness tool name is the spawn hop.
//
// 🚫 Do not inline a comparison against one of the constants at a call site.
// That is the exact shape of the silent failure described above.
func IsDelegationTool(toolName string) bool {
	return toolName == DelegationToolAgent || toolName == DelegationToolTask
}

// HookEvent is the subset of the harness hook payload the gate needs.
//
// Unknown fields are ignored by design: the hook contract belongs to a third
// party and gains fields between releases. Strict decoding would turn "the
// vendor added a field" into "the user's Agent will not start" — a failure we
// would have manufactured ourselves.
type HookEvent struct {
	SessionID string `json:"session_id"`
	// PromptID scopes one user turn. Used to pair a spawn request with the
	// SubagentStart that follows it (D-25 (d)).
	PromptID string `json:"prompt_id"`
	HookName string `json:"hook_event_name"`
	ToolName string `json:"tool_name,omitempty"`

	// AgentID is a POINTER because ABSENCE is the signal.
	//
	// 🔴 Measured: hook events raised by the MAIN agent have no `agent_id` key
	// at all, while events raised inside a sub-agent carry one. So "no field"
	// means "this is the main agent" — and writing the check as
	// `AgentID == ""` would fold that verdict together with "the field was
	// present but empty", i.e. with a decode failure. Those must stay
	// distinguishable for the same reason `null` and `[]` are kept apart all
	// the way to the console in the conversation-audit work.
	// Fence: TestMainActorIsFieldAbsenceNotEmptyString.
	AgentID   *string `json:"agent_id,omitempty"`
	AgentType string  `json:"agent_type,omitempty"`

	// ToolInput is the spawn request: subagent_type, prompt, description.
	ToolInput DelegationToolInput `json:"tool_input,omitempty"`
	ToolUseID string              `json:"tool_use_id,omitempty"`
}

// DelegationToolInput is the harness's spawn payload.
//
// 🔴 Read-only as far as AiKey is concerned. R66 forbids the gate from writing
// back a modified tool input, and the measurement behind that ban is worth
// keeping next to the type: extra fields never reach the child at all (it is
// handed only `prompt`), so the only thing that CAN be modified is the task
// prompt — which is prompt injection, banned by R59 — and when we did it in the
// probe, the parent agent noticed and said so in its answer.
type DelegationToolInput struct {
	SubagentType    string `json:"subagent_type,omitempty"`
	Description     string `json:"description,omitempty"`
	Prompt          string `json:"prompt,omitempty"`
	RunInBackground bool   `json:"run_in_background,omitempty"`
}

// IsMainActor reports whether this event came from the top-level agent.
//
// 🔴 Absence, not emptiness. See HookEvent.AgentID.
func (e HookEvent) IsMainActor() bool { return e.AgentID == nil }

// Actor returns the harness's identifier for whoever raised this event, and
// whether the harness supplied one.
//
// 🔴 The value is CLIENT-ASSERTED. It belongs to the same family as app_slug
// and session_id: display only, never authorisation, never routing, never
// billing (R62). The hook runs on the user's own machine — they can delete it
// or replace it with one that lies.
func (e HookEvent) Actor() (string, bool) {
	if e.AgentID == nil {
		return "", false
	}
	return *e.AgentID, true
}

// ---------------------------------------------------------------------------
// The hook reply
// ---------------------------------------------------------------------------

// HookDecision is what the gate writes to the harness on stdout.
//
// 🔴 THERE IS NO updatedInput FIELD HERE, AND THAT IS THE FEATURE.
//
// R66 forbids the delegation gate from rewriting business parameters. Enforcing
// it with a runtime check would leave the capability one line away; leaving the
// field out of the type makes the refusal structural — the serialiser cannot
// emit what the struct cannot hold. Fence: TestHookDecisionCannotCarryUpdatedInput
// asserts the marshalled shape, so re-adding the field goes red immediately.
type HookDecision struct {
	Specific hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// Harness permission decisions.
const (
	hookAllow = "allow"
	hookDeny  = "deny"
)

// HookReply renders a Decision as the harness's expected stdout shape.
//
// 🔴 narrow renders as ALLOW. Narrowing is not an interruption: the child still
// starts, it just carries fewer toolsets. Surfacing it to the developer as a
// refusal would train them to see the gate as breakage; the narrowing is
// recorded as an event for the administrator instead (EventNarrowed).
func HookReply(hookName string, d Decision) HookDecision {
	out := hookSpecificOutput{HookEventName: hookName, PermissionDecision: hookAllow}
	if d.Verdict == VerdictDeny {
		out.PermissionDecision = hookDeny
		out.PermissionDecisionReason = d.Reason
	}
	return HookDecision{Specific: out}
}

// MarshalHookReply is the single encoder for hook stdout.
func MarshalHookReply(hookName string, d Decision) ([]byte, error) {
	return json.Marshal(HookReply(hookName, d))
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

// Delegation event names. 🔴 Central enumeration — logging conventions forbid
// event.name literals at call sites. Prefix is `proxy.` because the decision
// and the accounting both happen in the local proxy; the CLI hook is a shell.
const (
	EventDelegationRequested = "proxy.mcp.delegation_requested"
	EventDelegationAllowed   = "proxy.mcp.delegation_allowed"
	// EventDelegationNarrowed is deliberately separate from allowed — see
	// VerdictNarrow.
	EventDelegationNarrowed = "proxy.mcp.delegation_narrowed"
	EventDelegationDenied   = "proxy.mcp.delegation_denied"
	// EventPolicyStale is the WARN that pays for the D-29 fail-open. 🔴 Emitting
	// it is not optional: without it, a gate deciding from a month-old snapshot
	// is indistinguishable from a healthy one.
	EventPolicyStale = "proxy.mcp.delegation_policy_stale"
	// EventActorUnresolved counts calls whose actor the client did not supply.
	// 🚫 Not an error — it is the coverage metric for actor attribution, and on
	// Claude Code today it is expected to be ~100%.
	EventActorUnresolved = "proxy.mcp.actor_unresolved"
)

// EventForVerdict maps a verdict to its event name.
//
// 🔴 A table, not a switch with a default. A default branch would file a new
// verdict under whatever happened to be the fallback and nobody would find out;
// TestEveryVerdictHasAnEvent keeps this exhaustive instead.
var EventForVerdict = map[Verdict]string{
	VerdictAllow:  EventDelegationAllowed,
	VerdictNarrow: EventDelegationNarrowed,
	VerdictDeny:   EventDelegationDenied,
}

// UnknownActor is the verdict recorded when a client supplies no actor id.
//
// 🔴 A word, never an empty string — the same rule app_slug already follows with
// unknown-app. "The client does not tell us" is a FINDING; a blank cell reads as
// a bug in us and invites somebody to go fill it in by guessing, which R63
// forbids.
const UnknownActor = "unknown-actor"

// ---------------------------------------------------------------------------
// Guard activity — "is the delegation gate actually being consulted on this
// seat?" (P15 · 15.16, ruling A-4 option (c)).
//
// # What question this answers, and why the obvious answers were rejected
//
// An administrator who has just configured delegation tiers asks exactly one
// question first: *is my rule biting anything at all?* Answering it needs a
// per-seat fact, pushed to the control plane — the console cannot pull it,
// because in Production the proxies live on employees' laptops and the console
// is a server (the same reason the 8.7 test panel was refused).
//
// Two cheaper-looking sources were refused:
//
//   - reading the developer's ~/.claude/settings.json from the gateway: it is
//     the developer's editor config, and a line in a file proves somebody wrote
//     it, not that the harness invokes it.
//   - reporting at `aikey mcp guard install` time: a user who later deletes the
//     hook by hand reports nothing, and that is precisely failure path 15.X5 —
//     the one case the number exists to make visible.
//
// One real call to POST /admin/mcp/delegation proves BOTH halves at once:
// installed, and actually consulted.
// ---------------------------------------------------------------------------

// GuardActivity is what a gateway says about its own delegation gate.
//
// 🔴 THREE states on the wire, and the third one is ABSENCE. A proxy built
// before 15.16 sends no parameter at all, and that is NOT the same as
// GuardIdle: "this build cannot tell us" and "this gateway has not been asked"
// send the reader to different next steps (upgrade that node's proxy vs. do
// nothing). Collapsing them is the same mistake `actor_id` avoids by keeping
// ” and unknown-actor apart, and R58 forbids in general: a thing we cannot
// measure must never render as a measured value.
type GuardActivity string

const (
	// GuardActive — the hook has reached this gateway since it started.
	GuardActive GuardActivity = "active"
	// GuardIdle — this gateway is running and reporting, and the hook has not
	// reached it since start.
	//
	// 🔴 Idle is NOT "not installed", and the console must not render it as
	// such. A developer who simply has not spawned a sub-agent today is idle,
	// and so is a developer who uninstalled the hook. Claiming to tell them
	// apart would be a confident wrong answer.
	GuardIdle GuardActivity = "idle"
)

// GuardActivityParam is the query parameter the credential rail carries it on.
//
// 🔴 It rides the CREDENTIAL rail (GET /accounts/me/mcp-credentials) and not the
// policy rail, because the policy rail is unauthenticated and takes its
// organisation from a query parameter — anyone could report governance state
// for anyone's organisation. On the credential rail the control plane derives
// org and seat from the caller's own seats, so the identity is computed by the
// server, never claimed by the client. Ratified as A-4.
const GuardActivityParam = "guard"

// ParseGuardActivity maps a wire value to a state, reporting whether it was one
// we recognise.
//
// 🔴 An unrecognised value is NOT folded into idle. A future proxy that reports
// a state this control plane predates must read as "cannot tell", exactly like
// absence — folding it into idle would make a newer node look like a node with
// no gate.
func ParseGuardActivity(raw string) (GuardActivity, bool) {
	switch GuardActivity(raw) {
	case GuardActive:
		return GuardActive, true
	case GuardIdle:
		return GuardIdle, true
	default:
		return "", false
	}
}
