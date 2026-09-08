package mcpwire

// callrecord.go — the record of ONE tool call, as it travels from the proxy
// (where the call happens) to the control plane (where an administrator reads
// it).
//
// # Why this is a record and not a usage event
//
// Usage events are token-billing shaped: their vocabulary is input/output
// tokens, model, cost. A tool call produces no tokens, and folding one into
// that stream would corrupt the cost vocabulary for everything else — which is
// why `mcp_call_event` is its own table rather than a flavour of
// `usage_event_ods`. The same reasoning applies to the wire: this is its own
// shape, delivered on its own rail.
//
// # 🔴 A refusal is a record (R10)
//
// Every terminal outcome of a tools/call is recorded, INCLUDING the ones where
// the gateway refused and the backend was never contacted. "Denied" and "never
// happened" must never be the same row: the first is precisely the signal an
// administrator is looking for during an incident, and a gateway that records
// only its successes cannot answer "did anyone try".
//
// Refusals are recorded and simply not billed. There is no cost field here at
// all, so the two cannot be conflated by accident.
//
// # 🔴 Arguments are DIGESTED by default (R6 / D-4)
//
// ArgsDigest — key names, JSON types, value lengths — is the default record.
// ArgsRaw is nil unless the organisation switched raw retention on AND the
// payload cleared DLP. Tool arguments are SQL statements, file contents,
// internal hostnames and sometimes outright credentials; storing them by
// default would make AiKey a new concentration of exactly the data it exists to
// de-concentrate.

import "encoding/json"

// CallRecord is one tools/call outcome.
//
// 🔴 Field names and JSON tags mirror `mcp_call_event`'s columns exactly. The
// control plane keeps its own copy of this struct (it must not import the
// proxy), and a wire-shape test on each side pins the JSON so the two cannot
// drift silently — the same arrangement ObservedManifest already uses.
type CallRecord struct {
	// CallID is the primary key, minted by the proxy from crypto/rand.
	//
	// 🔴 Minted at the CLIENT end, on purpose: it makes the control plane's
	// ingest idempotent (INSERT … ON CONFLICT DO NOTHING on this column), which
	// is what lets the delivery rail be at-least-once. A server-minted id would
	// turn every re-delivery after a lost response into a duplicate row.
	CallID string `json:"call_id"`
	OrgID  string `json:"org_id"`
	SeatID string `json:"seat_id,omitempty"`
	// VirtualServerID is the toolset the call came in on.
	VirtualServerID string `json:"virtual_server_id,omitempty"`
	ToolID          string `json:"tool_id,omitempty"`
	ToolName        string `json:"tool_name,omitempty"`
	BackendID       string `json:"backend_id,omitempty"`
	// SessionID is the Mcp-Session-Id THIS GATEWAY minted.
	//
	// 🔴 It does not join an MCP call to an LLM conversation. The client chooses
	// the conversation id; we choose this one. That asymmetry is why heuristic
	// correlation is forbidden (R17) — see the P13 leg-B design.
	SessionID string `json:"session_id,omitempty"`
	// ConversationSessionID is the LLM conversation this call belongs to, if the
	// client told us — extracted from the existing session-fingerprint table
	// (protocol: mcp), 🚫 never guessed.
	//
	// 🔴 A SECOND column rather than an overloaded SessionID. They are different
	// facts with different owners: SessionID is ours, this one is the client's,
	// and a single column holding "whichever we had" makes "which one is this"
	// unanswerable exactly when somebody is trying to trace an incident.
	//
	// 🔴 EMPTY for Claude Code, which sends neither convention header on its MCP
	// requests. That is the expected result, not a gap to fill: correlation by
	// time window or seat is forbidden (R17), because a plausible-but-wrong
	// audit row is worse than none — with none, the reader knows they do not know.
	ConversationSessionID string `json:"conversation_session_id,omitempty"`
	// AppSlug is which Agent made the call, from the existing uaattribution
	// word list. 🔴 Never empty: an unrecognised client is `unknown-app`, which
	// is a verdict, not a gap.
	AppSlug string `json:"app_slug"`
	// ActorID is the client's own identifier for WHICH AGENT made this call
	// (P15 · K3 · task 15.20), extracted at ingress from the actor fingerprint
	// table — 🚫 never guessed, never derived, never correlated.
	//
	// 🔴 Never empty on the wire. A client that supplies nothing is recorded as
	// `UnknownActor` ("unknown-actor"), which is a VERDICT — "we looked and the
	// client told us nothing" — and is a different fact from the empty string,
	// which means "this row was written by a proxy that did not collect an actor
	// at all". Both are permanent; they have different causes, and the console
	// must be able to tell them apart (R52's shape, applied to the actor).
	// 🚫 Do not "tidy" the constant away by defaulting to "": a blank cell reads
	// as a defect in us and invites somebody to go fill it in by guessing.
	//
	// 🔴 On Claude Code this is expected to be `unknown-actor` essentially 100%
	// of the time, and that is NOT a bug to go fix — PRD §0.7: Claude Code's MCP
	// requests structurally carry no agent identifier, the same reason they carry
	// no conversation id (see ConversationSessionID). The value of recording the
	// field is that the gap becomes MEASURABLE (EventActorUnresolved) instead of
	// being an assumption. 🚫 Closing it with a time-window or same-seat
	// heuristic is forbidden (I33): a plausible-but-wrong attribution in an audit
	// trail is worse than an admitted blank, because it gets acted on.
	// Fence: TestActor_NoHeuristicResolution.
	ActorID string `json:"actor_id"`
	// Origin separates a real Agent call from a console "try it" click.
	// 🔴 A value, never a bypass: a console test is billed, rate-limited and
	// recorded exactly like any other call.
	Origin string `json:"origin"`
	Status string `json:"status"`
	// ErrorCode is the frozen MCP_* / EXT_MCP_* code for a non-ok status, so a
	// reader gets the precise reason and not only the coarse status.
	ErrorCode  string `json:"error_code,omitempty"`
	DurationMs int64  `json:"duration_ms"`
	// ArgsDigest is the structural summary produced by DigestArgs, marshalled.
	// 🔴 Always present, even when raw retention is on — the digest is what the
	// console renders, and a record whose digest depended on a switch would make
	// the UI vary by organisation setting.
	ArgsDigest string `json:"args_digest"`
	// ArgsRaw is nil in the default configuration. A POINTER so "retention is
	// off" (nil) stays distinguishable from "retention is on and the arguments
	// were empty" ("").
	ArgsRaw *string `json:"args_raw,omitempty"`
	// UpstreamRequestID is the join key for after-the-fact tracing.
	// 🔴 Recorded here rather than sent upstream as a header: no X-Aikey-* ever
	// leaves for a backend (D-13).
	UpstreamRequestID string `json:"upstream_request_id,omitempty"`
	// ManifestHash is the PUBLISHED fingerprint of the tool as served, so a
	// reader can prove what ran matched what was approved.
	ManifestHash string `json:"manifest_hash,omitempty"`
	CreatedAtMs  int64  `json:"created_at_ms"`
}

// Call statuses. 🔴 These strings are the value domain of
// `mcp_call_event.status` (dbmigrate.MCPCallStatusValues). They are repeated
// here rather than imported because pkg/ must not depend on a service module;
// TestCallStatusesMatchTheColumnDomain in aikey-proxy — which imports both —
// keeps the two identical.
const (
	// CallStatusOK — the backend ran the tool and answered.
	CallStatusOK = "ok"
	// CallStatusForbidden — the seat is not granted this tool.
	CallStatusForbidden = "forbidden"
	// CallStatusSchemaRejected — the arguments failed the tool's own
	// inputSchema. 🔴 The upstream was NOT called.
	CallStatusSchemaRejected = "schema_rejected"
	// CallStatusUpstreamError — the backend was reached (or should have been)
	// and the call did not succeed.
	CallStatusUpstreamError = "upstream_error"
	// CallStatusTimeout — the backend did not answer in time. 🔴 Distinct from
	// upstream_error because the tool MAY have run; that difference is what
	// decides whether a retry is safe (R4).
	CallStatusTimeout = "timeout"
	// CallStatusRateLimited — a rate or concurrency gate refused the call.
	CallStatusRateLimited = "rate_limited"
	// CallStatusNeedsReview — the tool is frozen pending review of an upstream
	// manifest change.
	CallStatusNeedsReview = "needs_review"
	// CallStatusCredentialMissing — the backend has no usable credential.
	CallStatusCredentialMissing = "credential_missing"
	// CallStatusInternalError — AiKey's own defect. 🔴 Recorded rather than
	// dropped: a gateway bug that made calls VANISH from the audit trail would
	// be indistinguishable, to the administrator reading it, from nobody having
	// called. It is deliberately not one of the "blame the upstream" values.
	CallStatusInternalError = "internal_error"
)

// Call origins — the value domain of `mcp_call_event.origin`.
const (
	// OriginAgent — a real Agent call.
	OriginAgent = "agent"
	// OriginConsoleTest — the console's "try it" panel.
	OriginConsoleTest = "console_test"
)

// callStatusByErrorCode maps a frozen error code to the recorded status.
//
// 🔴 A TABLE, not a chain of ifs, and 🔴 fenced against ErrorCodeCatalog: a code
// added to the catalog without a status here makes
// TestEveryFrozenErrorCodeHasACallStatus go red. The alternative — a default
// branch — would file a new refusal shape under whatever value happened to be
// the fallback, and nobody would find out.
var callStatusByErrorCode = map[ErrorCode]string{
	ErrToolForbidden:     CallStatusForbidden,
	ErrToolNeedsReview:   CallStatusNeedsReview,
	ErrSchemaInvalid:     CallStatusSchemaRejected,
	ErrRateLimited:       CallStatusRateLimited,
	ErrCredentialMissing: CallStatusCredentialMissing,
	// 🔴 Recorded as `forbidden` — the gateway refused it — with the precise
	// reason preserved in error_code. A separate status would have meant a new
	// value in a domain that already answers the question an administrator asks
	// ("was it refused?"), while error_code answers the follow-up ("why?").
	ErrComplianceBlocked: CallStatusForbidden,
	// 🔴 Circuit-open, unreachable and "no transport for this backend" all land
	// here: from the caller's seat they are the same fact — the tool did not
	// run and the reason is on the backend side of the gateway.
	ErrBackendUnavailable: CallStatusUpstreamError,
	ErrUpstream5XX:        CallStatusUpstreamError,
	ErrUpstreamTimeout:    CallStatusTimeout,
	// 🔴 Session and protocol failures are transport-level: they happen before
	// a tool is even identified, so they are NOT recorded as tool calls at all.
	// They are mapped here only so the catalog fence stays exhaustive — see
	// CallStatusForErrorCode's second return.
	ErrSessionNotFound:     "",
	ErrProtocolUnsupported: "",
}

// CallStatusForErrorCode returns the status to record for a frozen error code.
//
// recordable is false for codes that are not tool-call outcomes (session and
// protocol failures, which happen before any tool is named), and for codes this
// build has never heard of. 🔴 An unknown code must NOT be silently filed as
// some existing status: the caller logs it and records internal_error, which is
// the honest description of "our own build emitted a code it cannot classify".
func CallStatusForErrorCode(code ErrorCode) (status string, recordable bool) {
	s, ok := callStatusByErrorCode[code]
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// MarshalArgsDigest renders a digest for storage, never returning invalid JSON.
//
// 🔴 An empty digest is "[]", not "": the column is NOT NULL and the console
// parses it, so an empty string would be a parse failure at read time for every
// call with no arguments — the most common call there is.
func MarshalArgsDigest(entries []ArgDigestEntry) string {
	if len(entries) == 0 {
		return "[]"
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		// Unreachable for this shape (three scalar fields), but a silent "" here
		// would be a read-time parse failure far from the cause.
		return "[]"
	}
	return string(raw)
}
