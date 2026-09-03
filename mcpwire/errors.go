package mcpwire

// errors.go — the FROZEN MCP error-code vocabulary (freeze 0.15, PRD §4.2).
//
// # Why a second code on top of the JSON-RPC number
//
// JSON-RPC gives five numeric codes, all of them about the SHAPE of the
// message. None of them can express "you are not authorised for this tool" or
// "the upstream timed out". Generic MCP clients switch on the number; our
// console, our support flow and the customer's own runbook switch on these
// strings. Both live on the wire: number in RPCError.Code, string in
// RPCError.Data.
//
// # 🔴 The EXT_ prefix is the whole point of two of these
//
// EXT_ means "the failure happened at the UPSTREAM MCP server, not inside
// AiKey". Without that distinction a customer staring at an error cannot tell
// whether to open a ticket with us or with whoever runs their GitHub MCP
// server — and that single question is most of the support cost of a gateway
// product. Same rule the repo already applies to LLM upstreams:
// workflow/CI/requirements/2026-06-05-aikey-vs-upstream-error-distinguishable.md.
//
// 🚫 No string literals at call sites. Adding a code means adding a constant
// here and a row to ErrorCodeCatalog; the fence
// TestEveryErrorCodeIsCatalogued keeps the two in step.

import "net/http"

// ErrorCode is an AiKey MCP-plane error code. UPPER_SNAKE_CASE per the repo's
// logging conventions.
type ErrorCode string

const (
	// ErrToolForbidden — the seat is not granted this tool. 403.
	ErrToolForbidden ErrorCode = "MCP_TOOL_FORBIDDEN"
	// ErrBackendUnavailable — the backend is circuit-open or unreachable. 503.
	// 🔴 The message MUST carry the remaining cooldown seconds; "try again
	// later" without a number is not actionable.
	ErrBackendUnavailable ErrorCode = "MCP_BACKEND_UNAVAILABLE"
	// ErrToolNeedsReview — manifest drift is frozen and this is a write tool.
	// 409. Read-only tools keep serving the old version instead (R3).
	ErrToolNeedsReview ErrorCode = "MCP_TOOL_NEEDS_REVIEW"
	// ErrSchemaInvalid — arguments do not satisfy the tool's own inputSchema.
	// 400. 🔴 The message MUST carry the offending field path, and the upstream
	// MUST NOT have been called.
	ErrSchemaInvalid ErrorCode = "MCP_SCHEMA_INVALID"
	// ErrRateLimited — a rate or concurrency gate rejected the call. 429.
	ErrRateLimited ErrorCode = "MCP_RATE_LIMITED"
	// ErrSessionNotFound — Mcp-Session-Id is unknown or expired. 404.
	ErrSessionNotFound ErrorCode = "MCP_SESSION_NOT_FOUND"
	// ErrProtocolUnsupported — version negotiation failed. 400.
	// 🔴 The data payload MUST list the full support set, otherwise the client
	// has no way to pick something that would work.
	ErrProtocolUnsupported ErrorCode = "MCP_PROTOCOL_UNSUPPORTED"
	// ErrCredentialMissing — the backend has no credential bound, or decryption
	// failed. 424. 🔴 Message must point at the credential-binding page.
	ErrCredentialMissing ErrorCode = "MCP_CREDENTIAL_MISSING"
	// ErrComplianceBlocked — an organisation's DLP policy refused this call. 403.
	//
	// 🔴 Its OWN code rather than reusing MCP_TOOL_FORBIDDEN. That code means
	// "this seat is not granted this tool", whose fix is "ask an administrator
	// for a grant" — advice that would send a developer to request a permission
	// they already have while the real cause (the content they sent) goes
	// unmentioned. Two different problems with two different fixes cannot share
	// one code.
	//
	// 🔴 The message names the POLICY and the finding id, 🚫 never the matched
	// content: echoing what was detected would send the sensitive value straight
	// back out, one more copy of exactly what the block exists to contain.
	ErrComplianceBlocked ErrorCode = "MCP_COMPLIANCE_BLOCKED"
	// ErrUpstream5XX — 🔴 the UPSTREAM MCP server returned 5xx. 502.
	ErrUpstream5XX ErrorCode = "EXT_MCP_UPSTREAM_5XX"
	// ErrUpstreamTimeout — 🔴 the UPSTREAM MCP server timed out. 504.
	ErrUpstreamTimeout ErrorCode = "EXT_MCP_UPSTREAM_TIMEOUT"
)

// ErrorCodeSpec describes one frozen code.
type ErrorCodeSpec struct {
	Code ErrorCode
	// HTTPStatus is the status the HTTP transport uses when this error is the
	// whole response. Inside a JSON-RPC batch the transport is still 200 and
	// only RPCError carries the failure — that asymmetry is the spec's, not
	// ours.
	HTTPStatus int
	// RPCCode is the JSON-RPC numeric code a generic client will switch on.
	RPCCode int
	// Upstream marks codes that describe a failure of the UPSTREAM MCP server
	// rather than of AiKey. Exactly the EXT_ ones.
	Upstream bool
	// Summary is the one-line meaning, in English (CLAUDE.md: all UI strings
	// and code comments are English).
	Summary string
}

// ErrorCodeCatalog is the single enumeration of the frozen codes.
//
// 🔴 Adding a row here is adding a PUBLIC contract element. Removing or
// renaming one is forbidden after release: customers write these strings into
// their alerting rules.
var ErrorCodeCatalog = []ErrorCodeSpec{
	{ErrToolForbidden, http.StatusForbidden, CodeInvalidRequest, false,
		"The seat is not granted this tool."},
	{ErrBackendUnavailable, http.StatusServiceUnavailable, CodeInternalError, false,
		"The MCP backend is circuit-open or unreachable; retry after the stated cooldown."},
	{ErrToolNeedsReview, http.StatusConflict, CodeInvalidRequest, false,
		"The upstream manifest changed and this write tool is frozen pending human review."},
	{ErrSchemaInvalid, http.StatusBadRequest, CodeInvalidParams, false,
		"Arguments do not satisfy the tool's inputSchema; the upstream was not called."},
	{ErrRateLimited, http.StatusTooManyRequests, CodeInvalidRequest, false,
		"A rate or concurrency limit rejected this call."},
	{ErrSessionNotFound, http.StatusNotFound, CodeInvalidRequest, false,
		"Mcp-Session-Id is unknown or expired; re-run initialize."},
	{ErrProtocolUnsupported, http.StatusBadRequest, CodeInvalidParams, false,
		"No common MCP protocol revision; see the supported set in error data."},
	{ErrCredentialMissing, http.StatusFailedDependency, CodeInternalError, false,
		"The backend has no usable credential bound."},
	{ErrComplianceBlocked, http.StatusForbidden, CodeInvalidRequest, false,
		"An organisation compliance policy refused this call's content."},
	{ErrUpstream5XX, http.StatusBadGateway, CodeInternalError, true,
		"The upstream MCP server returned a server error."},
	{ErrUpstreamTimeout, http.StatusGatewayTimeout, CodeInternalError, true,
		"The upstream MCP server did not respond in time."},
}

// specByCode is built once; the catalog is immutable after init.
var specByCode = func() map[ErrorCode]ErrorCodeSpec {
	m := make(map[ErrorCode]ErrorCodeSpec, len(ErrorCodeCatalog))
	for _, s := range ErrorCodeCatalog {
		m[s.Code] = s
	}
	return m
}()

// Spec returns the frozen spec for code, and whether it is a known code.
func Spec(code ErrorCode) (ErrorCodeSpec, bool) {
	s, ok := specByCode[code]
	return s, ok
}

// HTTPStatusFor returns the HTTP status for code, or 500 for an unknown code.
//
// Returning 500 rather than panicking is deliberate: an unknown code at
// runtime means a code path constructed an error we have not catalogued, which
// is a bug in US. Answering 500 tells the truth about that ("something went
// wrong inside AiKey") instead of mislabelling our own bug as, say, a 403 the
// customer would then go hunting for in their permissions.
func HTTPStatusFor(code ErrorCode) int {
	if s, ok := specByCode[code]; ok {
		return s.HTTPStatus
	}
	return http.StatusInternalServerError
}

// RPCCodeFor returns the JSON-RPC numeric code for code, or CodeInternalError.
func RPCCodeFor(code ErrorCode) int {
	if s, ok := specByCode[code]; ok {
		return s.RPCCode
	}
	return CodeInternalError
}

// IsUpstream reports whether code blames the upstream MCP server rather than
// AiKey. Callers use it to decide who the customer should contact.
func IsUpstream(code ErrorCode) bool {
	s, ok := specByCode[code]
	return ok && s.Upstream
}
