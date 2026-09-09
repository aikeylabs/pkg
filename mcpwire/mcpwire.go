// Package mcpwire is the FROZEN wire contract of the AiKey MCP gateway.
//
// # Why this package exists at all
//
// The MCP plane has three consumers that must agree byte-for-byte on what a
// tool, a tool call, and an error look like:
//
//	aikey-proxy           serves /mcp/* and proxies to upstream MCP servers
//	aikey-control-master  stores the published manifest, computes drift, and
//	                      renders the console
//	the web console       reads the JSON both of them produce
//
// If each of them declared its own structs, the first schema change would
// desynchronise them silently — the classic failure this repo already solved
// twice, for fallback thresholds (pkg/fallbackpolicy) and routing (pkg/routingwire).
// This package follows those two precedents exactly: ONE definition, several
// consumers, and the definition lives outside any single service.
//
// # 🔴 What "frozen" means here
//
// The endpoint shapes and the vocabulary below are a PUBLIC contract with
// third-party MCP clients (Claude Desktop, Claude Code, mcp-inspector). Once a
// customer's developer has written /mcp/<slug> into ~/.claude.json, renaming it
// is a silent breakage on their machine — the client only ever says "cannot
// connect". So:
//
//	adding a field / an error code / a protocol revision   ✅ allowed
//	renaming or removing one                               🚫 not allowed
//
// Frozen 2026-09-01 by
// roadmap20260320/技术实现/阶段8-平台化/MCP网关/openspec/changes/aikey-mcp-gateway/baseline-forensics.md §二
// (contract freeze 0.13–0.19). Requirement spec:
// workflow/CI/requirements/2026-08-20-mcp-gateway.md.
package mcpwire

import "encoding/json"

// ---------------------------------------------------------------------------
// Protocol revisions (freeze 0.14)
// ---------------------------------------------------------------------------

// ProtocolVersion is an MCP specification revision, spelled exactly as it
// appears on the wire in `initialize`.
type ProtocolVersion string

const (
	// ProtocolV20241105 is the earliest stable revision. Early Claude Desktop
	// builds still speak it, which is the whole reason it is in the set.
	ProtocolV20241105 ProtocolVersion = "2024-11-05"
	// ProtocolV20250326 introduced Streamable HTTP.
	ProtocolV20250326 ProtocolVersion = "2025-03-26"
	// ProtocolV20250618 is the latest published revision.
	ProtocolV20250618 ProtocolVersion = "2025-06-18"
)

// SupportedProtocolVersions is the gateway's advertised support set, NEWEST
// FIRST. Order is part of the contract: negotiation prefers the earliest
// element that both sides accept when the client asks for something we cannot
// speak but has not pinned a version, so "newest first" means "best first".
//
// 🔴 This slice is the ONE place the support set is written. GET
// /mcp/capabilities renders it and the negotiator consults it, so the
// documented answer and the enforced answer cannot drift — that identity is
// requirement R1 and is fenced by
// TestCapabilitiesMatchesNegotiator.
//
// 🚫 Do NOT hardcode "the latest revision" anywhere. R1: the version is
// NEGOTIATED, not compiled in. The incoming brief said "supports MCP 2025-03,
// the latest spec"; by the time this was written 2025-06-18 had shipped, and a
// gateway that only speaks one revision is simply unusable for the older
// Claude Desktop builds that are still in the field.
var SupportedProtocolVersions = []ProtocolVersion{
	ProtocolV20250618,
	ProtocolV20250326,
	ProtocolV20241105,
}

// IsSupported reports whether v is in SupportedProtocolVersions.
func IsSupported(v ProtocolVersion) bool {
	for _, s := range SupportedProtocolVersions {
		if s == v {
			return true
		}
	}
	return false
}

// SupportedProtocolStrings returns the support set as plain strings, for JSON
// bodies and error payloads that must not depend on this package's types.
func SupportedProtocolStrings() []string {
	out := make([]string, 0, len(SupportedProtocolVersions))
	for _, v := range SupportedProtocolVersions {
		out = append(out, string(v))
	}
	return out
}

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 envelope
// ---------------------------------------------------------------------------

// JSONRPCVersion is the only value the `jsonrpc` field may carry.
const JSONRPCVersion = "2.0"

// Method names MCP defines. Declared as constants because the logging
// convention in this repo forbids bare string literals for anything that ends
// up in an event name or a metric label.
const (
	MethodInitialize       = "initialize"
	MethodInitialized      = "notifications/initialized"
	MethodToolsList        = "tools/list"
	MethodToolsCall        = "tools/call"
	MethodPing             = "ping"
	MethodToolsListChanged = "notifications/tools/list_changed"
	MethodCancelled        = "notifications/cancelled"
)

// Envelope is a JSON-RPC 2.0 message. One struct serves requests, responses
// and notifications because MCP multiplexes all three over the same transport
// and a reader cannot know which it is holding until it has looked at the
// fields.
//
// ID is json.RawMessage rather than any/string/int64 deliberately: JSON-RPC
// allows string OR number ids, and a response MUST echo the request's id
// byte-for-byte. Decoding into `any` would turn 1 into float64(1) and echo
// back `1` — usually right, sometimes not (large ids lose precision). Keeping
// the raw bytes makes the echo exact by construction.
//
// A notification is an Envelope with Method set and ID absent (nil), which is
// distinguishable from `"id": null` — hence the pointer-free RawMessage: nil
// slice means "field absent", a 4-byte "null" means the client sent null.
type Envelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// IsNotification reports whether e carries no id, i.e. the peer expects no
// response. Answering a notification is a protocol violation that some clients
// treat as fatal, so every dispatcher must check this.
func (e *Envelope) IsNotification() bool { return len(e.ID) == 0 }

// IsRequest reports whether e is a call that expects a response.
func (e *Envelope) IsRequest() bool { return e.Method != "" && !e.IsNotification() }

// RPCError is the JSON-RPC error object.
//
// Code carries the JSON-RPC numeric code; Data carries AiKey's own structured
// payload including the frozen ErrorCode (see errors.go). Two levels are
// needed because generic MCP clients switch on the numeric code while our
// console and support flow switch on the string code.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// JSON-RPC 2.0 reserved codes.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

// Implementation identifies a peer (client or server) by name and version.
type Implementation struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
}

// ClientCapabilities is what the client says it can do. The gateway records it
// but does not currently vary behaviour on it; kept as RawMessage-free typed
// fields only for the parts we actually read.
type ClientCapabilities struct {
	Roots    *RootsCapability `json:"roots,omitempty"`
	Sampling json.RawMessage  `json:"sampling,omitempty"`
}

// RootsCapability mirrors the spec's roots capability object.
type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeRequest is the params object of `initialize`.
type InitializeRequest struct {
	ProtocolVersion ProtocolVersion    `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      Implementation     `json:"clientInfo"`
}

// ServerCapabilities is what the gateway advertises back.
//
// Only `tools` is populated today. `resources` / `prompts` are deliberately
// absent rather than present-and-empty: an absent capability means "not
// offered", while an empty object means "offered, currently nothing in it".
// Advertising an empty resources capability would make compliant clients call
// resources/list and get a method-not-found, which reads to the user as a
// broken server.
type ServerCapabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability advertises tool support. ListChanged is false today because
// the gateway does not push notifications/tools/list_changed — the manifest is
// FROZEN on drift (R3) rather than pushed, so there is nothing to notify about
// until a human adopts, and after adoption the client's next tools/list is
// already correct.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeResult is the result object of `initialize`.
type InitializeResult struct {
	ProtocolVersion ProtocolVersion    `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      Implementation     `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// ---------------------------------------------------------------------------
// tools/list · tools/call
// ---------------------------------------------------------------------------

// Tool is one tool as it appears on the wire.
//
// 🔴 Only Name, Description and InputSchema enter manifest_hash (freeze 0.17).
// Title and Annotations are carried but NOT hashed — see ManifestHash in
// manifest.go for the reasoning, which is a security argument, not a
// convenience one.
type Tool struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations,omitempty"`
	// Icons arrived with MCP revision 2025-11-25. Carried so a client that
	// wants them gets them, 🔴 NOT hashed — see ManifestHash.
	Icons json.RawMessage `json:"icons,omitempty"`
}

// ListToolsResult is the result of tools/list.
//
// NextCursor supports the spec's pagination. The gateway returns every tool in
// one page today (a toolset with enough tools to need pagination is already a
// usability problem the console flags), but the field is on the wire so a
// future page split is not a breaking change.
type ListToolsResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// CallToolRequest is the params object of tools/call.
type CallToolRequest struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ContentBlock is one piece of a tool's result.
type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// CallToolResult is the result of tools/call.
//
// IsError is the spec's in-band error channel: a tool that ran and failed
// returns IsError=true with the failure in Content, whereas a PROTOCOL failure
// (unknown tool, forbidden, backend down) is a JSON-RPC error. Conflating the
// two is a common gateway bug — it makes a permission denial look to the model
// like a tool that returned "access denied", which the model then narrates to
// the user as if the operation was attempted.
type CallToolResult struct {
	Content           []ContentBlock  `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
}

// ---------------------------------------------------------------------------
// Session header
// ---------------------------------------------------------------------------

// HeaderSessionID is the Streamable HTTP session header defined by the spec.
// The gateway MINTS this value at initialize; it is not something the client
// chooses. That asymmetry is why it cannot be used to join an MCP call back to
// an LLM conversation — see requirement R17.
const HeaderSessionID = "Mcp-Session-Id"

// HeaderProtocolVersion is the spec's per-request protocol echo header
// (2025-06-18 and later).
const HeaderProtocolVersion = "MCP-Protocol-Version"

// ---------------------------------------------------------------------------
// P13 · a tool call as seen from the CONVERSATION side
// ---------------------------------------------------------------------------

// LinkState is how confident we are that a tool call the model asked for was
// actually executed through this gateway.
//
// 🔴 Three values, never two. Requirement R17 forbids collapsing Pending and
// Bypassed: the first is noise (the usage-reporting channel has not caught up),
// the second is a SECURITY EVENT (the call did not go through AiKey at all).
// A boolean here would render "we haven't heard yet" and "somebody is bypassing
// the gateway" as the same pixel.
type LinkState string

const (
	// LinkStateLinked — an mcp_call_event was found via an EXPLICIT join key.
	LinkStateLinked LinkState = "linked"
	// LinkStatePending — nothing found yet, and the backfill window has not
	// closed. Expected to resolve on its own.
	LinkStatePending LinkState = "pending"
	// LinkStateBypassed — the backfill window closed with nothing found. The
	// call did not traverse the gateway.
	//
	// 🔴 Customer-facing wording must say "this call did not go through AiKey,
	// it may be a direct-connect configuration" plus a next step. It must NOT
	// read as "AiKey is broken" (R22).
	LinkStateBypassed LinkState = "bypassed"
	// LinkStateUnsupported — the proxy node that captured this turn predates
	// tool-call capture. 🔴 NOT the same as "this turn had no tool calls";
	// rendering it as the latter is a false report (tasks 13.8).
	LinkStateUnsupported LinkState = "unsupported"
)

// TurnToolCall is one tool call extracted from a model response, as stored in
// conversation_records.tool_calls and rendered in the conversation-audit
// drawer.
//
// 🔴 ONE definition, three consumers (proxy writes it, collector projects it,
// the console renders it) — tasks 13.5. It lives here rather than in the proxy
// for the same reason the rest of this package does.
//
// 🔴 ArgsDigest, not raw arguments. Requirement R16: the retention granularity
// of tool arguments follows the MCP RAW-ARGUMENTS switch, not the
// conversation-audit switch, because it is the SAME data (SQL, file contents,
// sometimes credentials) that R6 already ruled defaults to a summary. One piece
// of data behind two gates is no gate at all.
type TurnToolCall struct {
	// ToolCallID is the model-assigned id of this tool_use block. It is the
	// only thing that links the request to its tool_result in a later turn.
	ToolCallID string `json:"tool_call_id"`
	// ToolName as the model asked for it.
	ToolName string `json:"tool_name"`
	// ArgsDigest is the structural summary: key names, JSON types, value
	// lengths. Never values.
	ArgsDigest []ArgDigestEntry `json:"args_digest,omitempty"`
	// ArgsRaw is populated ONLY when the org's MCP raw-arguments switch is on,
	// AND after DLP. 🔴 Default nil. See R6 / R16.
	ArgsRaw json.RawMessage `json:"args_raw,omitempty"`
	// LinkState is the three-way join verdict. See LinkState.
	LinkState LinkState `json:"link_state"`
	// CallEventID is the mcp_call_event this was joined to. Empty unless
	// LinkState == LinkStateLinked.
	CallEventID string `json:"call_event_id,omitempty"`
}

// ArgDigestEntry is one key of a tool's arguments, described without its value.
//
// Type is the JSON type name ("string", "number", "boolean", "object",
// "array", "null") and Len is the value's length — byte length for strings,
// element count for arrays and objects, and 0 otherwise. That is enough for an
// auditor to see "a 4 kB string was passed as `query`" without the gateway
// storing the query.
type ArgDigestEntry struct {
	Key  string `json:"key"`
	Type string `json:"type"`
	Len  int    `json:"len"`
}
