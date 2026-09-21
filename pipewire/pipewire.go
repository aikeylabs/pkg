// Package pipewire is the SINGLE definition of the length-prefixed binary
// parent↔child IPC protocol between aikey-proxy (parent, internal/apphook) and
// ai-compliance-detector (child, cmd/detector).
//
//	[1-byte protocol version] [4-byte LE length] [N-byte payload]
//
// Why a shared module (not duplicated codecs): this protocol previously lived in
// ai-compliance-detector/internal/pipe, and `internal/` is scoped to the module
// that declares it — so every OTHER participant had to hand-roll its own copy of
// the frame header, the payload offsets, the op/action codes and the MaskMeta
// JSON tags, held in lockstep across three repos by nothing but a comment. By
// 2026-08-10 there were FIVE copies, and the protocol had drifted on two of its
// three version bumps:
//
//	v3 (2026-06-06) — the control-master Stage C test kept writing v1 frames;
//	                  the detector closed the pipe and the test failed with a
//	                  bare "read response: EOF". Blind for 4 days.
//	v4 (2026-08-08) — the same test kept writing v3 frames (blind for 2 months,
//	                  because nothing in CI or Make ran it), AND
//	                  ai-compliance-detector/scripts/e2e-echo.sh kept sending a
//	                  hardcoded v3 hex frame, breaking the detector's OWN
//	                  `make e2e` inside its own repo.
//
// Both were detected only by humans reading output. A version byte fails loud on
// header skew, but nothing at all guarded the MaskMeta JSON field names, the
// op/action code values, or the 64KB cap — those are duplicated semantics that a
// version byte cannot see. Importing THIS package via go.mod replace (same
// pattern as pkg/routingwire, pkg/seatassign) turns every one of those from a
// runtime mis-parse into a compile error.
//
// Evolution: bump ProtocolVersion on ANY wire-format change and append a
// changelog entry below. Parent and child are rebuilt and shipped together, so
// they move in lockstep and the version byte is the backstop, not the contract.
//
// Spike-validated latency (Day 14 P2): macOS arm64 native p99 36µs,
// Linux arm64 Docker p99 63µs. See cmd/ipc-spike/main.go in ai-compliance-spike
// for the original benchmark code.
package pipewire

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// ProtocolVersion bumped on any wire-format change.
//
// The version byte is enforced (方案 §6 invariant #15) — parent and child running
// different versions ⇒ child startup fails + reports degraded explicitly.
// Prevents app-upgrade half-completed states where proxy v1 talks to child v2.
//
// v2 (2026-06-03, team→master compliance pipeline): Request gains a 1-byte
// RouteClass (after op); Response gains a length-prefixed Findings + trailing
// Event blob. The version byte is enforced, so a v1↔v2 proxy/detector mismatch
// fails loud at child startup rather than silently mis-parsing — proxy and
// detector are rebuilt + shipped together, so they move in lockstep.
//
// v3 (2026-06-06, concurrent worker pool): Request + Response each gain a 4-byte
// LE request-id (Request: after route_class; Response: at the front). This lets
// the proxy multiplex many in-flight Detects on one pipe and match each response
// to its request by id (responses may now return out of order once the detector
// processes concurrently). Lockstep as before.
//
// v4 (2026-08-08, B3 CN_ADDRESS 占位替换/响应还原): Response gains a
// length-prefixed MaskMeta blob between Findings and Event. It carries the
// RESTORABLE-mask contract (JSON, see MaskMeta type): which placeholder token
// the masked payload contains and the byte spans of the ORIGINAL payload each
// occurrence replaced, so the proxy can (a) renumber the token into per-request
// labels and (b) restore the labels back to the original text on the RESPONSE
// path (spec 2026-06-04 合规过滤方向, 规则 2 唯一例外). Offsets only — the raw
// span text never travels twice (the proxy already holds the original payload
// it sent). Empty for non-mask verdicts and for masks with nothing restorable.
// Lockstep as before (proxy + detector rebuilt and shipped together; the
// version byte fails loud on skew).
//
// NOT a bump (2026-09-21, TODO-188 方案 C, 用户拍板 C.7-1): OpSetGrading = 5 was
// APPENDED to the op table. Same reasoning as ActionAnswer below: the version
// byte guards the BINARY layout, and the op field is the same 1 byte it has
// always been — the request and response frames are unchanged, the document
// rides the existing Prompt slot and the ack rides the existing Findings slot.
// A child that predates the op answers it through its `default:` arm with an
// EMPTY Findings slot, which the proxy reads as "unsupported" and falls back to
// the pre-C behaviour (a full generation reload). Bumping would instead make
// every old child fail its startup handshake — turning an optional
// optimisation into a fleet outage during a staggered upgrade.
const ProtocolVersion byte = 4

// Op codes for request payload.
const (
	OpDetect    uint8 = 1 // detect a prompt
	OpStatus    uint8 = 2 // query child health
	OpClose     uint8 = 3 // graceful shutdown signal
	OpListPacks uint8 = 4 // list currently-effective packs (built-in + pulled); response carries JSON in Findings
	// OpSetGrading hot-swaps the org 分类分级 document in a RUNNING child
	// (TODO-188 方案 C). Request.Prompt = the compact document bytes, exactly as
	// the proxy would have baked them into AIKEY_COMPLIANCE_GRADING (empty =
	// "no member", an old master). Response.Findings = GradingApplied JSON.
	//
	// WHY IT EXISTS: until then the document reached the child ONLY through its
	// spawn environment, so every ladder edit re-spawned the whole detector
	// pool (new generation first, old one drained after). On a 1.6 GB Cluster
	// worker the doubled pool crossed the unit's MemoryHigh and the node
	// livelocked (TODO-188 triage, 2026-09-21).
	//
	// 🔴 A child that cannot parse the document KEEPS the one it is enforcing
	// and says so (parse_ok=false + the token of the document still in force) —
	// 用户拍板 C.7-3. The proxy moves nothing (env, cache epoch, its own rules)
	// until parse_ok=true AND the token matches the bytes it sent.
	//
	// Appended, never renumbered; no ProtocolVersion bump (see there).
	// Pinned by TestOpCodes_AppendedNeverRenumbered.
	OpSetGrading uint8 = 5
)

// GradingApplied is the JSON payload Response.Findings carries for
// OpSetGrading. Field tags are the wire contract, pinned ONCE in
// TestGradingAppliedWireBytes; the detector encodes this type and aikey-proxy
// decodes it.
//
// GradingToken is GradingToken(document) of the document the child is
// enforcing AFTER handling the request: the new one when ParseOK, the previous
// one when not. It is a digest of an administrator POLICY document the proxy
// itself sent — not a value derived from user content — so it may appear on
// health surfaces and in logs.
type GradingApplied struct {
	GradingToken string `json:"grading_token"`
	ParseOK      bool   `json:"parse_ok"`
}

// GradingToken is THE one reduction of an org grading document to a token,
// spelled "grading:<sha256[:16]>" (design.md §4b). It hashes the EXACT bytes
// (no trimming — canonicalisation is the proxy's normalizeGradingPolicy, done
// once at the entry); empty input is the "no document" token.
//
// WHY IT LIVES HERE: the proxy uses it for the filter signature and the
// verdict-cache epoch, the detector for the OpSetGrading ack, and the proxy
// compares the two. Two hand-copied digests would turn any drift into "the
// child refused every document" — the hot swap silently never landing.
func GradingToken(doc []byte) string {
	sum := sha256.Sum256(doc)
	return "grading:" + hex.EncodeToString(sum[:])[:16]
}

// Action codes for response payload.
//
// Appended, never renumbered: the value travels the pipe as a raw byte, so
// reordering the rungs would reinterpret every verdict already in flight.
// Pinned by TestActionCodes_AppendedNeverRenumbered.
const (
	ActionAllow uint8 = 0
	ActionMask  uint8 = 1
	ActionBlock uint8 = 2
	ActionWarn  uint8 = 3
	// ActionAnswer is 安全代答 (canned answer): refuse the request like
	// ActionBlock, but let the proxy serve an administrator-authored reply
	// instead of a 403. On this verdict Response.Findings carries the
	// CannedAnswer JSON (the slot is free: nothing is masked, because nothing
	// is forwarded).
	//
	// Why no ProtocolVersion bump: the version byte guards the BINARY layout,
	// and the action field is the same 1 byte it has always been — appending a
	// value changes no offset and no length. A parent that does not recognize
	// the value must treat it as a block (aikey-proxy apphook.NormalizeAction,
	// R-compliance-canned-answer-6), never as an allow.
	//
	// Why it lives here (TODO-85, 2026-09-15): until then `4` was spelled in
	// aikey-proxy (apphook.ActionAnswer) and in ai-compliance-detector
	// (internal/pipe) separately, held together by a fence on each side — the
	// exact hand-copied shape this package exists to remove (see the package
	// doc). Consumers reference this constant; they must not re-spell it.
	ActionAnswer uint8 = 4
)

// RouteClass tells the detector where this request's compliance event should be
// reported (team→master vs personal→local). The proxy sets it from the request's
// RouteSource (VK class); the credential/URL never travel the pipe — only the
// class. See update doc 20260603 §2.3 / §3.
const (
	RouteClassPersonal uint8 = 0 // default: local self-view intake (DC5, current behavior)
	RouteClassTeam     uint8 = 1 // team key → detector returns the event for the proxy to upload to master
)

// MaxPayloadBytes is a sanity bound — Stage 1 prompts in real workloads are tens
// of KB at most. Anything larger is suspicious. Exported because every
// participant used to hard-code the same 65536 literal in its own reader.
const MaxPayloadBytes = 65536

var (
	ErrShortRead       = errors.New("pipe: short read")
	ErrVersionMismatch = errors.New("pipe: protocol version mismatch")
)

// ReadFrame reads one frame from r. Returns (version, payload, err).
// Caller MUST check returned version against ProtocolVersion.
func ReadFrame(r *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	version := header[0]
	length := binary.LittleEndian.Uint32(header[1:5])

	if length > MaxPayloadBytes {
		return version, nil, fmt.Errorf("pipe: payload too large (%d > %d)", length, MaxPayloadBytes)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return version, nil, err
	}
	return version, payload, nil
}

// WriteFrame writes one frame to w + flushes. payload may be nil for zero-length.
func WriteFrame(w *bufio.Writer, payload []byte) error {
	if _, err := w.Write(EncodeFrame(payload)); err != nil {
		return err
	}
	return w.Flush()
}

// EncodeFrame returns one complete on-wire frame (header + payload).
//
// Exported so that non-Go and non-bufio participants can obtain authoritative
// frame bytes instead of hand-writing hex literals: ai-compliance-detector's
// scripts/e2e-echo.sh shipped a hardcoded `\x03...` frame and silently broke the
// detector's own `make e2e` when the protocol moved to v4.
func EncodeFrame(payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = ProtocolVersion
	binary.LittleEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	return frame
}

// Request payload wire format (after pipe header), v3:
//
//	[1-byte op] [1-byte route_class] [4-byte LE req_id] [N-byte UTF-8 prompt]
type Request struct {
	Op         uint8
	RouteClass uint8  // RouteClassPersonal (0, default) / RouteClassTeam (1)
	ReqID      uint32 // v3: proxy-assigned id, echoed in Response.ReqID for demux
	Prompt     string
}

// Response payload wire format, v4:
//
//	[4-byte LE req_id] [1-byte action] [4-byte LE findings_len] [findings]
//	[4-byte LE maskmeta_len] [maskmeta_json] [N-byte event_json]
//
// ReqID echoes Request.ReqID so the proxy matches each response to its request —
// responses may return out of order once the detector processes concurrently.
// Findings and MaskMeta are length-prefixed so the trailing Event blob can be
// split out. MaskMeta is empty unless the mask verdict carries restorable spans
// (v4). What Event holds depends on the route class — see the Event field.
type Response struct {
	ReqID    uint32 // v3: echoes Request.ReqID
	Action   uint8
	Findings []byte // raw JSON (per-op meaning); empty on echo/allow
	// MaskMeta is the v4 restorable-mask contract: JSON encoding of MaskMeta
	// (restorable placeholder tokens + original-payload byte spans). NEVER
	// carries raw span text (offsets only) and MUST NOT be logged or persisted
	// downstream — the proxy keeps the derived placeholder↔original mapping in
	// per-request memory only (B3 拍板 2026-08-06).
	MaskMeta []byte
	// Event is a per-route-class slot (TODO-87, 2026-09-15 — this comment used
	// to say "empty for personal-routed requests", which is no longer true):
	//
	//	RouteClassTeam     — the FULL compliance event JSON. The proxy stamps
	//	                     attribution on it and uploads it to master.
	//	RouteClassPersonal — a CountProjection JSON, and only when the org
	//	                     grading document is non-empty and the piece has
	//	                     findings; empty otherwise. The detector has ALREADY
	//	                     uploaded the full event to the local self-view; the
	//	                     projection exists only so the proxy's request-level
	//	                     escalation counter can count this piece. The proxy
	//	                     MUST NOT upload it anywhere.
	//	non-Detect ops     — empty.
	//
	// Why no ProtocolVersion bump: the slot and its length framing are unchanged;
	// only the JSON inside differs, and an old proxy that reads a projection
	// decodes the same `findings` keys it already reads off a team event while
	// its route guard keeps the bytes from ever being uploaded.
	Event []byte
}

// MaskMeta is the JSON payload carried in Response.MaskMeta (v4). It is the
// single wire contract for "restorable masks": generic (entity-agnostic) so the
// proxy stays business-blind — it only learns "token X in the mutated payload
// stands for original bytes [s,e), and may be renumbered as prefix+N+suffix".
type MaskMeta struct {
	Restorables []Restorable `json:"restorables"`
}

// Restorable describes ONE placeholder token the planner substituted into the
// masked payload. Occurrences of Token appear in the masked text in the same
// order as Spans (both ascending by original offset).
type Restorable struct {
	// Token is the literal placeholder string present in the masked payload,
	// one occurrence per span.
	Token string `json:"token"`
	// NumberedPrefix/NumberedSuffix let the proxy rewrite the k-th occurrence
	// into a per-request numbered label `prefix + N + suffix` (label format is
	// owned by the detector's mask policy — single source of truth with it).
	NumberedPrefix string `json:"numbered_prefix"`
	NumberedSuffix string `json:"numbered_suffix"`
	// Spans are [start,end) BYTE offsets into the ORIGINAL request payload (the
	// exact bytes the proxy sent over the pipe), ascending, non-overlapping.
	Spans [][2]int `json:"spans"`
}

// CannedAnswer is the JSON payload Response.Findings carries when Action is
// ActionAnswer. Field tags are the wire contract; the exact bytes are pinned
// ONCE, in TestCannedAnswerWireBytes, and both participants use this type
// (ai-compliance-detector encodes it, aikey-proxy decodes it).
//
// Why a shared type and not a mirror on each side: a hand-retyped mirror drifts
// in a way the version byte cannot catch (the frame version guards the binary
// layout, never the JSON field names inside a slot) — a renamed tag decodes to
// an EMPTY text, which silently degrades a configured 代答 to a hard 403. Same
// reasoning, and same incident history, as MaskMeta.
//
// 🔴 The text is administrator-authored CONTENT. It travels exactly one hop
// (detector → proxy on the same machine) and is consumed there: it must not
// enter the audit event uploaded to master, must not enter the ListPacks
// report, and must not be logged — only its length.
type CannedAnswer struct {
	// Text is emitted to the user VERBATIM (R-compliance-canned-answer-3): no
	// template, no substitution, no concatenation with anything the detector
	// found. A placeholder-looking token inside it is literal text.
	Text string `json:"answer_text"`
	// Source names WHICH fallback tier supplied Text — `rule` / `level` /
	// `org`, spelled identically to the detector's actionpolicy.AnswerSource
	// and to the `events[].answer_source` event field. `none` never travels: it
	// means no tier had a text, and such a request is a block, not an answer.
	Source string `json:"answer_source"`
}

// CountProjection is the JSON payload Response.Event carries on a
// PERSONAL-routed Detect (TODO-87, design a2 「计数投影」, user decision
// 2026-09-15: an organization's cumulative escalation follows the PERSON, so a
// member's personal-key traffic counts too).
//
// WHY IT EXISTS: on the personal route the detector uploads its own event to the
// local self-view and used to hand the proxy nothing, so the proxy's
// request-level counter — the only place a whole request exists
// (DEC-compliance-grading-11 决定 1) — counted zero there and the org rule never
// fired. Returning the FULL event instead was rejected: it carries the raw
// context_snippet on that lane (the detector's mayCarryRawSnippet admits it for
// the local self-view), which would then sit in the proxy's verdict cache and be
// one broken route guard away from being uploaded a second time.
//
// 🔴 CONTENT-FREE BY CONSTRUCTION. Offsets, the tenant-defined level, the rule
// family label and the evidence gate's verdict — nothing else. No snippet, no
// hash, no fingerprint, no prompt_hash, no finding_id. EventID is the detector's
// CSPRNG id of the event it ALREADY uploaded locally (not content-derived), so
// the proxy can name that row on a local request-verdict row. Adding a field
// here puts new data on the pipe of a route whose rule is that the proxy never
// sees content; TestCountProjectionWireBytes pins the field count.
//
// Field names are the compliance intake wire's (ai-compliance-detector
// intake.Event / intake.Finding), because the proxy reads this slot with the
// SAME decoder it uses on a team event's findings. Both consumers pin their side
// against this type (detector: TestCountProjection_TagsMatchIntakeFinding;
// proxy: TestCountProjection_TagsMatchProxyFinding).
type CountProjection struct {
	EventID  string           `json:"event_id"`
	Findings []CountedFinding `json:"findings"`
}

// CountedFinding is one hit of a CountProjection. Level and Confirmed are
// POINTERS with omitempty for the same reason as on intake.Finding: absent means
// "not graded" / "no verdict travelled", and both read as zero on the proxy — an
// ungraded or unverified hit never helps a request escalate.
type CountedFinding struct {
	StartOffset int    `json:"start_offset"`
	EndOffset   int    `json:"end_offset"`
	Level       *int   `json:"level,omitempty"`
	Category    string `json:"category"`
	Confirmed   *bool  `json:"confirmed,omitempty"`
}

func EncodeRequest(req *Request) []byte {
	buf := make([]byte, 6+len(req.Prompt)) // op(1) + route_class(1) + req_id(4)
	buf[0] = req.Op
	buf[1] = req.RouteClass
	binary.LittleEndian.PutUint32(buf[2:6], req.ReqID)
	copy(buf[6:], req.Prompt)
	return buf
}

func DecodeRequest(payload []byte) (*Request, error) {
	if len(payload) < 1 {
		return nil, ErrShortRead
	}
	// Op-only requests (Status/ListPacks/Close) may carry just [op]; in v3 the
	// proxy always sends [op][route_class][req_id][prompt]. Tolerate both —
	// RouteClass/ReqID default to 0 when absent.
	req := &Request{Op: payload[0]}
	if len(payload) >= 6 {
		req.RouteClass = payload[1]
		req.ReqID = binary.LittleEndian.Uint32(payload[2:6])
		req.Prompt = string(payload[6:])
	}
	return req, nil
}

func EncodeResponse(res *Response) []byte {
	// v4: req_id(4) + action(1) + findings_len(4) + findings + maskmeta_len(4) + maskmeta + event
	buf := make([]byte, 13+len(res.Findings)+len(res.MaskMeta)+len(res.Event))
	binary.LittleEndian.PutUint32(buf[0:4], res.ReqID)
	buf[4] = res.Action
	binary.LittleEndian.PutUint32(buf[5:9], uint32(len(res.Findings)))
	off := 9 + copy(buf[9:], res.Findings)
	binary.LittleEndian.PutUint32(buf[off:off+4], uint32(len(res.MaskMeta)))
	off += 4
	off += copy(buf[off:], res.MaskMeta)
	copy(buf[off:], res.Event)
	return buf
}

func DecodeResponse(payload []byte) (*Response, error) {
	if len(payload) < 13 {
		return nil, ErrShortRead
	}
	flen := int(binary.LittleEndian.Uint32(payload[5:9]))
	if 9+flen+4 > len(payload) {
		return nil, fmt.Errorf("pipe: findings_len %d exceeds payload (%d)", flen, len(payload)-13)
	}
	moff := 9 + flen
	mlen := int(binary.LittleEndian.Uint32(payload[moff : moff+4]))
	if moff+4+mlen > len(payload) {
		return nil, fmt.Errorf("pipe: maskmeta_len %d exceeds payload (%d)", mlen, len(payload)-moff-4)
	}
	return &Response{
		ReqID:    binary.LittleEndian.Uint32(payload[0:4]),
		Action:   payload[4],
		Findings: payload[9:moff],
		MaskMeta: payload[moff+4 : moff+4+mlen],
		Event:    payload[moff+4+mlen:],
	}, nil
}
