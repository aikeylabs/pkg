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
	"encoding/binary"
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
const ProtocolVersion byte = 4

// Op codes for request payload.
const (
	OpDetect    uint8 = 1 // detect a prompt
	OpStatus    uint8 = 2 // query child health
	OpClose     uint8 = 3 // graceful shutdown signal
	OpListPacks uint8 = 4 // list currently-effective packs (built-in + pulled); response carries JSON in Findings
)

// Action codes for response payload.
const (
	ActionAllow uint8 = 0
	ActionMask  uint8 = 1
	ActionBlock uint8 = 2
	ActionWarn  uint8 = 3
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
// Findings and MaskMeta are length-prefixed so the trailing Event blob (the full
// compliance event JSON the proxy uploads to master for team-routed requests)
// can be split out. Event is empty for personal-routed requests and non-Detect
// ops; MaskMeta is empty unless the mask verdict carries restorable spans (v4).
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
	Event    []byte // team-routed compliance event JSON for the proxy to forward; empty otherwise
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
