package deepscan

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Coverage status values (design §4b.12). `partial` is not a soft `complete`:
// it is the difference between "we looked at all of it and found nothing" and
// "we ran out of budget", which is the whole reason scan_coverage exists.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

// Reasons a result is partial.
const (
	ReasonPieceCap  = "piece_cap"  // the piece was truncated before it was sent
	ReasonWindowCap = "window_cap" // bge hit AIKEY_DEEPSCAN_MAX_WINDOWS
	ReasonTransient = "transient"  // finalised after repeated transient failures
)

// Reject codes (design §4b.1). The node answers within 50ms with {job_id,
// reject} and nothing else.
//
// 🔴 These constants are mirrored in ai-compliance-workers wire.py and pinned by
// a cross-language fixture test. Same name, same value, or a node silently
// refuses frames for a reason the proxy cannot act on.
const (
	RejectBusy               = "busy"                // admission full — try the next node
	RejectUnauthorized       = "unauthorized"        // token invalid/expired — try the next node
	RejectTenantMismatch     = "tenant_mismatch"     // wrong org — do NOT try another node
	RejectBadFrame           = "bad_frame"           // malformed — do NOT try another node
	RejectVersionUnsupported = "version_unsupported" // wire skew — do NOT try another node
)

// EngineResult is one engine's outcome inside a result frame.
type EngineResult struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	// Windows is how many bge windows were encoded (bge only).
	Windows int `json:"windows,omitempty"`
	// Chunks is how many rule chunks were scanned (rules only).
	Chunks int `json:"chunks,omitempty"`
	// DetectorVersion / ContentVersion let the proxy count version skew between
	// what the node ran and what it runs itself, instead of silently merging
	// results produced by a different ruleset.
	DetectorVersion string `json:"detector_version,omitempty"`
	ContentVersion  string `json:"content_version,omitempty"`
}

// EngineResults groups the per-engine outcomes.
type EngineResults struct {
	BGE   EngineResult `json:"bge,omitempty"`
	Rules EngineResult `json:"rules,omitempty"`
}

// Finding is one hit the asynchronous scan produced.
//
// 🔴 Offsets are ABSOLUTE into the piece the proxy sent, never relative to a
// chunk or window. The receiver adds the chunk/window origin before it answers,
// because the proxy merges findings against HeadBytes and cannot re-derive an
// origin it never saw. Fence: TestResultFrame_RoundTrip + the workers-side
// test_tail_chunks_absolute_offsets.
//
// 🚫 No raw matched text. The result travels back over the network and lands in
// an audit event; the evidence stays on the box that produced it.
type Finding struct {
	Engine     string `json:"engine"`
	RuleID     string `json:"rule_id,omitempty"`
	Category   string `json:"category"`
	EntityType string `json:"entity_type"`
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Detector   string `json:"detector,omitempty"`
}

// RangeVerdict is one rule chunk's raw action, kept separate from Findings so
// the proxy can decide "this WOULD have been blocked" against its own ceilings
// rather than trusting a verdict computed on a box with a different policy.
type RangeVerdict struct {
	Start  int    `json:"start"`
	End    int    `json:"end"`
	Action string `json:"action"`
}

// ResultFrame is what a node (or the on-machine daemon, for v2 frames) answers
// on the same connection. Results may come back out of order; JobID matches
// them up.
type ResultFrame struct {
	JobID string `json:"job_id"`
	// Reject, when set, is the ONLY other field present: a refused frame was
	// never scanned, so any coverage number alongside it would be a lie the
	// proxy would go on to store as a real scan result.
	Reject string `json:"reject,omitempty"`

	Status       string         `json:"status,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	ScannedBytes int            `json:"scanned_bytes,omitempty"`
	TotalBytes   int            `json:"total_bytes,omitempty"`
	Engines      EngineResults  `json:"engines,omitempty"`
	Findings     []Finding      `json:"findings,omitempty"`
	RuleVerdicts []RangeVerdict `json:"rule_verdicts,omitempty"`
}

// EncodeResult marshals a result and wraps it in the shared frame header.
func EncodeResult(r ResultFrame) ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("deepscan: encode result: %w", err)
	}
	return EncodeFrame(FrameVersionV2, body), nil
}

// DecodeResult parses a framed result.
func DecodeResult(frame []byte) (ResultFrame, error) {
	version, body, err := SplitFrame(frame)
	if err != nil {
		return ResultFrame{}, err
	}
	if version != FrameVersionV2 {
		return ResultFrame{}, fmt.Errorf("deepscan: result frame version %d is not v2", version)
	}
	var r ResultFrame
	if err := json.Unmarshal(body, &r); err != nil {
		return ResultFrame{}, fmt.Errorf("deepscan: decode result: %w", err)
	}
	return r, nil
}

// ReadResult reads exactly one framed result — [1B version][4B LE length][JSON]
// — from r. The declared length is checked against MaxFrameBytes BEFORE any
// allocation, so a hostile or corrupt peer cannot make the reader allocate
// whatever it claims. Every sink that reads a node's answer uses this, so the
// framing cannot drift between the TLS and the local-socket paths.
func ReadResult(r io.Reader) (ResultFrame, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return ResultFrame{}, fmt.Errorf("deepscan: read result header: %w", err)
	}
	n := binary.LittleEndian.Uint32(head[1:5])
	if n > MaxFrameBytes {
		return ResultFrame{}, fmt.Errorf("deepscan: result declares %d bytes, over the %d cap", n, MaxFrameBytes)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return ResultFrame{}, fmt.Errorf("deepscan: read result body: %w", err)
	}
	return DecodeResult(append(head[:], body...))
}

// RejectError is a node's refusal of one frame, carried as an error so a
// delivery loop can tell "this node said no, and why" from "this node is
// unreachable". Code is one of the Reject* constants.
type RejectError struct{ Code string }

func (e *RejectError) Error() string { return "deepscan: node rejected the frame: " + e.Code }
