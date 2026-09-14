package deepscan

import (
	"encoding/json"
	"fmt"
)

// Source values for FrameV2.Source (design §3.1).
const (
	SourceRequest  = "request"
	SourceResponse = "response"
)

// Engine names carried in FrameV2.Engines and Finding.Engine.
const (
	EngineBGE   = "bge"
	EngineRules = "rules"
)

// Range is a half-open [Start, End) byte interval into the piece.
type Range struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// FrameV2 is one asynchronous scan task: proxy → scan node over TLS, or proxy →
// on-machine daemon over a unix socket (same shape, no token on the socket).
//
// 🔴 WHAT IS DELIBERATELY ABSENT, AND WHY (design §3.1, R-scan-node-deepscan-3.S1):
//
//   - seat_id / virtual_key_id / session_id / trace_id / user_id. A node is a
//     SHARED box that several employees' content passes through, and it uploads
//     nothing — the proxy stamps identity onto the event after the result comes
//     back. Sending identity would tell a compromised node WHO said WHAT and buy
//     nothing. TenantID is the one exception: without it the node cannot refuse
//     content belonging to another org.
//
//   - spans (the fast layer's hits). v1 frames DO carry them, because in v1 the
//     sender is the detector, which owns the findings. In v1.1 the sender is the
//     proxy, and apphook.Response / pkg/pipewire.Response hand the proxy OFFSETS
//     ONLY — by design, not by omission: "the proxy never learns what the token
//     stands for business-wise" (aikey-proxy internal/apphook/apphook.go
//     invariant #16), re-verified in baseline-forensics §F1 on 2026-09-11.
//     User decision 2026-09-11: the node re-scans [0, HeadBytes) itself to get
//     the equivalent hit list for bge position-dedup, instead of the proxy
//     learning categories it is forbidden to know.
//     Fence: TestFrameV2_NoSeatOrSessionFields.
type FrameV2 struct {
	Version int    `json:"version"`
	JobID   string `json:"job_id"`
	// Token is the `sct1` org-scoped scan token. Empty on the unix-socket form
	// (same machine, same trust domain).
	Token         string `json:"token,omitempty"`
	TenantID      string `json:"tenant_id"`
	AuditUnitID   string `json:"audit_unit_id"`
	ContentSHA256 string `json:"content_sha256"`
	Source        string `json:"source"`
	// HeadBytes is how many bytes the synchronous fast layer already inspected.
	// Rule findings that end at or before it are the fast layer's, not new
	// coverage; 0 when the fast layer degraded and inspected nothing.
	HeadBytes int `json:"head_bytes"`
	// Engines is the subset of {bge, rules} the receiver should run.
	Engines []string `json:"engines"`
	// RuleChunks are computed ONCE by the sender (pkg/scanchunk) and carried on
	// the wire so Go and Python never hold two chunking implementations that can
	// drift apart.
	RuleChunks []Range `json:"rule_chunks,omitempty"`
	Prompt     string  `json:"prompt"`
}

// EncodeFrameV2 marshals a v2 task and wraps it in the shared frame header.
func EncodeFrameV2(f FrameV2) ([]byte, error) {
	if f.Version == 0 {
		f.Version = int(FrameVersionV2)
	}
	body, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("deepscan: encode frame v2: %w", err)
	}
	if len(body)+frameHeaderLen > MaxFrameBytes {
		return nil, fmt.Errorf("deepscan: frame v2 is %d bytes, over the %d-byte cap", len(body)+frameHeaderLen, MaxFrameBytes)
	}
	return EncodeFrame(FrameVersionV2, body), nil
}

// DecodeFrameV2 parses a framed v2 task. It refuses any other version rather
// than guessing: a v1 body decoded as v2 would silently produce a frame with an
// empty tenant, which the node would then refuse for the wrong reason.
func DecodeFrameV2(frame []byte) (FrameV2, error) {
	version, body, err := SplitFrame(frame)
	if err != nil {
		return FrameV2{}, err
	}
	if version != FrameVersionV2 {
		return FrameV2{}, fmt.Errorf("deepscan: frame version %d is not v2", version)
	}
	var f FrameV2
	if err := json.Unmarshal(body, &f); err != nil {
		return FrameV2{}, fmt.Errorf("deepscan: decode frame v2: %w", err)
	}
	return f, nil
}
