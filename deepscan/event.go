// Package deepscan is the shared wire + queue layer for AiKey's asynchronous
// deep scan (深扫 / 补扫).
//
// It has two wire generations living side by side on purpose:
//
//	v1 — [1B version=1][4B LE len][{prompt, spans}]. Fire-and-forget: the sender
//	     never reads a response and the RECEIVER uploads its own findings. The
//	     sender is the detector (it owns the fast layer's findings, so its frames
//	     can carry `spans` with category/entity_type). Kept byte-for-byte so a
//	     new node still serves an old proxy's on-machine daemon.
//
//	v2 — [1B version=2][4B LE len][FrameV2] out, [1B version=2][4B LE len][ResultFrame]
//	     back on the SAME connection, matched by job_id. The sender is the PROXY
//	     and the receiver returns a result instead of uploading, because the proxy
//	     is the only party that knows who the content belongs to.
//
// The package deliberately depends on nothing but the standard library: it is
// imported by aikey-proxy (Go), mirrored by ai-compliance-workers (Python), and
// wrapped by ai-compliance-detector. A dependency here would have to be vendored
// into all three.
package deepscan

import "encoding/json"

// ProtocolVersion is the v1 deep-scan wire version. The framing mirrors the
// apphook stdio protocol ([1B version][4B LE length][payload]).
const ProtocolVersion byte = 1

// FrameVersionV2 is the v2 task/result frame version (design §4b.1).
const FrameVersionV2 byte = 2

// Span is the minimal description of one span the sync (快层) layer already
// matched.
//
// 🔴 v2 frames do NOT carry Spans — see FrameV2. This type survives because the
// v1 frame still does, and v1 exists so a node can serve an old proxy's
// on-machine daemon. Do not reintroduce it into FrameV2 without reopening the
// decision recorded there.
//
// A Span carries OFFSETS + structural type only — never the matched substring.
type Span struct {
	Start      int    `json:"start"`
	End        int    `json:"end"`
	Category   string `json:"category"`
	EntityType string `json:"entity_type"`
	Detector   string `json:"detector"`
	Confidence int    `json:"confidence"`
}

// payloadV1 is the JSON body of one v1 deep-scan task: the raw prompt to
// re-scan plus the fast layer's hit list. Span offsets index Prompt.
type payloadV1 struct {
	Prompt string `json:"prompt"`
	Spans  []Span `json:"spans"`
}

// EncodePayloadV1 marshals one v1 task body (raw prompt + fast-layer spans).
// Exported so the detector's thin wrapper and the golden-frame fixture both
// produce bytes through this one function rather than two hand-written copies.
func EncodePayloadV1(prompt string, spans []Span) ([]byte, error) {
	return json.Marshal(payloadV1{Prompt: prompt, Spans: spans})
}
