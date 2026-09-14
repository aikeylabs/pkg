package deepscan

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestFrameV2_NoSeatOrSessionFields is the wire-privacy fence for the v2 task
// frame.
//
// WHY this fence exists (design §3.1, R-scan-node-deepscan-3.S1): a scan node is
// a SHARED box that several employees' content flows through, and it does not
// upload anything itself — the proxy stamps identity onto the event afterwards.
// So the node needs exactly one identity field, `tenant_id`, to refuse content
// from another org. Every other identity field (seat, virtual key, session,
// trace, user) would tell a compromised node WHO said WHAT while buying nothing.
//
// It also asserts the frame carries NO `spans`. v1 frames did carry the fast
// layer's hits WITH their category, because in v1 the sender was the DETECTOR,
// which owns the findings. In v1.1 the sender is the PROXY, and the proxy is
// forbidden from learning what the detector matched (apphook.go invariant #16:
// "the proxy never learns what the token stands for business-wise"). Measured in
// baseline-forensics §F1: apphook.Response and pkg/pipewire.Response hand the
// proxy offsets only. User decision 2026-09-11: the node re-scans [0, head_bytes)
// itself instead. A `spans` field reappearing here means someone reintroduced the
// proxy→business-semantics coupling that decision removed.
func TestFrameV2_NoSeatOrSessionFields(t *testing.T) {
	f := FrameV2{
		Version:       int(FrameVersionV2),
		JobID:         "job-1",
		Token:         "sct1.org_a.1757620000.k1.abc",
		TenantID:      "org_a",
		AuditUnitID:   "au_deadbeef",
		ContentSHA256: "b1946ac92492d2347c6235b4d2611184",
		Source:        SourceRequest,
		HeadBytes:     16384,
		Engines:       []string{EngineBGE, EngineRules},
		RuleChunks:    []Range{{Start: 14336, End: 30720}},
		Prompt:        "hello",
	}
	b, err := EncodeFrameV2(f)
	if err != nil {
		t.Fatalf("EncodeFrameV2: %v", err)
	}
	if len(b) < frameHeaderLen || b[0] != FrameVersionV2 {
		t.Fatalf("frame header: want version byte %d, got % x", FrameVersionV2, b[:min(len(b), 8)])
	}
	body := string(b[frameHeaderLen:])

	for _, banned := range []string{"seat_id", "virtual_key_id", "session_id", "trace_id", "user_id", "spans"} {
		if strings.Contains(body, banned) {
			t.Errorf("v2 frame carries %q — it must not; body=%s", banned, body)
		}
	}

	var got map[string]any
	if err := json.Unmarshal(b[frameHeaderLen:], &got); err != nil {
		t.Fatalf("frame body is not JSON: %v", err)
	}
	if got["tenant_id"] != "org_a" {
		t.Errorf("tenant_id: want org_a, got %v — the node cannot refuse cross-org content without it", got["tenant_id"])
	}
	if got["audit_unit_id"] != "au_deadbeef" {
		t.Errorf("audit_unit_id: want au_deadbeef, got %v", got["audit_unit_id"])
	}
}

// TestResultFrame_RoundTrip pins the result frame both ways. The node answers on
// the SAME connection and results may come back out of order, so job_id has to
// survive the trip; findings carry ABSOLUTE offsets into the piece (design §3.6)
// because the proxy merges them against head_bytes without re-deriving anything.
func TestResultFrame_RoundTrip(t *testing.T) {
	in := ResultFrame{
		JobID:        "job-1",
		Status:       StatusPartial,
		Reason:       ReasonWindowCap,
		ScannedBytes: 240000,
		TotalBytes:   262144,
		Engines: EngineResults{
			BGE:   EngineResult{Status: StatusPartial, Windows: 4096, Reason: ReasonWindowCap},
			Rules: EngineResult{Status: StatusComplete, Chunks: 16, DetectorVersion: "95eebb1", ContentVersion: "cv-7"},
		},
		Findings: []Finding{{
			Engine: EngineRules, RuleID: "secret.connection-uri-password",
			Category: "secret", EntityType: "CREDENTIAL_DSN", Severity: "high",
			Confidence: 95, Start: 250000, End: 250072, Detector: "regex",
		}},
		RuleVerdicts: []RangeVerdict{{Start: 245760, End: 262144, Action: "block"}},
	}
	b, err := EncodeResult(in)
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	out, err := DecodeResult(b)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if out.JobID != in.JobID || out.Status != in.Status || out.Reason != in.Reason {
		t.Errorf("header round-trip: got %+v want %+v", out, in)
	}
	if out.ScannedBytes != in.ScannedBytes || out.TotalBytes != in.TotalBytes {
		t.Errorf("coverage round-trip: got %d/%d want %d/%d",
			out.ScannedBytes, out.TotalBytes, in.ScannedBytes, in.TotalBytes)
	}
	if len(out.Findings) != 1 || out.Findings[0].Start != 250000 || out.Findings[0].End != 250072 {
		t.Fatalf("finding offsets did not survive: %+v", out.Findings)
	}
	if out.Findings[0].EntityType != "CREDENTIAL_DSN" || out.Findings[0].RuleID != "secret.connection-uri-password" {
		t.Errorf("finding identity did not survive: %+v", out.Findings[0])
	}
	if len(out.RuleVerdicts) != 1 || out.RuleVerdicts[0].Action != "block" {
		t.Fatalf("rule verdicts did not survive: %+v", out.RuleVerdicts)
	}
	if out.Engines.Rules.DetectorVersion != "95eebb1" || out.Engines.BGE.Windows != 4096 {
		t.Errorf("engine block did not survive: %+v", out.Engines)
	}
}

// TestResultFrame_RejectIsSelfContained: a refused frame answers with job_id +
// reject ONLY. A node that refused a frame has not scanned it, so any coverage
// number it reported would be a lie the proxy would then store as `complete`.
func TestResultFrame_RejectIsSelfContained(t *testing.T) {
	b, err := EncodeResult(ResultFrame{JobID: "job-9", Reject: RejectTenantMismatch})
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	out, err := DecodeResult(b)
	if err != nil {
		t.Fatalf("DecodeResult: %v", err)
	}
	if out.Reject != RejectTenantMismatch {
		t.Fatalf("reject code lost: %+v", out)
	}
	if out.Status != "" || out.ScannedBytes != 0 || len(out.Findings) != 0 {
		t.Errorf("a rejected frame must carry no scan result, got %+v", out)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
