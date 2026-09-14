package deepscan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGoldenFrames_MatchFixture pins the exact BYTES of the v1 and v2 frames in
// testdata/golden_frames.json.
//
// WHY a byte fixture and not just a Go round-trip: ai-compliance-workers decodes
// these frames in PYTHON. A Go round-trip proves Go agrees with itself, which is
// precisely the failure this fixture exists to catch — the two languages drifting
// apart on field names, the 5-byte header, or little-endian length. The Python
// side reads the SAME file (tests/testdata/golden_frames.json) and must produce
// byte-identical output. Regenerate deliberately with -update, never casually:
// changing a byte here is a wire-compat decision.
func TestGoldenFrames_MatchFixture(t *testing.T) {
	path := filepath.Join("testdata", "golden_frames.json")
	got := buildGoldenFrames(t)

	if os.Getenv("UPDATE_GOLDEN") == "1" {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal golden: %v", err)
		}
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatalf("mkdir testdata: %v", err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("golden fixture regenerated at %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden fixture (regenerate with UPDATE_GOLDEN=1): %v", err)
	}
	var wantMap map[string]any
	if err := json.Unmarshal(want, &wantMap); err != nil {
		t.Fatalf("golden fixture is not JSON: %v", err)
	}
	gotJSON, _ := json.Marshal(got)
	var gotMap map[string]any
	_ = json.Unmarshal(gotJSON, &gotMap)

	for _, k := range []string{"v1_task", "v2_task", "v2_result", "v2_result_reject"} {
		if gotMap[k] == nil {
			t.Fatalf("generator produced no %q case", k)
		}
		if wantMap[k] == nil {
			t.Fatalf("fixture has no %q case — regenerate with UPDATE_GOLDEN=1", k)
		}
		g, _ := json.Marshal(gotMap[k])
		w, _ := json.Marshal(wantMap[k])
		if string(g) != string(w) {
			t.Errorf("%s drifted from the fixture the Python mirror reads.\n got: %s\nwant: %s", k, g, w)
		}
	}
}

type goldenCase struct {
	Description string `json:"description"`
	FrameHex    string `json:"frame_hex"`
	BodyJSON    string `json:"body_json"`
	Version     int    `json:"version"`
}

func buildGoldenFrames(t *testing.T) map[string]goldenCase {
	t.Helper()
	out := map[string]goldenCase{}

	v1Body, err := EncodePayloadV1("客户手机号 13800138000 请核对", []Span{
		{Start: 6, End: 17, Category: "pii", EntityType: "CN_PHONE", Detector: "regex", Confidence: 95},
	})
	if err != nil {
		t.Fatalf("v1 body: %v", err)
	}
	out["v1_task"] = mkCase(t, "v1 task frame: fire-and-forget, carries the fast layer's spans because the DETECTOR sends it",
		EncodeFrame(ProtocolVersion, v1Body), int(ProtocolVersion))

	v2, err := EncodeFrameV2(FrameV2{
		JobID:         "job-golden-1",
		Token:         "sct1.org_a.1757620000.k1.Zm9vYmFy",
		TenantID:      "org_a",
		AuditUnitID:   "au_0123456789abcdef",
		ContentSHA256: "b1946ac92492d2347c6235b4d2611184",
		Source:        SourceRequest,
		HeadBytes:     16384,
		Engines:       []string{EngineBGE, EngineRules},
		RuleChunks:    []Range{{Start: 14336, End: 30720}, {Start: 28672, End: 45056}},
		Prompt:        "客户手机号 13800138000 请核对",
	})
	if err != nil {
		t.Fatalf("v2 frame: %v", err)
	}
	out["v2_task"] = mkCase(t, "v2 task frame: NO spans and NO seat/session identity — the node re-scans the head itself", v2, int(FrameVersionV2))

	res, err := EncodeResult(ResultFrame{
		JobID: "job-golden-1", Status: StatusPartial, Reason: ReasonWindowCap,
		ScannedBytes: 240000, TotalBytes: 262144,
		Engines: EngineResults{
			BGE:   EngineResult{Status: StatusPartial, Windows: 4096, Reason: ReasonWindowCap},
			Rules: EngineResult{Status: StatusComplete, Chunks: 2, DetectorVersion: "95eebb1", ContentVersion: "cv-7"},
		},
		Findings: []Finding{{
			Engine: EngineRules, RuleID: "secret.connection-uri-password", Category: "secret",
			EntityType: "CREDENTIAL_DSN", Severity: "high", Confidence: 95,
			Start: 250000, End: 250072, Detector: "regex",
		}},
		RuleVerdicts: []RangeVerdict{{Start: 245760, End: 262144, Action: "block"}},
	})
	if err != nil {
		t.Fatalf("v2 result: %v", err)
	}
	out["v2_result"] = mkCase(t, "v2 result frame: absolute offsets, no raw matched text", res, int(FrameVersionV2))

	rej, err := EncodeResult(ResultFrame{JobID: "job-golden-1", Reject: RejectTenantMismatch})
	if err != nil {
		t.Fatalf("v2 reject: %v", err)
	}
	out["v2_result_reject"] = mkCase(t, "v2 reject: job_id + reject and nothing else", rej, int(FrameVersionV2))
	return out
}

func mkCase(t *testing.T, desc string, frame []byte, version int) goldenCase {
	t.Helper()
	_, body, err := SplitFrame(frame)
	if err != nil {
		t.Fatalf("%s: SplitFrame: %v", desc, err)
	}
	return goldenCase{Description: desc, FrameHex: hexOf(frame), BodyJSON: string(body), Version: version}
}

const hexDigits = "0123456789abcdef"

func hexOf(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}
