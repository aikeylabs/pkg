package pipewire

import (
	"bufio"
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// TestActionCodes_AppendedNeverRenumbered pins every action value. The byte
// travels the pipe unvalidated, so a renumbered or colliding rung reinterprets
// verdicts silently rather than failing to compile.
func TestActionCodes_AppendedNeverRenumbered(t *testing.T) {
	want := []struct {
		name  string
		value uint8
		code  uint8
	}{
		{"ActionAllow", 0, ActionAllow},
		{"ActionMask", 1, ActionMask},
		{"ActionBlock", 2, ActionBlock},
		{"ActionWarn", 3, ActionWarn},
		{"ActionAnswer", 4, ActionAnswer},
	}
	seen := map[uint8]string{}
	for _, w := range want {
		if w.code != w.value {
			t.Errorf("%s = %d, want %d (appended, never renumbered)", w.name, w.code, w.value)
		}
		if prev, dup := seen[w.code]; dup {
			t.Errorf("%s collides with %s on value %d", w.name, prev, w.code)
		}
		seen[w.code] = w.name
	}
}

// cannedAnswerWireGolden is the EXACT byte string the detector writes into
// Response.Findings for an ActionAnswer verdict and the proxy decodes.
//
// 🔴 THE ONLY BYTE LITERAL FOR THIS CONTRACT (TODO-85). It used to be pinned
// twice — ai-compliance-detector cmd/detector/canned_answer_carrier_test.go and
// aikey-proxy internal/apphook/canned_answer_carrier_test.go — as a stand-in for
// the shared type this package now provides. Both consumers alias CannedAnswer
// and assert the alias, so this one literal guards both sides.
const cannedAnswerWireGolden = `{"answer_text":"抱歉，这条内容命中了公司合规策略，无法发送给模型。\n如需帮助请联系合规部门。占位语法示例：{{IDCARD_1}} 原样保留。","answer_source":"level"}`

// TestCannedAnswerWireBytes pins the JSON contract in both directions: encoding
// produces the agreed bytes, and the agreed bytes decode back to the fields.
func TestCannedAnswerWireBytes(t *testing.T) {
	text := "抱歉，这条内容命中了公司合规策略，无法发送给模型。\n" +
		"如需帮助请联系合规部门。占位语法示例：{{IDCARD_1}} 原样保留。"

	encoded, err := json.Marshal(CannedAnswer{Text: text, Source: "level"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != cannedAnswerWireGolden {
		t.Errorf("CannedAnswer wire bytes drifted.\n got: %s\nwant: %s\n"+
			"A tag rename reaches the proxy as an EMPTY answer, which degrades a "+
			"configured 代答 to a hard 403.", encoded, cannedAnswerWireGolden)
	}

	var decoded CannedAnswer
	if err := json.Unmarshal([]byte(cannedAnswerWireGolden), &decoded); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if decoded.Text != text || decoded.Source != "level" {
		t.Errorf("golden bytes decoded to %+v, want Text=%q Source=\"level\"", decoded, text)
	}
}

// countProjectionWireGolden is the ONLY byte literal for the CountProjection
// contract (TODO-87). Keys, key order and the omitempty behaviour of `level` /
// `confirmed` are all part of it: the proxy decodes this slot with the SAME
// reader it uses on a team event's findings, so a renamed tag decodes to a zero
// value — an uncounted hit, silently, in the permissive direction.
const countProjectionWireGolden = `{"event_id":"0123456789abcdef0123456789abcdef","findings":[` +
	`{"start_offset":6,"end_offset":24,"level":4,"category":"pii","confirmed":true},` +
	`{"start_offset":30,"end_offset":41,"category":"secret"}]}`

// TestCountProjectionWireBytes pins the projection JSON in both directions and
// pins what it may NOT carry: exactly two top-level keys and exactly five
// finding keys. Anything else on this struct is a new field crossing the pipe on
// the personal route, and that route's rule is that the proxy never sees content.
func TestCountProjectionWireBytes(t *testing.T) {
	level := 4
	confirmed := true
	proj := CountProjection{
		EventID: "0123456789abcdef0123456789abcdef",
		Findings: []CountedFinding{
			{StartOffset: 6, EndOffset: 24, Level: &level, Category: "pii", Confirmed: &confirmed},
			{StartOffset: 30, EndOffset: 41, Category: "secret"},
		},
	}
	encoded, err := json.Marshal(proj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != countProjectionWireGolden {
		t.Errorf("CountProjection wire bytes drifted.\n got: %s\nwant: %s", encoded, countProjectionWireGolden)
	}

	var decoded CountProjection
	if err := json.Unmarshal([]byte(countProjectionWireGolden), &decoded); err != nil {
		t.Fatalf("unmarshal golden: %v", err)
	}
	if decoded.EventID != proj.EventID || len(decoded.Findings) != 2 ||
		decoded.Findings[0].Level == nil || *decoded.Findings[0].Level != 4 ||
		decoded.Findings[0].Confirmed == nil || !*decoded.Findings[0].Confirmed ||
		decoded.Findings[1].Level != nil || decoded.Findings[1].Confirmed != nil {
		t.Errorf("golden bytes decoded to %+v", decoded)
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatalf("decode top: %v", err)
	}
	if len(top) != 2 {
		t.Errorf("CountProjection carries %d top-level keys, want exactly 2 (event_id, findings): %s", len(top), encoded)
	}
	if n := reflect.TypeOf(CountedFinding{}).NumField(); n != 5 {
		t.Errorf("CountedFinding has %d fields, want exactly 5 (offsets, level, category, confirmed). "+
			"A sixth field is new data crossing the pipe on the personal route — no snippet, hash, "+
			"fingerprint, prompt_hash or finding_id may ride here.", n)
	}
}

func TestRoundtripFrame(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"empty", nil},
		{"small", []byte("hello")},
		{"prompt-sized", bytes.Repeat([]byte{'a'}, 2048)},
		{"max-ish", bytes.Repeat([]byte{'b'}, 60000)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := bufio.NewWriter(&buf)
			if err := WriteFrame(w, tc.payload); err != nil {
				t.Fatalf("write: %v", err)
			}

			r := bufio.NewReader(&buf)
			version, got, err := ReadFrame(r)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if version != ProtocolVersion {
				t.Errorf("version: got %d want %d", version, ProtocolVersion)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Errorf("payload mismatch: got %d bytes want %d", len(got), len(tc.payload))
			}
		})
	}
}

// TestEncodeFrameMatchesWriteFrame pins the byte-level equivalence of the two
// entry points. EncodeFrame exists so non-bufio callers (notably the detector's
// scripts/e2e-echo.sh, which used to hand-write a hex literal and silently broke
// on the v4 bump) can obtain authoritative frame bytes; if it ever diverges from
// WriteFrame those callers go back to being a separate, drifting implementation.
func TestEncodeFrameMatchesWriteFrame(t *testing.T) {
	for _, payload := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte{'z'}, 300)} {
		var buf bytes.Buffer
		w := bufio.NewWriter(&buf)
		if err := WriteFrame(w, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := EncodeFrame(payload), buf.Bytes(); !bytes.Equal(got, want) {
			t.Errorf("EncodeFrame != WriteFrame for %d-byte payload:\n got %x\nwant %x",
				len(payload), got, want)
		}
	}
}

func TestRequestResponseEncoding(t *testing.T) {
	req := &Request{Op: OpDetect, Prompt: "hello compliance"}
	encoded := EncodeRequest(req)
	decoded, err := DecodeRequest(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Op != req.Op || decoded.Prompt != req.Prompt {
		t.Errorf("request mismatch: got %+v want %+v", decoded, req)
	}

	res := &Response{Action: ActionMask, Findings: []byte(`[{"rule":"phone"}]`)}
	resEncoded := EncodeResponse(res)
	resDecoded, err := DecodeResponse(resEncoded)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resDecoded.Action != res.Action || !bytes.Equal(resDecoded.Findings, res.Findings) {
		t.Errorf("response mismatch: got %+v want %+v", resDecoded, res)
	}
}

// TestResponseEncodingV4MaskMetaAndEvent — v4 adds a length-prefixed MaskMeta
// section between Findings and Event. Round-trip all four field combinations so
// the trailing Event split can never absorb (or be absorbed by) MaskMeta.
func TestResponseEncodingV4MaskMetaAndEvent(t *testing.T) {
	meta := []byte(`{"restorables":[{"token":"[地址(已隐藏)]","numbered_prefix":"[地址#","numbered_suffix":"(已隐藏)]","spans":[[3,27]]}]}`)
	tests := []struct {
		name string
		res  Response
	}{
		{"mask+meta+event", Response{ReqID: 7, Action: ActionMask, Findings: []byte("masked text"), MaskMeta: meta, Event: []byte(`{"e":1}`)}},
		{"mask+meta", Response{ReqID: 8, Action: ActionMask, Findings: []byte("masked"), MaskMeta: meta}},
		{"mask+event only", Response{ReqID: 9, Action: ActionMask, Findings: []byte("masked"), Event: []byte(`{"e":2}`)}},
		{"allow empty", Response{ReqID: 10, Action: ActionAllow}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeResponse(EncodeResponse(&tc.res))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got.ReqID != tc.res.ReqID || got.Action != tc.res.Action ||
				!bytes.Equal(got.Findings, tc.res.Findings) ||
				!bytes.Equal(got.MaskMeta, tc.res.MaskMeta) ||
				!bytes.Equal(got.Event, tc.res.Event) {
				t.Errorf("round-trip mismatch:\n got %+v\nwant %+v", got, tc.res)
			}
		})
	}
}

func TestPayloadTooLarge(t *testing.T) {
	// Hand-craft a frame with length > MaxPayloadBytes
	var buf bytes.Buffer
	buf.WriteByte(ProtocolVersion)
	// 70000 in LE
	buf.Write([]byte{0x70, 0x11, 0x01, 0x00})
	// (don't bother writing the body — should error before that)

	r := bufio.NewReader(&buf)
	_, _, err := ReadFrame(r)
	if err == nil {
		t.Fatal("expected error for oversized payload, got nil")
	}
}
