package pipewire

import (
	"bufio"
	"bytes"
	"testing"
)

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
