package pipewire

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// TestReadFrame_OversizeSkipsPayloadAndNextFrameParses — fence F3 of TODO-120.
//
// GIVEN a response frame whose declared length exceeds MaxPayloadBytes, followed
// immediately by a normal frame
// WHEN the parent reads with ReadResponseFrame
// THEN it gets a typed *OversizeFrameError carrying the frame length and the
// response prefix (req_id + action), the oversize payload is consumed in full,
// and the very next ReadResponseFrame parses the following frame intact.
//
// WHY: until TODO-120 the only reader was ReadFrame, which stops after the 5-byte
// header. The stream is then misaligned by the whole payload, so the parent had
// no option but to abandon the pipe — and the proxy abandoned it by failing
// every in-flight request OPEN. Being able to resynchronise is what lets the
// proxy refuse just the one request instead.
func TestReadFrame_OversizeSkipsPayloadAndNextFrameParses(t *testing.T) {
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)

	big := EncodeResponse(&Response{
		ReqID:    7,
		Action:   ActionMask,
		Findings: bytes.Repeat([]byte("x"), MaxPayloadBytes+1234), // synthetic filler, no content meaning
	})
	if err := WriteFrame(w, big); err != nil {
		t.Fatalf("write oversize frame: %v", err)
	}
	next := EncodeResponse(&Response{ReqID: 8, Action: ActionAllow, Event: []byte(`{"fixture":"next-frame"}`)})
	if err := WriteFrame(w, next); err != nil {
		t.Fatalf("write next frame: %v", err)
	}

	r := bufio.NewReaderSize(&buf, 64*1024)

	_, payload, err := ReadResponseFrame(r)
	var ov *OversizeFrameError
	if !errors.As(err, &ov) {
		t.Fatalf("oversize frame: err = %v (payload %d bytes), want *OversizeFrameError", err, len(payload))
	}
	if payload != nil {
		t.Errorf("oversize frame must not hand back a payload, got %d bytes", len(payload))
	}
	if ov.Length != uint32(len(big)) {
		t.Errorf("Length = %d, want %d", ov.Length, len(big))
	}
	if ov.ReqID != 7 || ov.Action != ActionMask || ov.Version != ProtocolVersion {
		t.Errorf("prefix = {req_id:%d action:%d version:%d}, want {7 %d %d}",
			ov.ReqID, ov.Action, ov.Version, ActionMask, ProtocolVersion)
	}

	v, payload, err := ReadResponseFrame(r)
	if err != nil {
		t.Fatalf("frame after the oversize one did not parse — stream desynced: %v", err)
	}
	if v != ProtocolVersion {
		t.Errorf("next frame version = %d, want %d", v, ProtocolVersion)
	}
	res, err := DecodeResponse(payload)
	if err != nil {
		t.Fatalf("decode next frame: %v", err)
	}
	if res.ReqID != 8 || string(res.Event) != `{"fixture":"next-frame"}` {
		t.Errorf("next frame = {req_id:%d event:%q}, want {8 fixture}", res.ReqID, res.Event)
	}
	if _, _, err := ReadResponseFrame(r); !errors.Is(err, io.EOF) {
		t.Errorf("stream should be exhausted after two frames, got %v", err)
	}
}

// TestReadResponseFrame_OriginalPathForDesyncShapes pins the three shapes that
// must NOT be treated as a skippable oversize frame, because in each of them the
// bytes after the header cannot be trusted to be [req_id][action][...]:
//
//   - a length beyond MaxSkippableFrameBytes is a byte-stream misalignment, not a
//     large verdict — skipping it would swallow the pipe for gigabytes;
//   - a foreign version byte means the payload layout is not ours;
//   - a stream that ends mid-skip is a dead pipe.
func TestReadResponseFrame_OriginalPathForDesyncShapes(t *testing.T) {
	header := func(version byte, length uint32) []byte {
		h := make([]byte, 5)
		h[0] = version
		binary.LittleEndian.PutUint32(h[1:5], length)
		return h
	}
	var ov *OversizeFrameError

	t.Run("beyond_hard_cap", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append(header(ProtocolVersion, MaxSkippableFrameBytes+1), 1, 2, 3, 4, 5)))
		_, _, err := ReadResponseFrame(r)
		if err == nil || errors.As(err, &ov) {
			t.Fatalf("err = %v, want a plain (non-skippable) payload-too-large error", err)
		}
		if r.Buffered() != 5 {
			t.Errorf("a desync length must not consume past the header; %d bytes left buffered, want 5", r.Buffered())
		}
	})

	t.Run("foreign_version", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append(header(ProtocolVersion+1, MaxPayloadBytes+1), make([]byte, MaxPayloadBytes+1)...)))
		_, _, err := ReadResponseFrame(r)
		if err == nil || errors.As(err, &ov) {
			t.Fatalf("err = %v, want a plain error for a foreign-version oversize frame", err)
		}
	})

	t.Run("stream_ends_mid_skip", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append(header(ProtocolVersion, MaxPayloadBytes+100), make([]byte, 1000)...)))
		_, _, err := ReadResponseFrame(r)
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF (dead pipe, not a skippable frame)", err)
		}
	})
}
