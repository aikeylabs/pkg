package deepscan

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// The unix sink must write a well-formed [version][LE len][JSON] frame that a
// listener can parse back into {prompt, spans} — the contract the deep-scan
// reader (D2, Python) will implement.
func TestUnixSink_WritesFrame(t *testing.T) {
	// Short filename — macOS caps the full unix socket path at ~104 bytes.
	sockPath := filepath.Join(t.TempDir(), "s")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type received struct {
		frame []byte
		err   error
	}
	recvCh := make(chan received, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recvCh <- received{err: err}
			return
		}
		defer conn.Close()
		header := make([]byte, frameHeaderLen)
		if _, err := io.ReadFull(conn, header); err != nil {
			recvCh <- received{err: err}
			return
		}
		n := binary.LittleEndian.Uint32(header[1:frameHeaderLen])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			recvCh <- received{err: err}
			return
		}
		recvCh <- received{frame: append(header, body...)}
	}()

	sink := NewUnixSink(sockPath, time.Second, time.Second)
	defer sink.Close()

	const prompt = "re-scan me 0123"
	spans := []Span{{Start: 0, End: 2, Category: "pii", EntityType: "PHONE", Detector: "regex", Confidence: 90}}
	body, err := EncodePayloadV1(prompt, spans)
	if err != nil {
		t.Fatalf("EncodePayloadV1: %v", err)
	}
	if err := sink.Send(context.Background(), encodeFrame(body)); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case got := <-recvCh:
		if got.err != nil {
			t.Fatalf("listener: %v", got.err)
		}
		if got.frame[0] != ProtocolVersion {
			t.Errorf("version = %d, want %d", got.frame[0], ProtocolVersion)
		}
		var p payloadV1
		if err := json.Unmarshal(got.frame[frameHeaderLen:], &p); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if p.Prompt != prompt {
			t.Errorf("prompt = %q, want %q", p.Prompt, prompt)
		}
		if len(p.Spans) != 1 || p.Spans[0].EntityType != "PHONE" || p.Spans[0].Detector != "regex" {
			t.Errorf("spans = %+v, want one PHONE/regex span", p.Spans)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not receive a frame")
	}
}

// Dialing an absent socket must surface an error (so the forwarder counts a
// failure) and must not panic — the deep-scan process may not be up yet.
func TestUnixSink_DialErrorNoPanic(t *testing.T) {
	sink := NewUnixSink(filepath.Join(t.TempDir(), "absent"), 200*time.Millisecond, 200*time.Millisecond)
	defer sink.Close()
	if err := sink.Send(context.Background(), encodeFrame([]byte("x"))); err == nil {
		t.Error("Send to absent socket should return an error")
	}
}

// encodeFrame header round-trips: version byte + little-endian length.
func TestEncodeFrame_Header(t *testing.T) {
	body := []byte(`{"prompt":"x"}`)
	frame := encodeFrame(body)
	if frame[0] != ProtocolVersion {
		t.Errorf("version = %d, want %d", frame[0], ProtocolVersion)
	}
	if n := binary.LittleEndian.Uint32(frame[1:frameHeaderLen]); int(n) != len(body) {
		t.Errorf("length = %d, want %d", n, len(body))
	}
	if string(frame[frameHeaderLen:]) != string(body) {
		t.Errorf("body mismatch")
	}
}
