package deepscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Sink is the transport the forwarder writes encoded frames to. The seam keeps
// the forwarder's bounded-queue logic independent of the wire: tests inject a
// slow/dead/erroring sink, and the scan-node TLS sink (pkg/scannode) plugs in
// here — both without touching the forwarder (invariant I8: the endpoint
// changes, the protocol and forwarder code do not).
type Sink interface {
	// Send writes one already-framed message. It must honor ctx for
	// cancellation/deadline. Returning an error makes the forwarder count a
	// failure and move on; either way the detect hot path is never affected
	// (the bounded queue + non-blocking Enqueue absorb a slow/dead Sink).
	Send(ctx context.Context, frame []byte) error
	// Close releases any underlying connection.
	Close() error
}

// frameHeaderLen is the fixed [1B version][4B LE length] header, shared by v1
// and v2 so one parser shape reads both.
const frameHeaderLen = 5

// MaxFrameBytes bounds a single frame (design §4b.1: "整帧 ≤1MiB"). A reader
// must refuse anything larger rather than allocate it: the length prefix is
// attacker-influenced on the TLS path.
const MaxFrameBytes = 1 << 20

// EncodeFrame wraps a body as [1B version][4B LE length][body].
func EncodeFrame(version byte, body []byte) []byte {
	frame := make([]byte, frameHeaderLen+len(body))
	frame[0] = version
	binary.LittleEndian.PutUint32(frame[1:frameHeaderLen], uint32(len(body)))
	copy(frame[frameHeaderLen:], body)
	return frame
}

// encodeFrame keeps the v1 call sites byte-identical after the migration.
func encodeFrame(body []byte) []byte { return EncodeFrame(ProtocolVersion, body) }

// SplitFrame validates a framed message and returns its version and body.
// Length-prefix first, allocation never: a declared length over MaxFrameBytes is
// rejected without reading it.
func SplitFrame(frame []byte) (version byte, body []byte, err error) {
	if len(frame) < frameHeaderLen {
		return 0, nil, fmt.Errorf("deepscan frame: %d bytes is shorter than the %d-byte header", len(frame), frameHeaderLen)
	}
	n := binary.LittleEndian.Uint32(frame[1:frameHeaderLen])
	if n > MaxFrameBytes {
		return 0, nil, fmt.Errorf("deepscan frame: declared body %d bytes exceeds the %d-byte cap", n, MaxFrameBytes)
	}
	if int(n) != len(frame)-frameHeaderLen {
		return 0, nil, fmt.Errorf("deepscan frame: header says %d body bytes, got %d", n, len(frame)-frameHeaderLen)
	}
	return frame[0], frame[frameHeaderLen:], nil
}

// unixSink writes frames to a unix domain socket. It dials lazily and redials
// on the next Send after a write/dial error — a dead deep-scan endpoint
// degrades to dropped 补漏 tasks, never a stuck hot path (the forwarder's
// bounded queue takes up the slack and drops on overflow).
type unixSink struct {
	path         string
	dialTimeout  time.Duration
	writeTimeout time.Duration

	mu   sync.Mutex
	conn net.Conn
}

// NewUnixSink returns a Sink connecting to the unix socket at path. Dialing is
// lazy (first Send) so the sender starts even if the deep-scan process isn't up
// yet — it just drops/redials until the socket appears.
func NewUnixSink(path string, dialTimeout, writeTimeout time.Duration) Sink {
	if dialTimeout <= 0 {
		dialTimeout = 1 * time.Second
	}
	if writeTimeout <= 0 {
		writeTimeout = 1 * time.Second
	}
	return &unixSink{path: path, dialTimeout: dialTimeout, writeTimeout: writeTimeout}
}

func (s *unixSink) Send(ctx context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		d := net.Dialer{Timeout: s.dialTimeout}
		conn, err := d.DialContext(ctx, "unix", s.path)
		if err != nil {
			return fmt.Errorf("deepscan dial %s: %w", s.path, err)
		}
		s.conn = conn
	}

	if s.writeTimeout > 0 {
		_ = s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	}
	if _, err := s.conn.Write(frame); err != nil {
		// Broken pipe / timeout → drop the connection so the next Send redials
		// instead of reusing a wedged one.
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("deepscan write %s: %w", s.path, err)
	}
	return nil
}

func (s *unixSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}
