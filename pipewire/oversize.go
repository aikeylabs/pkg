package pipewire

// oversize.go — reading a RESPONSE frame that is larger than MaxPayloadBytes
// without losing the frame stream (TODO-120, P0, 2026-09-15).
//
// WHY THIS EXISTS. ReadFrame stops after the 5-byte header when the declared
// length exceeds MaxPayloadBytes, so every later byte of that frame would be
// parsed as the next header. The only safe move for a caller of ReadFrame is to
// abandon the pipe, and the proxy did — by marking the detector child degraded,
// which made that request and every other in-flight request FAIL OPEN (forwarded
// to the upstream LLM unscanned). A detector reply outgrows the limit simply
// because one piece has many findings (a sensitive value repeated a few hundred
// times on a team route), so the limit was an attacker-reachable bypass.
//
// WHAT IT DOES. The frame header carries the length, and a response payload
// always begins with [4-byte LE req_id][1-byte action] (see Response). The
// detector writes each frame whole from a single writer goroutine, so the stream
// is aligned again right after the declared length. ReadResponseFrame therefore
// reads those 5 prefix bytes, discards the rest, and hands the caller a typed
// *OversizeFrameError naming which request the unreadable verdict belonged to.
// The caller can refuse exactly that request and keep reading.
//
// WHAT DID NOT CHANGE, deliberately:
//   - ReadFrame keeps its semantics (other callers rely on them).
//   - The frame layout is unchanged, so ProtocolVersion is NOT bumped.
//   - A foreign version byte, a length beyond MaxSkippableFrameBytes, or a stream
//     that ends mid-frame are NOT skippable: in each the bytes after the header
//     cannot be trusted to be ours, so they return the same errors as ReadFrame.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// responsePrefixBytes is [req_id(4)][action(1)] — the part of a response payload
// that identifies whose verdict a frame carries.
const responsePrefixBytes = 5

// MaxSkippableFrameBytes bounds the declared length ReadResponseFrame is willing
// to skip. A real verdict frame measured 425,822 bytes (TODO-120 F1: a 16 KiB
// piece of repeated PII on a team route); 64 MiB is two orders of magnitude above
// that. A length past it is not a large verdict but a misaligned byte stream
// (four arbitrary bytes read as a length), and skipping it could swallow the
// pipe for gigabytes — so it takes the original "payload too large" path.
const MaxSkippableFrameBytes = 64 << 20

// OversizeFrameError reports a response frame that was longer than
// MaxPayloadBytes and has been consumed in full. The stream is positioned at the
// next frame header. It carries no payload bytes — only framing metadata.
type OversizeFrameError struct {
	Version byte   // header version byte (always ProtocolVersion — other versions are not skipped)
	Length  uint32 // declared payload length
	ReqID   uint32 // response req_id: whose verdict this was
	Action  uint8  // the action byte the child wrote (informational; the verdict body was not read)
}

func (e *OversizeFrameError) Error() string {
	return fmt.Sprintf("pipe: payload too large (%d > %d); frame skipped, stream in sync (req_id=%d)",
		e.Length, MaxPayloadBytes, e.ReqID)
}

// ReadResponseFrame reads one RESPONSE frame like ReadFrame, except that a frame
// longer than MaxPayloadBytes (and at most MaxSkippableFrameBytes, with this
// package's ProtocolVersion) is consumed and reported as *OversizeFrameError
// instead of leaving the stream misaligned. Returns (version, payload, err).
// Caller MUST still check the returned version against the version it expects.
//
// Only for the child → parent direction: the skip reads the response prefix.
func ReadResponseFrame(r *bufio.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	version := header[0]
	length := binary.LittleEndian.Uint32(header[1:5])

	if length > MaxPayloadBytes {
		if version != ProtocolVersion || length > MaxSkippableFrameBytes {
			return version, nil, fmt.Errorf("pipe: payload too large (%d > %d)", length, MaxPayloadBytes)
		}
		prefix := make([]byte, responsePrefixBytes)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return version, nil, err
		}
		if _, err := io.CopyN(io.Discard, r, int64(length)-responsePrefixBytes); err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return version, nil, err
		}
		return version, nil, &OversizeFrameError{
			Version: version,
			Length:  length,
			ReqID:   binary.LittleEndian.Uint32(prefix[0:4]),
			Action:  prefix[4],
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return version, nil, err
	}
	return version, payload, nil
}
