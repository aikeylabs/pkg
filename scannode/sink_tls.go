package scannode

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// Ack codes the proxy acts on. AckAccepted is the only non-reject outcome; the
// rest alias pkg/deepscan's reject constants so there is ONE definition of each
// string shared by the encoder, this client and the Python node.
const (
	AckAccepted           = "accepted"
	AckBusy               = deepscan.RejectBusy
	AckUnauthorized       = deepscan.RejectUnauthorized
	AckTenantMismatch     = deepscan.RejectTenantMismatch
	AckBadFrame           = deepscan.RejectBadFrame
	AckVersionUnsupported = deepscan.RejectVersionUnsupported
)

// tlsSink writes frames to one scan node over TLS and reads the result frame
// back on the same connection.
type tlsSink struct {
	node        Node
	trusted     func(string) bool
	dialTimeout time.Duration
	ackTimeout  time.Duration

	mu      sync.Mutex
	conn    net.Conn
	results chan deepscan.ResultFrame
}

// NewTLSSink returns a deepscan.Sink that delivers frames to n.
//
// GATE ORDER IS PART OF THE CONTRACT. Cheapest and most decisive first, so the
// expensive/irreversible step happens last:
//
//  1. is it in the trust set?      — no socket opened
//  2. is the scheme https?         — no socket opened
//  3. does it resolve private?     — no socket opened
//  4. does the presented cert match the pin? — handshake fails, no app bytes
//  5. only now is the frame written
//
// Fences: TestScanNodeClient_UnlistedFingerprintNeverReceivesBytes,
// _PlaintextNodeRefused, _PublicAddressRefused, _FingerprintMismatchAbortsBeforeBody.
func NewTLSSink(n Node, trusted func(string) bool, dialTimeout, ackTimeout time.Duration) deepscan.Sink {
	if dialTimeout <= 0 {
		dialTimeout = 2 * time.Second
	}
	if ackTimeout <= 0 {
		ackTimeout = 30 * time.Second
	}
	if trusted == nil {
		// A nil predicate must mean "trust nothing". Defaulting to trust-all here
		// would turn a wiring mistake into a silent content-disclosure path.
		trusted = func(string) bool { return false }
	}
	return &tlsSink{node: n, trusted: trusted, dialTimeout: dialTimeout, ackTimeout: ackTimeout,
		results: make(chan deepscan.ResultFrame, 8)}
}

// Results exposes result frames read back from this node.
func (s *tlsSink) Results() <-chan deepscan.ResultFrame { return s.results }

func (s *tlsSink) Send(ctx context.Context, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		c, err := s.dial(ctx)
		if err != nil {
			return err
		}
		s.conn = c
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.dialTimeout))
	if _, err := s.conn.Write(frame); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("scannode %s: write: %w", s.node.ID, err)
	}
	return nil
}

func (s *tlsSink) dial(ctx context.Context) (net.Conn, error) {
	// (1) allowlist — before anything touches the network.
	if !s.trusted(strings.ToLower(s.node.Fingerprint)) {
		return nil, fmt.Errorf("scannode %s: fingerprint %s is not in the trusted set (a node self-reporting its own fingerprint is not an answer)",
			s.node.ID, shortFP(s.node.Fingerprint))
	}
	// (2) https and (3) private address.
	if err := checkPrivateAddress(s.node.Addr); err != nil {
		return nil, err
	}
	u, err := checkScheme(s.node.Addr)
	if err != nil {
		return nil, err
	}

	want := strings.ToLower(strings.ReplaceAll(s.node.Fingerprint, ":", ""))
	d := &net.Dialer{Timeout: s.dialTimeout}
	// (4) certificate pin, enforced inside the handshake so a mismatch aborts
	// before any application byte can be written.
	//
	// 🔴 InsecureSkipVerify is TRUE ON PURPOSE and is NOT a weakening here.
	// This product has no CA, no issuance and no revocation anywhere in the tree
	// (verified 2026-09-11), so chain verification could only ever fail; nodes
	// carry installer-generated self-signed certs. The trust decision is moved
	// wholesale into VerifyPeerCertificate below, which is STRICTER than a chain
	// check: it accepts exactly one certificate, by its SHA-256, and nothing else.
	// Removing InsecureSkipVerify without replacing this pin would not make the
	// client safer — it would make it non-functional.
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // replaced by the exact-fingerprint pin below; see the comment above
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("scannode %s: node presented no certificate", s.node.ID)
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != want {
				return fmt.Errorf("scannode %s: certificate fingerprint %s does not match the pinned %s",
					s.node.ID, shortFP(got), shortFP(want))
			}
			return nil
		},
	}
	conn, err := tls.DialWithDialer(d, "tcp", u.Host, cfg)
	if err != nil {
		return nil, fmt.Errorf("scannode %s: tls dial %s: %w", s.node.ID, u.Host, err)
	}
	_ = ctx // dial deadline is carried by the dialer; ctx reserved for cancellation wiring
	return conn, nil
}

func (s *tlsSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// shortFP renders a fingerprint for logs. Never log the full pin: it is not a
// secret, but a truncated form keeps log lines readable and makes an accidental
// copy-paste into a config obviously wrong.
func shortFP(fp string) string {
	fp = strings.ToLower(fp)
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16] + "…"
}
