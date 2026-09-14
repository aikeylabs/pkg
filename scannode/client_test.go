package scannode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// ---------------------------------------------------------------------------
// These four fences all guard ONE property, from four directions:
//
//   a piece of an employee's raw prompt must never reach a box we did not
//   independently decide to trust.
//
// A scan node receives RAW USER CONTENT. That is the whole point of it and also
// the whole risk: every weakening here is a direct content-disclosure path, so
// each fence asserts BYTES RECEIVED == 0, not merely "an error was returned".
// An implementation that writes the frame and then notices the problem passes a
// naive error-check test and still leaked the prompt.
// ---------------------------------------------------------------------------

// tlsProbe is a real TLS listener with a self-signed cert. It counts how many
// APPLICATION bytes it managed to read, which is the only number these tests
// actually care about.
type tlsProbe struct {
	addr        string
	fingerprint string
	bytesRead   atomic.Int64
	conns       atomic.Int64
	// reply, when set, is written back after the first bytes of each read —
	// a node answering on the same connection.
	reply atomic.Pointer[[]byte]
	close func()
}

func startTLSProbe(t *testing.T) *tlsProbe {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "scan-node-probe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	sum := sha256.Sum256(der)
	p := &tlsProbe{fingerprint: hex.EncodeToString(sum[:])}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	p.addr = "https://" + ln.Addr().String()
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			p.conns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					p.bytesRead.Add(int64(n))
					if rp := p.reply.Load(); rp != nil && n > 0 {
						_, _ = c.Write(*rp)
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	p.close = func() { _ = ln.Close(); <-done }
	t.Cleanup(p.close)
	return p
}

func frame(t *testing.T) []byte {
	t.Helper()
	b, err := deepscan.EncodeFrameV2(deepscan.FrameV2{
		JobID: "job-1", TenantID: "org_a", ContentSHA256: "abc",
		Source: deepscan.SourceRequest, Prompt: "客户手机号 13800138000",
	})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func trustAll(string) bool  { return true }
func trustNone(string) bool { return false }

// TestScanNodeClient_PlaintextNodeRefused: a node URL that is not https is
// refused before a socket is opened. There is no "plaintext mode" — user
// decision D21, 2026-09-11: 「强制 TLS…永无明文模式」.
func TestScanNodeClient_PlaintextNodeRefused(t *testing.T) {
	p := startTLSProbe(t)
	host := p.addr[len("https://"):]

	sink := NewTLSSink(Node{ID: "n1", Addr: "http://" + host, Fingerprint: p.fingerprint},
		trustAll, time.Second, time.Second)
	err := sink.Send(context.Background(), frame(t))
	if err == nil {
		t.Fatal("a plaintext node URL was accepted")
	}
	if p.conns.Load() != 0 || p.bytesRead.Load() != 0 {
		t.Errorf("the refusal happened AFTER touching the node: conns=%d bytes=%d",
			p.conns.Load(), p.bytesRead.Load())
	}
}

// TestScanNodeClient_FingerprintMismatchAbortsBeforeBody: the node presents a
// valid, working TLS cert — just not the one we pinned. The handshake must fail
// and ZERO application bytes may be written. This is the fence for "someone
// stood up a look-alike node inside the network".
func TestScanNodeClient_FingerprintMismatchAbortsBeforeBody(t *testing.T) {
	p := startTLSProbe(t)
	wrong := "00" + p.fingerprint[2:]

	sink := NewTLSSink(Node{ID: "n1", Addr: p.addr, Fingerprint: wrong},
		trustAll, 2*time.Second, 2*time.Second)
	if err := sink.Send(context.Background(), frame(t)); err == nil {
		t.Fatal("a node presenting an unpinned certificate was accepted")
	}
	if got := p.bytesRead.Load(); got != 0 {
		t.Errorf("%d application bytes reached a node whose fingerprint did not match — the prompt leaked", got)
	}
}

// TestScanNodeClient_UnlistedFingerprintNeverReceivesBytes: the pin matches what
// the node presents, but the fingerprint is not in the trust set the control
// plane handed us. Same outcome, different gate — this is the one that catches
// "the node self-reported its own fingerprint and we believed it".
func TestScanNodeClient_UnlistedFingerprintNeverReceivesBytes(t *testing.T) {
	p := startTLSProbe(t)

	sink := NewTLSSink(Node{ID: "n1", Addr: p.addr, Fingerprint: p.fingerprint},
		trustNone, 2*time.Second, 2*time.Second)
	if err := sink.Send(context.Background(), frame(t)); err == nil {
		t.Fatal("a node outside the trust set was accepted")
	}
	if got := p.bytesRead.Load(); got != 0 {
		t.Errorf("%d application bytes reached an untrusted node — the prompt leaked", got)
	}
	if got := p.conns.Load(); got != 0 {
		t.Errorf("the untrusted node was dialed at all (conns=%d); the allowlist must be checked before the socket", got)
	}
}

// TestScanNodeClient_PublicAddressRefused: R-scan-node-deepscan-10 — a node
// address that resolves outside RFC1918 / RFC4193 / loopback is refused. A
// misconfigured or tampered node list must not become an exfiltration channel
// for raw prompts.
func TestScanNodeClient_PublicAddressRefused(t *testing.T) {
	for _, addr := range []string{
		"https://8.8.8.8:27411",
		"https://1.1.1.1:27411",
		"https://[2001:4860:4860::8888]:27411",
	} {
		sink := NewTLSSink(Node{ID: "n1", Addr: addr, Fingerprint: "aa"}, trustAll, time.Second, time.Second)
		if err := sink.Send(context.Background(), frame(t)); err == nil {
			t.Errorf("public address %s was accepted", addr)
		}
	}
	// ...and the private ones it exists to allow are not collateral damage.
	for _, addr := range []string{
		"https://10.2.3.4:27411",
		"https://192.168.1.9:27411",
		"https://172.16.0.1:27411",
		"https://127.0.0.1:27411",
		"https://[fd00::1]:27411",
	} {
		if err := checkPrivateAddress(addr); err != nil {
			t.Errorf("private address %s was refused: %v", addr, err)
		}
	}
}

func replyWith(t *testing.T, p *tlsProbe, r deepscan.ResultFrame) {
	t.Helper()
	b, err := deepscan.EncodeResult(r)
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	p.reply.Store(&b)
}

// TestScanNodeClient_ReadsTheResultBack — the sink returns the node's answer.
//
// 🔴 It used to return right after writing the frame, so no finding a node
// produced ever reached the proxy.
// bugfix: workflow/CI/bugfix/20260913-async-scan-lane-never-returned-findings.md
func TestScanNodeClient_ReadsTheResultBack(t *testing.T) {
	p := startTLSProbe(t)
	replyWith(t, p, deepscan.ResultFrame{JobID: "job-1", Status: deepscan.StatusComplete,
		Findings: []deepscan.Finding{{Engine: deepscan.EngineRules, EntityType: "CN_PHONE", Start: 10, End: 21}}})
	sink := NewTLSSink(Node{ID: "n1", Addr: p.addr, Fingerprint: p.fingerprint, Weight: 1}, trustAll, time.Second, 2*time.Second)
	defer sink.Close()

	if err := sink.Send(context.Background(), frame(t)); err != nil {
		t.Fatalf("send: %v", err)
	}
	rs, ok := sink.(interface {
		Results() <-chan deepscan.ResultFrame
	})
	if !ok {
		t.Fatal("the TLS sink does not expose Results()")
	}
	select {
	case r := <-rs.Results():
		if r.JobID != "job-1" || len(r.Findings) != 1 {
			t.Fatalf("result altered in transit: %+v", r)
		}
	default:
		t.Fatal("Send returned without the node's result being readable — the answer was not read back")
	}
}

// TestScanNodeClient_RejectIsATypedError — a refusal comes back as a
// RejectError carrying the code, never as a result and never as a generic error
// (the forwarder decides by code whether another node may be tried).
func TestScanNodeClient_RejectIsATypedError(t *testing.T) {
	p := startTLSProbe(t)
	replyWith(t, p, deepscan.ResultFrame{JobID: "job-1", Reject: deepscan.RejectTenantMismatch})
	sink := NewTLSSink(Node{ID: "n1", Addr: p.addr, Fingerprint: p.fingerprint, Weight: 1}, trustAll, time.Second, 2*time.Second)
	defer sink.Close()

	err := sink.Send(context.Background(), frame(t))
	var rej *deepscan.RejectError
	if !errors.As(err, &rej) || rej.Code != deepscan.RejectTenantMismatch {
		t.Fatalf("send error = %v, want RejectError{%s}", err, deepscan.RejectTenantMismatch)
	}
}
