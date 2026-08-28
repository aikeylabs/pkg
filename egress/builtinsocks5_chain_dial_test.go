package egress

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The builtin socks5 chain engine had no real dialing coverage: Claims/parse
// were fenced, but nothing ever pushed bytes through a composed chain. The
// Session Key composite-egress bridge (2026-08-27) made that gap load-bearing —
// a chain that parses but cannot carry traffic now fails a user login.

// miniSocks5 is a minimal RFC 1928 CONNECT server for tests. It records every
// CONNECT target so a test can prove which hop saw what.
// resolve maps a fake non-loopback hostname to the IP actually dialed. It is
// what lets a hermetic test point a chain at a loopback origin WITHOUT the
// loopback bypass short-circuiting the chain (the bypass is keyed on the
// destination the client asks for, and socks5 passes hostnames through).
type miniSocks5 struct {
	ln      net.Listener
	resolve map[string]string
	mu      sync.Mutex
	targets []string
}

func startMiniSocks5(t *testing.T, resolve map[string]string) *miniSocks5 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &miniSocks5{ln: ln, resolve: resolve}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *miniSocks5) addr() string { return s.ln.Addr().String() }

func (s *miniSocks5) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.targets...)
}

func (s *miniSocks5) handle(c net.Conn) {
	defer c.Close()
	hs := make([]byte, 2)
	if _, err := io.ReadFull(c, hs); err != nil || hs[0] != 0x05 {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, int(hs[1]))); err != nil {
		return
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[1] != 0x01 {
		return
	}
	var host string
	switch hdr[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return
		}
		host = string(b)
	default:
		return
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))
	target := net.JoinHostPort(host, port)
	s.mu.Lock()
	s.targets = append(s.targets, target)
	s.mu.Unlock()

	dialTarget := target
	if ip, ok := s.resolve[host]; ok {
		dialTarget = net.JoinHostPort(ip, port)
	}
	up, err := net.DialTimeout("tcp", dialTarget, 5*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(up, c) }()
	_, _ = io.Copy(c, up)
}

// TestBuiltinChain_CarriesTrafficThroughEveryHop dials a real HTTP origin
// through a TWO-HOP socks5 chain and asserts both hops actually relayed it —
// entry hop sees the exit hop, exit hop sees the origin.
func TestBuiltinChain_CarriesTrafficThroughEveryHop(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("through-the-chain"))
	}))
	defer origin.Close()

	// The origin is addressed by a fake NON-loopback name so the chain is not
	// bypassed; only the exit hop knows it resolves back to the test server.
	const originHost = "origin.chain.test"
	_, originPort, _ := net.SplitHostPort(origin.Listener.Addr().String())
	entry := startMiniSocks5(t, nil)
	exit := startMiniSocks5(t, map[string]string{originHost: "127.0.0.1"})

	dial, closer, err := BuildDialContext("socks5://" + entry.addr() + ",socks5://" + exit.addr())
	if err != nil {
		t.Fatalf("build two-hop chain: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}

	client := &http.Client{Transport: &http.Transport{DialContext: dial}, Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(originHost, originPort) + "/")
	if err != nil {
		t.Fatalf("GET through the two-hop chain failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "through-the-chain" {
		t.Fatalf("body = %q, want the origin's response", body)
	}

	// hop[0] is dialed first and must tunnel to hop[1]; hop[1] exits to origin.
	if got := entry.seen(); len(got) == 0 || got[0] != exit.addr() {
		t.Fatalf("entry hop targets = %v, want it to CONNECT to the exit hop %s", got, exit.addr())
	}
	if got := exit.seen(); len(got) == 0 {
		t.Fatal("exit hop relayed nothing — the chain did not reach its exit")
	}
	_ = context.Background()
}
