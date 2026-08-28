package egress

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// countingListener accepts TCP connections and counts them; connections are
// closed immediately (enough to observe "the chain's first hop was dialed").
func countingListener(t *testing.T) (net.Listener, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln, &hits
}

func TestBuildDialContext_UnclaimedSpecFailsLoudly(t *testing.T) {
	// A mihomo fragment in the OSS test build (no multi-protocol engine
	// registered) must error — never fall back to a direct dial.
	if _, _, err := BuildDialContext(`proxies:\n- {name: x}`); err == nil {
		t.Fatal("fragment spec must fail on a build without the multi-protocol engine")
	}
}

func TestBuildDialContext_NonLoopbackRidesTheChain(t *testing.T) {
	hop, hits := countingListener(t)
	dial, closer, err := BuildDialContext("socks5://" + hop.Addr().String())
	if err != nil {
		t.Fatalf("chain spec must build via the builtin engine: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// TEST-NET-3 address: never routable, so a successful direct dial is
	// impossible — any observed hop hit proves the chain path was taken.
	_, _ = dial(ctx, "tcp", "203.0.113.1:80")
	if hits.Load() == 0 {
		t.Fatal("dial to a public address bypassed the egress chain (would leak the node IP)")
	}
}

func TestBuildDialContext_LoopbackBypassesTheChain(t *testing.T) {
	// The chain's hop is a dead port: riding the chain can only fail. A
	// loopback destination must still connect (direct IPC bypass).
	dial, closer, err := BuildDialContext("socks5://127.0.0.1:1")
	if err != nil {
		t.Fatalf("chain spec must build: %v", err)
	}
	if closer != nil {
		defer closer.Close()
	}
	target, hits := countingListener(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", target.Addr().String())
	if err != nil {
		t.Fatalf("loopback destination must bypass the egress chain and dial direct: %v", err)
	}
	_ = conn.Close()
	if hits.Load() == 0 {
		t.Fatal("loopback listener saw no connection — bypass did not dial direct")
	}
}
