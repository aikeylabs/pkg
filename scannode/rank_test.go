package scannode

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

// TestRank_SameContentSameNode: the SAME content must always rank the same node
// first, and that node must stay first when OTHER nodes come and go.
//
// WHY this matters beyond load balancing (design D18/D19, 2026-09-11): the
// product deliberately does NOT build a shared "already scanned" table. The
// affinity IS the shared layer — the same piece of content always lands on the
// same node, so that node's own local record answers "has anyone in this org
// sent this before?" without a database. Break the affinity and the de-dup
// silently becomes a full re-scan on every node, which looks like nothing at all
// except a rising CPU bill.
//
// The key is `tenant_id‖content_sha256` (design §4b.2). Note what is NOT in it:
// no seat, no session. Two employees pasting the same text hit the same node on
// purpose — that is the whole de-dup.
func TestRank_SameContentSameNode(t *testing.T) {
	all := []Node{
		{ID: "scan-1", Addr: "https://10.0.0.1:27411", Weight: 1},
		{ID: "scan-2", Addr: "https://10.0.0.2:27411", Weight: 1},
		{ID: "scan-3", Addr: "https://10.0.0.3:27411", Weight: 1},
		{ID: "scan-4", Addr: "https://10.0.0.4:27411", Weight: 1},
	}
	key := contentKey("org_a", "the quarterly figures, verbatim")

	first := Rank(all, key)
	if len(first) != len(all) {
		t.Fatalf("Rank dropped nodes: %d in, %d out", len(all), len(first))
	}
	for i := 0; i < 50; i++ {
		got := Rank(all, key)
		if got[0].ID != first[0].ID {
			t.Fatalf("same key chose %s then %s — affinity is not deterministic", first[0].ID, got[0].ID)
		}
	}

	// Input order must not matter: two proxies holding the same node set in
	// different order have to agree, or the de-dup is per-proxy.
	shuffled := []Node{all[2], all[0], all[3], all[1]}
	if got := Rank(shuffled, key); got[0].ID != first[0].ID {
		t.Errorf("node input order changed the winner: %s vs %s", got[0].ID, first[0].ID)
	}

	// Removing an UNRELATED node must not move the winner (that is what
	// rendezvous hashing buys over modulo).
	var without []Node
	for _, n := range all {
		if n.ID != first[len(first)-1].ID {
			without = append(without, n)
		}
	}
	if got := Rank(without, key); got[0].ID != first[0].ID {
		t.Errorf("dropping the LAST-ranked node moved the winner from %s to %s — that is modulo behaviour, not rendezvous",
			first[0].ID, got[0].ID)
	}

	// Different content must spread; identical content must not.
	seen := map[string]int{}
	for i := 0; i < 2000; i++ {
		seen[Rank(all, contentKey("org_a", fmt.Sprintf("piece-%d", i)))[0].ID]++
	}
	if len(seen) != len(all) {
		t.Errorf("2000 distinct pieces only ever reached %d of %d nodes: %v", len(seen), len(all), seen)
	}
}

// TestBreaker_OpensAfterThreeFailuresAndRecovers pins the degrade rule the
// health section reports (design §3.4: "连续 3 次投递失败后为 degraded，一次成功归零").
func TestBreaker_OpensAfterThreeFailuresAndRecovers(t *testing.T) {
	b := NewBreaker(3)
	if !b.Allow("scan-1") {
		t.Fatal("a fresh breaker must allow")
	}
	b.Report("scan-1", false)
	b.Report("scan-1", false)
	if !b.Allow("scan-1") {
		t.Error("two failures must not open the breaker — a node is allowed to blip")
	}
	b.Report("scan-1", false)
	if b.Allow("scan-1") {
		t.Error("three consecutive failures must open the breaker")
	}
	// A different node is unaffected: the breaker is per-node or a single bad
	// box takes the whole lane down.
	if !b.Allow("scan-2") {
		t.Error("one node's failures opened another node's breaker")
	}
	b.Report("scan-1", true)
	if !b.Allow("scan-1") {
		t.Error("one success must close the breaker again")
	}
}

func contentKey(tenant, content string) string {
	sum := sha256.Sum256([]byte(content))
	return tenant + "‖" + hex.EncodeToString(sum[:])
}

// TestBreaker_HalfOpenLetsARecoveredNodeBackIn is the regression fence for a
// defect this package shipped with until 2026-09-12: the breaker opened after
// three failures and then refused every attempt, including the one that would
// have proven the node healthy again. A node that recovered stayed excluded
// until the proxy restarted, and nothing anywhere said so — the lane just
// quietly produced no coverage.
//
// Caught by TestDeepScanForward_DegradesAfterThreeFailuresAndRecovers in
// aikey-proxy, fenced here at the source.
func TestBreaker_HalfOpenLetsARecoveredNodeBackIn(t *testing.T) {
	b := NewBreakerWithCooldown(3, 40*time.Millisecond)
	for i := 0; i < 3; i++ {
		b.Report("scan-1", false)
	}
	if b.Allow("scan-1") {
		t.Fatal("breaker must be open immediately after the threshold")
	}
	time.Sleep(60 * time.Millisecond)
	if !b.Allow("scan-1") {
		t.Fatal("after the cooldown the breaker must allow an attempt, or a recovered node can never come back")
	}
	// Still down: the next failure re-opens it rather than flapping open/closed.
	b.Report("scan-1", false)
	if b.Allow("scan-1") {
		t.Error("a node that failed again during half-open must be refused again")
	}
	// Recovered: one success clears everything.
	time.Sleep(60 * time.Millisecond)
	b.Report("scan-1", true)
	if !b.Allow("scan-1") {
		t.Error("a success must fully close the breaker")
	}
}
