// SPIKE — openspec/changes/add-scan-node-deepscan tasks.md 1.5
//
// Question: the scan-node design picks a node with weighted rendezvous hashing
// over the key `tenant_id‖content_sha256` (design §4b.2). seatassign.Primary is
// the chosen implementation. Does that key shape actually spread evenly over 4
// equal-weight nodes, or does the shared tenant prefix bias one node?
//
// This is a measurement, not a fence: it prints the distribution so the number
// can be written into baseline-forensics.md §F5.
package seatassign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"testing"
)

func TestSpikeContentKeyDistributionOverFourNodes(t *testing.T) {
	nodes := []Account{
		{AccountID: "scan-1", Weight: 1},
		{AccountID: "scan-2", Weight: 1},
		{AccountID: "scan-3", Weight: 1},
		{AccountID: "scan-4", Weight: 1},
	}
	const (
		keys   = 10000
		tenant = "org_bosera_prod"
	)
	counts := map[string]int{}
	for i := 0; i < keys; i++ {
		sum := sha256.Sum256([]byte(fmt.Sprintf("piece-%d", i)))
		key := tenant + "‖" + hex.EncodeToString(sum[:])
		counts[Primary(key, nodes)]++
	}

	ideal := float64(keys) / float64(len(nodes))
	worst := 0.0
	for _, n := range nodes {
		c := counts[n.AccountID]
		dev := (float64(c) - ideal) / ideal * 100
		if math.Abs(dev) > math.Abs(worst) {
			worst = dev
		}
		t.Logf("MEASURED %s: %d keys (%.2f%%), deviation from even share %+.2f%%",
			n.AccountID, c, float64(c)/float64(keys)*100, dev)
	}
	t.Logf("MEASURED worst-node deviation over %d keys x %d nodes: %+.2f%%", keys, len(nodes), worst)

	// Same content must always pick the same node — the affinity the design
	// relies on for "the node's own record becomes the de-facto shared layer".
	sum := sha256.Sum256([]byte("stable-piece"))
	key := tenant + "‖" + hex.EncodeToString(sum[:])
	first := Primary(key, nodes)
	for i := 0; i < 100; i++ {
		if got := Primary(key, nodes); got != first {
			t.Fatalf("same key picked %s then %s — rendezvous is not deterministic", first, got)
		}
	}
	t.Logf("MEASURED same tenant+content key -> %s on 100/100 draws", first)
}
