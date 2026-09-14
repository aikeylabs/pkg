package scannode

import (
	"sync"
	"time"

	"github.com/AiKeyLabs/pkg/seatassign"
)

// Rank orders nodes by preference for one content key, best first.
//
// The key is `tenant_id‖content_sha256` (design §4b.2). Same content → same node,
// every time, from every proxy — which is what makes the node's own local record
// a de-facto shared "already scanned" layer WITHOUT a shared table (D18/D19).
//
// 🔴 It reuses pkg/seatassign rather than hashing here. That package is the
// weighted-rendezvous implementation master and proxy already agree on
// byte-for-byte, and a second implementation of the same idea is exactly how two
// sides of a distributed system quietly stop choosing the same box. The
// vocabulary mismatch (Account/seatID vs Node/contentKey) is cosmetic: both are
// "pick one of N by a stable key, weighted".
func Rank(nodes []Node, key string) []Node {
	if len(nodes) == 0 {
		return nil
	}
	accounts := make([]seatassign.Account, 0, len(nodes))
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		w := float64(n.Weight)
		if w <= 0 {
			w = 1
		}
		accounts = append(accounts, seatassign.Account{AccountID: n.ID, Weight: w})
		byID[n.ID] = n
	}
	ranked := seatassign.Rank(key, accounts)
	out := make([]Node, 0, len(ranked))
	for _, a := range ranked {
		out = append(out, byID[a.AccountID])
	}
	return out
}

// Breaker decides whether a node may be tried right now.
type Breaker interface {
	Allow(nodeID string) bool
	Report(nodeID string, ok bool)
}

// NewBreaker returns a per-node consecutive-failure breaker with the default
// half-open cooldown.
func NewBreaker(threshold int) Breaker {
	return NewBreakerWithCooldown(threshold, DefaultBreakerCooldown)
}

// DefaultBreakerCooldown is how long an open breaker refuses a node before it
// lets ONE attempt through again.
const DefaultBreakerCooldown = 30 * time.Second

// NewBreakerWithCooldown returns a per-node breaker that opens after threshold
// consecutive failures and, once open, refuses the node until cooldown has
// elapsed — then allows attempts again so a recovered node can prove itself.
//
// 🔴 THE COOLDOWN IS NOT OPTIONAL, and leaving it out is not a smaller design —
// it is a broken one. A breaker that opens on failures and only closes on a
// success, while also refusing every attempt, can never close: the one request
// that would have proven the node healthy is the request it blocks. That is not
// hypothetical; it is what this package did until
// TestDeepScanForward_DegradesAfterThreeFailuresAndRecovers caught it on
// 2026-09-12. The node came back, and the lane stayed dark until a proxy restart.
//
// Half-open is deliberately generous: after the cooldown EVERY attempt is
// allowed again (not a single probe), because the cost of being wrong is one
// dropped background task, never a failed user request — and being slow to
// notice a recovery costs real compliance coverage.
func NewBreakerWithCooldown(threshold int, cooldown time.Duration) Breaker {
	if threshold <= 0 {
		threshold = 3
	}
	if cooldown <= 0 {
		cooldown = DefaultBreakerCooldown
	}
	return &breaker{threshold: threshold, cooldown: cooldown, state: map[string]*breakerState{}, now: time.Now}
}

type breakerState struct {
	fails    int
	openedAt time.Time
}

type breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	mu    sync.Mutex
	state map[string]*breakerState
}

func (b *breaker) Allow(nodeID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	st, ok := b.state[nodeID]
	if !ok || st.fails < b.threshold {
		return true
	}
	if b.now().Sub(st.openedAt) >= b.cooldown {
		// Half-open: let attempts through again. The counter is NOT reset here —
		// only an actual success clears it (Report), so a node that is still down
		// re-opens on its next failure instead of flapping every cooldown.
		return true
	}
	return false
}

func (b *breaker) Report(nodeID string, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ok {
		delete(b.state, nodeID)
		return
	}
	st := b.state[nodeID]
	if st == nil {
		st = &breakerState{}
		b.state[nodeID] = st
	}
	st.fails++
	if st.fails >= b.threshold {
		// >= not ==: a failure while the breaker is HALF-OPEN must restart the
		// cooldown. With `==` the window would only ever be set once, so after the
		// first cooldown elapsed the breaker would allow every attempt forever —
		// open in name only, which is worse than no breaker because the health
		// section would still report it as protecting something.
		st.openedAt = b.now()
	}
}
