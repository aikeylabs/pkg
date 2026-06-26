// Package seatassign is the SINGLE SOURCE OF TRUTH for mapping a seat to its
// preferred order of provider accounts within a seat_group (weighted rendezvous
// / HRW hashing).
//
// Why a shared module (not duplicated in master + proxy): the master computes a
// seat's account assignment (the hash default, before any scheduler override)
// and the proxy computes the SAME hash default locally so it can route while
// offline or before the routing-override poll returns. If the two sides ranked
// accounts even slightly differently, the proxy's offline default would disagree
// with the master's assignment → inconsistent routing (a request could land on
// an account the master accounts to a different seat, breaking the per-account
// user caps and prompt-cache stickiness). Both repos import THIS package via
// go.mod replace (like pkg/usagehash), so the ordering is identical by
// construction. Any change to the algorithm flips the pinned-vector test on
// purpose — that is the signal to re-validate BOTH consumers.
//
// Algorithm: weighted rendezvous hashing (WRH). For each candidate account a,
//
//	score(seat, a) = -weight / ln( h01(seat, a) )
//
// (the standard WRH form: P(account is the max) ∝ weight) where h01 ∈ (0,1) is a
// uniform hash of (seatID, accountID). Highest score =
// the seat's primary; the full descending order is its fallback chain. WRH gives
// (1) even spread of seats across accounts, (2) adding/removing one account
// re-homes only ~1/N of seats — no mass reshuffle (unlike `hash mod N`), (3)
// per-account weights for capacity differences. Ties break deterministically by
// (priority, accountID) so the order is a total order with no hidden randomness.
package seatassign

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
)

// Account is one provider account a seat can be assigned to within a group.
type Account struct {
	// AccountID is the stable identity hashed for ranking
	// (seat_group_account.account_id). MUST be stable across master & proxy.
	AccountID string
	// Weight is the WRH capacity weight; <= 0 is treated as 1. A higher weight
	// proportionally attracts more seats (for accounts with larger quota).
	Weight float64
	// Priority is a deterministic tie-break when two accounts score equal
	// (astronomically rare). Lower wins.
	Priority int
}

// Rank returns accounts ordered by the seat's preference, primary first.
// Deterministic and byte-identical across master & proxy (cross-repo contract).
// The input slice is not mutated.
func Rank(seatID string, accounts []Account) []Account {
	out := make([]Account, len(accounts))
	copy(out, accounts)
	scores := make(map[string]float64, len(out))
	for _, a := range out {
		scores[a.AccountID] = score(seatID, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := scores[out[i].AccountID], scores[out[j].AccountID]
		if si != sj {
			return si > sj // higher score = preferred
		}
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].AccountID < out[j].AccountID
	})
	return out
}

// Primary returns the seat's top-ranked account ID, or "" if accounts is empty.
func Primary(seatID string, accounts []Account) string {
	if len(accounts) == 0 {
		return ""
	}
	best := accounts[0]
	bestScore := score(seatID, best)
	for _, a := range accounts[1:] {
		s := score(seatID, a)
		if s > bestScore || (s == bestScore && less(a, best)) {
			best, bestScore = a, s
		}
	}
	return best.AccountID
}

func less(a, b Account) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	return a.AccountID < b.AccountID
}

func score(seatID string, a Account) float64 {
	w := a.Weight
	if w <= 0 {
		w = 1
	}
	// Standard weighted rendezvous: -w/ln(h01). h01∈(0,1) ⇒ ln<0 ⇒ score>0;
	// higher weight ⇒ higher score ⇒ proportionally more seats.
	return -w / math.Log(h01(seatID, a.AccountID))
}

// h01 hashes (seatID, accountID) to a uniform float in (0,1). The seatID length
// prefix makes (seatID, accountID) unambiguous so ("ab","c") and ("a","bc")
// never collide.
func h01(seatID, accountID string) float64 {
	h := sha256.New()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(seatID)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(seatID))
	_, _ = h.Write([]byte(accountID))
	sum := h.Sum(nil)
	u := binary.BigEndian.Uint64(sum[:8])
	// Map to (0,1): +1 / +2 keeps the result strictly inside (0,1) so -ln is
	// finite and positive.
	return (float64(u) + 1) / (float64(math.MaxUint64) + 2)
}
