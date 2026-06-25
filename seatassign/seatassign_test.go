package seatassign

import (
	"fmt"
	"math"
	"testing"
)

func mkAccounts(n int) []Account {
	a := make([]Account, n)
	for i := 0; i < n; i++ {
		a[i] = Account{AccountID: fmt.Sprintf("acc-%02d", i)}
	}
	return a
}

func seats(n int) []string {
	s := make([]string, n)
	for i := 0; i < n; i++ {
		s[i] = fmt.Sprintf("seat-%05d", i)
	}
	return s
}

// TestDeterministic: Rank is a pure function — same inputs, same order, every
// call. This is the floor of the cross-repo byte-identical contract.
func TestDeterministic(t *testing.T) {
	accs := mkAccounts(8)
	for _, seat := range seats(50) {
		first := Rank(seat, accs)
		for r := 0; r < 5; r++ {
			again := Rank(seat, accs)
			for i := range first {
				if first[i].AccountID != again[i].AccountID {
					t.Fatalf("seat %s non-deterministic at %d: %s vs %s",
						seat, i, first[i].AccountID, again[i].AccountID)
				}
			}
		}
		if Primary(seat, accs) != first[0].AccountID {
			t.Fatalf("Primary != Rank[0] for %s", seat)
		}
	}
}

// TestGoldenOrder freezes the ranking for a fixed input — the cross-repo
// contract. If WRH math/hashing changes, this fails on purpose: re-validate both
// master & proxy consumers, don't just paste new strings.
func TestGoldenOrder(t *testing.T) {
	accs := mkAccounts(6)
	got := Rank("seat-00042", accs)
	order := make([]string, len(got))
	for i, a := range got {
		order[i] = a.AccountID
	}
	want := []string{"acc-01", "acc-05", "acc-00", "acc-03", "acc-04", "acc-02"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("golden order changed: got %v want %v", order, want)
		}
	}
}

// TestEvenSpread: WRH spreads seats ~uniformly across accounts.
func TestEvenSpread(t *testing.T) {
	const M, N = 10000, 10
	accs := mkAccounts(N)
	counts := map[string]int{}
	for _, seat := range seats(M) {
		counts[Primary(seat, accs)]++
	}
	exp := float64(M) / float64(N)
	for id, c := range counts {
		if dev := math.Abs(float64(c)-exp) / exp; dev > 0.15 {
			t.Errorf("account %s got %d primaries, expected ~%.0f (dev %.1f%% > 15%%)", id, c, exp, dev*100)
		}
	}
	if len(counts) != N {
		t.Errorf("expected all %d accounts to receive seats, got %d", N, len(counts))
	}
}

// TestAddAccountRehomesAboutOneOverN: adding one account re-homes only ~1/(N+1)
// of seats, and ONLY to the new account — existing accounts never trade seats
// among themselves (the core WRH property that avoids mass reshuffle).
func TestAddAccountRehomesAboutOneOverN(t *testing.T) {
	const M, N = 10000, 10
	before := mkAccounts(N)
	after := append(mkAccounts(N), Account{AccountID: "acc-NEW"})

	moved, movedToNew := 0, 0
	for _, seat := range seats(M) {
		b := Primary(seat, before)
		a := Primary(seat, after)
		if a != b {
			moved++
			if a == "acc-NEW" {
				movedToNew++
			} else {
				t.Fatalf("seat %s moved between OLD accounts %s→%s (should never happen)", seat, b, a)
			}
		}
	}
	if moved != movedToNew {
		t.Fatalf("all moves must go to the new account: moved=%d toNew=%d", moved, movedToNew)
	}
	exp := float64(M) / float64(N+1)
	if dev := math.Abs(float64(moved)-exp) / exp; dev > 0.20 {
		t.Errorf("re-homed %d seats, expected ~%.0f (1/(N+1)); dev %.1f%% > 20%%", moved, exp, dev*100)
	}
}

// TestWeightedFavorsHigh: a heavier-weight account attracts proportionally more
// seats.
func TestWeightedFavorsHigh(t *testing.T) {
	const M = 10000
	accs := []Account{
		{AccountID: "w1-a"}, {AccountID: "w1-b"}, {AccountID: "w1-c"}, {AccountID: "w1-d"},
		{AccountID: "w3-heavy", Weight: 3},
	}
	counts := map[string]int{}
	for _, seat := range seats(M) {
		counts[Primary(seat, accs)]++
	}
	// Total weight 7; heavy share ≈ 3/7. Each w1 ≈ 1/7. Heavy should clearly
	// dominate (> 2x any single light account).
	heavy := counts["w3-heavy"]
	for _, id := range []string{"w1-a", "w1-b", "w1-c", "w1-d"} {
		if heavy < 2*counts[id] {
			t.Errorf("heavy(%d) should be > 2x light %s(%d)", heavy, id, counts[id])
		}
	}
	if frac := float64(heavy) / M; frac < 0.33 || frac > 0.52 {
		t.Errorf("heavy share %.2f outside expected ~3/7≈0.43", frac)
	}
}

func TestEmptyAndSingle(t *testing.T) {
	if Primary("seat-x", nil) != "" {
		t.Error("empty accounts must yield empty primary")
	}
	if len(Rank("seat-x", nil)) != 0 {
		t.Error("empty accounts must yield empty rank")
	}
	one := []Account{{AccountID: "solo"}}
	if Primary("seat-x", one) != "solo" {
		t.Error("single account must be primary")
	}
}
