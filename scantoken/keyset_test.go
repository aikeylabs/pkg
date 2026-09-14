package scantoken

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type keysetFixture struct {
	Cases []struct {
		Name               string `json:"name"`
		Raw                string `json:"raw"`
		CurrentKeyID       string `json:"current_key_id"`
		CurrentSecret      string `json:"current_secret"`
		PreviousKeyID      string `json:"previous_key_id"`
		PreviousSecret     string `json:"previous_secret"`
		PreviousValidUntil int64  `json:"previous_valid_until"`
	} `json:"cases"`
	RejectCases []struct {
		Name string `json:"name"`
		Raw  string `json:"raw"`
	} `json:"reject_cases"`
}

func loadKeysetFixture(t *testing.T) keysetFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/keyset_vectors.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f keysetFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if len(f.Cases) == 0 || len(f.RejectCases) == 0 {
		t.Fatal("fixture is empty — this test would assert nothing")
	}
	return f
}

// TestParseKeySet_Fixture pins the file format against the SAME vectors the
// Python node parses (workers/scan_token.py). Two languages, one file on disk:
// if they ever disagree, the master mints with a key the node will not accept
// and every scan fails `unauthorized` with nothing to point at.
func TestParseKeySet_Fixture(t *testing.T) {
	f := loadKeysetFixture(t)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			ks, err := ParseKeySet([]byte(c.Raw))
			if err != nil {
				t.Fatalf("ParseKeySet: %v", err)
			}
			if ks.Current.ID != c.CurrentKeyID {
				t.Errorf("current id = %q, want %q", ks.Current.ID, c.CurrentKeyID)
			}
			if string(ks.Current.Secret) != c.CurrentSecret {
				t.Errorf("current secret = %q, want %q", ks.Current.Secret, c.CurrentSecret)
			}
			if c.PreviousSecret == "" {
				if ks.Previous != nil {
					t.Errorf("previous = %+v, want none", ks.Previous)
				}
				return
			}
			if ks.Previous == nil {
				t.Fatal("previous is nil, want a key")
			}
			if ks.Previous.ID != c.PreviousKeyID || string(ks.Previous.Secret) != c.PreviousSecret {
				t.Errorf("previous = %s:%s, want %s:%s",
					ks.Previous.ID, ks.Previous.Secret, c.PreviousKeyID, c.PreviousSecret)
			}
			if got := ks.PreviousValidUntil.Unix(); got != c.PreviousValidUntil {
				t.Errorf("previous_valid_until = %d, want %d", got, c.PreviousValidUntil)
			}
		})
	}
	for _, c := range f.RejectCases {
		t.Run("reject/"+c.Name, func(t *testing.T) {
			if _, err := ParseKeySet([]byte(c.Raw)); err == nil {
				t.Fatal("ParseKeySet accepted a file it must refuse — " +
					"downstream, 'no usable key' looks exactly like 'this deployment has no scan nodes'")
			}
		})
	}
}

// TestFormatKeySet_RoundTrips is what makes the installers safe to write: they
// call FormatKeySet, every reader calls ParseKeySet, so the shape exists in one
// place. A round-trip that loses a field would strand tokens on rotation.
func TestFormatKeySet_RoundTrips(t *testing.T) {
	until := time.Unix(1789200634, 0)
	in := KeySet{
		Current:            Key{ID: "k7", Secret: []byte("new-secret-value")},
		Previous:           &Key{ID: "k6", Secret: []byte("old-secret-value")},
		PreviousValidUntil: until,
	}
	out, err := ParseKeySet([]byte(FormatKeySet(in)))
	if err != nil {
		t.Fatalf("ParseKeySet(FormatKeySet(...)): %v", err)
	}
	if out.Current.ID != in.Current.ID || string(out.Current.Secret) != string(in.Current.Secret) {
		t.Errorf("current round-trip: %s:%s != %s:%s",
			out.Current.ID, out.Current.Secret, in.Current.ID, in.Current.Secret)
	}
	if out.Previous == nil ||
		out.Previous.ID != in.Previous.ID ||
		string(out.Previous.Secret) != string(in.Previous.Secret) {
		t.Errorf("previous round-trip: %+v != %+v", out.Previous, in.Previous)
	}
	if !out.PreviousValidUntil.Equal(until) {
		t.Errorf("previous_valid_until round-trip: %v != %v", out.PreviousValidUntil, until)
	}
}

// TestParseKeySet_RotatedKeySetActuallyVerifiesBothKeys is the assertion that
// matters operationally: a token minted with the key that was just retired must
// still verify during the grace window, and must stop afterwards. Everything
// else here is about parsing; this is about the outage rotation exists to avoid.
func TestParseKeySet_RotatedKeySetActuallyVerifiesBothKeys(t *testing.T) {
	now := time.Unix(1789200034, 0)
	old := Key{ID: "k1", Secret: []byte("OLDSECRET-bbbbbbbbbbbbbbbbbbbbbb")}
	inFlight := Mint(old, "org_a", now.Add(-30*time.Second))

	ks, err := ParseKeySet([]byte(
		"current: k2:NEWSECRET-aaaaaaaaaaaaaaaaaaaaaa\n" +
			"previous: k1:OLDSECRET-bbbbbbbbbbbbbbbbbbbbbb\n" +
			"previous_valid_until: " + "1789200634" + "\n"))
	if err != nil {
		t.Fatalf("ParseKeySet: %v", err)
	}

	if org, err := Verify(inFlight, ks, now); err != nil || org != "org_a" {
		t.Fatalf("a token minted seconds before the rotation was refused (org=%q err=%v) — "+
			"this is the ten-minute fleet-wide outage `previous` exists to prevent", org, err)
	}
	// One second past the grace instant the retired key is dead, even for a
	// token whose own expiry has not been reached.
	if _, err := Verify(inFlight, ks, time.Unix(1789200635, 0)); err == nil {
		t.Fatal("the retired key still verified after previous_valid_until — rotation never completes")
	}
}
