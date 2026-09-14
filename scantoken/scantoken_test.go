package scantoken

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	keyA = Key{ID: "k1", Secret: []byte("0123456789abcdef0123456789abcdef")}
	keyB = Key{ID: "k2", Secret: []byte("fedcba9876543210fedcba9876543210")}
)

// TestScanToken_ExpiredRejected: the token is STATELESS — a node cannot ask
// anyone whether it was revoked, so the only thing standing between a leaked
// token and an attacker feeding a node content is the clock. 600s of validity
// plus a 30s backward skew allowance is the whole revocation story
// (design §4b.7), which makes this the fence that matters most in this file.
func TestScanToken_ExpiredRejected(t *testing.T) {
	now := time.Unix(1_757_620_000, 0).UTC()
	keys := KeySet{Current: keyA}
	tok := Mint(keyA, "org_a", now)

	if org, err := Verify(tok, keys, now); err != nil || org != "org_a" {
		t.Fatalf("fresh token must verify: org=%q err=%v", org, err)
	}
	// Still inside the 600s lifetime.
	if _, err := Verify(tok, keys, now.Add(599*time.Second)); err != nil {
		t.Errorf("token at t+599s must still verify: %v", err)
	}
	// Past expiry but inside the 30s skew allowance.
	if _, err := Verify(tok, keys, now.Add(TTL+20*time.Second)); err != nil {
		t.Errorf("token %v past expiry is inside the %v skew allowance and must verify: %v",
			20*time.Second, SkewAllowance, err)
	}
	// Past expiry AND past the skew allowance.
	if _, err := Verify(tok, keys, now.Add(TTL+SkewAllowance+time.Second)); err == nil {
		t.Error("an expired token was accepted — a leaked token would then be usable forever")
	}
}

// TestScanToken_PreviousKeyWithinGrace: rotation must not blackhole in-flight
// tokens. The installer writes a new key and the old one moves to `previous`
// with a valid_until 600s out; tokens minted just before rotation keep working
// until then, and not one second longer.
func TestScanToken_PreviousKeyWithinGrace(t *testing.T) {
	now := time.Unix(1_757_620_000, 0).UTC()
	old := Mint(keyA, "org_a", now)

	rotated := KeySet{
		Current:            keyB,
		Previous:           &keyA,
		PreviousValidUntil: now.Add(600 * time.Second),
	}
	if org, err := Verify(old, rotated, now.Add(time.Second)); err != nil || org != "org_a" {
		t.Fatalf("token minted with the previous key must verify inside the grace: org=%q err=%v", org, err)
	}
	if _, err := Verify(old, rotated, now.Add(601*time.Second)); err == nil {
		t.Error("the previous key was still accepted after PreviousValidUntil — the grace never ends")
	}
	// A token minted with the CURRENT key is unaffected by the grace window.
	if _, err := Verify(Mint(keyB, "org_a", now), rotated, now.Add(time.Second)); err != nil {
		t.Errorf("current-key token must verify: %v", err)
	}
	// An unknown key id is refused outright rather than falling back to current.
	if _, err := Verify(Mint(Key{ID: "k9", Secret: keyA.Secret}, "org_a", now), rotated, now); err == nil {
		t.Error("a token naming an unknown key id was accepted")
	}
}

// TestScanToken_TamperedMacRejected covers the case the format invites: the
// org id sits in PLAINTEXT in the token, so "just edit it" must fail the MAC.
func TestScanToken_TamperedMacRejected(t *testing.T) {
	now := time.Unix(1_757_620_000, 0).UTC()
	keys := KeySet{Current: keyA}
	tok := Mint(keyA, "org_a", now)

	parts := strings.Split(tok, ".")
	if len(parts) != 5 {
		t.Fatalf("token shape changed: %q", tok)
	}
	for name, bad := range map[string]string{
		"org swapped":    strings.Join([]string{parts[0], "org_b", parts[2], parts[3], parts[4]}, "."),
		"expiry pushed":  strings.Join([]string{parts[0], parts[1], "9999999999", parts[3], parts[4]}, "."),
		"mac flipped":    strings.Join([]string{parts[0], parts[1], parts[2], parts[3], flipLast(parts[4])}, "."),
		"prefix swapped": strings.Join([]string{"sct2", parts[1], parts[2], parts[3], parts[4]}, "."),
		"field dropped":  strings.Join(parts[:4], "."),
	} {
		if _, err := Verify(bad, keys, now); err == nil {
			t.Errorf("%s: tampered token was accepted (%q)", name, bad)
		}
	}
}

// TestScanToken_VectorsStable pins fixed (key, org, exp) → token strings in
// testdata/vectors.json.
//
// WHY: ai-compliance-workers verifies these tokens in PYTHON (workers/scan_token.py).
// A Go-only test proves Go agrees with itself. These vectors are what stops the
// two implementations from drifting into "the node rejects every token and the
// proxy cannot tell why" — the failure mode that looks exactly like a network
// problem. Regenerate with UPDATE_VECTORS=1 only as a deliberate wire change.
func TestScanToken_VectorsStable(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	got := buildVectors()

	if os.Getenv("UPDATE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("vectors regenerated at %s", path)
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors (regenerate with UPDATE_VECTORS=1): %v", err)
	}
	var want vectorFile
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("vectors.json is not JSON: %v", err)
	}
	if len(want.Vectors) != len(got.Vectors) {
		t.Fatalf("vector count drifted: fixture %d, generator %d", len(want.Vectors), len(got.Vectors))
	}
	for i := range got.Vectors {
		if got.Vectors[i] != want.Vectors[i] {
			t.Errorf("vector %d drifted — the Python mirror reads this file.\n got %+v\nwant %+v",
				i, got.Vectors[i], want.Vectors[i])
		}
	}
	// The vectors must also VERIFY, so a regenerate can never bless a token that
	// the library itself would reject.
	for _, v := range want.Vectors {
		keys := KeySet{Current: Key{ID: v.KeyID, Secret: []byte(v.SecretUTF8)}}
		org, err := Verify(v.Token, keys, time.Unix(v.ExpUnix-1, 0).UTC())
		if err != nil || org != v.OrgID {
			t.Errorf("fixture token does not verify: %+v org=%q err=%v", v, org, err)
		}
	}
}

type vector struct {
	KeyID      string `json:"key_id"`
	SecretUTF8 string `json:"secret_utf8"`
	OrgID      string `json:"org_id"`
	ExpUnix    int64  `json:"exp_unix"`
	Token      string `json:"token"`
}

type vectorFile struct {
	Note    string   `json:"note"`
	TTLSecs int      `json:"ttl_seconds"`
	SkewSec int      `json:"skew_allowance_seconds"`
	Vectors []vector `json:"vectors"`
}

func buildVectors() vectorFile {
	cases := []struct {
		key  Key
		org  string
		mint int64
	}{
		{keyA, "org_a", 1_757_620_000},
		{keyA, "org_with_underscores_and_digits_42", 1_700_000_000},
		{keyB, "org_b", 1_757_620_000},
		{Key{ID: "k-rotated-2026-09", Secret: []byte("a-32-byte-secret-with-dashes-01!")}, "org_c", 1_800_000_000},
	}
	out := vectorFile{
		Note:    "Cross-language fixture: Go pkg/scantoken and Python ai-compliance-workers/workers/scan_token.py must both produce and accept these byte-for-byte.",
		TTLSecs: int(TTL / time.Second),
		SkewSec: int(SkewAllowance / time.Second),
	}
	for _, c := range cases {
		now := time.Unix(c.mint, 0).UTC()
		out.Vectors = append(out.Vectors, vector{
			KeyID: c.key.ID, SecretUTF8: string(c.key.Secret), OrgID: c.org,
			ExpUnix: c.mint + int64(TTL/time.Second),
			Token:   Mint(c.key, c.org, now),
		})
	}
	return out
}

func flipLast(s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}
