// Package scantoken mints and verifies the short-lived, org-scoped bearer token
// a proxy presents to a scan node with every task frame.
//
// FORMAT (design §4b.7 — this string is a wire contract, mirrored in Python by
// ai-compliance-workers/workers/scan_token.py and pinned by testdata/vectors.json):
//
//	sct1.<org_id>.<exp_unix>.<key_id>.<base64url_nopad(HMAC-SHA256(secret, "sct1|org_id|exp_unix|key_id"))>
//
// WHY STATELESS, AND WHAT THAT COSTS
// ---------------------------------------------------------------------------
// A node must be able to refuse a frame WITHOUT calling anyone: it sits on the
// data path, and a lookup per frame would put the control plane in the way of
// every scan. The price is that there is no revocation list — a leaked token
// stays usable until it expires. That is why the lifetime is 600s and why
// Verify refuses to be generous about the clock: the TTL *is* the revocation
// mechanism. Rotation (KeySet.Previous + PreviousValidUntil) exists so changing
// the signing key does not blackhole tokens already in flight.
//
// 🚫 The org id travels in PLAINTEXT inside the token. That is deliberate — the
// node needs it before it can verify anything — and it is exactly why every
// field is inside the MAC: editing the org id, the expiry or the key id must
// invalidate the token. Fence: TestScanToken_TamperedMacRejected.
package scantoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Prefix is the format marker. A different prefix is a different format and is
// refused rather than best-effort parsed.
const Prefix = "sct1"

// TTL is how long a minted token stays valid. Short on purpose: with no
// revocation list this is the only bound on a leaked token's usefulness.
const TTL = 600 * time.Second

// SkewAllowance is how far past expiry a node still accepts a token, to absorb
// clock drift between an employee laptop and a scan node. Kept small for the
// same reason TTL is: every second here is a second a leaked token still works.
const SkewAllowance = 30 * time.Second

// Errors callers may branch on. A node maps all of them to the single reject
// code `unauthorized`: telling a caller WHICH check failed is free help for
// someone probing the token format.
var (
	ErrMalformed  = errors.New("scantoken: malformed token")
	ErrUnknownKey = errors.New("scantoken: unknown key id")
	ErrExpired    = errors.New("scantoken: token expired")
	ErrBadMAC     = errors.New("scantoken: signature mismatch")
	ErrGraceEnded = errors.New("scantoken: previous key is past its grace window")
)

// Key is one signing key: a stable id (which travels in the token so a verifier
// knows which secret to use) and the secret itself.
type Key struct {
	ID     string
	Secret []byte
}

// KeySet is what a verifier holds: the key in use now, plus optionally the key
// it just rotated away from and the instant that key stops being accepted.
type KeySet struct {
	Current            Key
	Previous           *Key
	PreviousValidUntil time.Time
}

// Mint returns a token for orgID valid for TTL from now.
func Mint(key Key, orgID string, now time.Time) string {
	exp := now.Add(TTL).Unix()
	return assemble(key, orgID, exp)
}

// MintUntil returns a token that expires at the given instant. Used by callers
// that must align a token's life with something else (a response's
// token_expires_at, a test vector); Mint is the normal entry point.
func MintUntil(key Key, orgID string, exp time.Time) string {
	return assemble(key, orgID, exp.Unix())
}

func assemble(key Key, orgID string, exp int64) string {
	expStr := strconv.FormatInt(exp, 10)
	mac := sign(key.Secret, orgID, expStr, key.ID)
	return strings.Join([]string{Prefix, orgID, expStr, key.ID, mac}, ".")
}

// signingInput is the exact byte string covered by the MAC. Pipe-separated with
// no length prefixes is safe here ONLY because none of the four fields may
// contain a pipe or a dot — enforced by validateField below. Without that check
// ("a|b", "c") and ("a", "b|c") would sign identically.
func signingInput(orgID, expStr, keyID string) string {
	return Prefix + "|" + orgID + "|" + expStr + "|" + keyID
}

func sign(secret []byte, orgID, expStr, keyID string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(signingInput(orgID, expStr, keyID)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks a token against keys at time now and returns the org it names.
//
// Order matters and is deliberate: shape → key lookup → MAC → expiry. The MAC
// is checked BEFORE the expiry so an attacker cannot learn anything by feeding
// tokens with edited expiry fields; and the grace window is checked against the
// KEY, not the token, so a rotated-away key stops working on schedule even for
// tokens minted seconds before the rotation.
func Verify(tok string, keys KeySet, now time.Time) (string, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 5 || parts[0] != Prefix {
		return "", ErrMalformed
	}
	orgID, expStr, keyID, mac := parts[1], parts[2], parts[3], parts[4]
	if orgID == "" || keyID == "" || mac == "" {
		return "", ErrMalformed
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", ErrMalformed
	}

	var secret []byte
	switch {
	case keyID == keys.Current.ID:
		secret = keys.Current.Secret
	case keys.Previous != nil && keyID == keys.Previous.ID:
		if !keys.PreviousValidUntil.IsZero() && now.After(keys.PreviousValidUntil) {
			return "", ErrGraceEnded
		}
		secret = keys.Previous.Secret
	default:
		return "", ErrUnknownKey
	}

	want := sign(secret, orgID, expStr, keyID)
	// hmac.Equal, not ==: string comparison short-circuits on the first differing
	// byte and leaks how much of a guessed MAC was right.
	if !hmac.Equal([]byte(want), []byte(mac)) {
		return "", ErrBadMAC
	}
	if now.After(time.Unix(exp, 0).Add(SkewAllowance)) {
		return "", fmt.Errorf("%w at %s (now %s)", ErrExpired,
			time.Unix(exp, 0).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	return orgID, nil
}

// ValidateField reports whether s may be used as an org id or key id. The MAC's
// signing input is pipe-separated and the token itself is dot-separated, so a
// value containing either character would make two different (org, exp, key)
// triples sign or parse identically.
func ValidateField(s string) error {
	if s == "" {
		return fmt.Errorf("scantoken: empty field")
	}
	if strings.ContainsAny(s, ".|") {
		return fmt.Errorf("scantoken: %q contains '.' or '|', which the token format reserves as separators", s)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Key-file format
// ---------------------------------------------------------------------------
//
// ONE FILE, THREE READERS: the Production master (which mints), a Cluster proxy
// node (which also mints), and every scan node (which verifies). The installers
// write it; nobody edits it by hand. It lives at AIKEY_SCAN_TOKEN_KEY_FILE.
//
//	current: k2:<secret>
//	previous: k1:<secret>
//	previous_valid_until: <unix seconds>
//
// 🔴 WHY `previous` EXISTS AT ALL. The token is stateless with a 600s TTL and no
// revocation list. At the instant a rotation lands, tokens minted seconds ago
// with the old key are still in flight and still legitimately valid for up to
// 600 more seconds. A rotation that simply overwrote the secret would make every
// node answer `unauthorized` for ten minutes — indistinguishable, from the
// console, from the nodes being down. `previous_valid_until` is therefore
// now+TTL exactly: the last token mintable with the old key expires precisely
// then, so a longer window keeps a retired key alive for nobody and a shorter
// one strands tokens that were valid when they were issued.
//
// 🔴 LEGACY ONE-LINER IS STILL VALID and must stay that way: the first
// installers wrote a bare secret, then `<key_id>:<secret>`. Those files are on
// deployed machines right now. Refusing them would turn an upgrade into an
// outage for every deployment that has not rotated yet, so a file with no
// `current:` line is read as the current key with no previous.
//
// Mirrored in Python by ai-compliance-workers/workers/scan_token.py
// (parse_keyset) and pinned across both by testdata/keyset_vectors.json.
const (
	fieldCurrent            = "current"
	fieldPrevious           = "previous"
	fieldPreviousValidUntil = "previous_valid_until"
)

// ParseKeySet reads the key file's contents.
//
// Parsing is deliberately forgiving about blank lines and comments and
// deliberately STRICT about a malformed `current`: everything downstream — the
// endpoint that mints, the node that verifies — treats "no key" as "this
// deployment has no scan nodes", which is a silent, correct-looking state. A
// key file that exists but is unreadable is an operator mistake, and it must
// surface as an error rather than as a feature quietly switching itself off.
func ParseKeySet(raw []byte) (KeySet, error) {
	var ks KeySet
	var prevID, prevSecret string
	sawCurrent := false

	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		name, value, ok := strings.Cut(t, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		switch name {
		case fieldCurrent:
			id, secret := splitKeyValue(value)
			if secret == "" {
				return KeySet{}, fmt.Errorf("scantoken: key file has an empty `current` secret")
			}
			ks.Current = Key{ID: id, Secret: []byte(secret)}
			sawCurrent = true
		case fieldPrevious:
			prevID, prevSecret = splitKeyValue(value)
		case fieldPreviousValidUntil:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return KeySet{}, fmt.Errorf("scantoken: key file has an unparsable `previous_valid_until` %q: %w", value, err)
			}
			ks.PreviousValidUntil = time.Unix(n, 0)
		}
	}

	if !sawCurrent {
		// Legacy form: the whole file is the key, either `<id>:<secret>` or a
		// bare secret. See the LEGACY note above — this path is load-bearing for
		// every machine installed before rotation existed.
		id, secret := splitKeyValue(strings.TrimSpace(string(raw)))
		if secret == "" {
			return KeySet{}, fmt.Errorf("scantoken: key file is empty")
		}
		ks.Current = Key{ID: id, Secret: []byte(secret)}
		return ks, nil
	}

	// A previous key with no grace instant would be accepted FOREVER, which is
	// the opposite of what rotating is for. Drop it and say so, rather than
	// quietly keeping a retired secret live.
	if prevSecret != "" && !ks.PreviousValidUntil.IsZero() {
		ks.Previous = &Key{ID: prevID, Secret: []byte(prevSecret)}
	} else if prevSecret != "" {
		return KeySet{}, fmt.Errorf("scantoken: key file has `previous` but no `previous_valid_until`, " +
			"which would keep the retired key valid forever")
	}
	return ks, nil
}

// splitKeyValue parses `<key_id>:<secret>`, defaulting the id to DefaultKeyID
// when the value carries no id. A secret may itself contain ':' (base64 does
// not, but nothing stops an operator), so only the FIRST colon separates.
func splitKeyValue(v string) (id, secret string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", ""
	}
	if i, rest, ok := strings.Cut(v, ":"); ok && i != "" && strings.TrimSpace(rest) != "" {
		return strings.TrimSpace(i), strings.TrimSpace(rest)
	}
	return DefaultKeyID, v
}

// DefaultKeyID is the id assumed for a key file that names none. It is the id
// the very first installers minted with, so it must not change.
const DefaultKeyID = "k1"

// FormatKeySet renders a KeySet back to the file format. The installers use it
// so the writer and the reader can never drift — the shape exists in exactly
// one place in Go, and is mirrored once in Python.
func FormatKeySet(ks KeySet) string {
	var b strings.Builder
	b.WriteString(fieldCurrent + ": " + ks.Current.ID + ":" + string(ks.Current.Secret) + "\n")
	if ks.Previous != nil {
		b.WriteString(fieldPrevious + ": " + ks.Previous.ID + ":" + string(ks.Previous.Secret) + "\n")
		b.WriteString(fieldPreviousValidUntil + ": " + strconv.FormatInt(ks.PreviousValidUntil.Unix(), 10) + "\n")
	}
	return b.String()
}
