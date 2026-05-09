package secretobf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// In dev / unit-test builds, the linker has not injected anything, so
// SMTPPassword must be the empty string. This guards against a future
// edit accidentally putting a hardcoded fallback back into the package.
func TestSMTPPasswordEmptyByDefault(t *testing.T) {
	if got := SMTPPassword(); got != "" {
		t.Fatalf("expected empty SMTP password in dev build, got %q", got)
	}
}

func TestDecryptRoundTrip(t *testing.T) {
	key := mustRandomKey(t)
	plain := "test-smtp-secret-x9k2"
	cipherB64 := mustEncrypt(t, key, plain)

	got, err := decryptB64(cipherB64, base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("decryptB64 failed: %v", err)
	}
	if got != plain {
		t.Fatalf("decryptB64 = %q, want %q", got, plain)
	}
}

func TestDecryptRejectsBadKeyLength(t *testing.T) {
	if _, err := decryptB64("AAAA", base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("expected error for invalid key length")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := mustRandomKey(t)
	cipherB64 := mustEncrypt(t, key, "plain")
	raw, _ := base64.StdEncoding.DecodeString(cipherB64)
	raw[len(raw)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(raw)
	if _, err := decryptB64(tampered, base64.StdEncoding.EncodeToString(key)); err == nil {
		t.Fatal("expected GCM auth error for tampered ciphertext")
	}
}

func TestSMTPPasswordWithInjection(t *testing.T) {
	// Simulate ldflags injection by setting package vars manually.
	key := mustRandomKey(t)
	plain := "live-injected-pwd"
	cipherB64 := mustEncrypt(t, key, plain)

	prevCipher, prevKey := smtpCipherB64, keyB64
	t.Cleanup(func() { smtpCipherB64, keyB64 = prevCipher, prevKey })
	smtpCipherB64 = cipherB64
	keyB64 = base64.StdEncoding.EncodeToString(key)

	if got := SMTPPassword(); got != plain {
		t.Fatalf("SMTPPassword() = %q, want %q", got, plain)
	}
}

func mustRandomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func mustEncrypt(t *testing.T, key []byte, plain string) string {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct)
}
