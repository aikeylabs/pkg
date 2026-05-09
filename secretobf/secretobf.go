// Package secretobf returns AES-256-GCM-obfuscated string constants whose
// ciphertext and key are injected at release time via -ldflags "-X" so that
// shipped binaries do not contain cleartext secrets at fixed offsets.
//
// Why obfuscation, not encryption: the decryption key ships in the same
// binary as the ciphertext, so a determined reverse-engineer can recover
// the cleartext. The goal is only to defeat trivial discovery (`grep`,
// `strings`) on shipped artifacts. Real protection of long-lived secrets
// must come from periodic rotation, and from B2B customers bringing their
// own SMTP credentials at install time (the env override path stays open).
//
// Dev / non-release builds leave the package vars empty, so SMTPPassword
// returns "" and callers fall through to env override or disable email.
//
// Why this lives in pkg/ instead of any single service's internal/:
// three editions (Personal / Trial / Production) all need the same
// obfuscated SMTP fallback so activation emails work out-of-the-box.
// Keeping a single source of truth here prevents the three editions
// drifting on cipher format or var-name contract that release.sh -X
// flags depend on.
package secretobf

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

// Populated by release.sh via:
//
//	-ldflags "-X 'github.com/AiKeyLabs/pkg/secretobf.smtpCipherB64=...' \
//	          -X 'github.com/AiKeyLabs/pkg/secretobf.keyB64=...'"
//
// Both must be left as bare `var` declarations (no initializer) so the
// linker's -X flag can override them.
var (
	smtpCipherB64 string
	keyB64        string
)

// SMTPPassword returns the SMTP authentication password injected at release
// time, or "" when no injection happened (dev builds, or release without
// the secret configured). Callers should treat "" as "no built-in default"
// and rely on env / yaml override.
func SMTPPassword() string {
	if smtpCipherB64 == "" || keyB64 == "" {
		return ""
	}
	pt, err := decryptB64(smtpCipherB64, keyB64)
	if err != nil {
		return ""
	}
	return pt
}

// decryptB64 expects key and ciphertext (nonce-prefixed) both base64-encoded.
// Nonce prefix layout matches workflow/CD/publish/secretobf-encrypt.
func decryptB64(cipherB64, keyB64Str string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64Str)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", errors.New("secretobf: key must be 32 bytes (AES-256)")
	}
	blob, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(blob) < gcm.NonceSize() {
		return "", errors.New("secretobf: ciphertext too short for nonce")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}
