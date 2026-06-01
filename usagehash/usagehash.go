// Package usagehash is the SINGLE SOURCE OF TRUTH for a usage event's
// content hash — the financial-grade tamper/corruption fingerprint over a
// usage event's metering fields (design doc 阶段6-企业定制/20260530-财务对账级
// 用量审计, stage C, §5.7).
//
// Why a shared module (not duplicated in proxy + collector): the proxy STAMPS
// the hash and the collector RECOMPUTES it to validate. If the two sides
// computed the bytes even slightly differently, healthy events would be
// quarantined (false positive) — worse than the silent-zero bug C exists to
// fix. Both repos import THIS package (via go.mod replace, like pkg/aikeytime),
// so the marshaled bytes and the hash are identical by construction.
//
// Threat addressed: a metering field (token count) silently corrupting to 0 in
// transit/parse and being billed as a real 0. The client hashes the correct
// values; if a value corrupts before the server recomputes, the server's hash
// differs → the event is quarantined + alerted instead of silently mis-billed.
package usagehash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Scheme is the hash-scheme version. It is embedded in the wire format
// ("sha256:<Scheme>:<hex>") so a validator can tell whether it understands the
// field set that produced a given hash. BUMP THIS whenever the Input field set
// or its normalization changes — an old validator then sees an unknown scheme
// and SKIPS validation (conserve: accept, never false-quarantine) rather than
// recomputing with the wrong field set. The server-first deploy order means a
// newer client can reach an older server, so forward-skip is mandatory.
const Scheme = "1"

const prefix = "sha256:" + Scheme + ":"

// Input is the canonical metering tuple that gets hashed. ONLY billed/metering
// fields plus the context that gives them meaning (model + provider) — derived
// audit artifacts (request_count, timestamps, ids) are intentionally excluded;
// they don't affect the financial figure C protects.
//
// Field declaration order IS the JSON key order (encoding/json emits struct
// fields in declaration order), which makes Marshal deterministic. There are no
// `omitempty` tags ON PURPOSE: a zero must serialize as `0`, not vanish — that
// is exactly the "silently became 0" case we must be able to detect. Both
// client and server build this struct, deref-or-zero their pointer fields, and
// get byte-identical JSON.
type Input struct {
	InputTokens              int64  `json:"input_tokens"`
	OutputTokens             int64  `json:"output_tokens"`
	TotalTokens              int64  `json:"total_tokens"`
	CacheReadInputTokens     int64  `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64  `json:"cache_creation_input_tokens"`
	Model                    string `json:"model"`
	ProviderCode             string `json:"provider_code"`
}

// Compute returns the wire-format content hash "sha256:<Scheme>:<hex>" for the
// given metering tuple. Deterministic and identical on any platform/Go build.
func Compute(in Input) string {
	b, _ := json.Marshal(in) // struct has no unmarshalable types → err always nil
	sum := sha256.Sum256(b)
	return prefix + hex.EncodeToString(sum[:])
}

// SchemeKnown reports whether hash was produced by a scheme THIS package can
// validate. An empty hash (older client that doesn't stamp one) or a different
// scheme version returns false — the caller then skips validation and accepts
// the event normally (conserve), never quarantining on uncertainty.
func SchemeKnown(hash string) bool {
	return strings.HasPrefix(hash, prefix)
}

// Verify recomputes the hash from in and reports whether it matches the
// client-stamped hash. PRECONDITION: SchemeKnown(stamped) is true — callers
// must gate on that first so an unknown/empty scheme is skipped, not failed.
func Verify(in Input, stamped string) bool {
	return Compute(in) == stamped
}
