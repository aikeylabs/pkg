// Package scanchunk splits a content piece into the fixed-size, overlapping
// ranges the asynchronous rule lane scans, and merges what comes back.
//
// ONE implementation, on purpose (design §3.6): the proxy computes the ranges
// and ships them inside the task frame, and the receiver — Go on the local
// executor, PYTHON on a scan node — only slices what it was told to slice. A
// second chunker on the Python side would be a second thing that can drift, and
// the symptom of that drift is a missed credential, not a crash.
package scanchunk

import (
	"unicode/utf8"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// SizeBytes is the maximum bytes in one chunk. It matches the detector's
// small-lane input cap (ai-compliance-detector engine.go) — a chunk larger than
// this is silently truncated by the detector, which is the blind spot this whole
// lane exists to close.
const SizeBytes = 16 * 1024

// OverlapDefault is how much consecutive chunks overlap, so an entity sitting on
// a boundary still appears WHOLE in at least one chunk.
//
// 🔴 2048, NOT 512. MEASURED 2026-09-11 with ai-compliance-detector's
// tools/rulespan, which computes each built-in rule's maximum possible match
// length from its parsed syntax tree: 9 rules can match more than 512 bytes, the
// longest being secret.connection-uri-password (CREDENTIAL_DSN) at 1939 bytes.
// With a 512-byte overlap such a credential can span the boundary so that
// NEITHER chunk contains it whole — both miss it, and nothing anywhere reports a
// gap. User decision 2026-09-11 after the measurement was presented.
//
// 22 further rules have an UNBOUNDED maximum match (secret.private-key — a PEM
// key — secret.jwt, secret.generic-api-key, …). No fixed overlap can cover those;
// they are a registered known limitation (design §10 R15), not something this
// constant should be inflated to chase.
//
// Before changing this, re-run: go run ./tools/rulespan internal/baselines/built-in
// Fence: TestChunker_OverlapCoversLongestBoundedRule.
const OverlapDefault = 2048

// Range is a half-open [Start, End) byte interval into the piece.
type Range = deepscan.Range

// Chunks splits text[start:] into ranges of at most size bytes, overlapping by
// overlap bytes, with every boundary pulled back to a UTF-8 rune boundary.
//
// Returns nil when there is nothing left to scan (start at or past the end, or
// empty text) — a piece the fast layer already covered in full must produce no
// rule work at all.
func Chunks(text string, start, size, overlap int) []Range {
	if size <= 0 {
		size = SizeBytes
	}
	if overlap < 0 {
		overlap = 0
	}
	if overlap >= size {
		// An overlap at or above the chunk size would never advance.
		overlap = size / 2
	}
	if start < 0 {
		start = 0
	}
	if start >= len(text) {
		return nil
	}
	// Pull the very first boundary back to a rune start too: `start` is derived
	// from head_bytes minus the overlap and has no reason to be rune-aligned.
	start = runeStartAtOrBefore(text, start)

	var out []Range
	pos := start
	for pos < len(text) {
		end := pos + size
		if end >= len(text) {
			out = append(out, Range{Start: pos, End: len(text)})
			break
		}
		end = runeStartAtOrBefore(text, end)
		if end <= pos {
			// A single rune longer than the whole chunk cannot happen in UTF-8
			// (max 4 bytes), but refusing to emit a non-advancing chunk keeps this
			// loop structurally unable to spin.
			end = pos + size
		}
		out = append(out, Range{Start: pos, End: end})
		next := end - overlap
		if next <= pos {
			next = end
		}
		pos = runeStartAtOrBefore(text, next)
	}
	return out
}

// runeStartAtOrBefore returns the largest index <= i that begins a UTF-8 rune.
func runeStartAtOrBefore(s string, i int) int {
	if i <= 0 {
		return 0
	}
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}
