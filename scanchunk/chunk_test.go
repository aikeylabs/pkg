package scanchunk

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// TestChunker_ChunksWithinSmallLaneAndRuneBoundary: every chunk must fit the
// detector's small lane (16 KiB input cap) and must not cut a UTF-8 rune in
// half, and together the chunks must cover every byte from start to the end of
// the piece.
//
// The rune-boundary half is not cosmetic: a chunk ending mid-rune hands the
// detector invalid UTF-8, and the regex engine's behaviour on invalid UTF-8 is
// not something a compliance guarantee should rest on.
func TestChunker_ChunksWithinSmallLaneAndRuneBoundary(t *testing.T) {
	// CJK: 3 bytes per rune, so byte-cutting will land mid-rune constantly
	// unless the implementation backs off deliberately.
	text := strings.Repeat("客户资料需要保密不要外发。", 6000) // ~234 KiB
	for _, start := range []int{0, 1, 12345, len(text) - 10} {
		chunks := Chunks(text, start, SizeBytes, OverlapDefault)
		if len(chunks) == 0 {
			t.Fatalf("start=%d produced no chunks for a %d-byte piece", start, len(text))
		}
		covered := make([]bool, len(text))
		for i, c := range chunks {
			if c.End-c.Start > SizeBytes {
				t.Errorf("start=%d chunk %d is %d bytes, over the %d-byte small lane", start, i, c.End-c.Start, SizeBytes)
			}
			if c.Start < 0 || c.End > len(text) || c.Start >= c.End {
				t.Fatalf("start=%d chunk %d has impossible bounds %+v (text %d bytes)", start, i, c, len(text))
			}
			if !utf8.ValidString(text[c.Start:c.End]) {
				t.Errorf("start=%d chunk %d [%d,%d) is not valid UTF-8 — a rune was cut in half", start, i, c.Start, c.End)
			}
			for b := c.Start; b < c.End; b++ {
				covered[b] = true
			}
		}
		for b := chunks[0].Start; b < len(text); b++ {
			if !covered[b] {
				t.Fatalf("start=%d byte %d is not covered by any chunk", start, b)
				break
			}
		}
		if chunks[len(chunks)-1].End != len(text) {
			t.Errorf("start=%d last chunk ends at %d, not the end of the piece (%d)", start, chunks[len(chunks)-1].End, len(text))
		}
	}
}

// TestChunker_OverlapCatchesBoundaryEntity: an entity straddling a chunk
// boundary must appear WHOLE inside at least one chunk, or both chunks see half
// of it and neither reports it — a silent miss with no signal anywhere.
func TestChunker_OverlapCatchesBoundaryEntity(t *testing.T) {
	const secret = "postgres://svc_user:S3cr3tP4ssw0rd@10.2.3.4:5432/analytics"
	filler := strings.Repeat("a", SizeBytes-len(secret)/2)
	text := filler + secret + strings.Repeat("b", SizeBytes)

	chunks := Chunks(text, 0, SizeBytes, OverlapDefault)
	idx := strings.Index(text, secret)
	whole := false
	for _, c := range chunks {
		if c.Start <= idx && idx+len(secret) <= c.End {
			whole = true
			break
		}
	}
	if !whole {
		t.Fatalf("a %d-byte credential straddling the boundary at %d appears whole in NO chunk: %+v", len(secret), SizeBytes, chunks)
	}
}

// TestChunker_OverlapCoversLongestBoundedRule is the fence for the P0 §F8
// measurement that changed this package's constant.
//
// MEASURED 2026-09-11 (ai-compliance-detector/tools/rulespan): 9 built-in rules
// can match MORE than the 512-byte overlap the design originally specified, the
// longest being secret.connection-uri-password at 1939 bytes. With overlap=512 a
// 1939-byte DSN sitting across a chunk boundary is split so that neither chunk
// contains it whole — both miss it, and nothing reports a gap. User decision
// 2026-09-11: raise the overlap to 2048.
//
// If this test ever fails because someone lowered OverlapDefault, the question
// to ask is NOT "how do I make the test pass" — it is "has the rule set's longest
// bounded match changed?", and the way to answer it is to re-run
// `go run ./tools/rulespan internal/baselines/built-in` in ai-compliance-detector.
func TestChunker_OverlapCoversLongestBoundedRule(t *testing.T) {
	const longestBoundedRuleBytes = 1939 // secret.connection-uri-password, measured

	if OverlapDefault < longestBoundedRuleBytes {
		t.Fatalf("OverlapDefault is %d, below the measured longest bounded rule match (%d bytes). "+
			"A credential that long can straddle a chunk boundary and be missed by BOTH chunks.",
			OverlapDefault, longestBoundedRuleBytes)
	}

	// And prove it end to end, not just by comparing constants.
	entity := strings.Repeat("X", longestBoundedRuleBytes)
	// Place it so it starts just before a boundary and runs past it.
	head := strings.Repeat("a", SizeBytes-20)
	text := head + entity + strings.Repeat("b", SizeBytes)
	idx := len(head)

	for _, c := range Chunks(text, 0, SizeBytes, OverlapDefault) {
		if c.Start <= idx && idx+len(entity) <= c.End {
			return // found whole in one chunk
		}
	}
	t.Fatalf("a %d-byte entity starting at %d (boundary %d) appears whole in no chunk", len(entity), idx, SizeBytes)
}

// TestChunker_SinglePieceNoChunks: a piece the fast layer already covered in
// full produces no rule work at all. Without this the async lane re-scans every
// short prompt for nothing (design §3.6 / R-scan-node-deepscan-16.S3).
func TestChunker_SinglePieceNoChunks(t *testing.T) {
	text := strings.Repeat("a", 8000)
	if got := Chunks(text, len(text), SizeBytes, OverlapDefault); len(got) != 0 {
		t.Errorf("start at end of piece must yield no chunks, got %+v", got)
	}
	if got := Chunks("", 0, SizeBytes, OverlapDefault); len(got) != 0 {
		t.Errorf("empty text must yield no chunks, got %+v", got)
	}
}

// TestChunker_MergeFindingsDeduplicatesOverlapRegion: the overlap means a
// credential sitting in it is found TWICE, once per chunk. Merging on
// (entity_type, absolute start, absolute end) collapses those, while two genuinely
// different entity types at the same offsets stay separate.
func TestChunker_MergeFindingsDeduplicatesOverlapRegion(t *testing.T) {
	dup := deepscan.Finding{Engine: "rules", EntityType: "CREDENTIAL_DSN", Category: "secret", Start: 16300, End: 16360, Severity: "high", Confidence: 90}
	sameSpanOtherType := dup
	sameSpanOtherType.EntityType = "CREDENTIAL_PASSWORD"
	other := dup
	other.Start, other.End = 40000, 40011

	got := MergeFindings([]ChunkFindings{
		{Range: Range{Start: 0, End: 16384}, Findings: []deepscan.Finding{dup}},
		{Range: Range{Start: 14336, End: 30720}, Findings: []deepscan.Finding{dup, sameSpanOtherType}},
		{Range: Range{Start: 30720, End: 47104}, Findings: []deepscan.Finding{other}},
	})
	if len(got) != 3 {
		t.Fatalf("want 3 merged findings (dup collapsed, other type kept, third kept), got %d: %+v", len(got), got)
	}
	seen := map[string]int{}
	for _, f := range got {
		seen[f.EntityType]++
	}
	if seen["CREDENTIAL_DSN"] != 2 || seen["CREDENTIAL_PASSWORD"] != 1 {
		t.Errorf("merge collapsed the wrong things: %v", seen)
	}
	// Output must be ordered by offset so the audit event reads top to bottom.
	for i := 1; i < len(got); i++ {
		if got[i-1].Start > got[i].Start {
			t.Errorf("findings are not ordered by offset: %+v", got)
			break
		}
	}
}
