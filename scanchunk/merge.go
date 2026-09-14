package scanchunk

import (
	"sort"

	"github.com/AiKeyLabs/pkg/deepscan"
)

// ChunkFindings is one chunk's range plus what was found inside it. Offsets in
// Findings are ABSOLUTE into the piece — the producer adds the chunk origin
// before handing them over, because only the producer knows it.
type ChunkFindings struct {
	Range    Range
	Findings []deepscan.Finding
}

// MergeFindings collapses the duplicates the overlap creates and returns one
// list ordered by position.
//
// The identity is (entity_type, absolute start, absolute end). Why those three
// and not the whole finding: a credential inside the overlap region is found
// once per chunk, and the two copies can legitimately differ in confidence or
// rule_id (a different rule may win in a different context window) — keeping
// both would double-count one credential in the audit record. Two DIFFERENT
// entity types at the same offsets are kept apart on purpose: a string that is
// both a password and part of a DSN is two findings a reviewer needs to see.
//
// Engine is NOT part of the identity because callers pass one engine's findings
// at a time; bge and rules results are never merged (design §3.6: 跨引擎不去重).
func MergeFindings(chunks []ChunkFindings) []deepscan.Finding {
	type key struct {
		entityType string
		start, end int
	}
	seen := make(map[key]deepscan.Finding)
	order := make([]key, 0)
	for _, c := range chunks {
		for _, f := range c.Findings {
			k := key{f.EntityType, f.Start, f.End}
			prev, ok := seen[k]
			if !ok {
				seen[k] = f
				order = append(order, k)
				continue
			}
			// Same span, same type, seen twice: keep the higher-confidence copy so
			// a merge never lowers a finding's severity signal.
			if f.Confidence > prev.Confidence {
				seen[k] = f
			}
		}
	}
	out := make([]deepscan.Finding, 0, len(order))
	for _, k := range order {
		out = append(out, seen[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		if out[i].End != out[j].End {
			return out[i].End < out[j].End
		}
		return out[i].EntityType < out[j].EntityType
	})
	return out
}
