// Package maskrestore owns the placeholder RENUMBERING and RESTORE algorithm
// for compliance masking: given the original text, the detector's masked text
// and the per-entity restorable metadata, it rewrites each numberless token
// into a request-scoped numbered label (`{{ADDR_1}}`), remembers what each
// label stood for, and later swaps those labels back to the original text.
//
// WHY this is a shared module and not a package inside aikey-proxy (2026-08-31,
// 方案「脱敏 MCP 服务」DEC-redaction-mcp-21): the algorithm used to live in
// `aikey-proxy/internal/proxy/filter_restore.go`, which Go makes un-importable
// from anywhere else. The moment a second product needed the same behaviour the
// only options were "copy it" or "move it". Copying loses: the four defects this
// file's comments record (family 串味, substring double-count, tolerant-restore
// drift, duplicate-token silent mis-restore) were each found once, and a copy
// would have to find them again independently.
//
// 🔴 BUSINESS-BLIND BY CONTRACT. This package must never learn what an entity
// is. It knows "token T stands for these byte spans of the original" and
// nothing else — no `ADDR`, no "address", no entity table. Callers own the
// business meaning; this package owns only the string surgery. A fence in
// maskrestore_test.go asserts no entity vocabulary appears in this file.
//
// 🚫 PRIVACY INVARIANT (B3 拍板 2026-08-06): the label→original mapping this
// package builds is CALLER-SCOPED memory. This package never persists, uploads
// or logs it — it has no logger and no IO on purpose. It reports degrade
// conditions as DATA (Report) and lets the caller decide how to surface them,
// which also keeps the "counts only, never content" rule mechanically true here.
package maskrestore

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Restorable describes ONE placeholder token the detector substituted into the
// masked text. Occurrences of Token appear in the masked text in the same order
// as Spans (both ascending by original offset).
//
// 🔴 Deliberately NOT reusing pipewire.Restorable even though the shapes match:
// pipewire owns the cross-process WIRE format and is versioned with the pipe
// protocol; this package owns an ALGORITHM that must not be dragged along by a
// protocol bump. Callers convert at the boundary — one struct literal.
type Restorable struct {
	// Token is the literal placeholder string present in the masked text, one
	// occurrence per span.
	Token string
	// NumberedPrefix/NumberedSuffix compose the request-scoped numbered label
	// substituted for the k-th token occurrence: prefix + N + suffix. Owned by
	// the caller's mask policy (single source of truth with it).
	NumberedPrefix string
	NumberedSuffix string
	// Spans are [start,end) BYTE offsets into the ORIGINAL text, ascending and
	// non-overlapping.
	Spans [][2]int
}

// Placeholder syntax constants — the ONLY place the shipped `{{CODE_N}}` shape
// is spelled out on the consuming side. The detector's planner.NewLabel owns
// the same knowledge on its side; the wire carries prefix/suffix explicitly so
// an operator's custom label keeps working through the exact-match path below.
var (
	// CanonicalLabelRe recognizes a label as belonging to the shipped
	// `{{CODE_N}}` family, which is what makes it eligible for the tolerant
	// matcher. Custom operator labels (e.g. `[ADDR#1-X]`) simply do not match
	// and fall back to byte-exact restore.
	CanonicalLabelRe = regexp.MustCompile(`^\{\{([A-Za-z][A-Za-z0-9]*)_(\d{1,9})\}\}$`)

	// TolerantPlaceholderRe is the L3 matcher (方案 20260808 §3.2 L3). It accepts
	// the cosmetic drift LLMs actually introduce, each variant bounded so a
	// streaming holdback window stays finite:
	//   - single braces:            {ADDR_1}
	//   - one space in each slot:   {{ ADDR _ 1 }}
	//   - any case:                 {{addr_1}} / {{Addr_1}}
	//   - quotes INSIDE the braces: {{"ADDR_1"}} (outside-the-braces quoting
	//     needs no support — the placeholder itself still matches).
	// It deliberately does NOT accept an arbitrary run of whitespace: an
	// unbounded variant would make a streaming holdback window unbounded too.
	// Matching is only the FIRST half of restore — the captured code+number must
	// still resolve in the caller-scoped table or the match is left untouched.
	TolerantPlaceholderRe = regexp.MustCompile(
		`\{\{?[ \t]?["'` + "`" + `\x{201C}\x{2018}]?[ \t]?([A-Za-z][A-Za-z0-9]*)[ \t]?_[ \t]?([0-9]{1,9})[ \t]?["'` + "`" + `\x{201D}\x{2019}]?[ \t]?\}?\}`)

	// TolerantPlaceholderPrefixRe is TolerantPlaceholderRe with every element
	// made optional and the whole thing anchored: it matches exactly the set of
	// PREFIXES of a tolerant placeholder. Used by Holdback to decide whether a
	// trailing `{…` may still grow into one. Derived from the pattern above —
	// keep the two in sync.
	TolerantPlaceholderPrefixRe = regexp.MustCompile(
		`^\{\{?[ \t]?["'` + "`" + `\x{201C}\x{2018}]?[ \t]?(?:[A-Za-z][A-Za-z0-9]*)?[ \t]?(?:_[ \t]?[0-9]{0,9}[ \t]?["'` + "`" + `\x{201D}\x{2019}]?[ \t]?\}?)?$`)
)

// TolerantHoldbackSlack is how many bytes a tolerant variant may exceed the
// canonical label it stands for: 5 optional single spaces + 2 quote characters
// (≤3 bytes each for the curly Unicode ones) = 11, rounded up to 16 for margin.
// A streaming holdback window is widened by this so a placeholder split across
// frames is still re-assembled when the model added spaces/quotes.
const TolerantHoldbackSlack = 16

// Table is the caller-scoped placeholder→original state. Built on the request
// leg, consumed on the response leg.
//
// Concurrency: callers are expected to finish all writes (Renumber/Add) before
// any concurrent read (Restore/Holdback). Only the restore bookkeeping — the
// one thing a second response-side consumer could touch concurrently — is
// locked.
type Table struct {
	// Entries maps every numbered label (ALL shapes) to its original text.
	Entries map[string]string
	// Canonical maps the normalized id of a shipped `{{CODE_N}}` label
	// (UPPERCASE code + "_" + number without leading zeros) to its original.
	// This — not a regex over the response — is the authority the L3 tolerant
	// matcher resolves against: a miss means "leave verbatim" (不变量 §5.2).
	Canonical map[string]string
	// Keys lists labels in allocation order (used for prefix holdback).
	Keys []string
	// NextN is the next label number (starts at 1). 🔴 This counter is the ONLY
	// state behind numbering; a second counter anywhere is a second numbering
	// path.
	NextN int

	// OnIssue, if set, is called once per label the table takes ownership of.
	// OnFirstRestore, if set, is called the first time a given label id is
	// restored in this table's lifetime (repeats are suppressed so a caller
	// counting fidelity cannot exceed 100%).
	//
	// 🔴 These exist so this package stays IO-free: fidelity accounting is the
	// caller's concern, and giving it a hook is what keeps the counters out of
	// here. When OnFirstRestore is nil the dedup map is never allocated — the
	// no-observer path pays nothing.
	OnIssue        func(label string)
	OnFirstRestore func(id string)

	// custom holds labels that are NOT of the shipped shape (operator override).
	// They get byte-exact restore only: this package cannot invent a tolerant
	// grammar for a string it does not own.
	custom      []string
	restoredIDs map[string]bool
	replacer    *strings.Replacer // custom-label replacer, built lazily
	mu          sync.Mutex        // guards restoredIDs only
	maxKeyLen   int               // longest label byte length (holdback window base)
}

// NewTable returns an empty table whose first allocated label is numbered 1.
func NewTable() *Table {
	return &Table{Entries: make(map[string]string), NextN: 1}
}

// Add records one label→original pair.
func (t *Table) Add(label, original string) {
	t.Entries[label] = original
	t.Keys = append(t.Keys, label)
	if len(label) > t.maxKeyLen {
		t.maxKeyLen = len(label)
	}
	if m := CanonicalLabelRe.FindStringSubmatch(label); m != nil {
		if t.Canonical == nil {
			t.Canonical = make(map[string]string)
		}
		t.Canonical[CanonicalID(m[1], m[2])] = original
	} else {
		t.custom = append(t.custom, label)
	}
	if t.OnIssue != nil {
		t.OnIssue(label)
	}
}

// CanonicalID normalizes a code+number pair into the lookup key: codes are
// case-folded (the model may lowercase them) and the number loses leading zeros
// (`{{ADDR_01}}` and `{{ADDR_1}}` are the same placeholder). Normalization is
// EXACT, never fuzzy — it maps two spellings of the SAME id together and never
// bridges two different ids.
func CanonicalID(code, number string) string {
	n := strings.TrimLeft(number, "0")
	if n == "" {
		n = "0"
	}
	return strings.ToUpper(code) + "_" + n
}

// rep returns the custom-label→original replacer (built once; the write leg is
// done mutating by the time the read leg calls this).
func (t *Table) rep() *strings.Replacer {
	if t.replacer == nil {
		pairs := make([]string, 0, len(t.custom)*2)
		for _, k := range t.custom {
			pairs = append(pairs, k, t.Entries[k])
		}
		t.replacer = strings.NewReplacer(pairs...)
	}
	return t.replacer
}

// Restore swaps placeholders in s back to their originals.
//
// Two passes, in this order and for this reason:
//  1. the L3 tolerant pass over the shipped `{{CODE_N}}` family. It also covers
//     the byte-exact spelling (a subset of the tolerant pattern), and — because
//     it never re-scans the text it just inserted — an original that happens to
//     contain placeholder-looking text can never be restored a second time.
//  2. the byte-exact replacer for operator-custom labels, skipped entirely in
//     the shipped configuration (no custom labels → single pass).
func (t *Table) Restore(s string) string {
	if len(t.Keys) == 0 || s == "" {
		return s
	}
	out := s
	if len(t.Canonical) > 0 && strings.IndexByte(out, '{') >= 0 {
		out = t.restoreCanonical(out)
	}
	if len(t.custom) > 0 {
		for _, k := range t.custom {
			if strings.Contains(out, k) {
				t.markRestored(k)
			}
		}
		out = t.rep().Replace(out)
	}
	return out
}

// restoreCanonical is the L3 fault-tolerant half. Every regex hit is resolved
// through t.Canonical; a MISS is copied through byte-for-byte.
//
// 🔴 不变量 §5.2 lives here: an unknown id is never mapped to "the nearest"
// entry, never to the only entry, never to anything. The user sees the
// placeholder — 失败要显眼 — instead of another person's address.
func (t *Table) restoreCanonical(s string) string {
	locs := TolerantPlaceholderRe.FindAllStringSubmatchIndex(s, -1)
	if len(locs) == 0 {
		return s
	}
	var sb strings.Builder
	last := 0
	for _, m := range locs {
		id := CanonicalID(s[m[2]:m[3]], s[m[4]:m[5]])
		orig, ok := t.Canonical[id]
		if !ok {
			continue // unknown id → leave the bytes exactly as the model wrote them
		}
		sb.WriteString(s[last:m[0]])
		sb.WriteString(orig)
		last = m[1]
		t.markRestored(id)
	}
	if last == 0 {
		return s // nothing resolved — hand back the original string, no copy
	}
	sb.WriteString(s[last:])
	return sb.String()
}

// markRestored records the first successful restore of one placeholder id and
// notifies the observer exactly once for it.
func (t *Table) markRestored(id string) {
	if t.OnFirstRestore == nil {
		return
	}
	t.mu.Lock()
	if t.restoredIDs == nil {
		t.restoredIDs = make(map[string]bool)
	}
	if t.restoredIDs[id] {
		t.mu.Unlock()
		return
	}
	t.restoredIDs[id] = true
	t.mu.Unlock()
	t.OnFirstRestore(id)
}

// Holdback returns the trailing bytes a streaming restorer must withhold until
// the next frame because they may be the beginning of a placeholder that got
// split across frames. Two independent detectors, longest answer wins:
//
//   - exact: the longest proper suffix of s that is a strict prefix of a known
//     label (covers custom labels and the byte-exact shipped spelling);
//   - tolerant: an unterminated `{`-run that could still grow into a tolerant
//     `{{CODE_N}}` variant (covers the spaced/quoted/single-brace forms, which
//     are longer than the label itself — hence TolerantHoldbackSlack).
//
// Both are bounded by the window, so withholding can never stall a stream: the
// held bytes are prepended to the next text frame and flushed before any
// boundary frame / EOF regardless.
func (t *Table) Holdback(s string) string {
	hold := t.holdbackExact(s)
	if len(t.Canonical) > 0 {
		if h := t.holdbackTolerant(s); len(h) > len(hold) {
			hold = h
		}
	}
	return hold
}

func (t *Table) holdbackExact(s string) string {
	maxHold := t.maxKeyLen - 1
	if maxHold > len(s) {
		maxHold = len(s)
	}
	for l := maxHold; l > 0; l-- {
		suf := s[len(s)-l:]
		for _, k := range t.Keys {
			if len(k) > l && strings.HasPrefix(k, suf) {
				return suf
			}
		}
	}
	return ""
}

// holdbackTolerant withholds a trailing `{…` run that is still a VIABLE PREFIX
// of a tolerant placeholder — i.e. the model may be halfway through writing one
// and the rest arrives in the next frame.
//
// Viability is decided by TolerantPlaceholderPrefixRe: the tolerant grammar
// with every trailing element made optional, anchored, so it accepts exactly
// "some prefix of a tolerant placeholder" and nothing else. That precision is
// the point — a character-class heuristic would withhold the `{` of every JSON
// or code block a model streams back, turning byte-identical passthrough into a
// re-encode for a whole class of ordinary answers.
func (t *Table) holdbackTolerant(s string) string {
	window := t.maxKeyLen + TolerantHoldbackSlack - 1
	if window > len(s) {
		window = len(s)
	}
	tail := s[len(s)-window:]
	// EARLIEST viable `{` in the window, not the last one: `{{ad` must be held
	// whole — starting at the second brace would emit the first one and the
	// placeholder could never be re-assembled on the next frame.
	for i := 0; i < len(tail); i++ {
		if tail[i] != '{' {
			continue
		}
		if TolerantPlaceholderPrefixRe.MatchString(tail[i:]) {
			return tail[i:]
		}
	}
	return ""
}

// scanTokenOccurrences locates the occurrences of EVERY token in one left→right
// pass over s, longest-match-wins, and returns them keyed by token.
//
// WHY not one independent strings.Index loop per token (the pre-P2 shape): if
// token A is a substring of token B, A's independent scan also lands inside
// every B occurrence. Those phantom hits are not harmless — when the phantom
// count happens to equal A's real span count, the alignment check passes and
// the renumberer writes A's label INTO the middle of a B token, corrupting B
// and mapping one of A's originals onto text that was never A's. Silent
// mis-restore, exactly what 不变量 §5.2 forbids.
//
// The SHIPPED short codes cannot be substrings of one another (`{{`/`}}`
// delimiters make `{{CARD}}` ⊄ `{{IDCARD}}`), so the live risk surface is
// operator-authored labels, which may be any string. The detector's
// planner.ValidateLabels rejects colliding tables at load time; this scan is
// the consuming half of that defense, because the consumer must stay correct
// against ANY producer it is handed (older build, skewed protocol version)
// rather than trusting the producer's validation.
//
// Longest-match-wins is what makes the two halves agree: whatever the producer
// actually substituted is the longest token that fits at that position, since a
// shorter token could only match there by living inside the longer one.
func scanTokenOccurrences(s string, tokens []string) map[string][]int {
	if len(tokens) == 0 || s == "" {
		return nil
	}
	// Order longest-first so the first match at a position is the longest one.
	ordered := make([]string, len(tokens))
	copy(ordered, tokens)
	sort.SliceStable(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	// First-byte filter: shipped tokens all start with '{', so ordinary prose
	// skips the inner loop entirely.
	var firstBytes [256]bool
	for _, t := range ordered {
		firstBytes[t[0]] = true
	}
	out := make(map[string][]int, len(tokens))
	for i := 0; i < len(s); {
		if !firstBytes[s[i]] {
			i++
			continue
		}
		matched := ""
		for _, t := range ordered {
			if strings.HasPrefix(s[i:], t) {
				matched = t
				break
			}
		}
		if matched == "" {
			i++
			continue
		}
		out[matched] = append(out[matched], i)
		i += len(matched)
	}
	return out
}

// AlignMismatch reports one restorable family whose token occurrences could not
// be aligned with its spans. Counts only — never content.
type AlignMismatch struct {
	TokenOccurrences int
	Spans            int
	SpansValid       bool
}

// Report carries everything a caller needs to surface a degrade condition.
//
// 🔴 WHY data instead of a logger: this package must stay IO-free (see the
// package doc). Handing back counts also makes the "counts only, never content"
// privacy rule structurally true here — there is no field that could hold text.
type Report struct {
	// RestorablesIn / Usable / DuplicateTokenDropped describe the wire-contract
	// filter: one token ⇒ exactly one Restorable.
	RestorablesIn         int
	Usable                int
	DuplicateTokenDropped int
	// AlignMismatches lists families dropped because occurrences ≠ spans.
	AlignMismatches []AlignMismatch
	// Overlap is set when merged occurrences overlapped and the WHOLE piece kept
	// its numberless mask. Occurrences is the merged count at that point.
	Overlap     bool
	Occurrences int
}

// Renumber rewrites each restorable token occurrence in masked into a
// caller-scoped numbered label and records label→original (sliced from head —
// the exact bytes the spans refer to) into t.
//
// Validation is all-or-nothing PER RESTORABLE and fails toward the safe side:
// on any inconsistency (bad spans, token/span count mismatch) that restorable
// keeps its numberless token — the sensitive text stays masked, only the
// response-side restore is lost.
//
// It also returns spanLabels: the [start,end) span of each masked original in
// HEAD → the label that span went out as. This is the ONLY output of the
// numbering; nothing else may derive a label.
//
// 🔴 The map is deliberately keyed on the span and NOT on the label: a label is
// unique per table, but this map is consumed per piece, and building the
// reverse direction would invite a "look up a finding by its label" call site —
// exactly the ambiguity the three degrade paths below exist to avoid. A span
// with no entry means "this text was not substituted by a placeholder of its
// own", which is a meaningful answer, not a lookup failure.
//
// Privacy: keys are integer offsets and values are synthetic placeholder names.
// No original text is in the returned map (the label→original table stays in t,
// caller-scoped memory only, never persisted/uploaded/logged).
func Renumber(head, masked string, restorables []Restorable, t *Table) (string, map[[2]int]string, Report) {
	rep := Report{RestorablesIn: len(restorables)}
	usable, tokens := usableRestorables(restorables, &rep)
	if len(usable) == 0 {
		// Degrade path 3 (two families share one token) lands here when it drops
		// everything: no labels are allocated, so no span gets one. The caller
		// backfills nothing and the finding records "not placeholder-substituted",
		// which is exactly what happened.
		return masked, nil, rep
	}
	positionsByToken := scanTokenOccurrences(masked, tokens)

	type occ struct {
		pos      int
		tokenLen int
		prefix   string
		suffix   string
		orig     string
		span     [2]int
	}
	var occs []occ
	for _, r := range usable {
		valid := true
		prevEnd := 0
		for _, sp := range r.Spans {
			if sp[0] < prevEnd || sp[0] >= sp[1] || sp[1] > len(head) {
				valid = false
				break
			}
			prevEnd = sp[1]
		}
		positions := positionsByToken[r.Token]
		if !valid || len(positions) != len(r.Spans) {
			// Count mismatch: e.g. the user's own text contains the literal token,
			// or spans drifted. Alignment is ambiguous → keep the numberless mask.
			rep.AlignMismatches = append(rep.AlignMismatches, AlignMismatch{
				TokenOccurrences: len(positions), Spans: len(r.Spans), SpansValid: valid,
			})
			continue
		}
		for i, pos := range positions {
			// prefix/suffix come from THIS restorable, not from a scan keyed on the
			// token (the pre-P2 shape): with several families in one request a
			// linear "first restorable whose Token matches" lookup hands family B
			// family A's numbered form (串味).
			occs = append(occs, occ{
				pos: pos, tokenLen: len(r.Token),
				prefix: r.NumberedPrefix, suffix: r.NumberedSuffix,
				orig: head[r.Spans[i][0]:r.Spans[i][1]],
				span: r.Spans[i],
			})
		}
	}
	if len(occs) == 0 {
		// Degrade path 1 (token occurrences ≠ span count) dropped every family.
		return masked, nil, rep
	}
	// Numbered in text order — the numbers the user's forwarded text shows must
	// run 1,2,3… left to right regardless of which family each one belongs to.
	sort.SliceStable(occs, func(i, j int) bool { return occs[i].pos < occs[j].pos })
	// Guard: merged occurrences must not overlap. scanTokenOccurrences already
	// guarantees this (one pass, cursor advanced past each match); kept as the
	// cheap invariant assertion for the day someone changes the scanner.
	for i := 1; i < len(occs); i++ {
		if occs[i].pos < occs[i-1].pos+occs[i-1].tokenLen {
			// Degrade path 2 (merged occurrences overlap): the whole piece keeps the
			// numberless mask, so no span has a label to report.
			rep.Overlap = true
			rep.Occurrences = len(occs)
			return masked, nil, rep
		}
	}
	// Rebuild left→right, allocating caller-scoped numbers.
	//
	// 🔴 This is the ONE place in the entire system that composes a numbered
	// label. Everything downstream — the response-leg restore table, the health
	// counters, and any wire label recorded on an event — reads the labels
	// produced HERE. Do not add a second composer anywhere.
	var sb strings.Builder
	sb.Grow(len(masked) + len(occs)*4)
	spanLabels := make(map[[2]int]string, len(occs))
	last := 0
	for _, o := range occs {
		label := o.prefix + strconv.Itoa(t.NextN) + o.suffix
		t.NextN++
		sb.WriteString(masked[last:o.pos])
		sb.WriteString(label)
		t.Add(label, o.orig)
		spanLabels[o.span] = label
		last = o.pos + o.tokenLen
	}
	sb.WriteString(masked[last:])
	return sb.String(), spanLabels, rep
}

// usableRestorables filters the producer's metadata down to the families the
// renumberer may act on, and returns their tokens for the occurrence scan.
//
// It enforces the wire invariant "one token ⇒ exactly one Restorable" (alias
// entities such as CN_PHONE/PHONE share a placeholder, so the producer MERGES
// their spans into a single Restorable before sending). If that ever breaks —
// an older producer, a protocol skew, a regression in the grouping — the
// consequence downstream is silent and severe: scanTokenOccurrences reports the
// SAME occurrence list to both entries, so every occurrence is consumed twice
// and the second family's numbers are written over the first family's spans,
// handing the user someone else's original text on the response leg.
//
// 处置 = drop EVERY family sharing the duplicated token, keep the numberless
// mask, report it. WHY not fail the request (fail-loud in the hard sense): the
// sensitive text is ALREADY masked at this point, so dropping restore costs the
// user a placeholder they must read past — while failing the request would
// break traffic over a producer-metadata defect, violating the fail-open
// invariant that governs the whole filter chain. WHY not keep the first and
// drop the rest: with two span lists and one occurrence list, "which spans
// belong to which occurrences" is exactly the ambiguity that makes the result
// wrong; there is no safe pick.
func usableRestorables(restorables []Restorable, rep *Report) (usable []Restorable, tokens []string) {
	seen := make(map[string]int, len(restorables))
	for _, r := range restorables {
		if !restorableWellFormed(r) {
			continue
		}
		seen[r.Token]++
	}
	usable = make([]Restorable, 0, len(restorables))
	tokens = make([]string, 0, len(restorables))
	for _, r := range restorables {
		if !restorableWellFormed(r) {
			continue
		}
		if seen[r.Token] > 1 {
			rep.DuplicateTokenDropped++
			continue
		}
		usable = append(usable, r)
		tokens = append(tokens, r.Token)
	}
	rep.Usable = len(usable)
	return usable, tokens
}

func restorableWellFormed(r Restorable) bool {
	return r.Token != "" && (r.NumberedPrefix != "" || r.NumberedSuffix != "") && len(r.Spans) > 0
}
