package pipewire

// capabilities_test.go — the wire spelling and the parsing rules of the
// parent→child capability declaration (TODO-114).
//
// WHY THESE TWO TESTS AND NOT MORE: the declaration has exactly two failure
// modes that matter. Either the two repositories stop agreeing on the byte
// string (the env name or a token), in which case the detector sees an
// undeclared proxy forever and the feature silently never runs; or the match
// becomes loose, in which case a FUTURE token (`count_projection_v2`) is read as
// today's — a semantic change accepted as compatible, which is the failure the
// token scheme exists to prevent.

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// TestProxyCapabilities_WireSpellingPinned nails the literals. Both aikey-proxy
// and ai-compliance-detector import this package, so this is the ONLY place the
// strings exist — but they still travel through a process boundary as bytes, and
// a rename here would be invisible until a customer's personal-route traffic
// stopped counting.
func TestProxyCapabilities_WireSpellingPinned(t *testing.T) {
	if EnvProxyCapabilities != "AIKEY_PROXY_CAPABILITIES" {
		t.Errorf("EnvProxyCapabilities = %q, want AIKEY_PROXY_CAPABILITIES — the name is the contract "+
			"between a proxy that already shipped and a detector that has not", EnvProxyCapabilities)
	}
	if CapCountProjection != "count_projection" {
		t.Errorf("CapCountProjection = %q, want count_projection", CapCountProjection)
	}
	if CapCannedAnswer != "canned_answer" {
		t.Errorf("CapCannedAnswer = %q, want canned_answer", CapCannedAnswer)
	}

	t.Run("format sorts, de-duplicates and drops blanks", func(t *testing.T) {
		got := FormatProxyCapabilities([]string{CapCountProjection, "", CapCannedAnswer, CapCountProjection, "  "})
		const want = "canned_answer,count_projection"
		if got != want {
			t.Errorf("FormatProxyCapabilities = %q, want %q — the VALUE must be a pure function of the SET, "+
				"or reordering a switch changes the bytes a reader diffs across two spawns", got, want)
		}
	})

	t.Run("the empty set formats as the empty string", func(t *testing.T) {
		if got := FormatProxyCapabilities(nil); got != "" {
			t.Errorf("FormatProxyCapabilities(nil) = %q, want \"\"", got)
		}
		if got := FormatProxyCapabilities([]string{"", "   "}); got != "" {
			t.Errorf("FormatProxyCapabilities(blanks) = %q, want \"\"", got)
		}
		// 🔴 The CALLER still emits `NAME=` with this empty value; that
		// unconditional line is the whole defence against an inherited residue
		// value (aikey-proxy internal/apphook ProxyCapabilitiesEnv). Formatting to
		// "" must therefore not tempt anyone into omitting the line.
	})

	t.Run("the zero value declares nothing", func(t *testing.T) {
		var zero ProxyCapabilities
		if zero.Has(CapCountProjection) || zero.Len() != 0 {
			t.Error("the zero ProxyCapabilities must be an EMPTY set — a caller that skipped parsing " +
				"has to get the safe answer, not a declaration")
		}
	})
}

// TestParseProxyCapabilities_ExactTokenMatch is the parsing table. Every row is a
// value that could actually appear on the env: what the proxy writes, what an
// older/newer proxy writes, and what a stale environment could be carrying.
func TestParseProxyCapabilities_ExactTokenMatch(t *testing.T) {
	cases := []struct {
		name              string
		raw               string
		wantCountProj     bool
		wantCannedAnswer  bool
		wantTokenCount    int
	}{
		{
			name: "unset / empty — an old proxy declares nothing",
			raw:  "",
		},
		{
			name: "only whitespace still declares nothing",
			raw:  "   ",
		},
		{
			name:           "the single capability this batch consumes",
			raw:            "count_projection",
			wantCountProj:  true,
			wantTokenCount: 1,
		},
		{
			name:             "both, with the spacing a hand-edited value would have",
			raw:              " canned_answer , count_projection ",
			wantCountProj:    true,
			wantCannedAnswer: true,
			wantTokenCount:   2,
		},
		{
			// 🔴 The rule this whole scheme exists for. A future revision with
			// DIFFERENT semantics must NOT be accepted as this one.
			name:           "a versioned successor token is NOT this capability",
			raw:            "count_projection_v2",
			wantTokenCount: 1,
		},
		{
			name:           "a prefix of the token is not the token",
			raw:            "count_projec",
			wantTokenCount: 1,
		},
		{
			name:           "case matters — nothing generates this spelling",
			raw:            "COUNT_PROJECTION",
			wantTokenCount: 1,
		},
		{
			name:           "unknown tokens are kept and ignored, the known one still reads",
			raw:            "bogus,count_projection,some_future_thing",
			wantCountProj:  true,
			wantTokenCount: 3,
		},
		{
			name:           "empty members between commas are skipped",
			raw:            ",,count_projection,,",
			wantCountProj:  true,
			wantTokenCount: 1,
		},
		{
			name:           "duplicates collapse",
			raw:            "count_projection,count_projection",
			wantCountProj:  true,
			wantTokenCount: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseProxyCapabilities(c.raw)
			if got.Has(CapCountProjection) != c.wantCountProj {
				t.Errorf("Has(count_projection) = %v, want %v for %q",
					got.Has(CapCountProjection), c.wantCountProj, c.raw)
			}
			if got.Has(CapCannedAnswer) != c.wantCannedAnswer {
				t.Errorf("Has(canned_answer) = %v, want %v for %q",
					got.Has(CapCannedAnswer), c.wantCannedAnswer, c.raw)
			}
			if got.Len() != c.wantTokenCount {
				t.Errorf("Len() = %d, want %d for %q", got.Len(), c.wantTokenCount, c.raw)
			}
		})
	}

	t.Run("round trip: everything Format writes, Parse reads back", func(t *testing.T) {
		set := []string{CapCannedAnswer, CapCountProjection}
		encoded := FormatProxyCapabilities(set)
		parsed := ParseProxyCapabilities(encoded)
		for _, c := range set {
			if !parsed.Has(c) {
				t.Errorf("Parse(Format(%v)) lost %q (encoded %q)", set, c, encoded)
			}
		}
		if parsed.Len() != len(set) {
			t.Errorf("Parse(Format(%v)).Len() = %d, want %d", set, parsed.Len(), len(set))
		}
		// And the encoding itself is the sorted join — asserted against an
		// independently built expectation rather than against Format's own output.
		want := append([]string(nil), set...)
		sort.Strings(want)
		if !reflect.DeepEqual(strings.Split(encoded, ","), want) {
			t.Errorf("encoded %q does not split into the sorted set %v", encoded, want)
		}
	})
}
