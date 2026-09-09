package mcpwire

import (
	"encoding/json"
	"testing"
)

// TestEveryFrozenErrorCodeHasACallStatus is fence 7.F5.
//
// 🔴 It iterates ErrorCodeCatalog — the frozen catalog itself — rather than a
// hand-written list of codes. That is what makes it non-vacuous: adding a
// frozen code without deciding how a call carrying it is RECORDED goes red
// here, instead of silently filing that refusal under whatever the fallback
// happened to be.
func TestEveryFrozenErrorCodeHasACallStatus(t *testing.T) {
	for _, spec := range ErrorCodeCatalog {
		if _, ok := callStatusByErrorCode[spec.Code]; !ok {
			t.Errorf("frozen error code %q has no entry in callStatusByErrorCode. "+
				"Decide how a tools/call that ends with this code is recorded in mcp_call_event: "+
				"map it to one of the CallStatus* values, or to \"\" if it is a transport-level "+
				"failure that happens before a tool is named (like MCP_SESSION_NOT_FOUND).",
				spec.Code)
		}
	}
}

// TestCallStatusForErrorCodeRefusesWhatItCannotClassify pins the fail-loud
// direction: an unknown code must NOT come back as some plausible status.
func TestCallStatusForErrorCodeRefusesWhatItCannotClassify(t *testing.T) {
	if _, ok := CallStatusForErrorCode(ErrorCode("MCP_INVENTED_TOMORROW")); ok {
		t.Error("an unrecognised error code was classified into a call status. " +
			"That would file an unknown refusal under an existing value, where nobody would find it.")
	}
	// A transport-level code is in the table but is NOT recordable.
	if _, ok := CallStatusForErrorCode(ErrSessionNotFound); ok {
		t.Error("MCP_SESSION_NOT_FOUND was reported as recordable. A session failure happens " +
			"before any tool is named, so recording it as a tool call would invent a call that never was.")
	}
	if got, ok := CallStatusForErrorCode(ErrUpstreamTimeout); !ok || got != CallStatusTimeout {
		t.Errorf("EXT_MCP_UPSTREAM_TIMEOUT -> (%q,%v), want (%q,true). A timeout must stay "+
			"distinct from upstream_error: only the timeout case leaves the tool possibly executed.",
			got, ok, CallStatusTimeout)
	}
}

// TestMarshalArgsDigestNeverEmitsUnparseableJSON guards the read side: the
// column is NOT NULL and the console parses it, so "" would be a parse failure
// on the commonest call there is (one with no arguments).
func TestMarshalArgsDigestNeverEmitsUnparseableJSON(t *testing.T) {
	for name, entries := range map[string][]ArgDigestEntry{
		"nil":   nil,
		"empty": {},
		"one":   {{Key: "path", Type: "string", Len: 24}},
	} {
		var v []ArgDigestEntry
		if err := json.Unmarshal([]byte(MarshalArgsDigest(entries)), &v); err != nil {
			t.Errorf("%s: MarshalArgsDigest produced unparseable JSON %q: %v",
				name, MarshalArgsDigest(entries), err)
		}
	}
}

// TestArgsRawIsAPointerSoOffIsNotEmpty pins the one struct-tag decision that
// carries meaning: with a plain string, "retention is off" and "retention is on
// and the arguments were empty" would be the same wire bytes.
func TestArgsRawIsAPointerSoOffIsNotEmpty(t *testing.T) {
	off := CallRecord{}
	empty := ""
	on := CallRecord{ArgsRaw: &empty}
	a, _ := json.Marshal(off)
	b, _ := json.Marshal(on)
	if string(a) == string(b) {
		t.Fatalf("a record with raw retention OFF and one with retention ON but empty arguments "+
			"serialise identically (%s). The control plane cannot then tell a withheld payload "+
			"from an empty one.", a)
	}
}
