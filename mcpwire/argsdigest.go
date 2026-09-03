package mcpwire

// argsdigest.go — the STRUCTURAL SUMMARY of tool arguments (R6 / R16).
//
// # The rule this implements
//
// Tool arguments are SQL statements, file contents, internal hostnames, and
// sometimes outright credentials. Storing them by default would make AiKey a
// new concentration of exactly the sensitive data the product exists to keep
// concentrated in fewer places, not more. So:
//
//	default            key names + JSON type + value LENGTH. No values.
//	raw arguments      only with an explicit ORG-LEVEL switch, a retention
//	                   period, and only after DLP.
//
// 🔴 Both consumers use THIS function: the MCP call record and the
// conversation-audit tool-call list. One gate for one piece of data — R16
// exists because a second gate on the same data is the same as no gate.
//
// 🔴 The fail-safe direction: callers decide whether raw is allowed; when the
// switch cannot be read (e.g. leg A of the conversation work ships before the
// MCP gateway and the switch does not exist yet), the answer is CLOSED. Read
// the gate, cannot read it ⇒ the gate is shut. Falling open would leave a gate
// that has not been built yet standing wide.

import (
	"bytes"
	"encoding/json"
	"sort"
)

// DigestArgs converts a tool's arguments object into a structural summary.
//
// Entries are sorted by key so two calls with the same shape produce
// byte-identical digests regardless of upstream key order — otherwise the same
// call would look different every time in the audit UI.
//
// Non-object arguments (the spec permits any JSON value) are summarised as a
// single entry with an empty key, so the caller never has to special-case
// them. Unparseable arguments produce a single entry of type "invalid":
// 🔴 that is deliberately NOT an empty result — "we could not read the
// arguments" and "there were no arguments" are different facts, and the audit
// must not render the first as the second.
func DigestArgs(raw json.RawMessage) []ArgDigestEntry {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		// Not an object. Try any JSON value before declaring it invalid.
		var v any
		if err2 := json.Unmarshal(trimmed, &v); err2 != nil {
			return []ArgDigestEntry{{Key: "", Type: "invalid", Len: len(trimmed)}}
		}
		t, n := describe(trimmed)
		return []ArgDigestEntry{{Key: "", Type: t, Len: n}}
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]ArgDigestEntry, 0, len(keys))
	for _, k := range keys {
		t, n := describe(obj[k])
		out = append(out, ArgDigestEntry{Key: k, Type: t, Len: n})
	}
	return out
}

// describe returns the JSON type name and the length of one value.
//
// Length semantics, chosen so an auditor can reason about volume without
// seeing content:
//
//	string   byte length of the DECODED string (not of its JSON escaping —
//	         "\n" is one byte of content, not two)
//	array    element count
//	object   key count
//	other    0
func describe(raw json.RawMessage) (string, int) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "invalid", 0
	}
	switch trimmed[0] {
	case '"':
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return "invalid", len(trimmed)
		}
		return "string", len(s)
	case '{':
		var m map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &m); err != nil {
			return "invalid", len(trimmed)
		}
		return "object", len(m)
	case '[':
		var a []json.RawMessage
		if err := json.Unmarshal(trimmed, &a); err != nil {
			return "invalid", len(trimmed)
		}
		return "array", len(a)
	case 't', 'f':
		return "boolean", 0
	case 'n':
		return "null", 0
	default:
		var n json.Number
		if err := json.Unmarshal(trimmed, &n); err != nil {
			return "invalid", len(trimmed)
		}
		return "number", 0
	}
}
