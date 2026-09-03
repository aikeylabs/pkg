package mcpwire

// restbinding.go — how a tool that is really a REST endpoint gets called.
//
// # 🔴 What this is, and what it is NOT
//
// An MCP-native backend answers `tools/call`. A REST API does not: it has a
// method, a path, and a set of places a value can go. The gateway therefore has
// to know, per tool, how to turn `{"orderId": "A-1", "note": "x"}` into
// `POST /v1/orders/A-1` with `{"note":"x"}` as the body.
//
// That mapping is AUTHORED BY THE CONTROL PLANE at import time and EXECUTED BY
// THE PROXY at call time, which makes it a wire contract and puts it here.
//
// 🚫 It is not a general HTTP client configuration. There is no place for a
// header the admin types, no place for a template expression, and no place for
// a second URL. Every one of those would turn an import feature into a
// request-forging feature — an admin who can author arbitrary requests through
// a tool the Agent then calls has built an SSRF with an audit trail.
//
// # 🔴 The argument placements are a CLOSED set
//
// path / query / header / body. Deliberately no `cookie`: a cookie is session
// state, and a tool that can set one is a session-fixation primitive shaped
// like a parameter. The importer refuses operations that need one rather than
// dropping the parameter silently — dropping it would produce a tool that
// looks complete and calls the API wrong.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Argument placements. 🔴 A closed set; see the file header for why `cookie` is
// not among them.
const (
	// RESTInPath — substituted into a {placeholder} in the path.
	RESTInPath = "path"
	// RESTInQuery — appended as a query parameter.
	RESTInQuery = "query"
	// RESTInHeader — sent as a request header.
	RESTInHeader = "header"
	// RESTInBody — a field of the JSON request body.
	RESTInBody = "body"
)

// RESTBinding is how one tool maps onto one HTTP endpoint.
type RESTBinding struct {
	// Method is upper-case: GET / POST / PUT / PATCH / DELETE / HEAD.
	Method string `json:"method"`
	// Path is relative to the backend's endpoint_url and may contain
	// {placeholders} matching path arguments.
	//
	// 🔴 It is a PATH, never a full URL. A binding that could carry a host would
	// let a published tool address a machine the administrator never registered,
	// which is the whole of SSRF in one field.
	Path string `json:"path"`
	// Params maps an argument name to its placement.
	//
	// 🔴 An argument NOT listed here is not sent at all. Fail-closed: an
	// unrecognised argument silently appended to the query string would let a
	// caller reach parameters the reviewer never saw.
	Params map[string]string `json:"params"`
}

// Validate reports why a binding cannot be executed.
//
// 🔴 Checked at IMPORT time, not only at call time. A binding that is refused
// here never becomes a published tool; a binding first checked at call time
// would be a tool that exists, looks approved, and fails for everyone.
func (b RESTBinding) Validate() error {
	switch b.Method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
	default:
		return fmt.Errorf("method %q is not one this gateway will issue", b.Method)
	}
	if !strings.HasPrefix(b.Path, "/") {
		return fmt.Errorf("path %q must start with / — it is joined to the backend's address, "+
			"and a binding that could carry a host would let a tool address a machine nobody registered", b.Path)
	}
	// 🔴 No scheme, no authority, no traversal. Each of these turns a path into
	// an address, which is the one thing this field must never be.
	if strings.Contains(b.Path, "://") || strings.HasPrefix(b.Path, "//") {
		return fmt.Errorf("path %q looks like a URL; only a path is permitted", b.Path)
	}
	if strings.Contains(b.Path, "..") {
		return fmt.Errorf("path %q contains '..'; a tool must not be able to climb out of its API's namespace", b.Path)
	}
	for name, in := range b.Params {
		switch in {
		case RESTInPath, RESTInQuery, RESTInHeader, RESTInBody:
		default:
			return fmt.Errorf("argument %q has placement %q; only path/query/header/body are permitted", name, in)
		}
		if in == RESTInPath && !strings.Contains(b.Path, "{"+name+"}") {
			return fmt.Errorf("argument %q is placed in the path but %q has no {%s} placeholder", name, b.Path, name)
		}
	}
	// Every placeholder must have an argument, or the request goes out with a
	// literal `{id}` in the URL and the API answers something confusing.
	for _, ph := range pathPlaceholders(b.Path) {
		if b.Params[ph] != RESTInPath {
			return fmt.Errorf("path %q has a {%s} placeholder with no path argument to fill it", b.Path, ph)
		}
	}
	return nil
}

// pathPlaceholders extracts {names} from a path template.
func pathPlaceholders(path string) []string {
	var out []string
	for {
		open := strings.Index(path, "{")
		if open < 0 {
			return out
		}
		closeAt := strings.Index(path[open:], "}")
		if closeAt < 0 {
			return out
		}
		out = append(out, path[open+1:open+closeAt])
		path = path[open+closeAt+1:]
	}
}

// RESTRequest is the concrete request a binding produced.
type RESTRequest struct {
	Method string
	// Path is the path plus query string, still relative to the backend address.
	Path   string
	Header map[string]string
	// Body is nil when the binding places nothing in the body.
	Body json.RawMessage
}

// Build turns arguments into a request.
//
// 🔴 Arguments the binding does not name are DROPPED, not appended. An importer
// reviewer approved a specific parameter list; silently forwarding anything else
// a caller invents would let an Agent reach parameters nobody reviewed.
//
// 🔴 Path values are percent-encoded per segment. Without it, an `orderId` of
// `../../admin` would rewrite the path — the same traversal the binding's own
// validation forbids, arriving through the argument instead.
func (b RESTBinding) Build(args json.RawMessage) (RESTRequest, error) {
	if err := b.Validate(); err != nil {
		return RESTRequest{}, err
	}
	var obj map[string]json.RawMessage
	if len(args) > 0 {
		if err := json.Unmarshal(args, &obj); err != nil {
			return RESTRequest{}, fmt.Errorf("arguments are not a JSON object: %w", err)
		}
	}

	req := RESTRequest{Method: b.Method, Header: map[string]string{}}
	path := b.Path
	query := url.Values{}
	body := map[string]json.RawMessage{}

	// 🔴 Sorted, so the same call produces the same query string every time.
	// An unstable ordering makes two identical calls look different in a log and
	// defeats any upstream cache keyed on the URL.
	names := make([]string, 0, len(b.Params))
	for name := range b.Params {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		raw, present := obj[name]
		if !present {
			// Absent is absent. 🚫 No default is invented here: the tool's
			// inputSchema already declares what is required, and a value made up
			// at this layer would be one the reviewer never saw.
			continue
		}
		switch b.Params[name] {
		case RESTInPath:
			path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(scalarString(raw)))
		case RESTInQuery:
			query.Set(name, scalarString(raw))
		case RESTInHeader:
			// 🔴 Newlines stripped: a header value carrying CRLF is request
			// splitting, and the value here comes from a model's output.
			req.Header[name] = stripCTL(scalarString(raw))
		case RESTInBody:
			body[name] = raw
		}
	}
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	req.Path = path
	if len(body) > 0 {
		encoded, err := json.Marshal(body)
		if err != nil {
			return RESTRequest{}, fmt.Errorf("encode request body: %w", err)
		}
		req.Body = encoded
	}
	return req, nil
}

// scalarString renders one JSON value for a path/query/header slot.
//
// 🔴 A JSON string becomes its CONTENT (`"A-1"` → `A-1`), everything else keeps
// its JSON form. Sending `"A-1"` with the quotes is the classic mistake here and
// produces a 404 that looks like a missing record.
func scalarString(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// stripCTL removes characters that would end a header line.
func stripCTL(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

// MarshalRESTBinding renders a binding for storage. Empty string for the zero
// value, which is what every MCP-native tool carries.
func MarshalRESTBinding(b RESTBinding) (string, error) {
	if b.Method == "" && b.Path == "" {
		return "", nil
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ParseRESTBinding reads a stored binding. An empty string yields the zero
// value and ok=false — which is the normal case for an MCP-native tool, not an
// error.
func ParseRESTBinding(stored string) (RESTBinding, bool, error) {
	if strings.TrimSpace(stored) == "" {
		return RESTBinding{}, false, nil
	}
	var b RESTBinding
	if err := json.Unmarshal([]byte(stored), &b); err != nil {
		return RESTBinding{}, false, fmt.Errorf("stored REST binding is not readable: %w", err)
	}
	return b, true, nil
}
