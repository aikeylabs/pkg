package mcpwire

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustBuild(t *testing.T, b RESTBinding, args string) RESTRequest {
	t.Helper()
	req, err := b.Build(json.RawMessage(args))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return req
}

// TestABindingCannotCarryAnAddress is the SSRF guard.
//
// A binding is authored in the console and executed by a proxy that sits inside
// the customer's network. If the path could carry a host, a published tool would
// address a machine the administrator never registered — which is the whole of
// server-side request forgery in one field.
func TestABindingCannotCarryAnAddress(t *testing.T) {
	for _, path := range []string{
		"https://evil.example/steal",
		"//evil.example/steal",
		"/v1/../../admin",
		"relative/path",
	} {
		b := RESTBinding{Method: "GET", Path: path}
		if err := b.Validate(); err == nil {
			t.Errorf("path %q was accepted; a binding must be a PATH, never an address", path)
		}
	}
	if err := (RESTBinding{Method: "GET", Path: "/v1/orders"}).Validate(); err != nil {
		t.Errorf("a plain path was refused: %v", err)
	}
}

// TestOnlyIssuableMethodsAreAccepted — the gateway issues a closed set. A
// binding naming something else is refused at import, not at call time: a
// binding first checked at call time is a tool that exists, looks approved, and
// fails for everyone.
func TestOnlyIssuableMethodsAreAccepted(t *testing.T) {
	for _, m := range []string{"CONNECT", "TRACE", "get", ""} {
		if err := (RESTBinding{Method: m, Path: "/x"}).Validate(); err == nil {
			t.Errorf("method %q was accepted", m)
		}
	}
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
		if err := (RESTBinding{Method: m, Path: "/x"}).Validate(); err != nil {
			t.Errorf("method %q was refused: %v", m, err)
		}
	}
}

// TestCookieIsNotAPlacement — a cookie is session state, and a tool that can set
// one is a session-fixation primitive shaped like a parameter.
func TestCookieIsNotAPlacement(t *testing.T) {
	b := RESTBinding{Method: "GET", Path: "/x", Params: map[string]string{"sid": "cookie"}}
	if err := b.Validate(); err == nil {
		t.Error("a cookie placement was accepted")
	}
}

// TestAPlaceholderWithoutAnArgumentIsRefused — otherwise the request goes out
// with a literal {id} in the URL and the API answers something confusing.
func TestAPlaceholderWithoutAnArgumentIsRefused(t *testing.T) {
	b := RESTBinding{Method: "GET", Path: "/v1/orders/{orderId}"}
	if err := b.Validate(); err == nil {
		t.Error("a path with an unfilled placeholder was accepted")
	}
	b.Params = map[string]string{"orderId": RESTInPath}
	if err := b.Validate(); err != nil {
		t.Errorf("a filled placeholder was refused: %v", err)
	}
	// And the reverse: a path argument with no placeholder to go into.
	orphan := RESTBinding{Method: "GET", Path: "/v1/orders", Params: map[string]string{"orderId": RESTInPath}}
	if err := orphan.Validate(); err == nil {
		t.Error("a path argument with no placeholder was accepted; its value would vanish silently")
	}
}

// TestAnUnnamedArgumentIsDroppedNotForwarded is the fail-closed rule.
//
// A reviewer approved a specific parameter list. Silently forwarding anything
// else a caller invents would let an Agent reach parameters nobody saw.
func TestAnUnnamedArgumentIsDroppedNotForwarded(t *testing.T) {
	b := RESTBinding{
		Method: "GET", Path: "/v1/orders",
		Params: map[string]string{"status": RESTInQuery},
	}
	req := mustBuild(t, b, `{"status":"open","admin":"true","internal_flag":1}`)
	if strings.Contains(req.Path, "admin") || strings.Contains(req.Path, "internal_flag") {
		t.Errorf("an argument the binding does not name reached the request: %s", req.Path)
	}
	if !strings.Contains(req.Path, "status=open") {
		t.Errorf("the named argument did not reach the request: %s", req.Path)
	}
}

// TestPathValuesAreEscaped — an orderId of "../../admin" would otherwise
// rewrite the path: the same traversal Validate forbids, arriving through the
// argument instead of the template.
func TestPathValuesAreEscaped(t *testing.T) {
	b := RESTBinding{
		Method: "GET", Path: "/v1/orders/{orderId}",
		Params: map[string]string{"orderId": RESTInPath},
	}
	req := mustBuild(t, b, `{"orderId":"../../admin"}`)
	if strings.Contains(req.Path, "../") {
		t.Errorf("a traversal in an argument reached the path: %s", req.Path)
	}
	if !strings.HasPrefix(req.Path, "/v1/orders/") {
		t.Errorf("the escaped path lost its prefix: %s", req.Path)
	}
}

// TestHeaderValuesCannotSplitTheRequest — the value comes from a model's
// output, and CRLF in a header is request splitting.
func TestHeaderValuesCannotSplitTheRequest(t *testing.T) {
	b := RESTBinding{
		Method: "GET", Path: "/v1/x",
		Params: map[string]string{"X-Trace": RESTInHeader},
	}
	req := mustBuild(t, b, `{"X-Trace":"abc\r\nX-Admin: true"}`)
	v := req.Header["X-Trace"]
	if strings.ContainsAny(v, "\r\n") {
		t.Errorf("a header value kept its line breaks: %q", v)
	}
	if !strings.Contains(v, "abc") {
		t.Errorf("the header value was destroyed rather than sanitised: %q", v)
	}
}

// TestAStringArgumentLosesItsQuotes — sending `"A-1"` with the quotes is the
// classic mistake here and produces a 404 that reads as a missing record.
func TestAStringArgumentLosesItsQuotes(t *testing.T) {
	b := RESTBinding{
		Method: "GET", Path: "/v1/orders/{id}",
		Params: map[string]string{"id": RESTInPath},
	}
	req := mustBuild(t, b, `{"id":"A-1"}`)
	if req.Path != "/v1/orders/A-1" {
		t.Errorf("path = %q, want /v1/orders/A-1", req.Path)
	}
}

// TestBodyArgumentsBecomeAJSONObject.
func TestBodyArgumentsBecomeAJSONObject(t *testing.T) {
	b := RESTBinding{
		Method: "POST", Path: "/v1/orders",
		Params: map[string]string{"note": RESTInBody, "qty": RESTInBody, "dry": RESTInQuery},
	}
	req := mustBuild(t, b, `{"note":"hi","qty":3,"dry":true}`)
	var body map[string]any
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatalf("body is not JSON (%s): %v", req.Body, err)
	}
	if body["note"] != "hi" || body["qty"].(float64) != 3 {
		t.Errorf("body = %v", body)
	}
	if _, leaked := body["dry"]; leaked {
		t.Error("a query argument also landed in the body")
	}
	if !strings.Contains(req.Path, "dry=true") {
		t.Errorf("the query argument did not reach the path: %s", req.Path)
	}
}

// TestNoBodyWhenNothingIsPlacedThere — an empty `{}` body on a GET is a real
// interoperability problem with APIs that reject a body they did not expect.
func TestNoBodyWhenNothingIsPlacedThere(t *testing.T) {
	b := RESTBinding{Method: "GET", Path: "/v1/x", Params: map[string]string{"q": RESTInQuery}}
	if req := mustBuild(t, b, `{"q":"a"}`); req.Body != nil {
		t.Errorf("a body was produced for a binding that places nothing there: %s", req.Body)
	}
}

// TestQueryOrderIsStable — an unstable ordering makes two identical calls look
// different in a log and defeats any upstream cache keyed on the URL.
func TestQueryOrderIsStable(t *testing.T) {
	b := RESTBinding{
		Method: "GET", Path: "/v1/x",
		Params: map[string]string{"a": RESTInQuery, "b": RESTInQuery, "c": RESTInQuery},
	}
	first := mustBuild(t, b, `{"a":"1","b":"2","c":"3"}`).Path
	for i := 0; i < 20; i++ {
		if got := mustBuild(t, b, `{"a":"1","b":"2","c":"3"}`).Path; got != first {
			t.Fatalf("query order is unstable: %q vs %q", got, first)
		}
	}
}

// TestAnEmptyBindingRoundTripsAsEmpty — every MCP-native tool stores "", and
// reading it back must not be an error.
func TestAnEmptyBindingRoundTripsAsEmpty(t *testing.T) {
	stored, err := MarshalRESTBinding(RESTBinding{})
	if err != nil || stored != "" {
		t.Fatalf("marshal empty = %q, %v", stored, err)
	}
	b, ok, err := ParseRESTBinding("")
	if err != nil || ok {
		t.Fatalf("parse empty = %+v, ok=%v, err=%v; an MCP-native tool has no binding and that is "+
			"not an error", b, ok, err)
	}
}

// TestAnUnreadableStoredBindingIsAnErrorNotAnEmptyOne.
//
// Returning the zero value would turn "this row is corrupt" into "this tool is
// MCP-native", and the call would then be attempted against a backend that
// speaks a different protocol entirely.
func TestAnUnreadableStoredBindingIsAnError(t *testing.T) {
	if _, _, err := ParseRESTBinding("{not json"); err == nil {
		t.Error("a corrupt stored binding parsed as an empty one")
	}
}
