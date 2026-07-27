package routingwire

import (
	"encoding/json"
	"strings"
	"testing"
)

// The wire shape is a cross-repo contract — lock the exact field names and the
// round-trip so an accidental tag rename shows up here first (both repos import
// this package, so a STRUCT change breaks their builds; this test pins the JSON).
func TestRoutingResponse_RoundTripAndFieldNames(t *testing.T) {
	in := RoutingResponse{
		RoutingVersion: 42,
		Routes: []RouteEntry{
			{SeatID: "seat-1", GroupID: "g1", AccountID: "acc-1"},
			{SeatID: "seat-1", GroupID: "g2", AccountID: "acc-2"},
			{SeatID: "seat-2", GroupID: "g1", Blocked: true},
			{SeatID: "seat-3", GroupID: "g1", Removed: true},
		},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"routing_version":42`, `"routes":[`, `"seat_id":"seat-1"`, `"group_id":"g2"`, `"account_id":"acc-2"`, `"blocked":true`, `"removed":true`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("wire JSON missing %q: %s", want, raw)
		}
	}
	// A blocked entry must not carry an account_id (omitempty on the empty string).
	if strings.Contains(string(raw), `"account_id":""`) {
		t.Fatalf("empty account_id must be omitted: %s", raw)
	}
	var out RoutingResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.RoutingVersion != 42 || len(out.Routes) != 4 ||
		out.Routes[1].AccountID != "acc-2" || !out.Routes[2].Blocked || out.Routes[2].AccountID != "" || !out.Routes[3].Removed {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
