// Package routingwire is the SINGLE definition of the GET /accounts/me/routing
// wire contract between aikey-control-master (emitter: the allocation engine's
// per-(seat,group) account bindings) and aikey-proxy (consumer: the
// RoutingOverrideCache the hot-path resolver reads).
//
// Why a shared module (not duplicated structs): this wire previously carried its
// per-(seat,group) semantics inside string-concatenated map keys ("seat|group"),
// held in lockstep across the two repos by nothing but a comment — a format drift
// on either side made every lookup miss SILENTLY (override loss + the ≤3-users
// pool-full 429 vanishing; 2026-07 review finding F1). Both repos import THIS
// package via go.mod replace (like pkg/seatassign), so a field change breaks the
// build on both sides instead of breaking routing at runtime.
//
// Evolution: entries are self-describing objects — add optional fields here
// (additive) instead of inventing new key encodings. The structured shape was
// finalized 2026-07-02 while the enterprise edition is still unpublished (no
// external consumers), per the "design the final schema before first release"
// rule; there is deliberately NO legacy assignments/blocked map emission.
package routingwire

// RoutingResponse is the GET /accounts/me/routing body: the engine's
// AUTHORITATIVE per-(seat,group) account bindings projected from the
// oauth_group_member_identity ledger, plus a routing_version the proxy compares
// to skip unchanged polls. A (seat,group) pair with NO entry isn't bound yet —
// the proxy local-picks for ≤1 engine tick until the next bind.
type RoutingResponse struct {
	RoutingVersion int64        `json:"routing_version"`
	Routes         []RouteEntry `json:"routes"`
}

// RouteEntry is one seat's binding within one group.
//
// Exactly one of the two states is expressed:
//   - AccountID != ""            → the engine's sticky binding (proxy applies it
//     when the account is still a valid, usable candidate; else local pick).
//   - Blocked == true            → the engine left this (seat,group) UNBOUND
//     (every pool account is at the per-account user cap, or no account may take
//     a binding at all). The proxy MUST 429 and never fall back to the cap-blind
//     local pick.
//
// AccountID == "" with Blocked == false is not emitted.
type RouteEntry struct {
	SeatID    string `json:"seat_id"`
	GroupID   string `json:"group_id"`
	AccountID string `json:"account_id,omitempty"`
	Blocked   bool   `json:"blocked,omitempty"`
}
