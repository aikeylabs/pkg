package mcpwire

import "time"

// Delivery timing for MCP call records, and the window the conversation side
// waits before it is willing to say a tool call never arrived.
//
// # 🔴 Why these live HERE and not where they are used (2026-09-02)
//
// Two processes have to agree on one number, and they are in different modules:
//
//	aikey-proxy      ships call records on a ticker (the "call rail")
//	aikey-data       decides, at drawer-render time, whether a tool call that
//	                 has no matching record is merely late or actually absent
//
// The second answer is only correct if it is expressed in terms of the first
// cadence. Written as two independent literals they drift, and the drift is
// silent in the worst direction: shorten the proxy's interval and nothing
// happens, lengthen it past the reader's window and every in-flight call
// briefly becomes a `bypassed` — a SECURITY finding — until it lands.
//
// `aikey-proxy/internal/supervisor` is an internal package of another module,
// so the reader cannot import it. This package is already a dependency of all
// three consumers (proxy, control plane, query service), which makes it the
// only place the two sides can meet.
//
// 🚫 Do not re-declare either value anywhere else. `TestCallRailUsesTheShared
// DrainInterval` in aikey-proxy fails on a re-declared literal, and
// `TestBackfillWindowIsDerivedFromTheDrainInterval` below fails if the window
// stops being a multiple of the interval.
const (
	// CallRailDrainInterval is how often a proxy ships undelivered call records.
	//
	// 🔴 Thirty seconds, and deliberately NOT per-call. A tool call must not
	// wait on our control plane (the whole point of the local-first write), and
	// a batched drain also means a burst of 500 calls is one request rather
	// than 500. It is shorter than the manifest rail's five minutes because
	// this is OUR control plane, not a third party's server.
	//
	// (Moved here from aikey-proxy/internal/supervisor on 2026-09-02; that
	// package now aliases this constant.)
	CallRailDrainInterval = 30 * time.Second

	// ConversationLinkBackfillMultiple is how many consecutive drains may fail
	// before a missing call record stops being "late" and starts being evidence.
	//
	// 🔴 A COUNT OF DRAINS, not a duration. That is the whole reason it is
	// written this way: "five minutes" is a number nobody can evaluate, while
	// "ten drains in a row failed to deliver anything" is a statement an
	// operator can judge, and it stays true if the interval is ever retuned.
	//
	// Task 13.10b says the window must inherit the existing reporting cadence
	// and 🚫 must not introduce a new constant. This is that inheritance made
	// explicit: the only new thing is the multiple, and the multiple is a
	// policy ("how much delivery failure do we tolerate before accusing
	// somebody"), not a second timing source.
	ConversationLinkBackfillMultiple = 10
)

// ConversationLinkBackfillWindow is how long a tool call with no matching
// mcp_call_event stays LinkStatePending before the reader is willing to settle
// it (tasks 13.10b / 13.11).
//
// 🔴 Settling does NOT mean LinkStateBypassed. When the window closes, the
// reader still has to ask whether the join key was ever available on this path;
// if it was not, the answer is LinkStateUnlinkable. See LinkStateUnlinkable for
// why — without that check this window produces a false security finding on
// 100% of traffic from the main client.
//
// 🔴 KNOWN GAP, registered rather than papered over: this window covers a
// stalled rail, NOT a backlogged one. After a long control-plane outage the
// rail catches up at one batch per drain, so a large backlog can take far
// longer than this window to clear — and every call still in that backlog would
// read as "window closed, nothing found". The window cannot see the backlog:
// it is local to each proxy and the reader is on the server. Closing this needs
// a liveness signal the reader CAN see (e.g. the newest delivered call event
// for the org), which is a semantics decision, not an implementation detail.
// 🚫 Do not "fix" it by widening the multiple — that trades one silent wrong
// answer for a slower silent wrong answer.
func ConversationLinkBackfillWindow() time.Duration {
	return CallRailDrainInterval * ConversationLinkBackfillMultiple
}
