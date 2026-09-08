package mcpwire

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestBackfillWindowIsDerivedFromTheDrainInterval — task 13.10b.
//
// 🔴 What this is protecting: the window is only meaningful as a MULTIPLE of the
// delivery cadence. The moment somebody writes `5 * time.Minute` here because it
// reads more naturally, the two numbers are independent, and the next person to
// retune the rail's interval has no way to know they also just changed when a
// tool call gets accused of bypassing the gateway.
func TestBackfillWindowIsDerivedFromTheDrainInterval(t *testing.T) {
	w := ConversationLinkBackfillWindow()

	if w%CallRailDrainInterval != 0 {
		t.Fatalf("backfill window %v is not a whole multiple of the drain interval %v — "+
			"it has stopped being derived and is now a second, independent timing source",
			w, CallRailDrainInterval)
	}
	if got := w / CallRailDrainInterval; got != ConversationLinkBackfillMultiple {
		t.Errorf("window is %d drains, the declared multiple is %d",
			got, ConversationLinkBackfillMultiple)
	}

	// 🔴 Strictly longer than ONE drain. A window of one interval (or less)
	// settles a call before the first drain that could have carried it has even
	// been attempted — every tool call would spend its first seconds looking
	// like it never reached the gateway.
	if w <= CallRailDrainInterval {
		t.Fatalf("backfill window %v <= one drain interval %v: a call would be settled "+
			"before the drain that carries it has run", w, CallRailDrainInterval)
	}
}

// TestDrainIntervalIsSaneForACallRail guards the interval itself against the two
// edits that would quietly break the other side.
//
// 🔴 Not a style assertion. Zero would spin the rail's ticker (time.NewTicker
// panics on a non-positive duration, taking the proxy down at start-up), and an
// interval longer than the reader's window inverts the relationship the whole
// file exists to hold: records would routinely arrive AFTER the reader had
// already settled them.
func TestDrainIntervalIsSaneForACallRail(t *testing.T) {
	if CallRailDrainInterval <= 0 {
		t.Fatal("drain interval must be positive; time.NewTicker panics otherwise")
	}
	if CallRailDrainInterval >= ConversationLinkBackfillWindow() {
		t.Fatalf("drain interval %v >= backfill window %v: the reader settles calls "+
			"before the rail that delivers them has had a chance to run",
			CallRailDrainInterval, ConversationLinkBackfillWindow())
	}
}

// TestBackfillWindowIsComputedNotWritten is the source half of the pair.
//
// # 🔴 Why this exists: the value assertions above are VACUOUS against the edit
// they were written to catch
//
// The first version of this file asserted only the arithmetic — window is a
// whole multiple of the interval, window/interval equals the multiple, window
// equals interval times multiple. The drill that was supposed to prove it went
// red replaced the function body with `5 * time.Minute` … and everything stayed
// green, because 5 minutes IS 30s × 10. The mutation never touched the product
// the assertions observe (a duration), only how it was produced.
//
// That is the R43 shape, and the answer R43 prescribes: assert the production
// point, not just the produced value. A hard-coded window is wrong the moment
// somebody retunes the interval — and on that day the failure would surface as
// healthy tool calls rendering `bypassed`, in a different module, weeks later.
//
// 🚫 Do not "simplify" this back into a value comparison. It passed for the
// wrong reason once already.
func TestBackfillWindowIsComputedNotWritten(t *testing.T) {
	src, err := os.ReadFile("linktiming.go")
	if err != nil {
		t.Fatalf("read linktiming source: %v", err)
	}
	body := regexp.MustCompile(
		"(?s)func ConversationLinkBackfillWindow\\(\\) time\\.Duration \\{(.*?)\n\\}").FindSubmatch(src)
	if body == nil {
		t.Fatal("ConversationLinkBackfillWindow is no longer a function in linktiming.go; " +
			"if its shape changed, move this fence with it")
	}
	expr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(body[1])), "return"))
	const want = "CallRailDrainInterval * ConversationLinkBackfillMultiple"
	if expr != want {
		t.Fatalf("window is computed as %q, must be exactly %q.\n"+
			"A literal duration here decouples the window from the delivery cadence it is "+
			"supposed to describe. It can be numerically identical today and still be the bug: "+
			"the next person to retune the drain interval gets no signal, and the symptom lands "+
			"in another module as healthy tool calls marked `bypassed`.", expr, want)
	}

	// 🔴 And the multiple must stay a bare count, not a duration wearing a
	// count's name. `ConversationLinkBackfillMultiple = 5 * time.Minute / 30 /
	// time.Second` would satisfy the string check above and reintroduce the
	// second timing source through the back door.
	if _, isDuration := any(ConversationLinkBackfillMultiple).(time.Duration); isDuration {
		t.Fatal("ConversationLinkBackfillMultiple has become a Duration; it must stay a " +
			"dimensionless count of drains")
	}
}
