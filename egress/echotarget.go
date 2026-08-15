// echotarget.go — the ONE definition of "which endpoint does an egress probe
// dial to learn its exit IP" (§ egress connectivity test).
//
// WHY THIS LIVES HERE (2026-08-14): this concept previously had four private
// copies — aikey-proxy's upstreamProbeTarget() / egressSelfCheckEcho() /
// egressTestEchoURL() and control-master's egressprobe.EchoURL(). The 2026-07-24
// neutral-probe fix (see workflow/CI/bugfix/2026-07-24-upstream-probe-targets-anthropic.md)
// reached the three proxy-side copies and missed the control-plane one, which sat
// on a different default for three weeks while egressSelfCheckEcho's own comment
// claimed "mirrors the master endpoint's env + default". A concept with four
// outputs gets re-derived by hand and drifts; with one output a drift is a compile
// or fence failure. Callers keep their thin named wrappers (readability at the call
// site) but must delegate here rather than restate the literal.
package egress

import (
	"os"
	"strings"
)

// AIKEY_EGRESS_TEST_ECHO is the single knob a private / air-gapped deployment sets
// to point EVERY egress probe (control plane and node alike) at an internal echo.
// One variable on purpose: an operator who has no external internet must not have
// to discover which of several probes uses which variable.
const EchoURLEnv = "AIKEY_EGRESS_TEST_ECHO"

// neutralEchoURL is the default probe target: a bare-IP echo that belongs to no
// LLM provider.
//
// It must stay NEUTRAL for two independent reasons:
//
//   - Security. This probe leaves the machine through a JUST-PASTED egress, at the
//     moment the operator clicks "test". A provider target would make that exit's
//     very first packet an unauthenticated GET to that provider.
//   - Correctness. Cloudflare-fronted providers silently blackhole datacenter IP
//     ranges (no RST, no response), so a provider target renders a HEALTHY tunnel
//     as "context deadline exceeded" and blocks the operator from saving it.
//
// It must also stay a BARE-IP echo rather than a richer geo page: the exit IP is
// recovered by scanning the response for the first IP-shaped token (extractIP),
// which is robust against a one-line echo and fragile against an HTML page whose
// layout can change under us. The console renders only exit_ip + latency, so a geo
// body buys nothing today.
const neutralEchoURL = "https://api.ipify.org"

// DefaultEchoURL returns the probe target: the AIKEY_EGRESS_TEST_ECHO override
// when set, otherwise the neutral default.
func DefaultEchoURL() string {
	if v := strings.TrimSpace(os.Getenv(EchoURLEnv)); v != "" {
		return v
	}
	return neutralEchoURL
}
