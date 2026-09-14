// Package scannode is the proxy's client side of the scan-node protocol: which
// nodes exist, which of them may be handed raw prompt bytes, and how those bytes
// get there.
//
// 🔴 EVERYTHING IN THIS PACKAGE GUARDS ONE SENTENCE: a piece of an employee's
// raw prompt must never reach a box we did not independently decide to trust.
// The four gates below are ANDed and every one of them is checked BEFORE the
// frame is written, because "returned an error after sending" is indistinguishable
// from success as far as disclosure goes.
package scannode

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Node is one scan node the proxy may send work to.
type Node struct {
	ID   string
	Addr string // https://<private-ip>:<port>
	// Fingerprint is the SHA-256 of the node's DER certificate, lowercase hex.
	// It is the ONLY thing that authenticates the node: there is no CA in this
	// product (verified across the whole tree, 2026-09-11), so the chain is not
	// checked and this pin replaces it entirely.
	Fingerprint string
	Weight      int
}

// NodeSet is a resolved node list plus the decision of which fingerprints the
// control plane vouched for.
//
// Trusted is a FUNCTION and not a []string because the two editions answer the
// question from different sources — Production from an HTTPS member-auth
// response, Cluster from a list the installer rendered onto the box — and a node
// self-reporting its own fingerprint may never be an answer. Reason carries why
// the set is empty (no_nodes / insecure_control_plane / disabled) so the health
// surface can say something an operator can act on instead of "0 nodes".
type NodeSet struct {
	Nodes   []Node
	Trusted func(fingerprint string) bool
	Reason  string
}

// Reasons a NodeSet is empty or unusable. These strings surface verbatim in the
// proxy's health section (design §4b.3), so they are part of an external contract.
const (
	ReasonOK                   = "ok"
	ReasonNoNodes              = "no_nodes"
	ReasonInsecureControlPlane = "insecure_control_plane"
	ReasonLocalDaemonAbsent    = "local_daemon_absent"
	ReasonDisabled             = "disabled"
)

// checkScheme refuses anything but https. There is no plaintext mode and no
// opt-out flag: user decision D21 (2026-09-11) 「强制 TLS…永无明文模式」. A flag
// here would become the thing that is set "just for debugging" on the one
// machine that then stays that way.
func checkScheme(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("scannode: unparsable node address %q: %w", addr, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("scannode: node address %q is %q, not https — raw prompt content is never sent in the clear", addr, u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("scannode: node address %q has no host", addr)
	}
	return u, nil
}

// checkPrivateAddress resolves the node's host and requires every resolved IP to
// be RFC1918, RFC4193 (fc00::/7), link-local or loopback (R-scan-node-deepscan-10).
//
// WHY resolve instead of pattern-matching the string: the guard exists to stop a
// tampered or fat-fingered node list from becoming an exfiltration channel, and
// a hostname is exactly how such a list would point outside without looking like
// it. EVERY resolved address must pass — a name that returns one private and one
// public address is refused, because we do not control which one the dialer picks.
func checkPrivateAddress(addr string) error {
	u, err := checkScheme(addr)
	if err != nil {
		return err
	}
	host := u.Hostname()
	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		resolved, rerr := net.LookupIP(host)
		if rerr != nil {
			return fmt.Errorf("scannode: cannot resolve node host %q: %w", host, rerr)
		}
		ips = resolved
	}
	if len(ips) == 0 {
		return fmt.Errorf("scannode: node host %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if !isPrivate(ip) {
			return fmt.Errorf("scannode: node %q resolves to %s, which is not a private address — refusing to send raw content off the private network", addr, ip)
		}
	}
	return nil
}

// isPrivate covers RFC1918, RFC4193 unique-local, loopback and link-local.
func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}
