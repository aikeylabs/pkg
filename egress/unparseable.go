// unparseable.go — the one reason to give when a proxy URL does not parse.
package egress

import (
	"errors"
	"net/url"
	"strings"
)

// ErrUnparseableProxyURL is the reason to give when a proxy URL does not parse,
// or parses into a different address than the one typed. Name the address
// with RedactSpec and wrap this error after it:
//
//	fmt.Errorf("invalid proxy url %q: %w", egress.RedactSpec(raw), egress.ErrUnparseableProxyURL)
//
// never url.Parse's own error: a *url.Error quotes the whole URL, and its inner
// reason can quote the password ("invalid port \":<password>\" after host" when
// the password holds a '/').
//
// Why one exported error (Ruling-35, review-2.4 D4): the same sentence was
// being copied into every place that validates a proxy URL — pkg/egress, the
// aikey-proxy validators and probes, the master Nodes page. A wrapped sentinel
// keeps the words in one place and lets callers classify the failure with
// errors.Is. It names the host too, not only the port: a host with a space or
// an unclosed IPv6 bracket fails the same way (review-2.4 m-3).
//
// It also carries the %2F advice, because the D3 refusal wraps it too (D3 甲,
// 2026-09-24): an unescaped '/' in the user name or password parses cleanly
// into the wrong host and a path holding the rest. Folding that advice into
// this one sentence keeps "no new API" (the approved D3 option) and one hint.
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
var ErrUnparseableProxyURL = errors.New("not a valid URL (check the host and the port, which must be a number; " +
	"in the user name or password, write '/' as %2F and percent-encode other special characters)")

// pathHoldsUserinfo reports whether url.Parse read part of the userinfo as the
// path: the typed user name or password held an unescaped '/', so the
// authority ended there and everything up to the real '@host' became the path.
// Such a URL "parses" into the wrong host ("user:12/pass@host" → host "user:12"),
// is never usable, and its dial errors quote that host — the user name. Every
// proxy-URL parse point refuses it (D3 甲, review-2.4 I-3). pkg/egress uses
// this helper; other modules repeat the one-line check next to their own parse
// (the approved option adds no new API).
func pathHoldsUserinfo(u *url.URL) bool {
	return strings.Contains(u.Path, "@")
}
