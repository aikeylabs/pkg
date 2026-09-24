// unparseable.go — the one reason to give when a proxy URL does not parse.
package egress

import "errors"

// ErrUnparseableProxyURL is the reason to give when a proxy URL does not parse.
// Name the address with RedactSpec and wrap this error after it:
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
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
var ErrUnparseableProxyURL = errors.New("not a valid URL (check the host and the port, which must be a number, " +
	"and percent-encode special characters in the user name or password)")
