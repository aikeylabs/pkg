// redact.go — the one way to name an egress address in an error or a log line.
package egress

import "strings"

// Placeholders RedactSpec shows instead of text it cannot safely show.
const (
	redactedFragment    = "(multi-protocol config fragment)"
	redactedUnparseable = "(unparseable)"
)

// RedactSpec renders an egress spec (a single proxy URL, a comma-separated
// chain, or a multi-protocol config fragment) for an error message or a log
// line, without the proxy credentials it may carry:
//
//   - each hop becomes scheme://host:port as typed, with the user name and
//     password removed (everything up to the LAST '@') and anything after the
//     host dropped (path, query, fragment); hops keep their order;
//   - a hop that does not start with a well-formed "scheme://" becomes
//     "(unparseable)": with no URL shape there is no userinfo to cut, and the
//     text may be a stray piece of a fragment;
//   - a hop with no '@' whose host is followed by something other than a port
//     number also becomes "(unparseable)": "http://user:password" typed
//     without its "@host" looks exactly like that, and the password is the
//     part that would be shown;
//   - a config fragment becomes "(multi-protocol config fragment)" — its own
//     fields carry passwords, so none of its text is shown;
//   - an empty spec stays empty.
//
// Why this exists (DEC-master-central-login-15, TODO-17): an address written
// wrong (no port, a port that is not a number, a bad hop in a chain) used to
// be quoted whole in the error, and the password in it was usually right. That
// error reached the administrator's Session Key dialog, the Test egress
// results, the Nodes page, `aikey doctor`, and the Worker's and master's logs.
// Every place that names an egress address in an error or a log must call this
// function instead of printing the address or a url.Parse error: a *url.Error
// quotes the whole URL, and even its inner reason can quote the password
// ("invalid port \":<password>\" after host" when the password holds a '/').
//
// It never calls url.Parse, so it renders the same way whether or not the
// address parses — the unparseable case is exactly when a caller needs it.
//
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
func RedactSpec(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "" {
		return ""
	}
	if isFragment(s) {
		return redactedFragment
	}
	parts := strings.Split(s, ",")
	hops := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			hops = append(hops, redactHop(part))
		}
	}
	return strings.Join(hops, ",")
}

// redactHop renders one proxy URL as scheme://host:port without its userinfo.
func redactHop(hop string) string {
	scheme, rest, ok := strings.Cut(hop, "://")
	if !ok || !isURLScheme(scheme) {
		return redactedUnparseable
	}
	// Userinfo ends at the last '@' (RFC 3986 §3.2.1). Cutting there before
	// looking for '/', '?' or '#' also removes a password that holds one of
	// them unescaped — the typo that makes url.Parse misread the authority.
	at := strings.LastIndexByte(rest, '@')
	rest = rest[at+1:] // at == -1 keeps all of rest
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	if at < 0 && mayBeUserPassword(rest) {
		return redactedUnparseable
	}
	return scheme + "://" + rest
}

// mayBeUserPassword reports whether an authority typed WITHOUT an '@' could
// be "user:password" missing its "@host": a name, a ':', then something that is
// not a port number. An address that really has a bad port looks the same, so
// both are hidden. An IP literal ("[...") is shown: a user name cannot start
// with '[' (RFC 3986 §3.2.1 does not allow it in userinfo).
func mayBeUserPassword(authority string) bool {
	if strings.HasPrefix(authority, "[") {
		return false
	}
	_, after, found := strings.Cut(authority, ":")
	return found && strings.Trim(after, "0123456789") != ""
}

// isURLScheme reports whether s is a URL scheme per RFC 3986 §3.1:
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func isURLScheme(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case 'a' <= r && r <= 'z', 'A' <= r && r <= 'Z':
		case i > 0 && ('0' <= r && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return true
}
