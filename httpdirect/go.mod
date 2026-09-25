module github.com/AiKeyLabs/pkg/httpdirect

go 1.26.1

// pkg/egress owns the one way to name a proxy address in an error or a log
// line (egress.RedactSpec) and the one reason for an address that does not
// parse (egress.ErrUnparseableProxyURL). Redact, ProxyOverride and
// SetProxyOverride use both (2026-09-24 user decisions A and B,
// DEC-master-central-login-15). No cycle: pkg/egress imports nothing from here.
require github.com/AiKeyLabs/pkg/egress v0.0.0

require (
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/text v0.36.0 // indirect
)

replace github.com/AiKeyLabs/pkg/egress => ../egress
