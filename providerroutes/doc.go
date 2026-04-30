// Package providerroutes is the single source of truth for the per-host
// upstream routing table that aikey-cli, aikey-proxy, aikey-control
// service, and the web fallback all consume.
//
// # Yaml schema (provider_fingerprint.yaml `provider_routes`)
//
// Each row declares one upstream host's full route:
//
//	host       URL host portion (lowercase; how the row is keyed in lookups)
//	protocol   matches aikey-proxy provider registry's protocol name
//	           (anthropic / openai_compatible / gemini), drives RewriteRequest
//	provider   canonical provider_code stored in vault.entries.provider_code;
//	           multiple host rows can share the same provider (e.g. kimi
//	           family covers both api.kimi.com Kimi Coding and
//	           api.moonshot.cn Moonshot platform)
//	base_url   upstream root URL (host + any path BEFORE the version segment)
//	version    API version path; "" when the upstream has no version segment
//
// # Path stitch contract
//
// Given a request whose URL has been path-prefix-routed (i.e. the
// "/<provider>" prefix has already been stripped), the upstream URL is:
//
//	upstream = base_url + version + (req.URL.Path with leading version stripped)
//
// Why version is stripped from req then re-attached: clients differ in
// whether they include the API version in the request path (kimi-cli
// sends /v1/chat/..., OpenAI SDK omits /v1 since base_url config carries
// it). Stripping once and re-attaching from the table guarantees a
// single /version/ segment in the final URL no matter what the client
// sent. Segment-aligned strip avoids /v1 swallowing /v1abc.
//
// # Why this lives in pkg/
//
// The same routing semantics are needed by:
//   - aikey-proxy: actual HTTP request path stitching (StitchPath)
//   - aikey-control service: rules-endpoint fallback when CLI is unreachable
//     (TableJSON / All)
//   - Web fallback / display: showing the user the *effective* upstream URL
//     a particular vault entry will hit (EffectiveUpstream)
//
// Centralising prevents three drifting copies of the same data and lets
// new upstream hosts ship by adding one yaml row.
//
// # Loading
//
// The yaml byte content lives in aikey-cli/data/provider_fingerprint.yaml
// (the cli binary embeds it via include_str!). Each Go consumer either:
//
//  1. Embeds its own copy via go:embed of pkg/providerroutes/data/...,
//     synced from the cli source by the build script (see release.sh and
//     each consumer's Makefile sync-fingerprint target).
//  2. Calls Parse with bytes obtained from anywhere (CLI subprocess, file
//     on disk, etc.).
//
// The package itself does NOT bundle the yaml — that would couple a leaf
// utility to a specific source path. Consumers control where their bytes
// come from; this package only does parsing and lookups.
package providerroutes
