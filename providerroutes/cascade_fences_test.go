package providerroutes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Fences for the 2026-08-02 provider-credential-cascade change.
//
// Every fence here was deliberately broken once and observed red before being
// checked in; the actual failure text is recorded in
// roadmap20260320/技术实现/阶段8-平台化/供应商凭据三级联动/openspec/changes/
// provider-credential-cascade/fence-proof.md.
//
// 🚫 A fence with no recorded failure text is not a fence — it is a decoration
// that nobody has confirmed can fail.

// ─────────────────────────────────────────────────────────────────────────────
// P1c.1 / T-1 / I-3 — expanding the table must not move an existing row.
// ─────────────────────────────────────────────────────────────────────────────

// TestFence_I3_BaselineRoutesUnchanged pins every pre-cascade row against the
// frozen fixture generated BEFORE the table was expanded.
//
// 🔴 The assertion is "the row this URL resolves to has NOT CHANGED", not "the
// URL resolves to ITSELF". Two pre-existing rows are alias rows whose base_url
// deliberately points at a DIFFERENT host (www.kimi.com → api.kimi.com,
// platform.moonshot.cn → api.moonshot.cn), so a self-hit assertion would fail
// on real, intended behaviour on its very first run — and would then get
// "fixed" into a whitelist exception, which is how fences die. See
// baseline-routes.md for the round-trip table this fixture came from.
func TestFence_I3_BaselineRoutesUnchanged(t *testing.T) {
	baseline := loadBaseline(t)
	if len(baseline) == 0 {
		t.Fatal("baseline fixture is empty — anti-vacuous assertion (an empty fixture would pass everything)")
	}
	tbl := Default()

	for _, want := range baseline {
		name := want.Host + "|" + want.PathPrefix
		t.Run(name, func(t *testing.T) {
			// The row itself must still exist, unmodified in every routing field.
			var found *Route
			for _, r := range tbl.All() {
				if r.Host == want.Host && r.PathPrefix == want.PathPrefix {
					rr := r
					found = &rr
					break
				}
			}
			if found == nil {
				t.Fatalf("pre-cascade row (%q, %q) has DISAPPEARED from the table — expanding must only ADD rows", want.Host, want.PathPrefix)
			}
			if found.Protocol != want.Protocol || found.Provider != want.Provider ||
				found.BaseURL != want.BaseURL || found.Version != want.Version {
				t.Errorf("pre-cascade row (%q, %q) was MODIFIED:\n  protocol %q → %q\n  provider %q → %q\n  base_url %q → %q\n  version  %q → %q",
					want.Host, want.PathPrefix,
					want.Protocol, found.Protocol, want.Provider, found.Provider,
					want.BaseURL, found.BaseURL, want.Version, found.Version)
			}

			// And the round trip must still land on the same row it landed on before.
			eff := EffectiveUpstream(*found)
			if eff != want.EffectiveUpstream {
				t.Errorf("EffectiveUpstream drifted: got %q want %q", eff, want.EffectiveUpstream)
			}
			hit, ok := tbl.LookupByBaseURL(eff)
			if ok != want.LookupOK {
				t.Fatalf("LookupByBaseURL(%q) ok=%v, baseline recorded ok=%v", eff, ok, want.LookupOK)
			}
			if hit.Host != want.HitHost || hit.PathPrefix != want.HitPathPrefix {
				t.Errorf("ROUTE DRIFT for stored base_url %q:\n  baseline resolved to (%q, %q) protocol=%s\n  now resolves to   (%q, %q) protocol=%s\n  → every credential already stored with this URL changes upstream on upgrade",
					eff, want.HitHost, want.HitPathPrefix, want.HitProtocol,
					hit.Host, hit.PathPrefix, hit.Protocol)
			}
			if hit.Protocol != want.HitProtocol || hit.Provider != want.HitProvider {
				t.Errorf("PROTOCOL/PROVIDER DRIFT for %q: baseline (%s/%s) → now (%s/%s)",
					eff, want.HitProvider, want.HitProtocol, hit.Provider, hit.Protocol)
			}
		})
	}
}

func loadBaseline(t *testing.T) []baselineEntry {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", "baseline_routes_pre_cascade.json"))
	if err != nil {
		t.Fatalf("read baseline fixture: %v (it is generated ONCE, before the expansion — see baseline_export_test.go)", err)
	}
	var out []baselineEntry
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal baseline fixture: %v", err)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// P1c.2 / T-2 / I-4 — segment-aligned longest prefix; nothing gets swallowed.
// ─────────────────────────────────────────────────────────────────────────────

// prefixExpectation is one (stored path → the row it MUST select) pair for a
// host that carries several path_prefix rows.
type prefixExpectation struct {
	storedURL    string
	wantProtocol string
	wantPrefix   string
	why          string
}

// TestFence_I4_LongestPrefixWins asserts two separate things:
//
//	(a) auto-discovered: for every host, whenever one row's path_prefix is a
//	    segment-aligned prefix of another's, a stored URL sitting at the LONGER
//	    prefix must select the LONGER row. No whitelist — a new colliding pair
//	    added tomorrow is covered automatically.
//	(b) hand-written expectations for the rows where getting this wrong silently
//	    rewrites a request body into the wrong wire shape.
func TestFence_I4_LongestPrefixWins(t *testing.T) {
	tbl := Default()

	// (a) auto-discovered containment pairs.
	byHost := map[string][]Route{}
	for _, r := range tbl.All() {
		byHost[r.Host] = append(byHost[r.Host], r)
	}
	pairs := 0
	for host, rows := range byHost {
		for _, short := range rows {
			for _, long := range rows {
				if short.PathPrefix == long.PathPrefix || long.PathPrefix == "" {
					continue
				}
				if !pathPrefixMatches(short.PathPrefix, long.PathPrefix) {
					continue // not a segment-aligned containment pair
				}
				pairs++
				// A stored base_url sitting exactly at the longer prefix must
				// resolve to the longer row, never to the shorter one.
				hit, ok := tbl.Lookup(host, long.PathPrefix)
				if !ok {
					t.Errorf("%s%s resolves to nothing", host, long.PathPrefix)
					continue
				}
				if hit.PathPrefix != long.PathPrefix {
					t.Errorf("PREFIX SWALLOWED on %s: stored path %q resolved to the SHORTER row %q (protocol %s) instead of %q (protocol %s) — requests would be rewritten into the wrong wire shape",
						host, long.PathPrefix, hit.PathPrefix, hit.Protocol, long.PathPrefix, long.Protocol)
				}
			}
		}
	}
	if pairs == 0 {
		t.Fatal("no containment pairs discovered — the ark /api/coding vs /api/coding/v3 pair must exist; a zero-pair run means this fence is asserting nothing")
	}
	t.Logf("auto-discovered %d segment-aligned containment pair(s)", pairs)

	// (b) the named cases. These are the ones whose failure is silent.
	cases := []prefixExpectation{
		{
			storedURL: "https://ark.cn-beijing.volces.com/api/coding/v3", wantProtocol: "openai_compatible", wantPrefix: "/api/coding/v3",
			why: "the Coding Plan OpenAI endpoint. If /api/coding (anthropic) swallowed it, an OpenAI request body would be rewritten by the Anthropic adapter",
		},
		{
			storedURL: "https://ark.cn-beijing.volces.com/api/coding/v1", wantProtocol: "anthropic", wantPrefix: "/api/coding",
			why: "the Coding Plan Anthropic endpoint sits UNDER /api/coding but is not /api/coding/v3",
		},
		{
			storedURL: "https://ark.cn-beijing.volces.com/api/v3", wantProtocol: "openai_compatible", wantPrefix: "",
			why: "the pre-existing Ark fallback row must still win for the plain /api/v3 endpoint",
		},
		{
			storedURL: "https://open.bigmodel.cn/api/anthropic/v1", wantProtocol: "anthropic", wantPrefix: "/api/anthropic",
			why: "pre-existing zhipu anthropic face",
		},
		{
			storedURL: "https://open.bigmodel.cn/api/coding/paas/v4", wantProtocol: "openai_compatible", wantPrefix: "/api/coding/paas/v4",
			why: "pre-existing zhipu coding face",
		},
		{
			storedURL: "https://api.deepseek.com/anthropic/v1", wantProtocol: "anthropic", wantPrefix: "/anthropic",
			why: "NEW: the whole point of the change. Swallowed by the fallback row = an Anthropic body posted to the OpenAI endpoint",
		},
		{
			storedURL: "https://api.deepseek.com/v1", wantProtocol: "openai_compatible", wantPrefix: "",
			why: "the pre-existing deepseek row must be unaffected by its new anthropic sibling",
		},
		{
			storedURL: "https://api.moonshot.cn/anthropic/v1", wantProtocol: "anthropic", wantPrefix: "/anthropic",
			why: "NEW anthropic face on a host that already had a fallback row",
		},
		{
			storedURL: "https://dashscope.aliyuncs.com/api/v2/apps/claude-code-proxy/v1", wantProtocol: "anthropic", wantPrefix: "/api/v2/apps/claude-code-proxy",
			why: "NEW: deepest prefix in the whole table",
		},
		{
			storedURL: "https://dashscope.aliyuncs.com/compatible-mode/v1", wantProtocol: "openai_compatible", wantPrefix: "",
			why: "pre-existing qwen row: its base_url path is NOT declared as a path_prefix, so it must keep matching via the fallback row",
		},
		{
			storedURL: "https://api.z.ai/api/anthropic/v1", wantProtocol: "anthropic", wantPrefix: "/api/anthropic",
			why: "NEW zhipu international anthropic face",
		},
		{
			storedURL: "https://api.z.ai/api/paas/v4", wantProtocol: "openai_compatible", wantPrefix: "/api/paas",
			why: "NEW zhipu international openai face (tier-B)",
		},
	}
	for _, c := range cases {
		t.Run(c.storedURL, func(t *testing.T) {
			hit, ok := tbl.LookupByBaseURL(c.storedURL)
			if !ok {
				t.Fatalf("LookupByBaseURL(%q) miss — %s", c.storedURL, c.why)
			}
			if hit.PathPrefix != c.wantPrefix || hit.Protocol != c.wantProtocol {
				t.Errorf("%q resolved to (prefix=%q protocol=%s), want (prefix=%q protocol=%s)\n  why it matters: %s",
					c.storedURL, hit.PathPrefix, hit.Protocol, c.wantPrefix, c.wantProtocol, c.why)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P1c.3 / T-3 / I-5 — every (provider, protocol) has a truthful default.
// ─────────────────────────────────────────────────────────────────────────────

// TestFence_I5_EveryPairHasADefault walks every (provider, protocol) pair that
// the table declares and asserts ByProviderProtocol resolves it.
//
// Why this matters in THIS change: the console auto-fills the Base URL by
// calling exactly this function. ok=false is not an error the admin ever sees —
// the URL box simply stays blank. Silent blank is the failure mode.
func TestFence_I5_EveryPairHasADefault(t *testing.T) {
	tbl := Default()
	seen := map[[2]string]bool{}
	for _, r := range tbl.All() {
		seen[[2]string{strings.ToLower(r.Provider), strings.ToLower(r.Protocol)}] = true
	}
	if len(seen) == 0 {
		t.Fatal("zero (provider, protocol) pairs — anti-vacuous assertion")
	}
	pairs := make([][2]string, 0, len(seen))
	for k := range seen {
		pairs = append(pairs, k)
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] != pairs[j][0] {
			return pairs[i][0] < pairs[j][0]
		}
		return pairs[i][1] < pairs[j][1]
	})

	for _, p := range pairs {
		provider, protocol := p[0], p[1]
		if _, ok := tbl.ByProviderProtocol(provider, protocol); !ok {
			// Reproduce the diagnosis the maintainer needs, not just "false".
			var rows []string
			for _, r := range tbl.All() {
				if strings.EqualFold(r.Provider, provider) && strings.EqualFold(r.Protocol, protocol) {
					rows = append(rows, fmt.Sprintf("(host=%s prefix=%q default=%v)", r.Host, r.PathPrefix, r.Default))
				}
			}
			t.Errorf("ByProviderProtocol(%q, %q) = ok:false → the console's Base URL box stays SILENTLY BLANK for this combination.\n  matching rows: %s\n  fix: mark exactly one of them `default: true` (or give exactly one an empty path_prefix)",
				provider, protocol, strings.Join(rows, " "))
		}
	}
	t.Logf("checked %d (provider, protocol) pairs", len(pairs))
}

// ─────────────────────────────────────────────────────────────────────────────
// P1c.4 / T-4 / I-6 — every routed provider has a display identity.
// ─────────────────────────────────────────────────────────────────────────────

// TestFence_I6_EveryRoutedProviderIsInTheRegistry asserts
// provider_fingerprint.yaml's provider set ⊆ provider_registry.yaml's code set.
//
// 🔴 This fence RED-ON-ARRIVAL when first written: huggingface / yunwu /
// zeroeleven had been in the routing table for months with no registry entry.
// Nobody noticed because the generated compatibility matrix says of itself
// "This matrix has no web consumer today" — the two sets had never once been
// compared. Same shape as D-4.
func TestFence_I6_EveryRoutedProviderIsInTheRegistry(t *testing.T) {
	tbl := Default()

	registryPath := filepath.Join("..", "..", "aikey-cli", "data", "provider_registry.yaml")
	blob, err := os.ReadFile(registryPath)
	if err != nil {
		// Fail loud, never skip: a fence that silently disappears when its
		// input is missing is worse than no fence.
		t.Fatalf("read %s: %v", registryPath, err)
	}
	var reg struct {
		Providers []struct {
			Code string `yaml:"code"`
		} `yaml:"providers"`
	}
	if err := yaml.Unmarshal(blob, &reg); err != nil {
		t.Fatalf("parse provider_registry.yaml: %v", err)
	}
	codes := map[string]bool{}
	for _, p := range reg.Providers {
		codes[strings.ToLower(p.Code)] = true
	}
	if len(codes) == 0 {
		t.Fatal("provider_registry.yaml yielded zero codes — anti-vacuous assertion")
	}

	missing := map[string]bool{}
	for _, r := range tbl.All() {
		if !codes[strings.ToLower(r.Provider)] {
			missing[r.Provider] = true
		}
	}
	if len(missing) > 0 {
		var names []string
		for m := range missing {
			names = append(names, m)
		}
		sort.Strings(names)
		t.Errorf("provider(s) routed but with NO registry identity: %v\n  → the console renders these as a machine code or an empty string.\n  fix: add a `code:` entry to aikey-cli/data/provider_registry.yaml (and re-sync pkg/providerregistry/data/)",
			names)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P1c.5 / T-5 / I-9 — the file ships to every customer; no secrets in it.
// ─────────────────────────────────────────────────────────────────────────────

// TestFence_I9_NoSecretsInYAML scans the whole fingerprint file (comments
// included — a sample key pasted into a comment ships just as widely as one in
// a value).
//
// The regex table is deliberately shaped to skip the file's own classifier
// section, which legitimately contains secret-SHAPED *patterns* (`^sk-ant-api03-…`)
// but no secret VALUES. The discriminator is "a regex anchor or character class
// nearby" vs "a literal run of key material".
func TestFence_I9_NoSecretsInYAML(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("data", "provider_fingerprint.yaml"))
	if err != nil {
		t.Fatalf("read fingerprint yaml: %v", err)
	}
	type probe struct {
		name string
		re   *regexp.Regexp
	}
	probes := []probe{
		// A literal Anthropic / OpenAI / generic sk- key: 20+ chars of key
		// material with no regex metacharacters in it.
		{"literal sk- key", regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`)},
		{"AWS access key id", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{"bearer token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._\-]{16,}`)},
		{"password assignment", regexp.MustCompile(`(?i)\bpassword\s*[:=]\s*\S`)},
		{"token in query string", regexp.MustCompile(`(?i)[?&]token=\S`)},
		{"google api key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
		{"groq key", regexp.MustCompile(`gsk_[A-Za-z0-9]{40,}`)},
		{"slack token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,}`)},
		{"private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	}

	lines := strings.Split(string(blob), "\n")
	for i, line := range lines {
		// A line that declares a classifier pattern is describing a SHAPE, not
		// carrying a value. Those lines contain regex syntax; key material does not.
		if isRegexDeclaration(line) {
			continue
		}
		for _, p := range probes {
			if m := p.re.FindString(line); m != "" {
				t.Errorf("line %d looks like a %s — 🚫 this file ships to EVERY customer as a public vendor fact table.\n  offending line: %s\n  (if this is a pattern and not a value, it belongs in the classifier `regex:` section)",
					i+1, p.name, strings.TrimSpace(line))
			}
		}
	}
}

// isRegexDeclaration reports whether a yaml line is declaring a classifier
// pattern rather than carrying a literal value.
func isRegexDeclaration(line string) bool {
	trimmed := strings.TrimSpace(line)
	if strings.HasPrefix(trimmed, "regex:") {
		return true
	}
	// Anchors / character classes / quantifiers are regex syntax; a pasted key
	// contains none of them.
	return strings.Contains(trimmed, `[A-Za-z0-9`) || strings.Contains(trimmed, `^sk-`) ||
		strings.Contains(trimmed, `(?!`) || strings.Contains(trimmed, `\.`)
}

// ─────────────────────────────────────────────────────────────────────────────
// T-7 — the row primary key is unique. (Parse enforces it; this pins it.)
// ─────────────────────────────────────────────────────────────────────────────

func TestFence_RowKeyIsUnique(t *testing.T) {
	tbl := Default()
	seen := map[string]int{}
	for i, r := range tbl.All() {
		k := r.Host + "\x00" + r.PathPrefix
		if prev, dup := seen[k]; dup {
			t.Errorf("duplicate (host, path_prefix) key (%q, %q) at rows %d and %d", r.Host, r.PathPrefix, prev, i)
		}
		seen[k] = i
	}

	// And prove Parse itself rejects a duplicate, so the invariant survives even
	// if someone deletes the loop above.
	dupYAML := []byte(`
provider_routes:
  - { host: "dup.example.com", protocol: openai_compatible, provider: dup, base_url: "https://dup.example.com", version: "/v1" }
  - { host: "dup.example.com", protocol: anthropic,         provider: dup, base_url: "https://dup.example.com", version: "/v1" }
`)
	if _, err := Parse(dupYAML); err == nil {
		t.Error("Parse accepted a duplicate (host, path_prefix) key — the row primary key is not enforced")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// T-8 — host field agrees with base_url, except for declared alias rows.
// ─────────────────────────────────────────────────────────────────────────────

// aliasRows are the rows whose `host` intentionally differs from their
// base_url's host: the row exists to redirect a host users paste at the
// canonical API host.
//
// 🔴 This is an EXPLICIT allowlist on purpose. The naive assertion
// (host == HostFromURL(base_url)) reds on these two real rows, and the natural
// "fix" is to weaken the assertion to "base_url just has to parse" — which
// throws away the typo-catching that is the whole point. Naming the exceptions
// keeps the assertion strong AND keeps the exceptions reviewable.
var aliasRows = map[string]string{
	"www.kimi.com":         "api.kimi.com",
	"platform.moonshot.cn": "api.moonshot.cn",
}

func TestFence_HostMatchesBaseURL(t *testing.T) {
	tbl := Default()
	usedAlias := map[string]bool{}
	for _, r := range tbl.All() {
		h := HostFromURL(r.BaseURL)
		if h == "" {
			t.Errorf("row (%q, %q): base_url %q does not parse to a host", r.Host, r.PathPrefix, r.BaseURL)
			continue
		}
		if h == r.Host {
			continue
		}
		if want, isAlias := aliasRows[r.Host]; isAlias && want == h {
			usedAlias[r.Host] = true
			continue
		}
		t.Errorf("row host %q disagrees with its base_url host %q (base_url=%q).\n  If this is a deliberate alias row, add it to aliasRows with a comment. Otherwise it is a typo, and a typo here is a credential that routes to the wrong vendor.",
			r.Host, h, r.BaseURL)
	}
	// A stale allowlist entry is its own kind of rot.
	for host := range aliasRows {
		if !usedAlias[host] {
			t.Errorf("aliasRows lists %q but no row uses it — remove the stale exception", host)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// P1c.9 / T-9b / I-11 — the mixed-version difference is ENUMERATED, not vague.
// ─────────────────────────────────────────────────────────────────────────────

// mixedVersionRow is one row whose upstream differs between the pre-cascade
// table (an un-upgraded worker's embedded copy) and the post-cascade table.
type mixedVersionRow struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	Provider   string `json:"provider"`
	Protocol   string `json:"protocol"`
	StoredURL  string `json:"stored_base_url"`
	ClientPath string `json:"client_path"`
	OldUpstream string `json:"old_proxy_upstream"`
	NewUpstream string `json:"new_proxy_upstream"`
	// OldRouteKnown records whether the OLD table matched a row at all. This is
	// the difference between the two failure shapes: false → literal-prepend
	// /v1/v1 with a proxy.route.not_found WARN (loud); true → the fallback row
	// matched and silently DISCARDED the path (silent).
	OldRouteKnown bool   `json:"old_route_known"`
	Shape         string `json:"shape"`
}

// TestFence_I11_MixedVersionDiffIsEnumerated replays every newly-added row
// through BOTH tables and asserts the resulting difference set matches the
// checked-in manifest exactly — no missing rows, no stale rows.
//
// This is what turns X-2 from "a risk we are aware of" into "a list the release
// notes can name". Adding a route row without updating the manifest reds.
func TestFence_I11_MixedVersionDiffIsEnumerated(t *testing.T) {
	oldTbl := tableFromBaseline(t)
	newTbl := Default()

	// Every row present in the new table but not the old one.
	oldKeys := map[string]bool{}
	for _, r := range oldTbl.All() {
		oldKeys[r.Host+"\x00"+r.PathPrefix] = true
	}

	got := map[string]mixedVersionRow{}
	for _, r := range newTbl.All() {
		if oldKeys[r.Host+"\x00"+r.PathPrefix] {
			continue // pre-existing row; I-3 already covers it
		}
		stored := EffectiveUpstream(r)
		clientPath := clientPathFor(r.Protocol, r.Version)
		oldUp := stitchWith(t, oldTbl, stored, clientPath)
		newUp := stitchWith(t, newTbl, stored, clientPath)
		if oldUp == newUp {
			continue // an un-upgraded worker behaves identically; nothing to report
		}
		_, known := oldTbl.LookupByBaseURL(stored)
		shape := "B · /v1/v1 duplicate version segment — 404, WARN proxy.route.not_found IS emitted"
		if known {
			shape = "A · SILENT mis-route — the fallback row matched, the path segment was discarded, and NO WARN fires"
		}
		got[stored] = mixedVersionRow{
			Host: r.Host, PathPrefix: r.PathPrefix, Provider: r.Provider, Protocol: r.Protocol,
			StoredURL: stored, ClientPath: clientPath,
			OldUpstream: oldUp, NewUpstream: newUp,
			OldRouteKnown: known, Shape: shape,
		}
	}

	want := loadMixedVersionManifest(t)
	if len(want) == 0 {
		t.Fatal("mixed-version manifest is empty — anti-vacuous assertion (an empty manifest would let any new row through unlisted)")
	}

	wantByURL := map[string]mixedVersionRow{}
	for _, w := range want {
		wantByURL[w.StoredURL] = w
	}
	for url, g := range got {
		w, listed := wantByURL[url]
		if !listed {
			t.Errorf("NEW ROW NOT IN THE MANIFEST: %s (%s/%s)\n  an un-upgraded worker sends this to %q instead of %q\n  shape: %s\n  → add it to testdata/mixed_version_affected_rows.json AND to mixed-version-affected-rows.md; the release notes read that list",
				url, g.Provider, g.Protocol, g.OldUpstream, g.NewUpstream, g.Shape)
			continue
		}
		if w.OldUpstream != g.OldUpstream || w.NewUpstream != g.NewUpstream || w.OldRouteKnown != g.OldRouteKnown {
			t.Errorf("manifest is STALE for %s:\n  old upstream: manifest %q, actual %q\n  new upstream: manifest %q, actual %q\n  old_route_known: manifest %v, actual %v",
				url, w.OldUpstream, g.OldUpstream, w.NewUpstream, g.NewUpstream, w.OldRouteKnown, g.OldRouteKnown)
		}
	}
	for url := range wantByURL {
		if _, ok := got[url]; !ok {
			t.Errorf("manifest lists %s but the tables no longer differ there — remove the stale entry (a manifest that over-reports trains people to ignore it)", url)
		}
	}
	t.Logf("%d row(s) behave differently on an un-upgraded worker", len(got))
}

// clientPathFor returns the request path a real client of this row sends to the
// proxy, AFTER the proxy has stripped its "/<provider>" routing prefix.
//
// 🔴 The version segment comes from the ROW, not a hard-coded "/v1". An OpenAI
// SDK pointed at a /v3 provider never sends "/v1/..." — it treats the whole
// base_url (version included) as its base and appends "/chat/completions".
// Hard-coding "/v1" made this fence compute
//
//	https://ark.cn-beijing.volces.com/api/coding/v3/v1/chat/completions
//
// as doubao's "new upstream" — a URL no client ever produces. That column is
// what the release notes show operators, so a plausible-looking wrong value
// there is worse than no table at all.
//
// Both real client shapes converge under Stitch's one rule (the version is
// stripped once and re-attached once), so exercising the with-version shape
// also covers the without-version one.
func clientPathFor(protocol, version string) string {
	endpoint := "/chat/completions"
	if protocol == "anthropic" {
		endpoint = "/messages"
	}
	return version + endpoint
}

func stitchWith(t *testing.T, tbl *Table, storedBaseURL, clientPath string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://placeholder"+clientPath, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := tbl.Stitch(req, storedBaseURL); err != nil {
		t.Fatalf("stitch %q: %v", storedBaseURL, err)
	}
	return req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
}

// tableFromBaseline rebuilds the pre-cascade table from the frozen fixture, so
// the "old proxy" half of this fence cannot drift with the current yaml.
func tableFromBaseline(t *testing.T) *Table {
	t.Helper()
	entries := loadBaseline(t)
	rows := make([]Route, 0, len(entries))
	for _, e := range entries {
		rows = append(rows, Route{
			Host: e.Host, Protocol: e.Protocol, Provider: e.Provider,
			BaseURL: e.BaseURL, Version: e.Version, PathPrefix: e.PathPrefix, Default: e.Default,
		})
	}
	blob, err := yaml.Marshal(struct {
		ProviderRoutes []Route `yaml:"provider_routes"`
	}{rows})
	if err != nil {
		t.Fatalf("marshal baseline rows: %v", err)
	}
	tbl, err := Parse(blob)
	if err != nil {
		t.Fatalf("parse baseline table: %v", err)
	}
	return tbl
}

func loadMixedVersionManifest(t *testing.T) []mixedVersionRow {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("testdata", "mixed_version_affected_rows.json"))
	if err != nil {
		t.Fatalf("read mixed-version manifest: %v", err)
	}
	var out []mixedVersionRow
	if err := json.Unmarshal(blob, &out); err != nil {
		t.Fatalf("unmarshal mixed-version manifest: %v", err)
	}
	return out
}
