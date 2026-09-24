package egress

// Fence: an egress address written wrong never puts its proxy credentials in
// an error. Every consumer (member and administrator Session Key, the Test
// egress buttons, `aikey doctor`, the Worker's per-request ERROR log, master's
// token refresh WARN) prints these errors, so the source is where the fix and
// the fence belong.
//
// spec: R-master-central-login-6.S4 秘密不外泄（出口凭据部分）
// DEC-master-central-login-15 (出口地址不进报错与日志：只写去掉钥匙的地址)
// bugfix: workflow/CI/bugfix/2026-09-24-egress-credentials-echoed-in-errors.md
//
// 能红: put `raw` back in any parseSocks5URL / ValidateSpec message, or wrap
// url.Parse's error again (a *url.Error quotes the whole URL), and the markers
// appear.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Made-up credentials. Every case below must hide both.
const (
	markUser = "u-MARK7"
	markPass = "p-MARK7"
)

func assertNoCredentials(t *testing.T, where, got string) {
	t.Helper()
	for _, mark := range []string{markUser, markPass} {
		if strings.Contains(got, mark) {
			t.Errorf("%s echoed the proxy credential %q: %q", where, mark, got)
		}
	}
}

func assertMentions(t *testing.T, where, got string, want []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s = %q, want it to name %q so the operator can find the bad address", where, got, w)
		}
	}
}

// echoCase is one address written wrong. build is what every build entry
// (BuildDialer, both dial-context builders, TestDial) must say; validate is
// what the write-time shape check must say, or nil when that check does not
// look at this part of the address (it is shape-only and not pinned here).
type echoCase struct {
	name     string
	spec     string
	build    []string
	validate []string
}

var credentialEchoCases = []echoCase{
	{
		name:  "single socks5 without a port",
		spec:  "socks5://" + markUser + ":" + markPass + "@portless.example.test",
		build: []string{`"socks5://portless.example.test"`, "not a dialable host:port", "missing port"},
	},
	{
		name:     "single socks5 with a port that is not a number",
		spec:     "socks5://" + markUser + ":" + markPass + "@proxy.example.test:abc",
		build:    []string{`"socks5://proxy.example.test:abc"`},
		validate: []string{"socks5://proxy.example.test:abc", "not a valid URL"},
	},
	{
		name:  "single socks5 with port 0",
		spec:  "socks5://" + markUser + ":" + markPass + "@proxy.example.test:0",
		build: []string{`"socks5://proxy.example.test:0"`, "invalid port"},
	},
	{
		name:  "single socks5 with a port out of range",
		spec:  "socks5://" + markUser + ":" + markPass + "@proxy.example.test:99999",
		build: []string{`"socks5://proxy.example.test:99999"`, "invalid port"},
	},
	{
		name:  "chain whose second hop has no port",
		spec:  "socks5://front.example.test:1080,socks5://" + markUser + ":" + markPass + "@exit.example.test",
		build: []string{"hop 2", `"socks5://exit.example.test"`, "not a dialable host:port"},
	},
	{
		name:  "chain whose second hop has port 0",
		spec:  "socks5://front.example.test:1080,socks5://" + markUser + ":" + markPass + "@exit.example.test:0",
		build: []string{"hop 2", `"socks5://exit.example.test:0"`, "invalid port"},
	},
	{
		name:     "chain whose second hop has a port that is not a number",
		spec:     "socks5://front.example.test:1080,socks5://" + markUser + ":" + markPass + "@exit.example.test:abc",
		build:    []string{"hop 2", `"socks5://exit.example.test:abc"`},
		validate: []string{"hop 2", "socks5://exit.example.test:abc", "not a valid URL"},
	},
	{
		name:     "chain whose second hop has no host",
		spec:     "socks5://front.example.test:1080,socks5://" + markUser + ":" + markPass + "@",
		build:    []string{"hop 2", "has no host"},
		validate: []string{"hop 2", "missing host:port"},
	},
	{
		// No engine claims a chain mixing schemes, so the build answer names no
		// address at all; the shape check is the one that used to quote it.
		name:     "chain whose second hop is not socks5",
		spec:     "socks5://front.example.test:1080,http://" + markUser + ":" + markPass + "@exit.example.test:3128",
		build:    []string{"no egress engine handles this proxy spec"},
		validate: []string{"hop 2", "http://exit.example.test:3128", "must be socks5"},
	},
	{
		// An unescaped '/' in the password ends Go's authority early, so the
		// parser's own reason quotes the password ("invalid port \":p-MARK7\"").
		name:     "unparseable: a slash in the password",
		spec:     "socks5://" + markUser + ":" + markPass + "/x@proxy.example.test:1080",
		build:    []string{`"socks5://proxy.example.test:1080"`},
		validate: []string{"socks5://proxy.example.test:1080", "not a valid URL"},
	},
	{
		// url.Parse ends the authority at the first '/', reads the USER NAME as
		// the host ("u-MARK7"), and net.SplitHostPort then quotes that host:
		// "address u-MARK7: missing port in address". hostPortProblem keeps the
		// reason only; this row is what makes it load-bearing (review-2.4 m-1:
		// mutation MD, re-wrapping splitErr with %w, survived every fence).
		// If review-2.4 D3 is adopted, this input is refused earlier and the
		// row guards that branch instead.
		name:  "user name followed by a slash",
		spec:  "socks5://" + markUser + "/" + markPass + "@proxy.example.test:1080",
		build: []string{"not a dialable host:port", "missing port"},
	},
	{
		name:     "unparseable: a bad percent-escape in the password",
		spec:     "socks5://" + markUser + ":" + markPass + "%zz@proxy.example.test:1080",
		build:    []string{`"socks5://proxy.example.test:1080"`},
		validate: []string{"socks5://proxy.example.test:1080", "not a valid URL"},
	},
	{
		name:     "unparseable: a control character",
		spec:     "socks5://" + markUser + ":" + markPass + "@proxy.example.test:1080\x7f",
		build:    []string{"proxy.example.test:1080"},
		validate: []string{"proxy.example.test:1080", "not a valid URL"},
	},
}

// TestParseErrors_NeverEchoProxyCredentials walks every pkg/egress entry that
// reports a bad address: the three builders, TestDial (the Test egress
// buttons and `aikey doctor`), and the two write-time shape checks.
func TestParseErrors_NeverEchoProxyCredentials(t *testing.T) {
	builds := map[string]func(spec string) error{
		"BuildDialer": func(spec string) error {
			_, err := BuildDialer(spec)
			return err
		},
		"BuildDialContext": func(spec string) error {
			_, closer, err := BuildDialContext(spec)
			if closer != nil {
				_ = closer.Close()
			}
			return err
		},
		"BuildEgressOnlyDialContext": func(spec string) error {
			_, _, closer, err := BuildEgressOnlyDialContext(spec)
			if closer != nil {
				_ = closer.Close()
			}
			return err
		},
		"TestDial": func(spec string) error {
			// The spec never builds, so the echo is never contacted.
			_, err := TestDial(context.Background(), spec, "http://echo.invalid/", 2*time.Second)
			return err
		},
	}
	validates := map[string]func(spec string) error{
		"ValidateSpec": ValidateSpec,
		"ValidateDeep": ValidateDeep,
	}
	for _, tc := range credentialEchoCases {
		t.Run(tc.name, func(t *testing.T) {
			for entry, build := range builds {
				err := build(tc.spec)
				if err == nil {
					t.Errorf("%s accepted %s", entry, tc.name)
					continue
				}
				assertNoCredentials(t, entry, err.Error())
				assertMentions(t, entry, err.Error(), tc.build)
			}
			for entry, validate := range validates {
				err := validate(tc.spec)
				if err != nil {
					assertNoCredentials(t, entry, err.Error())
				}
				if tc.validate == nil {
					continue
				}
				if err == nil {
					t.Errorf("%s accepted %s", entry, tc.name)
					continue
				}
				assertMentions(t, entry, err.Error(), tc.validate)
			}
		})
	}
}

// Ruling-35 (review-2.4 D4): the reason given for an address that does not
// parse lives in ONE place, ErrUnparseableProxyURL, and every caller wraps it
// after the address RedactSpec renders. errors.Is is what shows a caller did
// not write its own copy of the sentence.
func TestUnparseableProxyURL_WrapsTheOneSentinel(t *testing.T) {
	// review-2.4 m-3: a bad HOST (a space, an open IPv6 bracket) fails the same
	// way as a bad port, so the hint must not send the user to the port only.
	for _, word := range []string{"host", "port", "percent-encode"} {
		if !strings.Contains(ErrUnparseableProxyURL.Error(), word) {
			t.Errorf("the hint %q does not mention %q", ErrUnparseableProxyURL, word)
		}
	}
	for _, spec := range []string{
		"socks5://" + markUser + ":" + markPass + "@proxy.example.test:abc",
		"socks5://" + markUser + ":" + markPass + "@proxy host.example.test:1080",
		"socks5://front.example.test:1080,socks5://" + markUser + ":" + markPass + "@exit.example.test:abc",
	} {
		if _, err := BuildDialer(spec); !errors.Is(err, ErrUnparseableProxyURL) {
			t.Errorf("BuildDialer(%s) = %v, want it to wrap ErrUnparseableProxyURL", RedactSpec(spec), err)
		}
		if err := ValidateSpec(spec); !errors.Is(err, ErrUnparseableProxyURL) {
			t.Errorf("ValidateSpec(%s) = %v, want it to wrap ErrUnparseableProxyURL", RedactSpec(spec), err)
		}
	}
	// TestDial's single http(s) branch (task 2.0) says it the same way.
	_, err := TestDial(context.Background(), "http://"+markUser+":"+markPass+"@proxy host.example.test:3128", "http://echo.invalid/", 2*time.Second)
	if !errors.Is(err, ErrUnparseableProxyURL) {
		t.Errorf("TestDial through an http proxy URL that does not parse = %v, want it to wrap ErrUnparseableProxyURL", err)
	}
}

// A well-formed address that only fails to connect keeps its existing error
// text, and that text never carried the credentials (the dialer reports
// host:port only). DEC-master-central-login-15 constraint 3 and premise 4.
func TestTestDial_WellFormedButUnreachableKeepsItsText(t *testing.T) {
	spec := "socks5://" + markUser + ":" + markPass + "@127.0.0.1:1"
	_, err := TestDial(context.Background(), spec, "http://echo.invalid/", 2*time.Second)
	if err == nil {
		t.Fatal("TestDial through a dead egress succeeded")
	}
	if !strings.HasPrefix(err.Error(), "egress unreachable via builtin-socks5: ") {
		t.Errorf("error text changed for a well-formed address: %q", err)
	}
	assertMentions(t, "TestDial", err.Error(), []string{"127.0.0.1:1"})
	assertNoCredentials(t, "TestDial", err.Error())
}
