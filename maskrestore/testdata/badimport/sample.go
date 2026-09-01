// This file is fixture data for TestFence_NoExternalDependencies_CanGoRed.
// It lives under testdata/ so the go tool never builds it — it exists purely to
// give the import scanner a known-bad input to prove it reports violations.
package badimport

import (
	"strings"

	"golang.org/x/text/unicode/norm"
)

var _ = strings.TrimSpace
var _ = norm.NFC
