// Package buildinfo provides unified version information for all AiKey Go components.
//
// Version fields are injected via ldflags at build time by Makefile or release.sh.
// When ldflags are not set (bare "go build"), Revision and Dirty fall back to
// Go's embedded VCS metadata (debug.ReadBuildInfo); BuildID and BuildTime remain "unknown".
package buildinfo

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// Injected via ldflags: -X github.com/AiKeyLabs/pkg/buildinfo.Version=...
// Empty string means "not set by build system".
var (
	Version   string // semantic version, e.g. "1.0.2-alpha"
	Revision  string // git short SHA (12 chars), may have "-dirty" suffix
	BuildID   string // build-session ID, shared across components in one make/release run
	BuildTime string // UTC build timestamp, e.g. "2026-04-16T10:30:00Z"
)

// Info holds resolved version information for the running binary.
type Info struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Dirty     bool   `json:"dirty"`
	BuildID   string `json:"build_id"`
	BuildTime string `json:"build_time"`
	GoVersion string `json:"go_version"`
}

var (
	cached Info
	once   sync.Once
)

// Get returns version information (singleton, immutable for process lifetime).
//
// Priority: ldflags values > Go VCS metadata > defaults.
// BuildID has no runtime fallback — it strictly represents "build product ID".
func Get() Info {
	once.Do(func() {
		cached = resolve()
	})
	return cached
}

func resolve() Info {
	i := Info{
		Version:   Version,
		Revision:  Revision,
		BuildID:   BuildID,
		BuildTime: BuildTime,
		GoVersion: runtime.Version(),
	}

	if i.Version == "" {
		i.Version = "dev"
	}
	if i.Revision == "" {
		i.Revision, i.Dirty, i.BuildTime = readVCS()
	} else {
		i.Dirty = strings.HasSuffix(i.Revision, "-dirty")
	}
	if i.BuildID == "" {
		i.BuildID = "unknown"
	}
	if i.BuildTime == "" {
		i.BuildTime = "unknown"
	}
	return i
}

// readVCS extracts git info from debug.BuildInfo's vcs.* settings.
// Go 1.18+ embeds these automatically on "go build" (no ldflags needed).
//
// Limitations:
//   - vcs.modified only covers tracked file changes, not untracked files.
//     Makefile builds use "git status --porcelain" for full coverage.
//   - vcs.time is commit time, NOT build time. We intentionally skip it
//     to avoid misleading timestamps (showing days-old commit time as "Built").
func readVCS() (revision string, dirty bool, buildTime string) {
	revision = "unknown"
	buildTime = "unknown"

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 12 {
				revision = s.Value[:12]
			} else {
				revision = s.Value
			}
		case "vcs.modified":
			dirty = s.Value == "true"
			// vcs.time intentionally not read — it's commit time, not build time.
		}
	}
	if dirty {
		revision += "-dirty"
	}
	return
}

// String returns a human-readable version string.
// With BuildID:    "1.0.2-alpha+a3f7b2c1e9d4.f7a2 (built 2026-04-16T10:30:00Z, go1.26.1)"
// Without BuildID: "dev+a3f7b2c1e9d4-dirty (built unknown, go1.26.1)"
func (i Info) String() string {
	if i.BuildID == "unknown" {
		return fmt.Sprintf("%s+%s (built %s, %s)",
			i.Version, i.Revision, i.BuildTime, i.GoVersion)
	}
	return fmt.Sprintf("%s+%s.%s (built %s, %s)",
		i.Version, i.Revision, i.BuildID, i.BuildTime, i.GoVersion)
}

// JSON returns the Info as a JSON byte slice.
func (i Info) JSON() []byte {
	b, _ := json.Marshal(i)
	return b
}
