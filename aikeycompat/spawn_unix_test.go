//go:build !windows

package aikeycompat

import (
	"os/exec"
	"testing"
)

// Unix contract: HideSpawnConsole must be a pure no-op — in particular it
// must NOT allocate a SysProcAttr, because callers on the Unix service
// path may later install their own (setsid etc.) and an unexpected
// non-nil struct would silently merge with theirs.
func TestHideSpawnConsoleIsNoOpOnUnix(t *testing.T) {
	cmd := exec.Command("true")
	HideSpawnConsole(cmd)
	if cmd.SysProcAttr != nil {
		t.Fatalf("HideSpawnConsole must not touch SysProcAttr on Unix, got %+v", cmd.SysProcAttr)
	}
}
