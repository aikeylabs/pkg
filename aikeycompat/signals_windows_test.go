//go:build windows

package aikeycompat

import (
	"syscall"
	"testing"
)

// On Windows, ShutdownSignals must NOT include SIGTERM — the Windows
// kernel has no SIGTERM equivalent (TerminateProcess bypasses Go's
// signal machinery entirely), so listening for it would create a
// graceful-shutdown path that never fires. Anyone who later "fixes"
// this by adding SIGTERM back will trip this test.
func TestShutdownSignalsWindowsExcludesSIGTERM(t *testing.T) {
	got := ShutdownSignals()
	for _, s := range got {
		if s == syscall.SIGTERM {
			t.Fatalf("Windows ShutdownSignals() must NOT include SIGTERM (it never fires on Windows); got=%v", got)
		}
	}
}

func TestShutdownSignalsWindowsCount(t *testing.T) {
	got := ShutdownSignals()
	if len(got) != 1 {
		t.Errorf("Windows ShutdownSignals() should have exactly 1 entry (SIGINT); got %d: %v", len(got), got)
	}
}
