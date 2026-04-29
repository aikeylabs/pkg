//go:build !windows

package aikeycompat

import (
	"syscall"
	"testing"
)

// On Unix, ShutdownSignals must include SIGTERM — that's the canonical
// "graceful shutdown" verb every supervisor (systemd, docker stop,
// launchctl) sends first before falling back to SIGKILL.
func TestShutdownSignalsUnixIncludesSIGTERM(t *testing.T) {
	got := ShutdownSignals()
	found := false
	for _, s := range got {
		if s == syscall.SIGTERM {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Unix ShutdownSignals() must include SIGTERM (graceful-shutdown contract); got=%v", got)
	}
}

func TestShutdownSignalsUnixCount(t *testing.T) {
	got := ShutdownSignals()
	if len(got) != 2 {
		t.Errorf("Unix ShutdownSignals() should have exactly 2 entries (SIGINT, SIGTERM); got %d: %v", len(got), got)
	}
}
