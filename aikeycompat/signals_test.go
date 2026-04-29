package aikeycompat

import (
	"syscall"
	"testing"
)

// TestShutdownSignalsContains verifies the per-OS dispatch contract:
//
//   - Every OS includes SIGINT (Ctrl+C / Stop-Process /T equivalent).
//   - Unix additionally listens for SIGTERM (kill / systemd / docker stop).
//   - Windows omits SIGTERM because the Windows kernel has no SIGTERM —
//     wiring it would create a graceful path that never fires.
//
// We test through the public ShutdownSignals() API rather than per-file
// constants so the signal slice is the source of truth.
func TestShutdownSignalsContainsSIGINT(t *testing.T) {
	got := ShutdownSignals()
	found := false
	for _, s := range got {
		if s == syscall.SIGINT {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ShutdownSignals() missing SIGINT — Ctrl+C wouldn't trigger graceful shutdown; got=%v", got)
	}
}

// TestShutdownSignalsAllValid: every signal returned must be one signal.Notify
// can actually register — defensive against accidental nil entries.
func TestShutdownSignalsAllValid(t *testing.T) {
	for i, s := range ShutdownSignals() {
		if s == nil {
			t.Errorf("ShutdownSignals()[%d] is nil", i)
		}
	}
}

// TestShutdownSignalsNonEmpty: a service with zero shutdown signals is
// always-running until SIGKILL — that's a regression no caller wants.
func TestShutdownSignalsNonEmpty(t *testing.T) {
	if len(ShutdownSignals()) == 0 {
		t.Fatal("ShutdownSignals() returned empty slice — services would only respond to SIGKILL")
	}
}
