//go:build windows

package aikeycompat

import (
	"os"
	"syscall"
)

// ShutdownSignals returns the set of signals a long-running aikey
// service should listen for to perform a graceful shutdown.
//
// Windows: SIGINT only. The Go runtime accepts syscall.SIGTERM as an
// argument to signal.Notify without panicking, but the Windows kernel
// has no SIGTERM equivalent — TerminateProcess is the supervisor's
// stop verb and bypasses Go's signal machinery entirely. Listening for
// SIGTERM here would create the false impression of a graceful path
// that never fires.
//
// Why we don't add SIGBREAK here: SIGBREAK fires when a console window
// is closed or the user hits Ctrl+Break. Console-attached aikey
// processes (interactive `aikey-proxy serve`) are expected to exit
// when the console is closed regardless of any cleanup, and supervised
// processes don't see SIGBREAK at all. Adding it would obscure the
// dispatch contract without adding value.
func ShutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT}
}
