//go:build !windows

package aikeycompat

import (
	"os"
	"syscall"
)

// ShutdownSignals returns the set of signals a long-running aikey
// service should listen for to perform a graceful shutdown.
//
// Unix: SIGINT (Ctrl+C) + SIGTERM (kill / systemd / launchctl /
// docker stop). SIGTERM is the canonical "please clean up and exit"
// signal in the Unix process tree and the one our installer scripts
// always send first before falling back to SIGKILL.
func ShutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}
