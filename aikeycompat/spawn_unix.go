//go:build !windows

package aikeycompat

import "os/exec"

// HideSpawnConsole marks a child process so it never opens a console
// window. No-op on Unix: POSIX terminals attach via file descriptors,
// spawning can't create a new terminal window by itself.
//
// See spawn_windows.go for the Windows semantics and the bug this
// prevents (bridge subprocesses flashing cmd/Windows Terminal windows
// over the Web Console, 2026-07-07).
func HideSpawnConsole(cmd *exec.Cmd) {}
