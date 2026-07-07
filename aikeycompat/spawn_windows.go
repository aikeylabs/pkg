//go:build windows

package aikeycompat

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW — the child is a console-subsystem process but gets a
// console with no window at all. Defined here because package syscall
// doesn't export it (x/sys/windows does, but this is our only use — not
// worth the extra dependency).
const createNoWindow = 0x08000000

// HideSpawnConsole marks a child process so it never opens a console
// window.
//
// Why this exists (2026-07-07, Windows Web Console regression class): on
// Windows a console-subsystem child INHERITS the parent's console when the
// parent has one, but CREATES a fresh one — a visible cmd / Windows
// Terminal window — when the parent has none. Our Go services run
// console-less on the main user path (`aikey web start` spawns
// aikey-local-server with DETACHED_PROCESS, see aikey-cli
// local_server_probe.rs spawn_detached), so every web-bridge
// `aikey.exe _internal ...` invocation flashed a terminal window over the
// SPA — one per page request. The same services launched from the
// ScheduledTask (cmd.exe /c) happened to have a console to inherit, which
// is why the bug only showed on some launch paths.
//
// CREATE_NO_WINDOW is the standard fix: the child still gets a console
// (stdio redirection and Ctrl handlers keep working, and grandchildren
// inherit it — so an `_internal` call that itself starts aikey-proxy stays
// windowless too), it just never materializes a window. HideWindow is set
// as well for defense in depth (covers children that create their own
// windows via STARTUPINFO).
//
// Mirrors the Rust side's established DETACHED_NO_WINDOW pattern
// (aikey-cli local_server_probe.rs, 2026-04-30). We deliberately do NOT
// use DETACHED_PROCESS here: these are short-lived request-scoped children
// whose stdout/stderr the caller captures.
func HideSpawnConsole(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.HideWindow = true
	cmd.SysProcAttr.CreationFlags |= createNoWindow
}
