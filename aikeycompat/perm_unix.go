//go:build !windows

package aikeycompat

// EnforceOwnerOnly is a no-op on Unix.
//
// Why noop and not `os.Chmod(path, 0o600/0o700)`: Unix callers already
// pass an intentional mode to `os.MkdirAll` / `os.OpenFile` (often
// 0o750 or 0o755 for non-secret operational dirs like the event WAL —
// observability tools legitimately need group-read). Re-tightening to
// 0o700 here would silently change long-standing Unix behaviour for
// every event-WAL directory in the codebase. On Unix, existing umask /
// caller-supplied mode is the source of truth.
//
// On Windows the picture is different — see `perm_windows.go`. NTFS has
// no meaningful "0o755 group readable" granularity; the inherited DACL
// either has Authenticated Users or it doesn't. We tighten there
// because the inherited NTFS default is "Authenticated Users:(R)"
// regardless of the caller's mode argument, which on a multi-user
// workstation makes the file readable by anyone logged in.
func EnforceOwnerOnly(path string) error {
	_ = path
	return nil
}
