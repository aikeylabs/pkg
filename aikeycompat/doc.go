// Package aikeycompat hosts cross-platform shims for syscalls that have
// platform-divergent behaviour we need to paper over so the same `main`
// in aikey-proxy / aikey-trial-server / aikey-data services compiles and
// behaves correctly on Linux, macOS, and Windows.
//
// Why a dedicated package (vs. inlining `runtime.GOOS` checks):
//   - Single source of truth: every Go service calls the same helpers,
//     so when Windows behaviour shifts (e.g. a new SIGBREAK handling)
//     we change one file rather than five `main.go`s.
//   - Deterministic build tags: each helper splits into `_unix.go` /
//     `_windows.go` files with `//go:build` constraints, which means the
//     compiler — not runtime — picks the right code. Less reflection,
//     no risk of dead-code linker bloat.
//   - The package is intentionally tiny. Add new shims only when there
//     is a real platform divergence; do not turn this into a generic
//     "utility" package.
//
// Current shims:
//   - ShutdownSignals(): the set of signals to register with
//     signal.Notify for graceful shutdown. SIGTERM is meaningless on
//     Windows (signal.Notify accepts it but never fires), so the Windows
//     build returns SIGINT only — services still respond to Ctrl+C and
//     to TerminateProcess from the process supervisor.
//   - EnforceOwnerOnly(path): tighten file ACL to owner-only after a
//     write. Unix uses os.Chmod(0o600); Windows uses Win32 ACL APIs.
//     (Stage 2 of windows-compat, kept here as the scoping rationale is
//     the same as ShutdownSignals.)
package aikeycompat
