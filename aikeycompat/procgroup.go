package aikeycompat

import "os/exec"

// ProcessTree binds a spawned child AND every descendant it goes on to create,
// so that all of them can be terminated together.
//
// # Why this exists
//
// `cmd.Process.Kill()` kills ONE process. A hosted MCP backend is almost never
// one process: the canonical invocation from the design is
//
//	npx -y @modelcontextprotocol/server-postgres
//
// where `npx` is a launcher that execs `node`, and `node` is the thing actually
// holding the decrypted database password in its memory. Killing `npx` leaves
// `node` running, reparented to init, with the credential still in it — and
// with a pipe to a proxy that no longer exists, so it will never be asked to
// exit. Repeat across a few days of proxy restarts and the developer's machine
// accumulates processes each holding a production database password.
//
// 🔴 That is the failure this interface exists to make impossible, and it is
// why tasks 5.2 / 5.F1 / 5.F2 require the check to be made against the real
// PROCESS TABLE rather than against a log line saying we killed something.
//
// # The two platforms are genuinely different
//
//	Unix     a process GROUP. The child is made a group leader, descendants
//	         inherit the group, and a signal to -pgid reaches all of them.
//	Windows  a JOB OBJECT. There are no process groups in the POSIX sense;
//	         a job is the only OS primitive that owns a subtree, and it has
//	         one property Unix cannot match — KILL_ON_JOB_CLOSE means the
//	         kernel reaps the tree even if the proxy dies without running
//	         any cleanup code at all.
//
// A single implementation with `if runtime.GOOS` would be a lie in both
// directions, so this is an interface with two build-tagged implementations
// (the same shape HideSpawnConsole already uses in this package).
//
// # Order of operations — all four calls are required
//
//	tree := NewProcessTree()
//	tree.Prepare(cmd)          // BEFORE cmd.Start()
//	err := cmd.Start()
//	tree.Adopt(cmd)            // AFTER a successful Start()
//	...
//	tree.Terminate()           // graceful: SIGTERM / job terminate
//	tree.Kill()                // after a grace period
//	tree.Close()               // release the OS handle
//
// Skipping Adopt is the dangerous mistake: on Unix the group still exists (so
// it mostly works and hides the bug), while on Windows nothing is in the job
// and Terminate silently affects zero processes.
type ProcessTree interface {
	// Prepare configures cmd so its children can be tracked. Must be called
	// before cmd.Start(); calling it after has no effect and no error, which is
	// why the fence checks ordering rather than trusting the call.
	Prepare(cmd *exec.Cmd)

	// Adopt records the started process. Must be called after a successful
	// cmd.Start(). Returns an error only when the OS refuses; a caller that
	// cannot adopt should kill the child immediately rather than run untracked.
	Adopt(cmd *exec.Cmd) error

	// Terminate asks the whole tree to exit (SIGTERM on Unix). Windows has no
	// tree-wide graceful signal, so there it is the same as Kill — documented
	// rather than papered over, because a caller that waits for a graceful
	// shutdown that cannot happen just adds latency to every restart.
	Terminate() error

	// Kill force-ends the whole tree.
	Kill() error

	// Close releases the OS resources. On Windows this ALSO kills the tree
	// (KILL_ON_JOB_CLOSE), which is the property that survives a proxy crash.
	Close() error
}

// NewProcessTree returns the platform implementation.
func NewProcessTree() ProcessTree { return newProcessTree() }
