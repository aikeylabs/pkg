//go:build !windows

package aikeycompat

import (
	"errors"
	"os/exec"
	"syscall"
)

// unixProcessTree uses a POSIX process group.
//
// The child is made a group leader (Setpgid with Pgid 0 ⇒ "use my own pid"), so
// every descendant inherits the group unless it deliberately calls setpgid
// itself. Signalling the NEGATIVE pgid delivers to the whole group.
type unixProcessTree struct{ pgid int }

func newProcessTree() ProcessTree { return &unixProcessTree{} }

// Prepare makes the child a process-group leader.
//
// 🔴 Setsid is deliberately NOT used. A new session would also detach the child
// from the proxy's controlling terminal, which sounds tidy and would break the
// one case that matters most in support: a developer running `aikey-proxy` in a
// terminal and pressing Ctrl-C expects the whole thing to go away. Setpgid
// gives us a killable subtree while keeping the terminal relationship.
func (t *unixProcessTree) Prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pgid = 0 // 0 ⇒ the child's own pid becomes the group id
}

func (t *unixProcessTree) Adopt(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("aikeycompat: Adopt called before the process started")
	}
	// The pgid EQUALS the pid because Prepare asked for a new group led by the
	// child. Reading it back with Getpgid would be more faithful, but it races
	// with a child that exits immediately — and if the child is already gone
	// there is no group left to signal anyway.
	t.pgid = cmd.Process.Pid
	return nil
}

func (t *unixProcessTree) Terminate() error { return t.signal(syscall.SIGTERM) }
func (t *unixProcessTree) Kill() error      { return t.signal(syscall.SIGKILL) }

// Close is a no-op on Unix: a process group is not a handle, it is just an id.
//
// 🔴 This is the asymmetry that matters for correctness. On Windows, Close()
// alone reaps the tree even if the proxy is SIGKILLed. On Unix there is no such
// guarantee — a SIGKILLed proxy leaves the group running, reparented to init.
// The caller must therefore reap explicitly on every exit path it controls,
// and the Unix orphan fence (5.F2) is testing exactly that discipline rather
// than an OS guarantee.
func (t *unixProcessTree) Close() error { return nil }

func (t *unixProcessTree) signal(sig syscall.Signal) error {
	if t.pgid <= 0 {
		return nil // never adopted, or already reaped
	}
	// 🔴 NEGATIVE pgid: this is the whole point. syscall.Kill(pid, …) reaches
	// one process; syscall.Kill(-pgid, …) reaches the group. A missing minus
	// sign here is invisible in every test that spawns a single-process child
	// and catastrophic for `npx`, which is the shape we actually ship.
	err := syscall.Kill(-t.pgid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil // already gone; not a failure
	}
	return err
}
