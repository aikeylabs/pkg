//go:build !windows

package aikeycompat

// P5 fence 5.F2 — orphan reaping on macOS / Linux, checked against the real
// PROCESS TABLE.
//
// 🔴 The task is explicit that a log assertion does not count, and the reason is
// concrete: every implementation of this logs "killed child" correctly,
// including the broken one. What separates them is whether a GRANDCHILD is
// still in the process table afterwards.
//
// The shape under test is the one we actually ship against:
//
//	npx -y @modelcontextprotocol/server-postgres
//	 └─ node …                      ← this is what holds the database password
//
// modelled here as `sh -c 'sleep & sleep'`: a launcher that spawns a worker and
// then keeps running. Killing the launcher alone leaves the worker.

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// spawnLauncherAndWorker starts a shell that forks a background worker and
// prints its pid, then keeps running itself. Returns the cmd and the worker pid.
func spawnLauncherAndWorker(t *testing.T, tree ProcessTree) (*exec.Cmd, int) {
	t.Helper()
	// The worker sleeps far longer than the test could ever run, so a live
	// worker at assertion time is a real leak and never a timing artefact.
	cmd := exec.Command("/bin/sh", "-c", `sleep 300 & echo WORKER:$!; sleep 300`)
	if tree != nil {
		tree.Prepare(cmd)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if tree != nil {
		if err := tree.Adopt(cmd); err != nil {
			t.Fatalf("adopt: %v", err)
		}
	}

	worker := 0
	scanner := bufio.NewScanner(stdout)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "WORKER:"); ok {
			worker, _ = strconv.Atoi(rest)
			break
		}
	}
	if worker <= 0 {
		t.Fatalf("the launcher never reported a worker pid; the scenario did not set up")
	}
	if !alive(worker) {
		t.Fatalf("precondition: worker %d is not running", worker)
	}
	return cmd, worker
}

// alive reports whether a pid exists, via signal 0.
//
// 🔴 Only valid for a process that is NOT our own child. A dead child we have
// not Wait()ed for is a zombie, and a zombie still answers signal 0 — which
// would make this helper report "alive" for something already dead. Every
// assertion below therefore targets the WORKER (a grandchild, reparented to
// init when its parent dies), never the launcher.
func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// reap waits for the launcher to be collected, but never forever.
//
// 🔴 Bounded on purpose. `cmd.Wait()` blocks until the process actually dies,
// so a BROKEN reap turns these tests into a HANG rather than a failure — which
// is what happened when the process-group mutation was drilled: the fence
// noticed, but reported it by wedging for the full test timeout with no
// message. A fence that hangs instead of failing is a bad fence: CI shows a
// timeout with no cause, and the developer has to bisect to learn what this
// file could have told them in one line.
func reap(t *testing.T, cmd *exec.Cmd, within time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(within):
		// Not fatal here: the ORPHAN assertion in the caller is the finding we
		// want reported, and failing first would hide it behind a less specific
		// message.
		t.Logf("launcher pid %d did not exit within %s — the reap did not reach it",
			cmd.Process.Pid, within)
	}
}

// waitGone polls until the pid disappears or the deadline passes.
func waitGone(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !alive(pid) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return !alive(pid)
}

// TestProcessTree_KillReapsTheWholeTree is the fence.
func TestProcessTree_KillReapsTheWholeTree(t *testing.T) {
	tree := NewProcessTree()
	cmd, worker := spawnLauncherAndWorker(t, tree)
	t.Cleanup(func() { _ = tree.Kill(); reap(t, cmd, 2*time.Second) })

	if err := tree.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	reap(t, cmd, 3*time.Second)

	if !waitGone(worker, 3*time.Second) {
		// Leave the pid in the message: on a failure the developer wants to go
		// look at it, and by the time they read this the test has exited.
		t.Fatalf("🔴 ORPHAN: worker %d survived the tree kill. On a real backend this is a "+
			"process holding a decrypted credential, reparented to init, with no proxy left "+
			"to ask it to exit.", worker)
	}
}

// TestProcessTree_TerminateReapsTheWholeTree — the graceful path.
func TestProcessTree_TerminateReapsTheWholeTree(t *testing.T) {
	tree := NewProcessTree()
	cmd, worker := spawnLauncherAndWorker(t, tree)
	t.Cleanup(func() { _ = tree.Kill(); reap(t, cmd, 2*time.Second) })

	if err := tree.Terminate(); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	reap(t, cmd, 3*time.Second)

	if !waitGone(worker, 3*time.Second) {
		t.Fatalf("🔴 ORPHAN: worker %d survived SIGTERM to the process group (pid %d)", worker, cmd.Process.Pid)
	}
}

// TestProcessTree_WithoutItTheWorkerSurvives is the CONTROL, and without it the
// two tests above prove nothing.
//
// 🔴 A fence that only ever sees the fixed code cannot tell "the fix works"
// from "this scenario never leaked in the first place". This asserts the leak
// EXISTS when the process tree is not used — i.e. that `cmd.Process.Kill()`,
// the obvious thing to write, really does leave the worker running.
//
// If this test ever starts failing, do not delete it: it means the scenario
// stopped reproducing the shape we ship against, and the two fences above
// silently became vacuous.
func TestProcessTree_WithoutItTheWorkerSurvives(t *testing.T) {
	cmd, worker := spawnLauncherAndWorker(t, nil)
	t.Cleanup(func() {
		_ = syscall.Kill(worker, syscall.SIGKILL)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	// The naive reap: kill the process we started, and only that one.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = cmd.Wait()

	// Give it the same grace the real assertions get. The worker must STILL be
	// there — that is the leak this feature exists to close.
	if waitGone(worker, 500*time.Millisecond) {
		t.Fatalf("the control scenario no longer leaks: worker %d died when its launcher was "+
			"killed. TestProcessTree_KillReapsTheWholeTree is now vacuous and this whole file "+
			"needs a scenario that reproduces the npx→node shape again.", worker)
	}
}

// TestProcessTree_AdoptBeforeStartIsRefused — the ordering mistake that would
// otherwise fail silently on Unix (the group exists either way) and reap
// nothing on Windows.
func TestProcessTree_AdoptBeforeStartIsRefused(t *testing.T) {
	tree := NewProcessTree()
	cmd := exec.Command("/bin/sh", "-c", "true")
	tree.Prepare(cmd)
	if err := tree.Adopt(cmd); err == nil {
		t.Fatal("Adopt before Start must be refused — on Windows it would assign nothing to " +
			"the job and every later Terminate would affect zero processes, with no error")
	}
}

// TestProcessTree_ReapingAnAlreadyDeadTreeIsNotAnError — restart paths call
// Kill unconditionally; a dead tree must not turn a normal restart into a
// logged failure.
func TestProcessTree_ReapingAnAlreadyDeadTreeIsNotAnError(t *testing.T) {
	tree := NewProcessTree()
	cmd := exec.Command("/bin/sh", "-c", "true")
	tree.Prepare(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := tree.Adopt(cmd); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	_ = cmd.Wait() // it has already exited

	if err := tree.Terminate(); err != nil {
		t.Fatalf("terminating an already-exited tree must be a no-op, got %v", err)
	}
	if err := tree.Kill(); err != nil {
		t.Fatalf("killing an already-exited tree must be a no-op, got %v", err)
	}
	if err := tree.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
