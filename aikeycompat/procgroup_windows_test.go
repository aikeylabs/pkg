//go:build windows

package aikeycompat

// P5 fence 5.F1 — orphan reaping on Windows, checked against the real PROCESS
// TABLE via OpenProcess.
//
// 🔴 STATUS: written, NEVER EXECUTED. It was authored on macOS and has not run
// on a Windows host. Treat a green CI run as the first real evidence; until
// then 5.F1 is unproven and tasks.md says so. This comment exists so nobody
// reads the file's existence as the check having passed.
//
// Windows is called out in the plan as the highest-risk part of P5 because its
// process model differs most: there are no process groups in the POSIX sense,
// the parent-pid chain is not authoritative, and `npx` — the canonical launcher
// — exits after spawning its worker, which breaks tree-walking tools outright.
// The Job Object is the only primitive that survives all three.

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// aliveWin reports whether a pid is a LIVE process.
//
// 🔴 OpenProcess alone is not enough: a handle can still be opened for a
// process that has exited but whose handle is not yet released, and it would
// answer "alive" for something already dead — the Windows counterpart of the
// Unix zombie trap. GetExitCodeProcess distinguishes them: STILL_ACTIVE (259)
// means running.
func aliveWin(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	const stillActive = 259
	return code == stillActive
}

func waitGoneWin(pid int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if !aliveWin(pid) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return !aliveWin(pid)
}

// spawnLauncherAndWorkerWin models npx→node: cmd.exe starts a detached worker,
// prints its pid, then keeps running.
func spawnLauncherAndWorkerWin(t *testing.T, tree ProcessTree) (*exec.Cmd, int) {
	t.Helper()
	// `start /b` gives a worker that is NOT a direct child of the process we
	// hold — the same relationship npx creates and the same one taskkill /T
	// gets wrong.
	script := `for /f "tokens=2 delims=," %A in ('wmic process call create "timeout /t 300" ^| findstr ProcessId') do @echo WORKER:%A & timeout /t 300 >nul`
	cmd := exec.Command("cmd.exe", "/c", script)
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
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if rest, ok := strings.CutPrefix(line, "WORKER:"); ok {
			worker, _ = strconv.Atoi(strings.TrimSpace(strings.Trim(rest, "\r\x00 ")))
			break
		}
	}
	if worker <= 0 {
		t.Skipf("could not establish the launcher→worker scenario on this host; " +
			"🔴 a SKIP here means 5.F1 did not run — it is not a pass")
	}
	if !aliveWin(worker) {
		t.Fatalf("precondition: worker %d is not running", worker)
	}
	return cmd, worker
}

// TestProcessTree_KillReapsTheWholeTree — the job terminates the subtree.
func TestProcessTree_KillReapsTheWholeTree(t *testing.T) {
	tree := NewProcessTree()
	cmd, worker := spawnLauncherAndWorkerWin(t, tree)
	t.Cleanup(func() { _ = tree.Kill(); _ = tree.Close(); _ = cmd.Wait() })

	if err := tree.Kill(); err != nil {
		t.Fatalf("kill: %v", err)
	}
	_ = cmd.Wait()

	if !waitGoneWin(worker, 5*time.Second) {
		t.Fatalf("🔴 ORPHAN: worker %d survived TerminateJobObject. On a real backend this is a "+
			"process holding a decrypted credential with no proxy left to ask it to exit.", worker)
	}
}

// TestProcessTree_ClosingTheJobHandleReapsTheTree is the Windows-ONLY case, and
// the most important one in this file.
//
// 🔴 It exercises the property we rely on when the proxy does not get to run any
// cleanup at all — killed from Task Manager, or by the OS. On Unix there is no
// equivalent guarantee, which is why the Unix file has no counterpart to this
// and why the Unix side must reap explicitly on every exit path.
func TestProcessTree_ClosingTheJobHandleReapsTheTree(t *testing.T) {
	tree := NewProcessTree()
	cmd, worker := spawnLauncherAndWorkerWin(t, tree)
	t.Cleanup(func() { _ = cmd.Wait() })

	// 🚫 No Terminate, no Kill. Only the handle closing — which is what happens
	// when the proxy process dies without running anything.
	if err := tree.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !waitGoneWin(worker, 5*time.Second) {
		t.Fatalf("🔴 KILL_ON_JOB_CLOSE did not take effect: worker %d survived the job handle "+
			"closing. A hard-killed proxy would leave this process running with a live "+
			"credential in it.", worker)
	}
}

// TestProcessTree_WithoutItTheWorkerSurvives is the CONTROL.
//
// Without it the two tests above cannot distinguish "the job works" from "this
// scenario never leaked". If this ever passes-as-reaped, the scenario stopped
// reproducing the shape we ship against and 5.F1 became vacuous.
func TestProcessTree_WithoutItTheWorkerSurvives(t *testing.T) {
	cmd, worker := spawnLauncherAndWorkerWin(t, nil)
	t.Cleanup(func() {
		if h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(worker)); err == nil {
			_ = windows.TerminateProcess(h, 1)
			_ = windows.CloseHandle(h)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill launcher: %v", err)
	}
	_ = cmd.Wait()

	if waitGoneWin(worker, 1*time.Second) {
		t.Fatalf("the control scenario no longer leaks: worker %d died with its launcher. "+
			"The Job Object fences above are now vacuous and this file needs a scenario that "+
			"reproduces the npx→node shape again.", worker)
	}
}
