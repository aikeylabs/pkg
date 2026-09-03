//go:build windows

package aikeycompat

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// unsafePointer / unsafeSizeof isolate the two unsafe operations this file
// needs, so a reader can see the whole unsafe surface in four lines rather than
// hunting for it inside the job-configuration call.
func unsafePointer(v *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) unsafe.Pointer {
	return unsafe.Pointer(v)
}

func unsafeSizeof(v windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) uintptr {
	return unsafe.Sizeof(v)
}

// windowsProcessTree uses a Job Object.
//
// # Why a job and not "kill the process"
//
// Windows has no POSIX process group that a signal can address. `taskkill /T`
// walks the parent-pid chain, which is unreliable precisely where it matters:
// the parent pid is not authoritative, it is reused, and a launcher that exits
// after spawning its real worker (which `npx` does) breaks the chain outright.
// A Job Object is the only primitive the kernel itself maintains: a process
// assigned to a job cannot leave it, and every process it creates joins it.
//
// # The one property Unix cannot match
//
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: when the LAST handle to the job closes,
// the kernel terminates everything in it. That includes the case where the
// proxy is killed outright and runs no cleanup code — the handle closes because
// the process died, and the tree dies with it.
//
// 🔴 This is why the Windows orphan fence (5.F1) must include a HARD-KILL case,
// not only a graceful shutdown: the graceful path exercises our code, and the
// hard-kill path exercises the property we are actually relying on.
type windowsProcessTree struct {
	job windows.Handle
}

func newProcessTree() ProcessTree { return &windowsProcessTree{} }

// Prepare puts the child in its own process group.
//
// CREATE_NEW_PROCESS_GROUP is NOT what does the tree-killing here — the job
// does that. It is set so that a Ctrl-C delivered to the proxy's console is not
// broadcast into the backend child, which would race our own shutdown sequence
// and produce a child that dies before we can record why.
func (t *windowsProcessTree) Prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_NEW_PROCESS_GROUP
}

// Adopt creates the job and assigns the started process to it.
//
// 🔴 KNOWN RACE, recorded rather than hidden. The job is created and assigned
// AFTER cmd.Start() returns, because os/exec gives no hook between "process
// created" and "process runs" — Go does not expose the child's primary thread
// handle, so the textbook CREATE_SUSPENDED + assign + ResumeThread sequence is
// not available without reimplementing CreateProcess.
//
// The window is the microseconds between Start() returning and the assignment.
// A grandchild created inside that window would escape the job. In practice the
// first thing an MCP backend does is read its stdin, and no launcher we ship
// against forks that fast — but "in practice" is the honest strength of this
// claim, not "cannot happen".
//
// What the window does NOT affect: the child itself is always assigned, so the
// common case (kill the backend and its worker) is covered, and
// KILL_ON_JOB_CLOSE still reaps everything that IS in the job when the proxy
// dies. If a real escape is ever observed, the fix is a CreateProcess wrapper,
// not a bigger sleep.
func (t *windowsProcessTree) Adopt(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return errors.New("aikeycompat: Adopt called before the process started")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafePointer(&info)),
		uint32(unsafeSizeof(info)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("set job limits: %w", err)
	}
	// OpenProcess rather than reusing cmd.Process: os/exec's handle is owned by
	// the runtime and closed when Wait() returns, and assigning through a handle
	// somebody else may close is how this ends up silently doing nothing.
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("open child process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()

	if err := windows.AssignProcessToJobObject(job, h); err != nil {
		_ = windows.CloseHandle(job)
		return fmt.Errorf("assign child to job: %w", err)
	}
	t.job = job
	return nil
}

// Terminate is the same as Kill on Windows.
//
// 🔴 Stated rather than emulated. There is no tree-wide graceful signal: a
// console Ctrl event only reaches processes attached to the same console, which
// a detached backend child is not. Pretending otherwise would make every
// restart wait out a grace period for a signal nobody receives — latency spent
// on a fiction.
func (t *windowsProcessTree) Terminate() error { return t.Kill() }

func (t *windowsProcessTree) Kill() error {
	if t.job == 0 {
		return nil
	}
	if err := windows.TerminateJobObject(t.job, 1); err != nil {
		return fmt.Errorf("terminate job: %w", err)
	}
	return nil
}

func (t *windowsProcessTree) Close() error {
	if t.job == 0 {
		return nil
	}
	// Closing the last handle terminates everything still in the job.
	err := windows.CloseHandle(t.job)
	t.job = 0
	return err
}
