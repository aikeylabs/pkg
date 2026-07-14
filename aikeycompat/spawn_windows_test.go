//go:build windows

package aikeycompat

import (
	"os/exec"
	"syscall"
	"testing"
)

// Windows contract: the child must get CREATE_NO_WINDOW + HideWindow, and
// pre-existing SysProcAttr contents (e.g. a caller-set flag) must survive.
func TestHideSpawnConsoleSetsNoWindowFlags(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	HideSpawnConsole(cmd)
	if cmd.SysProcAttr == nil {
		t.Fatal("SysProcAttr not allocated")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Error("HideWindow not set")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Errorf("CREATE_NO_WINDOW missing from CreationFlags: %#x", cmd.SysProcAttr.CreationFlags)
	}
}

func TestHideSpawnConsolePreservesExistingFlags(t *testing.T) {
	const createNewProcessGroup = 0x00000200
	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGroup}
	HideSpawnConsole(cmd)
	if cmd.SysProcAttr.CreationFlags&createNewProcessGroup == 0 {
		t.Error("pre-existing CreationFlags were clobbered")
	}
	if cmd.SysProcAttr.CreationFlags&createNoWindow == 0 {
		t.Error("CREATE_NO_WINDOW not OR-ed in")
	}
}
