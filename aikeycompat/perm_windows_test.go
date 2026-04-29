//go:build windows

package aikeycompat

import (
	"os"
	"path/filepath"
	"testing"
)

// Windows smoke: EnforceOwnerOnly on a real file in a real tempdir
// must complete without error. We can't easily inspect the resulting
// DACL from go test (no Get-Acl), so the smoke verifies the icacls
// subprocess chain works — a regression here usually means either
// icacls.exe is missing from PATH (it shouldn't be, it's a Win32
// builtin) or the args we pass have parse issues.
func TestWindowsEnforceOwnerOnlyFileSmoke(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "vault.db")
	if err := os.WriteFile(file, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := EnforceOwnerOnly(file); err != nil {
		t.Errorf("Windows EnforceOwnerOnly(file) smoke failed: %v", err)
	}
}

func TestWindowsEnforceOwnerOnlyDirSmoke(t *testing.T) {
	dir := t.TempDir()
	if err := EnforceOwnerOnly(dir); err != nil {
		t.Errorf("Windows EnforceOwnerOnly(dir) smoke failed: %v", err)
	}
}

// After hardening the dir, files we create inside must still be
// readable + writable by the current process (the inheritance flags
// ensure files inherit owner-only, with the current user as owner).
func TestWindowsFilesInsideHardenedDirAreOwnerWritable(t *testing.T) {
	dir := t.TempDir()
	if err := EnforceOwnerOnly(dir); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "inherited.db")
	if err := os.WriteFile(file, []byte("after-acl"), 0o600); err != nil {
		t.Fatalf("write after enforce: %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read after enforce: %v", err)
	}
	if string(got) != "after-acl" {
		t.Errorf("data round-trip failed; got %q", string(got))
	}
}

// USERNAME-empty fallback: the Windows perm helper says
// "Empty USERNAME falls through to skip — leaves the path with
// SYSTEM/Administrators only, which is more secure than failing open".
// Pin that contract so a future "let me just return an error" never
// silently breaks startup on a USERNAME-less environment (rare but
// possible: stripped service accounts).
func TestWindowsEnforceOwnerOnlyHandlesEmptyUsername(t *testing.T) {
	prev, hadPrev := os.LookupEnv("USERNAME")
	if err := os.Unsetenv("USERNAME"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if hadPrev {
			os.Setenv("USERNAME", prev)
		}
	}()

	dir := t.TempDir()
	// Must succeed — the SYSTEM + Administrators-only path is
	// intentional fallback, not an error.
	if err := EnforceOwnerOnly(dir); err != nil {
		t.Errorf("EnforceOwnerOnly with empty USERNAME should succeed; got %v", err)
	}
}
