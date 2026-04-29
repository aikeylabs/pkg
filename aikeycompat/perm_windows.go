//go:build windows

package aikeycompat

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// EnforceOwnerOnly tightens an NTFS file or directory ACL so only the
// current user (plus SYSTEM and Administrators for service / recovery
// access) can read or write.
//
// Why icacls and not `golang.org/x/sys/windows.SetNamedSecurityInfo`:
//
//   - icacls is Microsoft-tested for the exact "owner-only file" use
//     case; building an explicit DACL via the Win32 SID + ACE APIs is
//     ~150 lines of unsafe FFI with several easy-to-miss security
//     pitfalls (wrong inheritance flags, empty DACL = "no access" vs
//     missing DACL = "full access", SID resolution races on domain
//     accounts, etc.).
//   - The installer scripts (Stage 4 D6/D7) will use icacls anyway,
//     so this keeps the hardening tool consistent end-to-end.
//   - aikey-cli's Rust storage_acl module makes the same call for the
//     same reasons — see `aikey-cli/src/storage_acl.rs`.
//
// Idempotent: re-running on the same path replaces existing grants
// rather than appending. Returns nil if the path doesn't exist (no-op
// — caller's MkdirAll/WriteFile error path will surface the problem).
func EnforceOwnerOnly(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve abs path: %w", err)
	}
	if _, err := os.Stat(abs); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	// Step 1: strip inherited ACEs (the source of the Authenticated
	// Users grant we want to remove).
	if err := runIcacls(abs, "/inheritance:r"); err != nil {
		return err
	}

	// Step 2: grant current user FullControl. Use USERNAME env var
	// rather than os/user (extra dep + WMI roundtrip on domain
	// accounts). Empty USERNAME falls through to skip — leaves the
	// path with SYSTEM/Administrators only, which is more secure than
	// failing open.
	username := os.Getenv("USERNAME")
	for _, principal := range []string{username, "SYSTEM", "Administrators"} {
		if principal == "" {
			continue
		}
		// (OI)(CI)F = object + container inheritance, full control —
		// applied to dirs so files created inside inherit owner-only.
		// On a file the inheritance flags are no-ops; icacls accepts
		// them silently.
		grant := fmt.Sprintf("%s:(OI)(CI)F", principal)
		if err := runIcacls(abs, "/grant:r", grant); err != nil {
			return err
		}
	}

	return nil
}

func runIcacls(path string, args ...string) error {
	full := append([]string{path}, args...)
	cmd := exec.Command("icacls", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls %v: %w (output: %s)", args, err, string(out))
	}
	return nil
}
