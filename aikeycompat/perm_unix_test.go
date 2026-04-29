//go:build !windows

package aikeycompat

import (
	"os"
	"path/filepath"
	"testing"
)

// On Unix, EnforceOwnerOnly is intentionally a no-op (perm_unix.go
// docstring spells out why). The test pins this contract so a future
// "I'll just add a Chmod" temptation gets caught immediately — that
// would silently tighten every event-WAL directory in the codebase
// from 0o755 to 0o600, breaking any observability tooling that runs as
// a different unix user but the same group.
func TestUnixEnforceOwnerOnlyDoesNotChmod(t *testing.T) {
	dir := t.TempDir()
	// Caller's MkdirAll mode (0o755) is the source of truth on Unix;
	// EnforceOwnerOnly must not touch it.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("setup chmod: %v", err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnforceOwnerOnly(dir); err != nil {
		t.Fatalf("EnforceOwnerOnly: %v", err)
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != after.Mode().Perm() {
		t.Errorf(
			"EnforceOwnerOnly silently chmod'd Unix dir from %v to %v — Unix contract violated",
			before.Mode().Perm(), after.Mode().Perm(),
		)
	}

	// Same check for a file.
	file := filepath.Join(dir, "wal.jsonl")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	beforeF, _ := os.Stat(file)
	if err := EnforceOwnerOnly(file); err != nil {
		t.Fatalf("EnforceOwnerOnly file: %v", err)
	}
	afterF, _ := os.Stat(file)
	if beforeF.Mode().Perm() != afterF.Mode().Perm() {
		t.Errorf(
			"EnforceOwnerOnly silently chmod'd Unix file from %v to %v",
			beforeF.Mode().Perm(), afterF.Mode().Perm(),
		)
	}
}
